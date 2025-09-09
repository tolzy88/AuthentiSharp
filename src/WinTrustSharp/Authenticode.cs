//
// Authors:
//   Steven Tolzmann
//
// Copyright (C) 2025 Steven Tolzmann

using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using WinTrustSharp.Internal;

namespace WinTrustSharp
{
    /// <summary>
    /// Provides helper methods for validating Authenticode (Windows code-signing) signatures on PE files (EXE/DLL, etc.).
    /// </summary>
    /// <remarks>
    /// <para>These APIs ultimately invoke the native WinVerifyTrust infrastructure (via <c>wintrust.dll</c>)
    /// to determine signature validity. They are only meaningful on Windows; use-site guards are recommended
    /// if your library/app can execute on non-Windows platforms.</para>
    /// <para>No exceptions are thrown for an invalid or untrusted signature; the methods simply return <c>false</c>.
    /// A <see cref="CryptographicException"/> is thrown only when the target file is not Authenticode signed at all
    /// (i.e. no embedded signature is present) during the certificate extraction phase of the <c>VerifyFull</c> methods.</para>
    /// <para>The methods are thread-safe and impose no mutable shared state.</para>
    /// </remarks>
    /// <example>
    /// <code>
    /// var file = new FileInfo("SomeLibrary.dll");
    /// if (Authenticode.Verify(file))
    /// {
    ///     // Signature structure is valid (hash matches, signature block parses)
    /// }
    /// 
    /// bool fullyTrusted = Authenticode.VerifyFull(file);
    /// // fullyTrusted == true means: signature structurally valid AND certificate basic validation succeeded.
    /// </code>
    /// </example>
    public static class Authenticode
    {
        /// <summary>
        /// Performs a basic Authenticode signature validation on the specified file.
        /// </summary>
        /// <param name="file">The file whose Authenticode signature should be validated.</param>
        /// <returns>
        /// <c>true</c> if the file contains an Authenticode signature and the low-level WinVerifyTrust
        /// policy check reports success; otherwise <c>false</c>.
        /// </returns>
        /// <remarks>
        /// <para>This does NOT perform certificate chain or revocation validation. It only verifies the
        /// embedded signature blob (hash/content) via WinVerifyTrust with minimal policy flags.</para>
        /// <para>If the file is completely unsigned, this method returns <c>false</c> rather than throwing.</para>
        /// </remarks>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool Verify(FileInfo file) =>
            WinTrustInternal.VerifyAuthenticode(file.FullName);

        /// <summary>
        /// Performs a two-phase validation on the specified file:
        /// (1) basic certificate verification using <see cref="X509Certificate2.Verify()"/> and
        /// (2) structural Authenticode signature verification.
        /// </summary>
        /// <param name="file">The file to validate.</param>
        /// <returns>
        /// <c>true</c> if the file is Authenticode signed, the signing certificate passes
        /// <see cref="X509Certificate2.Verify()"/> basic checks, and the signature itself is valid; otherwise <c>false</c>.
        /// </returns>
        /// <exception cref="CryptographicException">
        /// Thrown if the file is not Authenticode signed (no embedded signature to extract).
        /// </exception>
        /// <remarks>
        /// <para>No revocation configuration is explicitly applied; platform defaults are used by
        /// <see cref="X509Certificate2.Verify()"/>.</para>
        /// <para>Failure of certificate trust or signature validity yields <c>false</c>, not an exception.</para>
        /// </remarks>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool VerifyFull(FileInfo file)
            => VerifyFull(file.FullName);

        /// <summary>
        /// Performs basic certificate validation (via <see cref="X509Certificate2.Verify()"/>) followed by
        /// Authenticode signature validation on the specified file path.
        /// </summary>
        /// <param name="filePath">The full path to the file to validate.</param>
        /// <returns>
        /// <c>true</c> if the file is signed, the certificate passes basic trust validation, and the signature is valid;
        /// otherwise <c>false</c>.
        /// </returns>
        /// <exception cref="CryptographicException">
        /// Thrown if the file is not Authenticode signed (no embedded signature present).
        /// </exception>
        /// <remarks>
        /// <para>Chain building nuances (revocation mode, extra stores, etc.) are not controlled here; for advanced
        /// scenarios use the overload that accepts a validation callback.</para>
        /// </remarks>
        public static bool VerifyFull(string filePath)
        {
            using (var cert = LoadAuthenticodeCertificate(filePath))
            {
                if (!cert.Verify())
                    return false;
            }
            return WinTrustInternal.VerifyAuthenticode(filePath);
        }

        /// <summary>
        /// Performs certificate and chain evaluation using a caller-supplied callback before performing
        /// Authenticode signature validation (if the callback indicates validity).
        /// </summary>
        /// <param name="file">The file to validate.</param>
        /// <param name="isCertValid">
        /// A delegate that receives the extracted signing certificate and a new <see cref="X509Chain"/> instance.
        /// Return <c>true</c> to proceed with signature verification; <c>false</c> to short-circuit and return <c>false</c>.
        /// </param>
        /// <returns>
        /// <c>true</c> only if the callback returns <c>true</c> and the signature validation succeeds; otherwise <c>false</c>.
        /// </returns>
        /// <exception cref="CryptographicException">The file is not Authenticode signed.</exception>
        /// <remarks>
        /// <para>Use this overload to implement custom chain policies (revocation flags, additional trust anchors, etc.).</para>
        /// </remarks>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool VerifyFull(FileInfo file, Func<X509Certificate2, X509Chain, bool> isCertValid)
            => VerifyFull(file.FullName, isCertValid);

        /// <summary>
        /// Performs certificate and chain evaluation using a caller-supplied callback for the file at the given path,
        /// and if that succeeds, performs Authenticode signature validation.
        /// </summary>
        /// <param name="filePath">The full path to the file being validated.</param>
        /// <param name="isCertValid">
        /// A delegate that receives the extracted signing certificate and a disposable <see cref="X509Chain"/>.
        /// Return <c>true</c> to proceed with signature verification; <c>false</c> to fail fast.
        /// </param>
        /// <returns>
        /// <c>true</c> if the callback approves the certificate/chain AND the Authenticode signature is valid; otherwise <c>false</c>.
        /// </returns>
        /// <exception cref="CryptographicException">The file is not Authenticode signed.</exception>
        /// <remarks>
        /// <para>The chain object is created per invocation; customize <see cref="X509Chain.ChainPolicy"/> inside the callback.</para>
        /// </remarks>
        public static bool VerifyFull(string filePath, Func<X509Certificate2, X509Chain, bool> isCertValid)
        {
            using (var cert = LoadAuthenticodeCertificate(filePath))
            using (var chain = new X509Chain())
            {
                if (!isCertValid(cert, chain))
                    return false;
            }
            return WinTrustInternal.VerifyAuthenticode(filePath);
        }

        /// <summary>
        /// Loads the signing certificate from an Authenticode signed file.
        /// https://github.com/dotnet/runtime/discussions/108740
        /// </summary>
        /// <param name="file">The path to the file from which to extract the certificate.</param>
        /// <returns>The extracted <see cref="X509Certificate2"/>.</returns>
        /// <exception cref="CryptographicException">Thrown when the file is not Authenticode signed.</exception>
        private static X509Certificate2 LoadAuthenticodeCertificate(string file)
        {
            if (X509Certificate2.GetCertContentType(file) == X509ContentType.Authenticode)
            {
#pragma warning disable SYSLIB0057
                return new X509Certificate2(file);
#pragma warning restore SYSLIB0057
            }

            throw new CryptographicException("The file is not Authenticode Signed.");
        }
    }
}