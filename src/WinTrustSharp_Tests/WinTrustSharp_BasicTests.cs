//
// Authors:
//   Steven Tolzmann
//
// Copyright (C) 2025 Steven Tolzmann

using System.Security.Cryptography.X509Certificates;
using WinTrustSharp;

namespace WinTrustSharp_Tests
{
    public class WinTrustSharp_BasicTests
    {
        private const string ValidFileName = @"TestFiles\wintrust_VALID.dll";           // Signed & valid
        private const string InvalidFileName = @"TestFiles\wintrust_INVALID.dll";       // Signed but tampered/invalid signature
        private const string NoCertFileName = @"TestFiles\HelloWorld_NOCERT.dll";       // Completely unsigned
        private const string MissingFileName = @"TestFiles\missing_does_not_exist.dll"; // Intentionally absent

        [Fact]
        public void TestEnvironment_WindowsOnly()
        {
            Assert.True(OperatingSystem.IsWindows(), "Tests can only be run on Windows.");
        }

        // VALID FILE TESTS ----------------------------------------------------

        [Fact]
        public void Verify_ValidFile_ReturnsTrue()
        {
            Assert.True(Authenticode.Verify(new FileInfo(ValidFileName)));
        }

        [Fact]
        public void VerifyFull_ValidFile_ReturnsTrue()
        {
            Assert.True(Authenticode.VerifyFull(ValidFileName));
        }

        [Fact]
        public void VerifyFull_Callback_ValidFile_ReturnsTrue()
        {
            bool result = Authenticode.VerifyFull(ValidFileName, (cert, chain) =>
            {
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.Build(cert);
                return cert.Verify();
            });

            Assert.True(result);
        }

        [Fact]
        public void VerifyFull_Callback_ValidFile_ForcedFailure_ReturnsFalse()
        {
            bool result = Authenticode.VerifyFull(ValidFileName, (_, _) => false);
            Assert.False(result);
        }

        // INVALID (SIGNED BUT NOT TRUSTED) FILE TESTS -------------------------

        [Fact]
        public void Verify_InvalidFile_ReturnsFalse()
        {
            Assert.False(Authenticode.Verify(new FileInfo(InvalidFileName)));
        }

        [Fact]
        public void VerifyFull_InvalidFile_ReturnsFalse_DoesNotThrow()
        {
            bool result = Authenticode.VerifyFull(InvalidFileName);
            Assert.False(result); // Certificate loaded, but cert.Verify() failed.
        }

        [Fact]
        public void VerifyFull_Callback_InvalidFile_CallbackSeesCert_ReturnsFalse()
        {
            bool callbackInvoked = false;
            bool result = Authenticode.VerifyFull(InvalidFileName, (cert, chain) =>
            {
                callbackInvoked = true;
                chain.Build(cert); // Likely fails, we force false anyway.
                return false;
            });

            Assert.True(callbackInvoked);
            Assert.False(result);
        }

        // NO CERT (UNSIGNED) FILE TESTS ---------------------------------------

        [Fact]
        public void Verify_NoCertFile_ReturnsFalse()
        {
            Assert.False(Authenticode.Verify(new FileInfo(NoCertFileName)));
        }

        [Fact]
        public void VerifyFull_NoCertFile_ReturnsFalse()
        {
            // Unsigned => public API now returns false instead of throwing.
            bool result = Authenticode.VerifyFull(NoCertFileName);
            Assert.False(result);
        }

        [Fact]
        public void VerifyFull_Callback_NoCertFile_ReturnsFalse_CallbackNotInvoked()
        {
            bool callbackInvoked = false;
            bool result = Authenticode.VerifyFull(NoCertFileName, (cert, chain) =>
            {
                callbackInvoked = true; // Should not happen for unsigned file.
                return true;
            });

            Assert.False(callbackInvoked);
            Assert.False(result);
        }

        // MISSING FILE TESTS (FileNotFoundException should propagate) ---------

        [Fact]
        public void VerifyFull_MissingFile_ThrowsFileNotFoundException()
        {
            Assert.Throws<FileNotFoundException>(() => Authenticode.VerifyFull(MissingFileName));
        }

        [Fact]
        public void VerifyFull_Callback_MissingFile_ThrowsFileNotFoundException()
        {
            Assert.Throws<FileNotFoundException>(() =>
                Authenticode.VerifyFull(MissingFileName, (_, _) => true));
        }
    }
}