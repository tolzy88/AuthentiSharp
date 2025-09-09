using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using WinTrustSharp;
using Xunit;

namespace WinTrustSharp_Tests
{
    public class WinTrustSharp_BasicTests
    {
        private const string ValidFileName = "wintrust_VALID.dll";          // Signed & valid
        private const string InvalidFileName = "wintrust_INVALID.dll";      // Signed but not trusted / invalid
        private const string NoCertFileName = "HelloWorld_NOCERT.dll";      // Completely unsigned

        private static string GetTestFile(string fileName)
            => Path.Combine(AppContext.BaseDirectory, "TestFiles", fileName);

        private static void EnsureExists(string path)
            => Assert.True(File.Exists(path), $"Test file not found: {path}");

        [Fact]
        public void TestEnvironment_WindowsOnly()
        {
            Assert.True(OperatingSystem.IsWindows(), "Tests can only be run on Windows.");
        }

        // VALID FILE TESTS ----------------------------------------------------

        [Fact]
        public void Verify_ValidFile_ReturnsTrue()
        {
            var path = GetTestFile(ValidFileName);
            EnsureExists(path);

            Assert.True(Authenticode.Verify(new FileInfo(path)));
        }

        [Fact]
        public void VerifyFull_ValidFile_ReturnsTrue()
        {
            var path = GetTestFile(ValidFileName);
            EnsureExists(path);

            Assert.True(Authenticode.VerifyFull(path));
        }

        [Fact]
        public void VerifyFull_Callback_ValidFile_ReturnsTrue()
        {
            var path = GetTestFile(ValidFileName);
            EnsureExists(path);

            bool result = Authenticode.VerifyFull(path, (cert, chain) =>
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
            var path = GetTestFile(ValidFileName);
            EnsureExists(path);

            bool result = Authenticode.VerifyFull(path, (_, _) => false);
            Assert.False(result);
        }

        // INVALID (SIGNED BUT NOT TRUSTED) FILE TESTS -------------------------

        [Fact]
        public void Verify_InvalidFile_ReturnsFalse()
        {
            var path = GetTestFile(InvalidFileName);
            EnsureExists(path);

            Assert.False(Authenticode.Verify(new FileInfo(path)));
        }

        [Fact]
        public void VerifyFull_InvalidFile_ReturnsFalse_DoesNotThrow()
        {
            var path = GetTestFile(InvalidFileName);
            EnsureExists(path);

            bool result = Authenticode.VerifyFull(path);
            Assert.False(result); // Certificate loaded, but cert.Verify() failed.
        }

        [Fact]
        public void VerifyFull_Callback_InvalidFile_CallbackSeesCert_ReturnsFalse()
        {
            var path = GetTestFile(InvalidFileName);
            EnsureExists(path);

            bool callbackInvoked = false;
            bool result = Authenticode.VerifyFull(path, (cert, chain) =>
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
            var path = GetTestFile(NoCertFileName);
            EnsureExists(path);

            Assert.False(Authenticode.Verify(new FileInfo(path)));
        }

        [Fact]
        public void VerifyFull_NoCertFile_ThrowsCryptographicException()
        {
            var path = GetTestFile(NoCertFileName);
            EnsureExists(path);

            Assert.Throws<CryptographicException>(() => Authenticode.VerifyFull(path));
        }

        [Fact]
        public void VerifyFull_Callback_NoCertFile_ThrowsCryptographicException()
        {
            var path = GetTestFile(NoCertFileName);
            EnsureExists(path);

            Assert.Throws<CryptographicException>(() => Authenticode.VerifyFull(path));
        }
    }
}