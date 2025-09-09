# WinTrustSharp

Lightweight .NET interop for validating Windows Authenticode (code-signing) signatures on PE files (EXE/DLL).

```
WinTrustSharp_Tests
  Tests in group: 11
   Total Duration: 38 ms

Outcomes
   11 Passed
```

---

## Features

- **Verify**: Check if a file has a valid Authenticode signature (structural only).
- **VerifyFull**: Validate both the signature and the signing certificate chain.
- **Custom Policy**: Supply your own `X509Chain` policy for revocation checks, extra roots, etc.
- **Thread-safe** and dependency-free (just P/Invoke to `wintrust.dll`).

---

## Install
[Get it on NuGet!](https://www.nuget.org/packages/WinTrustSharp)

```bash
# Package Id
WinTrustSharp

# dotnet CLI
dotnet add package WinTrustSharp

# Package Manager
Install-Package WinTrustSharp
```

## Usage

```csharp
using System.IO;
using WinTrustSharp;

// Structural signature check only
bool ok = Authenticode.Verify(new FileInfo("SomeLibrary.dll"));

// Full validation (certificate trust + signature structure)
bool trusted;
try
{
    trusted = Authenticode.VerifyFull("SomeLibrary.dll");
}
catch (CryptographicException)
{
    // File is not Authenticode signed
    trusted = false;
}
```

## Custom certificate validation

```csharp
using System.Security.Cryptography.X509Certificates;

bool ok = Authenticode.VerifyFull("SomeLibrary.dll", (cert, chain) =>
{
    chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
    return chain.Build(cert);
});
```

## Notes

- Windows only (wintrust.dll interop).
- Verify works for embedded or catalog signatures.
- VerifyFull requires an embedded signature (throws if unsigned or catalog-only).
- Revocation checks are not automatic—configure them via X509Chain if needed.
