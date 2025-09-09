# WinTrustSharp

Lightweight .NET interop for validating Windows Authenticode (code-signing) signatures on PE files (EXE/DLL).

```
WinTrustSharp_Tests
  Tests in group: 13
   Total Duration: 41 ms

Outcomes
   13 Passed
```

---

## Features

- **Verify**: Check if a file has a valid Authenticode signature. If the file was tampered with after signing, this will return false since the digital signature is no longer valid.
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

// Digital signature check only
bool validDigitalSignature = Authenticode.Verify(new FileInfo("SomeLibrary.dll"));

// Full validation (certificate trust + signature structure)
bool trusted = Authenticode.VerifyFull("SomeLibrary.dll");
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
