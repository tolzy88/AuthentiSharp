using System;
using System.Runtime.InteropServices;

namespace WinTrustSharp.Internal.Structures
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WINTRUST_DATA
    {
        public readonly uint cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>();
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pInfo; // Union: pFile, pCatalog, pBlob, pSgnr, pCert
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;

        public WINTRUST_DATA() { }
    }
}

/*
https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data

typedef struct _WINTRUST_DATA {
  DWORD                               cbStruct;
  LPVOID                              pPolicyCallbackData;
  LPVOID                              pSIPClientData;
  DWORD                               dwUIChoice;
  DWORD                               fdwRevocationChecks;
  DWORD                               dwUnionChoice;
  union {
#if ...
    WINTRUST_FILE_INFO_                *pFile;
#else
    struct WINTRUST_FILE_INFO_         *pFile;
#endif
#if ...
    WINTRUST_CATALOG_INFO_             *pCatalog;
#else
    struct WINTRUST_CATALOG_INFO_      *pCatalog;
#endif
#if ...
    WINTRUST_BLOB_INFO_                *pBlob;
#else
    struct WINTRUST_BLOB_INFO_         *pBlob;
#endif
#if ...
    WINTRUST_SGNR_INFO_                *pSgnr;
#else
    struct WINTRUST_SGNR_INFO_         *pSgnr;
#endif
#if ...
    WINTRUST_CERT_INFO_                *pCert;
#else
    struct WINTRUST_CERT_INFO_         *pCert;
#endif
#if ...
    WINTRUST_DETACHED_SIG_INFO_        *pDetachedSig;
#else
    struct WINTRUST_DETACHED_SIG_INFO_ *pDetachedSig;
#endif
  };
  DWORD                               dwStateAction;
  HANDLE                              hWVTStateData;
  WCHAR                               *pwszURLReference;
  DWORD                               dwProvFlags;
  DWORD                               dwUIContext;
  struct WINTRUST_SIGNATURE_SETTINGS_ *pSignatureSettings;
} WINTRUST_DATA, *PWINTRUST_DATA;
 */