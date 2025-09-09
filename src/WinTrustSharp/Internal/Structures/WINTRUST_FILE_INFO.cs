using System;
using System.Runtime.InteropServices;

namespace WinTrustSharp.Internal.Structures
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WINTRUST_FILE_INFO
    {
        public readonly uint cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>();
        [MarshalAs(UnmanagedType.LPWStr)] 
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;

        public WINTRUST_FILE_INFO() { }
    }
}

/*
https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_file_info

typedef struct WINTRUST_FILE_INFO_ {
  DWORD   cbStruct;
  LPCWSTR pcwszFilePath;
  HANDLE  hFile;
  GUID    *pgKnownSubject;
} WINTRUST_FILE_INFO, *PWINTRUST_FILE_INFO;
 */
