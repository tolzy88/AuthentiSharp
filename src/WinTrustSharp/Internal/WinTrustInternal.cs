//
// Authors:
//   Steven Tolzmann
//
// Copyright (C) 2025 Steven Tolzmann

using System;
using System.Runtime.InteropServices;
using WinTrustSharp.Internal.Structures;

namespace WinTrustSharp.Internal
{
    internal static class WinTrustInternal
    {
        private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid("00aac56b-cd44-11d0-8cc2-00c04fc295ee");

        /// <summary>
        /// Verify a file's Authenticode Signature.
        /// No additional checks are performed.
        /// </summary>
        /// <param name="filePath">Path to the file to check.</param>
        /// <returns>True if the authenticode signature is valid, otherwise False.</returns>
        public static bool VerifyAuthenticode(string filePath)
        {
            var fileInfo = new WINTRUST_FILE_INFO()
            {
                pcwszFilePath = filePath,
            };
            var pFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            try
            {
                Marshal.StructureToPtr(fileInfo, pFileInfo, false);
                var trustData = new WINTRUST_DATA()
                {
                    pInfo = pFileInfo,
                    pPolicyCallbackData = IntPtr.Zero,
                    pSIPClientData = IntPtr.Zero,
                    dwUIChoice = 2, // WTD_UI_NONE
                    fdwRevocationChecks = 0, // WTD_REVOKE_NONE
                    dwUnionChoice = 1, // WTD_CHOICE_FILE
                    dwStateAction = 0,
                    hWVTStateData = IntPtr.Zero,
                    pwszURLReference = null,
                    dwProvFlags = 0x200, // WTD_HASH_ONLY_FLAG
                    dwUIContext = 0,
                    pSignatureSettings = IntPtr.Zero
                };
                return WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, ref trustData) == 0;
            }
            finally
            {
                Marshal.DestroyStructure<WINTRUST_FILE_INFO>(pFileInfo);
                Marshal.FreeHGlobal(pFileInfo);
            }
        }

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
        private static extern int WinVerifyTrust([In] IntPtr hwnd, [In][MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, [In] ref WINTRUST_DATA pWVTData);
    }
}
