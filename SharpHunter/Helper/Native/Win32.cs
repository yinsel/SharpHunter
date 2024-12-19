using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpHunter.Utils
{
    class Win32
    {
        #region Impersonator

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            public LUID Luid;
            public uint Attributes;
        }

        private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const uint TOKEN_QUERY = 0x0008;
        private const uint TOKEN_DUPLICATE = 0x0002;
        private const uint MAXIMUM_ALLOWED = 0x02000000;
        private const uint TOKEN_ALL_ACCESS = 0x000F0000 | 0x0001 | 0x0020 | 0x0008;
        private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        private const string SE_DEBUG_NAME = "SeDebugPrivilege";
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const int SecurityIdentification = 1;
        private const int TokenPrimary = 1;
        private const int SecurityDelegation = 3;


        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess,
            IntPtr lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool RevertToSelf();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        public static bool ImpersonateProcessToken(int pid)
        {
            IntPtr hProcess = Win32.OpenProcess(Win32.PROCESS_ACCESS_FLAGS.PROCESS_QUERY_INFORMATION, true, pid);
            if (hProcess == IntPtr.Zero) return false;
            IntPtr hToken;
            if (!Win32.OpenProcessToken(hProcess, 0x00000002 | 0x00000004, out hToken)) return false;
            IntPtr DuplicatedToken = new IntPtr();
            if (!Win32.DuplicateToken(hToken, 2, ref DuplicatedToken)) return false;
            if (!Win32.SetThreadToken(IntPtr.Zero, DuplicatedToken)) return false;
            return true;
        }

        public unsafe static bool GetSystemPrivileges()
        {
            IntPtr hToken = IntPtr.Zero;
            if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
            {
                Console.WriteLine("[-] Failed to open process token.");
                return false;
            }

            LUID luid;
            if (!LookupPrivilegeValue(null, SE_DEBUG_NAME, out luid))
            {
                Console.WriteLine("[-] Failed to lookup privilege value.");
                CloseHandle(hToken);
                return false;
            }

            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Luid = luid,
                Attributes = SE_PRIVILEGE_ENABLED
            };

            if (!AdjustTokenPrivileges(hToken, false, ref tp, sizeof(TOKEN_PRIVILEGES), IntPtr.Zero, IntPtr.Zero))
            {
                Console.WriteLine("[-] Failed to adjust token privileges.");
                CloseHandle(hToken);
                return false;
            }

            CloseHandle(hToken);

            IntPtr hProcess = IntPtr.Zero;
            foreach (Process process in Process.GetProcesses())
            {
                if (process.ProcessName.Equals("lsass", StringComparison.OrdinalIgnoreCase) ||
                    process.ProcessName.Equals("winlogon", StringComparison.OrdinalIgnoreCase))
                {
                    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, process.Id);
                    if (hProcess != IntPtr.Zero) break;
                }
            }

            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to obtain system privileges.");
                return false;
            }

            IntPtr hTokenDuplicate;
            if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, out hTokenDuplicate))
            {
                CloseHandle(hProcess);
                Console.WriteLine("[-] Failed to open process token for duplication.");
                return false;
            }

            IntPtr hImpersonationToken;
            if (!DuplicateTokenEx(hTokenDuplicate, MAXIMUM_ALLOWED, IntPtr.Zero, SecurityIdentification, TokenPrimary, out hImpersonationToken))
            {
                Console.WriteLine("[-] Failed to duplicate token.");
                CloseHandle(hProcess);
                CloseHandle(hTokenDuplicate);
                return false;
            }

            if (!ImpersonateLoggedOnUser(hImpersonationToken))
            {
                Console.WriteLine("[-] Failed to impersonate logged on user.");
                CloseHandle(hProcess);
                CloseHandle(hTokenDuplicate);
                CloseHandle(hImpersonationToken);
                return false;
            }

            CloseHandle(hProcess);
            CloseHandle(hTokenDuplicate);
            return true;
        }

        public static void IdentityStealToken(int pid)
        {
            IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine($"[-] Could not open process {pid}: {Marshal.GetLastWin32Error()}");
                return;
            }

            IntPtr hToken;
            if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, out hToken))
            {
                Console.WriteLine($"[-] Could not open process token: {Marshal.GetLastWin32Error()}");
                CloseHandle(hProcess);
                return;
            }

            RevertToSelf();

            if (!ImpersonateLoggedOnUser(hToken))
            {
                Console.WriteLine($"[-] Failed to impersonate token from process {pid}: {Marshal.GetLastWin32Error()}");
                CloseHandle(hToken);
                CloseHandle(hProcess);
                return;
            }

            IntPtr gIdentityToken;
            if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, IntPtr.Zero, SecurityDelegation, TokenPrimary, out gIdentityToken))
            {
                Console.WriteLine($"[-] Failed to duplicate token from process {pid}: {Marshal.GetLastWin32Error()}");
                CloseHandle(hToken);
                CloseHandle(hProcess);
                return;
            }

            if (!ImpersonateLoggedOnUser(gIdentityToken))
            {
                Console.WriteLine($"[-] Failed to impersonate logged on user {pid}: {Marshal.GetLastWin32Error()}");
                CloseHandle(gIdentityToken);
            }

            CloseHandle(hProcess);
            CloseHandle(hToken);
        }
        #endregion
        #region ExcuteCmd
        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
        public enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }
        public enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }
        public enum TOKEN_INFORMATION_CLASS
        {
            /// <summary>
            /// The buffer receives a TOKEN_USER structure that contains the user account of the token.
            /// </summary>
            TokenUser = 1,
            /// <summary>
            /// The buffer receives a TOKEN_GROUPS structure that contains the group accounts associated with the token.
            /// </summary>
            TokenGroups,
            /// <summary>
            /// The buffer receives a TOKEN_PRIVILEGES structure that contains the privileges of the token.
            /// </summary>
            TokenPrivileges,
            /// <summary>
            /// The buffer receives a TOKEN_OWNER structure that contains the default owner security identifier (SID) for newly created objects.
            /// </summary>
            TokenOwner,
            /// <summary>
            /// The buffer receives a TOKEN_PRIMARY_GROUP structure that contains the default primary group SID for newly created objects.
            /// </summary>
            TokenPrimaryGroup,
            /// <summary>
            /// The buffer receives a TOKEN_DEFAULT_DACL structure that contains the default DACL for newly created objects.
            /// </summary>
            TokenDefaultDacl,
            /// <summary>
            /// The buffer receives a TOKEN_SOURCE structure that contains the source of the token. TOKEN_QUERY_SOURCE access is needed to retrieve this information.
            /// </summary>
            TokenSource,
            /// <summary>
            /// The buffer receives a TOKEN_TYPE value that indicates whether the token is a primary or impersonation token.
            /// </summary>
            TokenType,
            /// <summary>
            /// The buffer receives a SECURITY_IMPERSONATION_LEVEL value that indicates the impersonation level of the token. If the access token is not an impersonation token, the function fails.
            /// </summary>
            TokenImpersonationLevel,
            /// <summary>
            /// The buffer receives a TOKEN_STATISTICS structure that contains various token statistics.
            /// </summary>
            TokenStatistics,
            /// <summary>
            /// The buffer receives a TOKEN_GROUPS structure that contains the list of restricting SIDs in a restricted token.
            /// </summary>
            TokenRestrictedSids,
            /// <summary>
            /// The buffer receives a DWORD value that indicates the Terminal Services session identifier that is associated with the token.
            /// </summary>
            TokenSessionId,
            /// <summary>
            /// The buffer receives a TOKEN_GROUPS_AND_PRIVILEGES structure that contains the user SID, the group accounts, the restricted SIDs, and the authentication ID associated with the token.
            /// </summary>
            TokenGroupsAndPrivileges,
            /// <summary>
            /// Reserved.
            /// </summary>
            TokenSessionReference,
            /// <summary>
            /// The buffer receives a DWORD value that is nonzero if the token includes the SANDBOX_INERT flag.
            /// </summary>
            TokenSandBoxInert,
            /// <summary>
            /// Reserved.
            /// </summary>
            TokenAuditPolicy,
            /// <summary>
            /// The buffer receives a TOKEN_ORIGIN value.
            /// </summary>
            TokenOrigin,
            /// <summary>
            /// The buffer receives a TOKEN_ELEVATION_TYPE value that specifies the elevation level of the token.
            /// </summary>
            TokenElevationType,
            /// <summary>
            /// The buffer receives a TOKEN_LINKED_TOKEN structure that contains a handle to another token that is linked to this token.
            /// </summary>
            TokenLinkedToken,
            /// <summary>
            /// The buffer receives a TOKEN_ELEVATION structure that specifies whether the token is elevated.
            /// </summary>
            TokenElevation,
            /// <summary>
            /// The buffer receives a DWORD value that is nonzero if the token has ever been filtered.
            /// </summary>
            TokenHasRestrictions,
            /// <summary>
            /// The buffer receives a TOKEN_ACCESS_INFORMATION structure that specifies security information contained in the token.
            /// </summary>
            TokenAccessInformation,
            /// <summary>
            /// The buffer receives a DWORD value that is nonzero if virtualization is allowed for the token.
            /// </summary>
            TokenVirtualizationAllowed,
            /// <summary>
            /// The buffer receives a DWORD value that is nonzero if virtualization is enabled for the token.
            /// </summary>
            TokenVirtualizationEnabled,
            /// <summary>
            /// The buffer receives a TOKEN_MANDATORY_LABEL structure that specifies the token's integrity level.
            /// </summary>
            TokenIntegrityLevel,
            /// <summary>
            /// The buffer receives a DWORD value that is nonzero if the token has the UIAccess flag set.
            /// </summary>
            TokenUIAccess,
            /// <summary>
            /// The buffer receives a TOKEN_MANDATORY_POLICY structure that specifies the token's mandatory integrity policy.
            /// </summary>
            TokenMandatoryPolicy,
            /// <summary>
            /// The buffer receives the token's logon security identifier (SID).
            /// </summary>
            TokenLogonSid,
            /// <summary>
            /// The maximum value for this enumeration
            /// </summary>
            MaxTokenInfoClass
        }
        [DllImport("advapi32.dll",
              EntryPoint = "CreateProcessAsUser", SetLastError = true,
              CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern bool
          CreateProcessAsUser(IntPtr hToken, string lpApplicationName, string lpCommandLine,
                              ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes,
                              bool bInheritHandle, UInt32 dwCreationFlags, IntPtr lpEnvrionment,
                              string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo,
                              ref PROCESS_INFORMATION lpProcessInformation);
        [DllImport("kernel32.dll")]
        public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);


        [DllImport("kernel32.dll", BestFitMapping = true, CharSet = CharSet.Ansi)]
        public static extern bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);
        [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx", SetLastError = true)]
        public static extern bool DuplicateTokenEx(
            IntPtr hExistingToken,
            uint dwDesiredAccess,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            Int32 ImpersonationLevel,
            Int32 dwTokenType,
            ref IntPtr phNewToken);
        public const int SW_HIDE = 0;
        public const int STARTF_USESHOWWINDOW = 0x00000001;
        public const int STARTF_USESTDHANDLES = 0x00000100;
        public const int CREATE_NEW_CONSOLE = 0x00000010;
        public const uint CREATE_NO_WINDOW = 0x08000000;
        public const uint NORMAL_PRIORITY_CLASS = 0x00000020;
        public const uint GENERIC_ALL_ACCESS = 0x10000000;
        #endregion
        #region ProcessInfo
        
        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsWow64Process([In] IntPtr processHandle, [Out, MarshalAs(UnmanagedType.Bool)] out bool wow64Process);

        [DllImport("psapi.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumProcesses(uint[] lpidProcess, uint cb, out uint lpcbNeeded);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        public const uint PROCESS_VM_READ = 0x0010;

        [DllImport("psapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, [In] [MarshalAs(UnmanagedType.U4)] int nSize);

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            uint TokenInformationLength,
            out uint ReturnLength);
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LookupAccountSid(
            string lpSystemName,
            IntPtr Sid,
            StringBuilder lpName,
            ref uint cchName,
            StringBuilder lpReferencedDomainName,
            ref uint cchReferencedDomainName,
            out int peUse);


        #endregion
        #region RDPInfo

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID_AND_ATTRIBUTES
        {
            public LUID pLuid;
            public UInt32 Attributes;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct TokPriv1Luid
        {
            public int Count;
            public LUID Luid;
            public UInt32 Attr;
        }

        private const Int32 ANYSIZE_ARRAY = 1;

        private const uint HKEY_USERS = 0x80000003;
        private const string SE_RESTORE_NAME = "SeRestorePrivilege";
        private const string SE_BACKUP_NAME = "SeBackupPrivilege";

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();


        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        static extern bool AdjustTokenPrivileges(
            IntPtr htok,
            bool disableAllPrivileges,
            ref TokPriv1Luid newState,
            int len,
            IntPtr prev,
            IntPtr relen);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern long RegLoadKey(UInt32 hKey, String lpSubKey, String lpFile);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern long RegUnLoadKey(UInt32 hKey, string lpSubKey);

        private static IntPtr _myToken;
        private static TokPriv1Luid _tokenPrivileges = new TokPriv1Luid();
        private static TokPriv1Luid _tokenPrivileges2 = new TokPriv1Luid();

        private static LUID _restoreLuid;
        private static LUID _backupLuid;

        public static void EnablePrivilege()
        {
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out _myToken))
                Logger.WriteLine("OpenProcess Error");

            if (!LookupPrivilegeValue(null, SE_RESTORE_NAME, out _restoreLuid))
                Logger.WriteLine("LookupPrivilegeValue Error");

            if (!LookupPrivilegeValue(null, SE_BACKUP_NAME, out _backupLuid))
                Logger.WriteLine("LookupPrivilegeValue Error");

            _tokenPrivileges.Attr = SE_PRIVILEGE_ENABLED;
            _tokenPrivileges.Luid = _restoreLuid;
            _tokenPrivileges.Count = 1;

            _tokenPrivileges2.Attr = SE_PRIVILEGE_ENABLED;
            _tokenPrivileges2.Luid = _backupLuid;
            _tokenPrivileges2.Count = 1;

            if (!AdjustTokenPrivileges(_myToken, false, ref _tokenPrivileges, 0, IntPtr.Zero, IntPtr.Zero))
                Logger.WriteLine("AdjustTokenPrivileges Error: " + Marshal.GetLastWin32Error());

            if (!AdjustTokenPrivileges(_myToken, false, ref _tokenPrivileges2, 0, IntPtr.Zero, IntPtr.Zero))
                Logger.WriteLine("AdjustTokenPrivileges Error: " + Marshal.GetLastWin32Error());
        }

        public static string Load(string subkey, string file)
        {
            EnablePrivilege();
            long retVal = RegLoadKey(HKEY_USERS, subkey, file);

            return subkey;
        }

        public static void UnLoad(string subkey)
        {
            EnablePrivilege();
            long retVal = RegUnLoadKey(HKEY_USERS, subkey);
        }
        #endregion
        #region WLAN
        [DllImport("Wlanapi.dll")]
        public static extern int WlanOpenHandle(int dwClientVersion, IntPtr pReserved, [Out] out IntPtr pdwNegotiatedVersion, ref IntPtr ClientHandle);

        [DllImport("Wlanapi", EntryPoint = "WlanCloseHandle")]
        public static extern uint WlanCloseHandle([In] IntPtr hClientHandle, IntPtr pReserved);


        [DllImport("Wlanapi", EntryPoint = "WlanEnumInterfaces")]
        public static extern uint WlanEnumInterfaces([In] IntPtr hClientHandle, IntPtr pReserved, ref IntPtr ppInterfaceList);


        [DllImport("wlanapi.dll", SetLastError = true)]
        public static extern uint WlanGetProfile([In] IntPtr clientHandle, [In, MarshalAs(UnmanagedType.LPStruct)] Guid interfaceGuid, [In, MarshalAs(UnmanagedType.LPWStr)] string profileName, [In] IntPtr pReserved, [Out, MarshalAs(UnmanagedType.LPWStr)] out string profileXml, [In, Out, Optional] ref int flags, [Out, Optional] out IntPtr pdwGrantedAccess);

        [DllImport("wlanapi.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        public static extern uint WlanGetProfileList([In] IntPtr clientHandle, [In, MarshalAs(UnmanagedType.LPStruct)] Guid interfaceGuid, [In] IntPtr pReserved, ref IntPtr profileList);

        [StructLayout(LayoutKind.Sequential)]
        public struct WLAN_INTERFACE_INFO_LIST
        {

            public int dwNumberofItems;
            public int dwIndex;
            public WLAN_INTERFACE_INFO[] InterfaceInfo;


            public WLAN_INTERFACE_INFO_LIST(IntPtr pList)
            {
                dwNumberofItems = (int)Marshal.ReadInt64(pList, 0);
                dwIndex = (int)Marshal.ReadInt64(pList, 4);
                InterfaceInfo = new WLAN_INTERFACE_INFO[dwNumberofItems];
                for (int i = 0; i < dwNumberofItems; i++)
                {
                    IntPtr pItemList = new IntPtr(pList.ToInt64() + (i * 532) + 8);
                    var wii = (WLAN_INTERFACE_INFO)Marshal.PtrToStructure(pItemList, typeof(WLAN_INTERFACE_INFO));
                    InterfaceInfo[i] = wii;
                }
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WLAN_INTERFACE_INFO
        {
            public Guid InterfaceGuid;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string strInterfaceDescription;

        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WLAN_PROFILE_INFO
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string strProfileName;
            public WlanProfileFlags ProfileFLags;
        }

        [Flags]
        public enum WlanProfileFlags
        {
            AllUser = 0,
            GroupPolicy = 1,
            User = 2
        }

        public struct WLAN_PROFILE_INFO_LIST
        {
            public int dwNumberOfItems;
            public int dwIndex;
            public WLAN_PROFILE_INFO[] ProfileInfo;

            public WLAN_PROFILE_INFO_LIST(IntPtr ppProfileList)
            {
                dwNumberOfItems = (int)Marshal.ReadInt64(ppProfileList);
                dwIndex = (int)Marshal.ReadInt64(ppProfileList, 4);
                ProfileInfo = new WLAN_PROFILE_INFO[dwNumberOfItems];
                IntPtr ppProfileListTemp = new IntPtr(ppProfileList.ToInt64() + 8);

                for (int i = 0; i < dwNumberOfItems; i++)
                {
                    ppProfileList = new IntPtr(ppProfileListTemp.ToInt64() + i * Marshal.SizeOf(typeof(WLAN_PROFILE_INFO)));
                    ProfileInfo[i] = (WLAN_PROFILE_INFO)Marshal.PtrToStructure(ppProfileList, typeof(WLAN_PROFILE_INFO));
                }
            }
        }
        #endregion
        #region DPI
        private enum PROCESS_DPI_AWARENESS
        {
            Process_DPI_Unaware = 0,
            Process_System_DPI_Aware = 1,
            Process_Per_Monitor_DPI_Aware = 2
        }
        private enum DPI_AWARENESS_CONTEXT
        {
            DPI_AWARENESS_CONTEXT_UNAWARE = 16,
            DPI_AWARENESS_CONTEXT_SYSTEM_AWARE = 17,
            DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE = 18,
            DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = 34
        }
        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool SetProcessDpiAwarenessContext(int dpiFlag);

        [DllImport("SHCore.dll", SetLastError = true)]
        private static extern bool SetProcessDpiAwareness(PROCESS_DPI_AWARENESS awareness);

        [DllImport("user32.dll")]
        private static extern bool SetProcessDPIAware();

        public static void SetupDpiAwareness()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    int majorVersion = (int)key.GetValue("CurrentMajorVersionNumber");
                    int minorVersion = (int)key.GetValue("CurrentMinorVersionNumber");
                    int buildNumber = int.Parse(key.GetValue("CurrentBuildNumber").ToString());

                    Version version = new Version(majorVersion, minorVersion, buildNumber);
                    if (version >= new Version(6, 3, 0)) // Windows 8.1
                    {
                        if (version >= new Version(10, 0, 15063)) // Windows 10 1703
                        {
                            SetProcessDpiAwarenessContext((int)DPI_AWARENESS_CONTEXT.DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
                        }
                        else
                        {
                            SetProcessDpiAwareness(PROCESS_DPI_AWARENESS.Process_Per_Monitor_DPI_Aware);
                        }
                    }
                    else
                    {
                        SetProcessDPIAware();
                    }
                }
            }
            catch { }
        }
        #endregion

        #region UnLockFile
        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool CryptUnprotectData(
             ref DATA_BLOB pDataIn,
             string szDataDescr,
             IntPtr pOptionalEntropy,
             IntPtr pvReserved,
             IntPtr pPromptStruct,
             int dwFlags,
             ref DATA_BLOB pDataOut);

        [StructLayout(LayoutKind.Sequential)]
        public struct DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION64
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public uint __alignment1;
            public ulong RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
            public uint __alignment2;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION32
        {
            public UInt32 BaseAddress;
            public UInt32 AllocationBase;
            public UInt32 AllocationProtect;
            public UInt32 RegionSize;
            public UInt32 State;
            public UInt32 Protect;
            public UInt32 Type;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int nSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx")]
        internal static extern int VirtualQueryEx64(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION64 lpBuffer, uint dwLength);


        [DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx")]
        public static extern Int32 VirtualQueryEx32(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION32 lpBuffer, UInt32 dwLength);

        [DllImport("kernel32.dll", EntryPoint = "GetFirmwareEnvironmentVariableW", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
        public static extern int GetFirmwareType(string lpName, string lpGUID, IntPtr pBuffer, uint size);

        [DllImport("advapi32.dll")]
        public extern static bool DuplicateToken(IntPtr ExistingTokenHandle, int SECURITY_IMPERSONATION_LEVEL, ref IntPtr DuplicateTokenHandle);
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool SetThreadToken(IntPtr pHandle, IntPtr hToken);
        [DllImport("shell32.dll")]
        public static extern int SHGetFolderPath(IntPtr hwndOwner, int nFolder, IntPtr hToken, uint dwFlags, [Out] StringBuilder pszPath);

        [DllImport("kernel32.dll", EntryPoint = "SetFilePointer")]
        public static extern int SetFilePointer(IntPtr hFile, int lDistanceToMove, int lpDistanceToMoveHigh, int dwMoveMethod);

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct SYSTEM_HANDLE_INFORMATION
        { // Information Class 16
            public ushort ProcessID;
            public ushort CreatorBackTrackIndex;
            public byte ObjectType;
            public byte HandleAttribute;
            public ushort Handle;
            public IntPtr Object_Pointer;
            public IntPtr AccessMask;
        }

        public enum OBJECT_INFORMATION_CLASS
        {
            ObjectBasicInformation = 0,
            ObjectNameInformation = 1,
            ObjectTypeInformation = 2,
            ObjectAllTypesInformation = 3,
            ObjectHandleInformation = 4
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct FileNameInformation
        {
            public int NameLength;
            public char Name;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;

            public override string ToString()
            {
                return Buffer != IntPtr.Zero ? Marshal.PtrToStringUni(Buffer, Length / 2) : null;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct GENERIC_MAPPING
        {
            public int GenericRead;
            public int GenericWrite;
            public int GenericExecute;
            public int GenericAll;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_TYPE_INFORMATION
        {
            public UNICODE_STRING Name;
            int TotalNumberOfObjects;
            int TotalNumberOfHandles;
            int TotalPagedPoolUsage;
            int TotalNonPagedPoolUsage;
            int TotalNamePoolUsage;
            int TotalHandleTableUsage;
            int HighWaterNumberOfObjects;
            int HighWaterNumberOfHandles;
            int HighWaterPagedPoolUsage;
            int HighWaterNonPagedPoolUsage;
            int HighWaterNamePoolUsage;
            int HighWaterHandleTableUsage;
            int InvalidAttributes;
            GENERIC_MAPPING GenericMapping;
            int ValidAccess;
            bool SecurityRequired;
            bool MaintainHandleCount;
            ushort MaintainTypeList;
            POOL_TYPE PoolType;
            int PagedPoolUsage;
            int NonPagedPoolUsage;
        }

        public enum POOL_TYPE
        {
            NonPagedPool,
            PagedPool,
            NonPagedPoolMustSucceed,
            DontUseThisType,
            NonPagedPoolCacheAligned,
            PagedPoolCacheAligned,
            NonPagedPoolCacheAlignedMustS
        }

        public const int CNST_SYSTEM_HANDLE_INFORMATION = 0x10;
        public const int DUPLICATE_SAME_ACCESS = 0x2;

        [DllImport("ntdll.dll")]
        public static extern int NtQueryObject(IntPtr ObjectHandle, int ObjectInformationClass, IntPtr ObjectInformation, int ObjectInformationLength, ref int returnLength);


        [DllImport("ntdll.dll")]
        public static extern uint NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, ref int returnLength);


        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(PROCESS_ACCESS_FLAGS dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto, BestFitMapping = false)]
        public static extern IntPtr CreateFile(
            string lpFileName,
            int dwDesiredAccess,
            FileShare dwShareMode,
            IntPtr lpSecurityAttributes,
            FileMode dwCreationDisposition,
            int dwFlagsAndAttributes,
            IntPtr hTemplateFile);
        [DllImport("ntdll.dll")]
        public static extern uint NtQueryInformationFile(IntPtr fileHandle, ref IO_STATUS_BLOCK IoStatusBlock,
            IntPtr pInfoBlock, uint length, FILE_INFORMATION_CLASS fileInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle, uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

        public const uint STATUS_SUCCESS = 0;
        public const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct IO_STATUS_BLOCK
        {
            public uint Status;
            public IntPtr Information;
        }

        [Flags]
        public enum PROCESS_ACCESS_FLAGS : uint
        {
            PROCESS_ALL_ACCESS = 0x001F0FFF,
            PROCESS_CREATE_PROCESS = 0x0080,
            PROCESS_CREATE_THREAD = 0x0002,
            PROCESS_DUP_HANDLE = 0x0040,
            PROCESS_QUERY_INFORMATION = 0x0400,
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,
            PROCESS_SET_INFORMATION = 0x0200,
            PROCESS_SET_QUOTA = 0x0100,
            PROCESS_SUSPEND_RESUME = 0x0800,
            PROCESS_TERMINATE = 0x0001,
            PROCESS_VM_OPERATION = 0x0008,
            PROCESS_VM_READ = 0x0010,
            PROCESS_VM_WRITE = 0x0020,
            SYNCHRONIZE = 0x00100000
        }

        public enum FILE_INFORMATION_CLASS
        {
            FileDirectoryInformation = 1,
            FileFullDirectoryInformation = 2,
            FileBothDirectoryInformation = 3,
            FileBasicInformation = 4,
            FileStandardInformation = 5,
            FileInternalInformation = 6,
            FileEaInformation = 7,
            FileAccessInformation = 8,
            FileNameInformation = 9,
            FileRenameInformation = 10,
            FileLinkInformation = 11,
            FileNamesInformation = 12,
            FileDispositionInformation = 13,
            FilePositionInformation = 14,
            FileFullEaInformation = 15,
            FileModeInformation = 16,
            FileAlignmentInformation = 17,
            FileAllInformation = 18,
            FileAllocationInformation = 19,
            FileEndOfFileInformation = 20,
            FileAlternateNameInformation = 21,
            FileStreamInformation = 22,
            FilePipeInformation = 23,
            FilePipeLocalInformation = 24,
            FilePipeRemoteInformation = 25,
            FileMailslotQueryInformation = 26,
            FileMailslotSetInformation = 27,
            FileCompressionInformation = 28,
            FileObjectIdInformation = 29,
            FileCompletionInformation = 30,
            FileMoveClusterInformation = 31,
            FileQuotaInformation = 32,
            FileReparsePointInformation = 33,
            FileNetworkOpenInformation = 34,
            FileAttributeTagInformation = 35,
            FileTrackingInformation = 36,
            FileIdBothDirectoryInformation = 37,
            FileIdFullDirectoryInformation = 38,
            FileValidDataLengthInformation = 39,
            FileShortNameInformation = 40,
            FileIoCompletionNotificationInformation = 41,
            FileIoStatusBlockRangeInformation = 42,
            FileIoPriorityHintInformation = 43,
            FileSfioReserveInformation = 44,
            FileSfioVolumeInformation = 45,
            FileHardLinkInformation = 46,
            FileProcessIdsUsingFileInformation = 47,
            FileNormalizedNameInformation = 48,
            FileNetworkPhysicalNameInformation = 49,
            FileMaximumInformation = 50
        }
        #endregion
        #region BCrypt
        public const uint ERROR_SUCCESS = 0x00000000;
        public const uint BCRYPT_PAD_PSS = 8;
        public const uint BCRYPT_PAD_OAEP = 4;

        public static readonly byte[] BCRYPT_KEY_DATA_BLOB_MAGIC = BitConverter.GetBytes(0x4d42444b);

        public static readonly string BCRYPT_OBJECT_LENGTH = "ObjectLength";
        public static readonly string BCRYPT_CHAIN_MODE_GCM = "ChainingModeGCM";
        public static readonly string BCRYPT_AUTH_TAG_LENGTH = "AuthTagLength";
        public static readonly string BCRYPT_CHAINING_MODE = "ChainingMode";
        public static readonly string BCRYPT_KEY_DATA_BLOB = "KeyDataBlob";
        public static readonly string BCRYPT_AES_ALGORITHM = "AES";

        public static readonly string MS_PRIMITIVE_PROVIDER = "Microsoft Primitive Provider";

        public static readonly int BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG = 0x00000001;
        public static readonly int BCRYPT_INIT_AUTH_MODE_INFO_VERSION = 0x00000001;

        public static readonly uint STATUS_AUTH_TAG_MISMATCH = 0xC000A002;

        [DllImport("bcrypt.dll")]
        public static extern uint BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm,
                                                              [MarshalAs(UnmanagedType.LPWStr)] string pszAlgId,
                                                              [MarshalAs(UnmanagedType.LPWStr)] string pszImplementation,
                                                              uint dwFlags);

        [DllImport("bcrypt.dll")]
        public static extern uint BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint flags);

        [DllImport("bcrypt.dll", EntryPoint = "BCryptGetProperty")]
        public static extern uint BCryptGetProperty(IntPtr hObject, [MarshalAs(UnmanagedType.LPWStr)] string pszProperty, byte[] pbOutput, int cbOutput, ref int pcbResult, uint flags);

        [DllImport("bcrypt.dll", EntryPoint = "BCryptSetProperty")]
        internal static extern uint BCryptSetAlgorithmProperty(IntPtr hObject, [MarshalAs(UnmanagedType.LPWStr)] string pszProperty, byte[] pbInput, int cbInput, int dwFlags);


        [DllImport("bcrypt.dll")]
        public static extern uint BCryptImportKey(IntPtr hAlgorithm,
                                                  IntPtr hImportKey,
                                                  [MarshalAs(UnmanagedType.LPWStr)] string pszBlobType,
                                                  out IntPtr phKey,
                                                  IntPtr pbKeyObject,
                                                  int cbKeyObject,
                                                  byte[] pbInput, //blob of type BCRYPT_KEY_DATA_BLOB + raw key data = (dwMagic (4 bytes) | uint dwVersion (4 bytes) | cbKeyData (4 bytes) | data)
                                                  int cbInput,
                                                  uint dwFlags);

        [DllImport("bcrypt.dll")]
        public static extern uint BCryptDestroyKey(IntPtr hKey);

        [DllImport("bcrypt.dll")]
        internal static extern uint BCryptDecrypt(IntPtr hKey,
                                                  byte[] pbInput,
                                                  int cbInput,
                                                  ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo,
                                                  byte[] pbIV,
                                                  int cbIV,
                                                  byte[] pbOutput,
                                                  int cbOutput,
                                                  ref int pcbResult,
                                                  int dwFlags);

        [StructLayout(LayoutKind.Sequential)]
        public struct BCRYPT_PSS_PADDING_INFO
        {
            public BCRYPT_PSS_PADDING_INFO(string pszAlgId, int cbSalt)
            {
                this.pszAlgId = pszAlgId;
                this.cbSalt = cbSalt;
            }

            [MarshalAs(UnmanagedType.LPWStr)]
            public string pszAlgId;
            public int cbSalt;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO : IDisposable
        {
            public int cbSize;
            public int dwInfoVersion;
            public IntPtr pbNonce;
            public int cbNonce;
            public IntPtr pbAuthData;
            public int cbAuthData;
            public IntPtr pbTag;
            public int cbTag;
            public IntPtr pbMacContext;
            public int cbMacContext;
            public int cbAAD;
            public long cbData;
            public int dwFlags;

            public BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(byte[] iv, byte[] aad, byte[] tag) : this()
            {
                dwInfoVersion = BCRYPT_INIT_AUTH_MODE_INFO_VERSION;
                cbSize = Marshal.SizeOf(typeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));

                if (iv != null)
                {
                    cbNonce = iv.Length;
                    pbNonce = Marshal.AllocHGlobal(cbNonce);
                    Marshal.Copy(iv, 0, pbNonce, cbNonce);
                }

                if (aad != null)
                {
                    cbAuthData = aad.Length;
                    pbAuthData = Marshal.AllocHGlobal(cbAuthData);
                    Marshal.Copy(aad, 0, pbAuthData, cbAuthData);
                }

                if (tag != null)
                {
                    cbTag = tag.Length;
                    pbTag = Marshal.AllocHGlobal(cbTag);
                    Marshal.Copy(tag, 0, pbTag, cbTag);

                    cbMacContext = tag.Length;
                    pbMacContext = Marshal.AllocHGlobal(cbMacContext);
                }
            }

            public void Dispose()
            {
                if (pbNonce != IntPtr.Zero) Marshal.FreeHGlobal(pbNonce);
                if (pbTag != IntPtr.Zero) Marshal.FreeHGlobal(pbTag);
                if (pbAuthData != IntPtr.Zero) Marshal.FreeHGlobal(pbAuthData);
                if (pbMacContext != IntPtr.Zero) Marshal.FreeHGlobal(pbMacContext);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BCRYPT_OAEP_PADDING_INFO
        {
            public BCRYPT_OAEP_PADDING_INFO(string alg)
            {
                pszAlgId = alg;
                pbLabel = IntPtr.Zero;
                cbLabel = 0;
            }

            [MarshalAs(UnmanagedType.LPWStr)]
            public string pszAlgId;
            public IntPtr pbLabel;
            public int cbLabel;
        }
        #endregion
        #region VaultCli
        public enum VAULT_ELEMENT_TYPE
        {
            Undefined = -1,
            Boolean = 0,
            Short = 1,
            UnsignedShort = 2,
            Int = 3,
            UnsignedInt = 4,
            Double = 5,
            Guid = 6,
            String = 7,
            ByteArray = 8,
            TimeStamp = 9,
            ProtectedArray = 10,
            Attribute = 11,
            Sid = 12,
            Last = 13
        }

        public enum VAULT_SCHEMA_ELEMENT_ID
        {
            Illegal = 0,
            Resource = 1,
            Identity = 2,
            Authenticator = 3,
            Tag = 4,
            PackageSid = 5,
            AppStart = 100,
            AppEnd = 10000
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct VAULT_ITEM_WIN8
        {
            public Guid SchemaId;
            public IntPtr pszCredentialFriendlyName;
            public IntPtr pResourceElement;
            public IntPtr pIdentityElement;
            public IntPtr pAuthenticatorElement;
            public IntPtr pPackageSid;
            public UInt64 LastModified;
            public UInt32 dwFlags;
            public UInt32 dwPropertiesCount;
            public IntPtr pPropertyElements;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct VAULT_ITEM_WIN7
        {
            public Guid SchemaId;
            public IntPtr pszCredentialFriendlyName;
            public IntPtr pResourceElement;
            public IntPtr pIdentityElement;
            public IntPtr pAuthenticatorElement;
            public UInt64 LastModified;
            public UInt32 dwFlags;
            public UInt32 dwPropertiesCount;
            public IntPtr pPropertyElements;
        }

        [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Ansi)]
        public struct VAULT_ITEM_ELEMENT
        {
            [FieldOffset(0)] public VAULT_SCHEMA_ELEMENT_ID SchemaElementId;
            [FieldOffset(8)] public VAULT_ELEMENT_TYPE Type;
        }

        [DllImport("vaultcli.dll")]
        public static extern int VaultOpenVault(ref Guid vaultGuid, uint offset, ref IntPtr vaultHandle);

        [DllImport("vaultcli.dll")]
        public static extern int VaultEnumerateVaults(int offset, ref int vaultCount, ref IntPtr vaultGuid);

        [DllImport("vaultcli.dll")]
        public static extern int VaultEnumerateItems(IntPtr vaultHandle, int chunkSize, ref int vaultItemCount, ref IntPtr vaultItem);

        [DllImport("vaultcli.dll", EntryPoint = "VaultGetItem")]
        public static extern int VaultGetItem_WIN8(IntPtr vaultHandle, ref Guid schemaId, IntPtr pResourceElement, IntPtr pIdentityElement, IntPtr pPackageSid, IntPtr zero, int arg6, ref IntPtr passwordVaultPtr);

        [DllImport("vaultcli.dll", EntryPoint = "VaultGetItem")]
        public static extern int VaultGetItem_WIN7(IntPtr vaultHandle, ref Guid schemaId, IntPtr pResourceElement, IntPtr pIdentityElement, IntPtr zero, int arg5, ref IntPtr passwordVaultPtr);

        #endregion

    }

}