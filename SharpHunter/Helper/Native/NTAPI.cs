using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpHunter.Utils
{
    /// <summary>
    /// 提供与内存操作相关的通用函数
    /// </summary>
    public static class NTAPI
    {
        // 定义常量
        public const uint PROCESS_VM_READ = 0x0010;
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;

        // MEMORY_BASIC_INFORMATION 结构
        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        // NT API P/Invoke 声明
        [DllImport("ntdll.dll")]
        public static extern uint NtOpenProcess(out IntPtr ProcessHandle, uint AccessMask, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID ClientId);

        [DllImport("ntdll.dll")]
        public static extern uint NtReadVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, uint NumberOfBytesToRead, out uint NumberOfBytesRead);

        [DllImport("ntdll.dll")]
        public static extern uint NtClose(IntPtr Handle);

        [DllImport("ntdll.dll")]
        public static extern int NtWow64ReadVirtualMemory64(IntPtr hProcess, ulong pMemAddress, [Out] byte[] pBufferPtr, ulong nSize, out ulong nReturnSize);

        [DllImport("ntdll.dll")]
        public static extern uint NtQueryVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, int MemoryInformationClass, out MEMORY_BASIC_INFORMATION MemoryInformation, uint MemoryInformationLength, out uint ReturnLength);

        [DllImport("ntdll", SetLastError = true)]
        public static extern uint NtSuspendProcess([In] IntPtr Handle);

        [DllImport("ntdll.dll", SetLastError = false)]
        public static extern uint NtResumeProcess(IntPtr ProcessHandle);

        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        public static IntPtr OpenProcess(uint dwDesiredAccess, int dwProcessId)
        {
            IntPtr processHandle = IntPtr.Zero;
            CLIENT_ID clientId = new CLIENT_ID { UniqueProcess = (IntPtr)dwProcessId };
            OBJECT_ATTRIBUTES objectAttributes = new OBJECT_ATTRIBUTES { Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)) };

            uint status = NtOpenProcess(out processHandle, dwDesiredAccess, ref objectAttributes, ref clientId);
            if (status != 0)
            {
                //Console.WriteLine("[-] Error calling NtOpenProcess. NTSTATUS: 0x" + status.ToString("X"));
                return IntPtr.Zero;
            }
            return processHandle;
        }

        public static bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead)
        {
            uint bytesRead;
            uint status = NtReadVirtualMemory(hProcess, lpBaseAddress, lpBuffer, (uint)dwSize, out bytesRead);
            lpNumberOfBytesRead = (int)bytesRead;
            if (status != 0)
            {
                //Console.WriteLine("[-] Error calling NtReadVirtualMemory. NTSTATUS: 0x" + status.ToString("X"));
                return false;
            }
            return true;
        }

        public static bool CloseHandle(IntPtr hObject)
        {
            uint status = NtClose(hObject);
            if (status != 0)
            {
                //Console.WriteLine("[-] Error calling NtClose. NTSTATUS: 0x" + status.ToString("X"));
                return false;
            }
            return true;
        }

        public static IntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength)
        {
            uint returnLength;
            uint status = NtQueryVirtualMemory(hProcess, lpAddress, 0, out lpBuffer, dwLength, out returnLength);
            if (status != 0)
            {
                //Console.WriteLine("[-] Error calling NtQueryVirtualMemory. NTSTATUS: 0x" + status.ToString("X"));
                return IntPtr.Zero;
            }
            return (IntPtr)returnLength;
        }

        /// <summary>
        /// 在缓冲区中查找指定的字节序列
        /// </summary>
        /// <param name="buffer">数据缓冲区</param>
        /// <param name="pattern">要查找的字节序列</param>
        /// <param name="startIndex">可选参数，默认值为 0</param>
        /// <returns>字节序列的起始索引，未找到则返回 -1</returns>
        public static int FindBytes(byte[] buffer, byte[] pattern, int startIndex = 0)
        {
            for (int i = startIndex; i <= buffer.Length - pattern.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (buffer[i + j] != pattern[j])
                    {
                        found = false;
                        break;
                    }
                }
                if (found)
                {
                    return i;
                }
            }
            return -1;
        }

        /// <summary>
        /// 在缓冲区中查找指定的字节序列（使用 LINQ）
        /// </summary>
        /// <param name="buffer">数据缓冲区</param>
        /// <param name="pattern">要查找的字节序列</param>
        /// <returns>字节序列的起始索引，未找到则返回 -1</returns>
        public static int FindPattern(byte[] buffer, byte[] pattern)
        {
            for (int i = 0; i <= buffer.Length - pattern.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (buffer[i + j] != pattern[j])
                    {
                        found = false;
                        break;
                    }
                }
                if (found)
                {
                    return i;
                }
            }
            return -1;
        }

        /// <summary>
        /// 将字节数组转换为十六进制字符串
        /// </summary>
        /// <param name="bytes">字节数组</param>
        /// <returns>十六进制表示的字符串</returns>
        public static string BytesToHex(byte[] bytes)
        {
            StringBuilder hex = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
            {
                hex.AppendFormat("{0:X2}", b);
            }
            return hex.ToString();
        }
    }
}