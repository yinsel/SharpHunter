using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace SharpHunter.Utils
{
    class Enums
    {
        public enum OUTPUT_TYPE
        {
            SUCCESS = '+',
            VERBOSE = '*',
            ERROR = '!',
            Fail = '-',
            Normal = ' '
        };

        public enum VAULT_ELEMENT_TYPE : Int32
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

        public enum VAULT_SCHEMA_ELEMENT_ID : Int32
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

        public enum OBJECT_INFORMATION_CLASS
        {
            ObjectBasicInformation = 0,
            ObjectNameInformation = 1,
            ObjectTypeInformation = 2,
            ObjectAllTypesInformation = 3,
            ObjectHandleInformation = 4
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
    }
    internal class LockedFile
    {
        public static byte[] ReadLockedFile(string fileName)
        {
            try
            {
                int pid = GetProcessIDByFileName(fileName)[0];
                IntPtr hfile = DuplicateHandleByFileName(pid, fileName);
                var oldFilePointer = Win32.SetFilePointer(hfile, 0, 0, 1);
                int size = Win32.SetFilePointer(hfile, 0, 0, 2);
                byte[] fileBuffer = new byte[size];
                IntPtr hProcess = Win32.OpenProcess(Win32.PROCESS_ACCESS_FLAGS.PROCESS_SUSPEND_RESUME, false, pid);
                NTAPI.NtSuspendProcess(hProcess);
                Win32.SetFilePointer(hfile, 0, 0, 0);
                Win32.ReadFile(hfile, fileBuffer, (uint)size, out _, IntPtr.Zero);
                Win32.SetFilePointer(hfile, oldFilePointer, 0, 0);
                NTAPI.CloseHandle(hfile);
                NTAPI.NtResumeProcess(hProcess);
                NTAPI.CloseHandle(hProcess);
                return fileBuffer;
            }
            catch { return null; }
        }

        public static List<Win32.SYSTEM_HANDLE_INFORMATION> GetHandles(int pid)
        {
            List<Win32.SYSTEM_HANDLE_INFORMATION> aHandles = new List<Win32.SYSTEM_HANDLE_INFORMATION>();
            int handle_info_size = Marshal.SizeOf(new Win32.SYSTEM_HANDLE_INFORMATION()) * 20000;
            IntPtr ptrHandleData = IntPtr.Zero;
            try
            {
                ptrHandleData = Marshal.AllocHGlobal(handle_info_size);
                int nLength = 0;

                while (Win32.NtQuerySystemInformation(Win32.CNST_SYSTEM_HANDLE_INFORMATION, ptrHandleData, handle_info_size, ref nLength) == Win32.STATUS_INFO_LENGTH_MISMATCH)
                {
                    handle_info_size = nLength;
                    Marshal.FreeHGlobal(ptrHandleData);
                    ptrHandleData = Marshal.AllocHGlobal(nLength);
                }
                if (IntPtr.Size == 8)
                {
                    int handle_count = Marshal.ReadIntPtr(ptrHandleData).ToInt32();
                    IntPtr ptrHandleItem = new IntPtr(ptrHandleData.ToInt64() + IntPtr.Size);

                    for (long lIndex = 0; lIndex < handle_count; lIndex++)
                    {
                        Win32.SYSTEM_HANDLE_INFORMATION oSystemHandleInfo = new Win32.SYSTEM_HANDLE_INFORMATION();
                        oSystemHandleInfo = (Win32.SYSTEM_HANDLE_INFORMATION)Marshal.PtrToStructure(ptrHandleItem, oSystemHandleInfo.GetType());
                        ptrHandleItem = new IntPtr(ptrHandleItem.ToInt64() + Marshal.SizeOf(oSystemHandleInfo.GetType()));
                        if (oSystemHandleInfo.ProcessID != pid) { continue; }
                        aHandles.Add(oSystemHandleInfo);
                    }
                }
                else
                {
                    int handle_count = Marshal.ReadIntPtr(ptrHandleData).ToInt32();
                    IntPtr ptrHandleItem = new IntPtr(ptrHandleData.ToInt32() + IntPtr.Size);

                    for (long lIndex = 0; lIndex < handle_count; lIndex++)
                    {
                        Win32.SYSTEM_HANDLE_INFORMATION oSystemHandleInfo = new Win32.SYSTEM_HANDLE_INFORMATION();
                        oSystemHandleInfo = (Win32.SYSTEM_HANDLE_INFORMATION)Marshal.PtrToStructure(ptrHandleItem, oSystemHandleInfo.GetType());
                        ptrHandleItem = new IntPtr(ptrHandleItem.ToInt32() + Marshal.SizeOf(new Win32.SYSTEM_HANDLE_INFORMATION()));
                        if (oSystemHandleInfo.ProcessID != pid) { continue; }
                        aHandles.Add(oSystemHandleInfo);
                    }
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }
            finally
            {
                Marshal.FreeHGlobal(ptrHandleData);
            }
            return aHandles;
        }

        private static string TryGetName(IntPtr Handle)
        {
            Win32.IO_STATUS_BLOCK status = new Win32.IO_STATUS_BLOCK();
            uint bufferSize = 1024;
            var bufferPtr = Marshal.AllocHGlobal((int)bufferSize);
            Win32.NtQueryInformationFile(Handle, ref status, bufferPtr, bufferSize, Win32.FILE_INFORMATION_CLASS.FileNameInformation);
            var nameInfo = (Win32.FileNameInformation)Marshal.PtrToStructure(bufferPtr, typeof(Win32.FileNameInformation));
            if (nameInfo.NameLength > bufferSize || nameInfo.NameLength <= 0)
            {
                return null;
            }
            return Marshal.PtrToStringUni(new IntPtr((IntPtr.Size == 8 ? bufferPtr.ToInt64() : bufferPtr.ToInt32()) + 4), nameInfo.NameLength / 2);
        }

        public static IntPtr FindHandleByFileName(Win32.SYSTEM_HANDLE_INFORMATION systemHandleInformation, string filename, IntPtr processHandle)
        {
            IntPtr openProcessHandle = processHandle;
            try
            {
                if (!Win32.DuplicateHandle(openProcessHandle, new IntPtr(systemHandleInformation.Handle), Win32.GetCurrentProcess(), out var ipHandle, 0, false, Win32.DUPLICATE_SAME_ACCESS))
                {
                    return IntPtr.Zero;
                }
                int objectTypeInfoSize = 0x1000;
                IntPtr objectTypeInfo = Marshal.AllocHGlobal(objectTypeInfoSize);
                try
                {
                    int returnLength = 0;
                    if (Win32.NtQueryObject(ipHandle, (int)Win32.OBJECT_INFORMATION_CLASS.ObjectTypeInformation, objectTypeInfo, objectTypeInfoSize, ref returnLength) != 0)
                    {
                        return IntPtr.Zero;
                    }
                    var objectTypeInfoStruct = (Win32.OBJECT_TYPE_INFORMATION)Marshal.PtrToStructure(objectTypeInfo, typeof(Win32.OBJECT_TYPE_INFORMATION));
                    string typeName = objectTypeInfoStruct.Name.ToString();
                    if (typeName == "File")
                    {
                        string name = TryGetName(ipHandle);
                        if (name == filename.Substring(2, filename.Length - 2))
                            return ipHandle;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(objectTypeInfo);
                }
            }
            catch { }

            return IntPtr.Zero;
        }

        public static string FindHandleWithFileName(Win32.SYSTEM_HANDLE_INFORMATION systemHandleInformation, string filename, IntPtr processHandle)
        {
            IntPtr openProcessHandle = processHandle;
            try
            {
                if (!Win32.DuplicateHandle(openProcessHandle, new IntPtr(systemHandleInformation.Handle), Win32.GetCurrentProcess(), out var ipHandle, 0, false, Win32.DUPLICATE_SAME_ACCESS))
                {
                    return "";
                }
                int objectTypeInfoSize = 0x1000;
                IntPtr objectTypeInfo = Marshal.AllocHGlobal(objectTypeInfoSize);
                try
                {
                    int returnLength = 0;
                    if (Win32.NtQueryObject(ipHandle, (int)Win32.OBJECT_INFORMATION_CLASS.ObjectTypeInformation, objectTypeInfo, objectTypeInfoSize, ref returnLength) != 0)
                    {
                        return "";
                    }
                    var objectTypeInfoStruct = (Win32.OBJECT_TYPE_INFORMATION)Marshal.PtrToStructure(objectTypeInfo, typeof(Win32.OBJECT_TYPE_INFORMATION));
                    string typeName = objectTypeInfoStruct.Name.ToString();
                    if (typeName == "File")
                    {
                        string name = TryGetName(ipHandle);
                        if (name.Contains(filename))
                            return name;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(objectTypeInfo);
                }
            }
            catch { }

            return "";
        }

        private static IntPtr DuplicateHandleByFileName(int pid, string fileName)
        {
            IntPtr handle = IntPtr.Zero;
            List<Win32.SYSTEM_HANDLE_INFORMATION> syshInfos = GetHandles(pid);
            IntPtr processHandle = GetProcessHandle(pid);

            foreach (var t in syshInfos)
            {
                handle = FindHandleByFileName(t, fileName, processHandle);
                if (handle != IntPtr.Zero)
                {
                    Win32.CloseHandle(processHandle);
                    return handle;
                }
            }
            Win32.CloseHandle(processHandle);
            return handle;
        }

        private static List<int> GetProcessIDByFileName(string path)
        {
            List<int> result = new List<int>();
            var bufferPtr = IntPtr.Zero;
            var statusBlock = new Win32.IO_STATUS_BLOCK();

            try
            {
                var handle = GetFileHandle(path);
                uint bufferSize = 0x4000;
                bufferPtr = Marshal.AllocHGlobal((int)bufferSize);

                uint status;
                while ((status = Win32.NtQueryInformationFile(handle,
                    ref statusBlock, bufferPtr, bufferSize,
                    Win32.FILE_INFORMATION_CLASS.FileProcessIdsUsingFileInformation))
                    == Win32.STATUS_INFO_LENGTH_MISMATCH)
                {
                    Marshal.FreeHGlobal(bufferPtr);
                    bufferPtr = IntPtr.Zero;
                    bufferSize *= 2;
                    bufferPtr = Marshal.AllocHGlobal((int)bufferSize);
                }

                Win32.CloseHandle(handle);

                if (status != Win32.STATUS_SUCCESS)
                {
                    return result;
                }

                IntPtr readBuffer = bufferPtr;
                int numEntries = Marshal.ReadInt32(readBuffer); // NumberOfProcessIdsInList
                readBuffer = IntPtr.Size == 8 ? new IntPtr(readBuffer.ToInt64() + IntPtr.Size) : new IntPtr(readBuffer.ToInt32() + IntPtr.Size);
                for (int i = 0; i < numEntries; i++)
                {
                    IntPtr processId = Marshal.ReadIntPtr(readBuffer); // A single ProcessIdList[] element
                    result.Add(processId.ToInt32());
                    readBuffer = IntPtr.Size == 8 ? new IntPtr(readBuffer.ToInt64() + IntPtr.Size) : new IntPtr(readBuffer.ToInt32() + IntPtr.Size);
                }
            }
            catch { return result; }
            finally
            {
                if (bufferPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(bufferPtr);
                }
            }
            return result;
        }

        private static IntPtr GetFileHandle(string name)
        {
            return Win32.CreateFile(name,
                0,
                FileShare.Read | FileShare.Write | FileShare.Delete,
                IntPtr.Zero,
                FileMode.Open,
                (int)FileAttributes.Normal,
                IntPtr.Zero);
        }

        public static IntPtr GetProcessHandle(int pid)
        {
            return Win32.OpenProcess(Win32.PROCESS_ACCESS_FLAGS.PROCESS_DUP_HANDLE | Win32.PROCESS_ACCESS_FLAGS.PROCESS_VM_READ, false, pid);
        }
    }
}