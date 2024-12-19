using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using SharpHunter.Utils;
using System.IO;

namespace SharpHunter.Commands
{
    class SoftwareInfoCommand : ICommand
    {
        public void Execute(List<string> args)
        {
            SoftInstallInfo();
        }
        public static void SoftInstallInfo()
        {
            Logger.TaskHeader("Software Install", 1);
            List<SoftwareInfo> softwareList = GetAllSoftware();
            if (!softwareList.Any())
            {
                Logger.WriteLine("[-] No software found in registry.");
                return;
            }
            GlobalContext.InstalledSoftware = softwareList;


            List<SoftwareInfo> userSoftwareList = new List<SoftwareInfo>();
            List<SoftwareInfo> systemSoftwareList = new List<SoftwareInfo>();
            List<SoftwareInfo> specialSoftwareList = new List<SoftwareInfo>();

            foreach (SoftwareInfo s in softwareList)
            {
                if (IsSpecialSoftware(s.name))
                {
                    specialSoftwareList.Add(s);
                }
                else if (IsIgnoredSoftware(s.name))
                {
                    systemSoftwareList.Add(s);
                }
                else
                {
                    userSoftwareList.Add(s);
                }
            }
            List<string> headers = new List<string> { "Name", "Version", "Install Path", "Install Date" };
            List<List<string>> specialItems = specialSoftwareList.Select(s => new List<string>
            {
                s.name,
                s.version ?? "N/A",
                s.installPath ?? "N/A",
                s.installDate ?? "N/A"
            }).ToList();
            Logger.PrintTable(headers, specialItems);

            Logger.WriteLine("");
            PrintSoftwareList("User Softwares", userSoftwareList);
            Logger.WriteLine("");
            PrintSoftwareList("System Softwares", systemSoftwareList);
        }

        public struct SoftwareInfo
        {
            public string name;
            public string version;
            public string installPath;
            public string publisher;
            public string installDate;
        }

        public static List<SoftwareInfo> GetAllSoftware()
        {
            List<SoftwareInfo> softwareList = new List<SoftwareInfo>();
            HashSet<string> softwareNames = new HashSet<string>();

            string[] registryPaths = new string[]
            {
                @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
                @"Software\Microsoft\Windows\CurrentVersion\Uninstall"
            };

            foreach (string registryPath in registryPaths)
            {
                RetrieveSoftwareInfo(registryPath, softwareList, softwareNames);
            }

            return softwareList;
        }

        private static void RetrieveSoftwareInfo(string registryPath, List<SoftwareInfo> softwareList, HashSet<string> softwareNames)
        {
            using (RegistryKey keys = Registry.LocalMachine.OpenSubKey(registryPath, false))
            {
                if (keys != null)
                {
                    foreach (string key in keys.GetSubKeyNames())
                    {
                        using (RegistryKey k = keys.OpenSubKey(key, false))
                        {
                            if (k != null)
                            {
                                try
                                {
                                    string name = k.GetValue("DisplayName")?.ToString();
                                    string version = k.GetValue("DisplayVersion")?.ToString();
                                    string installPath = k.GetValue("InstallLocation")?.ToString();
                                    string publisher = k.GetValue("Publisher")?.ToString();
                                    string installDate = k.GetValue("InstallDate")?.ToString();

                                    if (string.IsNullOrEmpty(installPath))
                                    {
                                        string displayIcon = k.GetValue("DisplayIcon")?.ToString();
                                        if (!string.IsNullOrEmpty(displayIcon))
                                        {
                                            installPath = Path.GetDirectoryName(displayIcon);
                                        }
                                        else
                                        {
                                            installPath = "";
                                        }
                                    }


                                    if (!string.IsNullOrEmpty(name) && !softwareNames.Contains(name))
                                    {
                                        softwareNames.Add(name);
                                        softwareList.Add(new SoftwareInfo
                                        {
                                            name = name,
                                            version = version,
                                            installPath = installPath,
                                            publisher = publisher,
                                            installDate = installDate
                                        });

                                        //Logger.WriteLine($"[DEBUG] Software '{name}' found in registry path: {registryPath}");
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Logger.WriteLine($"Error reading registry key {key}: {ex.Message}");
                                }
                            }
                        }
                    }
                }
            }
        }

        private static bool IsSpecialSoftware(string name)
        {
            string[] specialSoftware = new string[]
            {
                "微信", "Google Chrome", "Xshell","Xftp","Xmanager","ToDesk","向日葵","MobaXterm","Foxmail"
            };

            return specialSoftware.Any(name.Contains);
        }
        private static bool IsIgnoredSoftware(string name)
        {
            string[] ignoredSoftware = new string[]
            {
                "Microsoft", "NVIDIA", "Intel(R)", "GameSDK Service", "VGA", "Visual C++", ".NET"
            };

            return ignoredSoftware.Any(name.Contains) || !Regex.IsMatch(name, @"[\u4e00-\u9fa5]");
        }

        private static void PrintSoftwareList(string header, List<SoftwareInfo> softwareList)
        {
            Logger.TaskHeader(header, 2);
            foreach (SoftwareInfo s in softwareList)
            {
                Logger.WriteLine($"  [ {s.name} ] -- {s.version}");
            }
        }
    }
}