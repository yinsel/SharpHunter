using System;
using System.IO;
using SharpHunter.Utils;
using Microsoft.VisualBasic.Devices;
using System.Management;
using Microsoft.Win32;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Linq;

namespace SharpHunter.Commands
{
    public class SystemAllInformations
    {
        public bool IsAdmin { get; set; }
        public string UserName { get; set; }
        public List<string> IPv4Addresses { get; set; }
        public string UserDomainName { get; set; }
        public string MachineName { get; set; }
        public string TimeZone { get; set; }
        public string LocalTime { get; set; }
        public string SystemInstallDate { get; set; }
        public string LastBootUpTime { get; set; }
        public string OSVersion { get; set; }
        public string[] Drives { get; set; }
        public string CurrentDirectory { get; set; }
        public string DotNetVersion { get; set; }
        public string BiosVersion { get; set; }
        public int ProcessorCount { get; set; }
        public double TotalPhysicalMemoryGB { get; set; }
        public double TotalDiskSizeGB { get; set; }
        public string ProcessorArchitecture { get; set; }
    }
    public class SystemInfoCommand : ICommand
    {
        public SystemAllInformations CollectSystemInfo()
        {
            TimeZone localZone = TimeZone.CurrentTimeZone;
            ComputerInfo computerInfo = new ComputerInfo();
            string[] logicalDrives = Environment.GetLogicalDrives();
            DriveInfo firstDrive = new DriveInfo(logicalDrives[0]);
            double totalSizeInGB = firstDrive.TotalSize / Math.Pow(1024, 3);
            List<string> ipv4Addresses = CommonUtils.GetValidIPv4Addresses();
            string biosVersion = "N/A";
            string systemInstallDate = "N/A";
            string lastBootUpTime = "N/A";

            try
            {
                using (ManagementObject Mobject = new ManagementClass("Win32_BIOS").GetInstances().OfType<ManagementObject>().FirstOrDefault())
                {
                    if (Mobject != null)
                    {
                        biosVersion = $"{Mobject["Manufacturer"]}";
                    }
                }

                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        systemInstallDate = ManagementDateTimeConverter.ToDateTime(obj["InstallDate"].ToString()).ToString();
                        lastBootUpTime = ManagementDateTimeConverter.ToDateTime(obj["LastBootUpTime"].ToString()).ToString();
                    }
                }
            }
            catch
            {
                // Handle exceptions if necessary
            }
            SystemAllInformations sysInfo = new SystemAllInformations
            {
                IsAdmin = CommonUtils.IsAdminRight(),
                UserName = Environment.UserName,
                IPv4Addresses = ipv4Addresses,
                UserDomainName = Environment.UserDomainName,
                MachineName = Environment.MachineName,
                TimeZone = localZone.StandardName,
                LocalTime = DateTime.Now.ToLocalTime().ToString(),
                SystemInstallDate = systemInstallDate,
                LastBootUpTime = lastBootUpTime,
                OSVersion = computerInfo.OSFullName,
                Drives = logicalDrives,
                CurrentDirectory = Environment.CurrentDirectory,
                DotNetVersion = Environment.Version.ToString(),
                BiosVersion = biosVersion,
                ProcessorCount = Environment.ProcessorCount,
                TotalPhysicalMemoryGB = computerInfo.TotalPhysicalMemory / (1024 * 1024 * 1024),
                TotalDiskSizeGB = totalSizeInGB,
                ProcessorArchitecture = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")
            };
            return sysInfo;
        }


        public void Execute(List<string> args)
        {
            SystemAllInformations sysInfo = CollectSystemInfo();

            GetSysBasicInfo();
            GetUserAccounts();
            GetDefenderExclusions();
            Environment_Variable();
            DotNet_Version();
        }

        public void GetSysBasicInfo()
        {
            SystemAllInformations sysInfo = CollectSystemInfo();

            Logger.TaskHeader("Collecting Target Machine Information", 1);
            Logger.WriteLine("IsAdmin：" + sysInfo.IsAdmin);
            Logger.WriteLine("Whoami: " + sysInfo.UserName);
            Logger.WriteLine("IPv4Addr: {0}", string.Join(" ", sysInfo.IPv4Addresses.ToArray()));
            Logger.WriteLine("Domain: " + sysInfo.UserDomainName);
            Logger.WriteLine("HostName: " + sysInfo.MachineName);
            Logger.WriteLine("TimeZone: " + sysInfo.TimeZone);
            Logger.WriteLine("LocalTime: " + sysInfo.LocalTime);
            Logger.WriteLine("OSVersion: " + sysInfo.OSVersion);
            Logger.WriteLine("OSInstall: " + sysInfo.SystemInstallDate);
            Logger.WriteLine("LastBootUp: " + sysInfo.LastBootUpTime);
            Logger.WriteLine("Drives: {0}", string.Join(", ", sysInfo.Drives));
            Logger.WriteLine("Path: " + sysInfo.CurrentDirectory);
            Logger.WriteLine("DotNet: {0}", sysInfo.DotNetVersion);
            Logger.WriteLine("BIOS: " + sysInfo.BiosVersion);
            Logger.WriteLine("CPUS: {0} Count  MEMS: {1} GB", sysInfo.ProcessorCount, sysInfo.TotalPhysicalMemoryGB);
            Logger.WriteLine("Disk: {0} GB", sysInfo.TotalDiskSizeGB.ToString("0.00"));
            Logger.WriteLine("Arch: " + sysInfo.ProcessorArchitecture);
        }

        public static string GetAntivirus()
        {
            try
            {
                using (var antiVirusSearch = new ManagementObjectSearcher(
                           @"\\" + Environment.MachineName + @"\root\SecurityCenter2",
                           "Select * from AntivirusProduct"))
                {
                    var av = new List<string>();
                    foreach (var searchResult in antiVirusSearch.Get())
                        av.Add(searchResult["displayName"].ToString());
                    if (av.Count == 0) return "Not installed";
                    return string.Join(", ", av.ToArray()) + "";
                }
            }
            catch
            {
                // ignored
            }

            return "N/A";
        }


        public static void GetDefenderExclusions()
        {
            Logger.TaskHeader("Defender Exclusions", 1);
            Logger.WriteLine("Antivirus: {0}\n", GetAntivirus());
            if (!CommonUtils.IsAdminRight())
            {
                Logger.WriteLine("[-] Administrator privileges required!");
                return;
            }
            RegistryKey exclusions = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Exclusions");

            if (exclusions == null)
            {
                Logger.WriteLine("[-] No exclusions specified");
            }
            else
            {
                foreach (string subKeyName in exclusions.GetSubKeyNames())
                {
                    RegistryKey subKey = exclusions.OpenSubKey(subKeyName);
                    Logger.WriteLine($"[*] {subKeyName}:");
                    if (subKey.ValueCount > 0)
                    {
                        foreach (string valueName in subKey.GetValueNames())
                        {
                            Logger.WriteLine($"    {valueName}");
                        }
                    }
                    else
                    {
                        Logger.WriteLine("    No values.");
                    }
                }
            }
        }

        public static void GetUserAccounts()
        {
            List<List<string>> rows = new List<List<string>>();
            Logger.TaskHeader("UserAccount", 1);
            // 创建表头
            List<string> headers = new List<string> { "Domain", "Name", "Status", "SID" };

            ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_UserAccount");
            foreach (ManagementObject user in searcher.Get())
            {

                List<string> row = new List<string>
                {
                    (string)user["Domain"],
                    (string)user["Name"],
                    (string)user["Status"],
                    (string)user["SID"]
                };
                rows.Add(row);
            }
            Logger.PrintTable(headers, rows);
        }

        public static void DotNet_Version()
        {
            Logger.WriteLine("[+] Microsoft.NET Versions Installed:\n");
            string[] Netdirectories = Directory.GetDirectories(@"C:\Windows\Microsoft.NET\Framework");
            for (int i = 0; i < Netdirectories.Length; i++)
            {
                Logger.WriteLine("  " + Netdirectories[i]);
            }
            //Logger.WriteLine("");
        }

        public static void Environment_Variable()
        {
            string path = "Environment";
            Logger.TaskHeader("Environment Variable", 1);
            Logger.WriteLine("[+] System Environment Variable Path:\n");

            RegistryKey masterKey = Registry.CurrentUser.OpenSubKey(path);
            if (masterKey != null)
            {
                object pathValue = masterKey.GetValue("Path");
                if (pathValue != null)
                {
                    string sPath = pathValue.ToString();
                    string[] sArray = Regex.Split(sPath, ";", RegexOptions.IgnoreCase);
                    foreach (string i in sArray)
                    {
                        Logger.WriteLine("  " + i);
                    }
                }
                else
                {
                    Logger.WriteLine("[-] 'Path' environment variable not found.");
                }
                masterKey.Close();
            }
            else
            {
                Logger.WriteLine("[-] Could not open registry key for environment variables.");
            }

            Logger.WriteLine("");
        }

    }

}