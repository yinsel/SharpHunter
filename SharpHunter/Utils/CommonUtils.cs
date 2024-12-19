using System;
using System.Collections.Generic;
using System.Security.Principal;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.IO;
using Microsoft.Win32;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Linq;
using System.Net;
using System.Diagnostics;

namespace SharpHunter.Utils
{

    public static class CommonUtils
    {
        public static void Banner()
        {
            string banner = @"
 $$\       $$$$$$\ $$$$$$$$\  $$$$$$\  $$$$$$$\  
 $$ |     $$  __$$\\__$$  __|$$  __$$\ $$  __$$\ 
 $$ |     $$ /  \__|  $$ |   $$ /  $$ |$$ |  $$ |
 $$ |     \$$$$$$\    $$ |   $$$$$$$$ |$$$$$$$  |
 $$ |      \____$$\   $$ |   $$  __$$ |$$  __$$< 
 $$ |     $$\   $$ |  $$ |   $$ |  $$ |$$ |  $$ |
 $$$$$$$$\\$$$$$$  |  $$ |   $$ |  $$ |$$ |  $$ |
 \________|\______/   \__|   \__|  \__|\__|  \__|";
            Logger.WriteLine(banner);
        }

        public static void DisplayHelp()
        {
            string helpInfo = @"
[*] Usage: SharpHunter [command] [options]

  Info Commands:
    all       - Hunt all informations and credentials.
    sys       - Collect basic system information.
    pid       - List and mark running processes.
    net       - Display network connection details.
    rdp       - Check RDP settings and connection history.
    soft      - List all installed software.
    file      - Gather information about user files.
    domain    - Enumerating Active Directory environments.

  Cred Commands:
    chrome    - Extract credentials from Chromium-based browsers.
    fshell    - Retrieve passwords saved by FinalShell.
    moba      - Extract MobaXterm credentials and passwords.
    todesk    - Hunt credentials from ToDesk process.
    sunlogin  - Hunt credentials from SunloginClient process.
    wechat    - Extract WeChatKey from the WeChat process.
    wifi      - Retrieve Wi-Fi SSIDs and passwords.

  Post Commands:
    run       - Execute commands using the current thread token.
    screen    - Capture a full-screen screenshot of all displays.
    adduser   - Add an administrator account for remote access.
    enrdp     - Enable RDP and create an administrator RDP user.
    down      - Download files remotely from the target server.

  Options:
    -log      - Enable logging.
    -zip      - Enable log compression.
";


            Logger.WriteLine(helpInfo);
        }

        public static bool IsAdminRight()
        {
            bool isElevated;
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                isElevated = principal.IsInRole(WindowsBuiltInRole.Administrator);

                return isElevated;
            }
        }

        public struct ProcessInfo
        {
            public int ProcessId;
            public string FilePath;
        }

        public static ProcessInfo? GetProcessInfoByName(string processName)
        {
            var processes = Process.GetProcessesByName(processName);
            foreach (var process in processes)
            {
                try
                {
                    string filePath = process.MainModule.FileName;
                    return new ProcessInfo
                    {
                        ProcessId = process.Id,
                        FilePath = filePath
                    };
                }
                catch
                {
                }
            }
            return null; 
        }

        public static ProcessInfo? GetProcessInfoByPattern(string pattern)
        {
            var regex = new Regex(pattern, RegexOptions.IgnoreCase);
            var processes = Process.GetProcesses();
            foreach (var process in processes)
            {
                try
                {
                    string processName = process.ProcessName;
                    if (regex.IsMatch(processName))
                    {
                        string filePath = process.MainModule.FileName;
                        return new ProcessInfo
                        {
                            ProcessId = process.Id,
                            FilePath = filePath
                        };
                    }
                }
                catch
                {
                }
            }
            return null; 
        }
        // Helper method to combine multiple paths
        public static string CombinePaths(params string[] paths)
        {
            if (paths == null || paths.Length == 0)
                throw new ArgumentException("No paths provided");

            string combinedPath = paths[0];
            for (int i = 1; i < paths.Length; i++)
            {
                combinedPath = Path.Combine(combinedPath, paths[i]);
            }
            return combinedPath;
        }

        public static void EnsureDirectoryExists(string filePath)
        {
            string directoryPath = Path.GetDirectoryName(filePath);

            if (!Directory.Exists(directoryPath))
            {
                Directory.CreateDirectory(directoryPath);
            }
        }

        public static string Base64Encode(string s)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(s));
        }
        public static string Base64Decode(string s)
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(s));
        }

        public static void ChangeRegistryKey(string registryPath, string valueName, object value, RegistryValueKind valueKind)
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(registryPath, true))
            {
                key.SetValue(valueName, value, valueKind);
            }
        }

        public static string GetURLStatusCode(string url)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "GET";
            request.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3";
            request.Timeout = 3000;
            try
            {
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    return ((int)response.StatusCode).ToString();
                }
            }
            catch (WebException ex)
            {
                if (ex.Response is HttpWebResponse errorResponse)
                {
                    return ((int)errorResponse.StatusCode).ToString();
                }
                else
                {
                    return "error";
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Unexpected error: {ex.Message}");
                return "error";
            }
        }
        // 获取有效的IPv4地址列表
        public static List<string> GetValidIPv4Addresses()
        {
            List<string> ipv4Addresses = new List<string>();
            NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();

            foreach (NetworkInterface adapter in interfaces)
            {
                if (adapter.Supports(NetworkInterfaceComponent.IPv4))
                {
                    IPInterfaceProperties adapterProperties = adapter.GetIPProperties();
                    foreach (UnicastIPAddressInformation ip in adapterProperties.UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == AddressFamily.InterNetwork &&
                            !IsIgnoredAddress(ip.Address.ToString()))
                        {
                            ipv4Addresses.Add(ip.Address.ToString());
                        }
                    }
                }
            }

            return ipv4Addresses;
        }

        private static readonly List<string> FixedIgnoredAddresses = new List<string>
        {
            "127.0.0.1", // 本地回环地址
            //"0.0.0.0",   // 一般用于表示未知地址
            "2.2.2.2"    // 示例中已有的地址
        };

        private static readonly List<Regex> IgnoredAddressPatterns = new List<Regex>
        {
            new Regex("^169\\.254\\..*$"),  // 排除APIPA地址
            new Regex("^\\d+\\.\\d+\\.\\d+\\.1$")  // 排除形如 x.x.x.1 的地址
        };
        public static bool IsIgnoredAddress(string address)
        {
            if (FixedIgnoredAddresses.Contains(address))
            {
                return true;
            }

            return IgnoredAddressPatterns.Any(pattern => pattern.IsMatch(address));
        }
    }
}