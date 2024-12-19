using System;
using System.Collections.Generic;
using System.IO;
using SharpHunter.Utils;

namespace SharpHunter.Commands
{
    class UserFileInfoCommand : ICommand
    {
        public void Execute(List<string> args)
        {
            HostFile();
            RecentFile();
            UserDesktopFileInfo();
        }

        public static void HostFile()
        {
            Logger.TaskHeader("HostsFile", 1);
            var hosts = new Dictionary<string, string>();
            var lines = File.ReadAllLines(@"C:\Windows\System32\drivers\etc\hosts");
            foreach (var line in lines)
            {
                if (string.IsNullOrEmpty(line) || line.Trim().Length == 0 || line.StartsWith("#") || line.StartsWith("0.0.0.0"))
                {
                    continue;
                }

                var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2)
                {
                    hosts[parts[1]] = parts[0];
                }
            }
            foreach (var host in hosts)
            {
                Logger.WriteLine($"[*] {host.Key} --- {host.Value} ");
            }
            if (hosts.Count == 0)
            {
                Logger.WriteLine("[-] Not hunted.");
            }
        }

        public static void RecentFile()
        {
            Logger.TaskHeader("RecentFile", 1);
            try
            {
                var recentsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Microsoft\Windows\Recent");
                var di = new DirectoryInfo(recentsPath);
                Logger.WriteLine("[*] " + recentsPath + "\n");
                foreach (var f in di.GetFiles())
                {
                    Logger.WriteLine("   [ " + f.LastAccessTime + " ] " + "-- " + f.Name);
                }
            }
            catch (Exception e)
            {
                Logger.WriteLine("[-]ERROR: {0}", e);
            }
        }

        public static void UserDesktopFileInfo()
        {
            Logger.TaskHeader("UserFileInfo", 1);
            Logger.WriteLine("[*] Hunting all user desktops and download folders.");
            var userpath = @"C:\Users";
            var userPathList = Directory.GetDirectories(userpath);
            if (Directory.Exists(userpath))
            {
                foreach (var user in userPathList)
                {
                    if (user.EndsWith("Default User") || user.EndsWith("All Users") || user.EndsWith("Default"))
                    {
                        continue;
                    }
                    Logger.TaskHeader($"{user}", 2);
                    ProcessDirectory(user, "Desktop");
                    ProcessDirectory(user, "Downloads");
                    ProcessCredentials(user);
                }
            }
        }

        private static void ProcessDirectory(string user, string folderName)
        {
            var directoryPath = Path.Combine(user, folderName);
            if (Directory.Exists(directoryPath))
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Logger.WriteLine("[*] " + directoryPath);
                Console.ForegroundColor = ConsoleColor.White;
                try
                {
                    var allFiles = Directory.GetFileSystemEntries(directoryPath, "*");
                    foreach (var file in allFiles)
                    {
                        var createTime = Directory.GetCreationTime(file).ToString();
                        Logger.WriteLine($"   [ {createTime} ] -- {file}");
                    }
                    var passFiles = Directory.GetFileSystemEntries(directoryPath, "*密码*");
                    foreach (var passfile in passFiles)
                    {
                        var createTime = Directory.GetCreationTime(passfile).ToString();
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Logger.WriteLine($"[+] Find PassFile: [ {createTime} ] -- {passfile}");
                        Console.ForegroundColor = ConsoleColor.White;
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Logger.WriteLine(ex.Message);
                    Console.ForegroundColor = ConsoleColor.White;
                }
            }
        }

        private static void ProcessCredentials(string user)
        {
            var credentialsPath = Path.Combine(user, "AppData\\Local\\Microsoft\\Credentials");
            if (Directory.Exists(credentialsPath))
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Logger.WriteLine("[+] Find RDPCredFile: " + credentialsPath);
                Console.ForegroundColor = ConsoleColor.White;
                try
                {
                    var allCredFiles = Directory.GetFileSystemEntries(credentialsPath, "*");
                    foreach (var file in allCredFiles)
                    {
                        var createTime = Directory.GetCreationTime(file).ToString();
                        Logger.WriteLine($"   [ {createTime} ] -- {file}");
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Logger.WriteLine(ex.Message);
                    Console.ForegroundColor = ConsoleColor.White;
                }
            }
        }
    }
}