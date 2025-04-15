using System;
using Microsoft.Win32;
using System.IO;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Xml;
using System.Linq;
using SharpHunter.Utils;

namespace SharpHunter.Commands
{
    public class RDPInfoCommand : ICommand
    {
        public void Execute(List<string> args)
        {
            RDPInfo.RdpStatus();
            RDPInfo.ListRDPOutConnections();
            RDPInfo.ListRDPInConnections();
        }
    }

    class RDPInfo
    {
        private static RegistryKey rk;
        private static string prefix = @"C:\Users\";

        private class Out
        {
            public string port;
            public string username;

            public Out(string v1, string v2)
            {
                port = v1;
                username = v2;
            }
        }

        private class Info
        {
            public int num;
            public string lastTime;

            public Info(int v1, string v2)
            {
                num = v1;
                lastTime = v2;
            }
        }

        private struct LoginRecord
        {
            public string LastRDPLoginTime;
            public int Num;
            public string Address;
            public string User;

            public LoginRecord(string lastTime, int num, string address, string user)
            {
                LastRDPLoginTime = lastTime;
                Num = num;
                Address = address;
                User = user;
            }
        }

        public static void RdpStatus()
        {
            Logger.TaskHeader("RdpInfo", 1);
            RegistryKey key = Registry.LocalMachine;
            //REG查询3389状态（0: ON 、1: OFF）
            RegistryKey RDPstatus = key.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server");
            string status = RDPstatus.GetValue("fDenyTSConnections").ToString();
            RegistryKey RDPport = key.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp");
            string port = RDPport.GetValue("PortNumber").ToString();
            RDPport.Close();

            if (status.Contains("0"))
            {
                Logger.WriteLine("[+] RDP is already enabled");
                Logger.WriteLine($"[+] RDP Port: {port}");
            }
            else
            {
                Logger.WriteLine("[-] RDP is disabled");
            }
        }

        public static void ListRDPOutConnections()
        {
            Logger.TaskHeader("RDP OutConnections", 2);
            List<string> sids = new List<string>(Registry.Users.GetSubKeyNames());

            // Load NTUSER.DAT
            foreach (string dic in Directory.GetDirectories(prefix))
            {
                try
                {
                    string subkey = "S-123456789-" + dic.Replace(prefix, "");
                    string sid = Win32.Load(subkey, $@"{dic}\NTUSER.DAT");
                    sids.Add(sid);
                }
                catch
                {
                    continue;
                }
            }

            // Dump RDP Connection History From Registry
            foreach (string sid in sids)
            {
                if (!sid.StartsWith("S-") || sid.EndsWith("Classes") || sid.Length < 10)
                    continue;

                Dictionary<string, Out> history = GetRegistryValues(sid);
                PrintRDPOutHistory(history, sid);

                if (sid.StartsWith("S-123456789-"))
                {
                    UnLoadHive(sid);
                }
            }

            // Dump RDP Connection History From RDP Files
            foreach (string dic in Directory.GetDirectories(prefix))
            {
                try
                {
                    foreach (string file in Directory.GetFiles($@"{dic}\Documents\", "*.rdp"))
                    {
                        Dictionary<string, Out> history = GetRdpFileValues(file);
                        PrintRDPOutHistory(history, file);
                    }
                }
                catch
                {
                    continue;
                }
            }
        }

        static void PrintRDPOutHistory(Dictionary<string, Out> values, string sid = "")
        {
            if (values.Count != 0)
            {
                Logger.WriteLine($"[{sid}]");
                foreach (var item in values)
                {
                    string port = item.Value.port != "" ? ":" + item.Value.port : "";
                    Logger.WriteLine($"  [+] {item.Key}{port}   {item.Value.username}");
                }
                Logger.WriteLine("");
            }
        }

        static void UnLoadHive(string sid)
        {
            if (sid.StartsWith("S-123456789-"))
            {
                Win32.UnLoad(sid);
            }
        }

        static Dictionary<string, Out> GetRegistryValues(string sid)
        {
            Dictionary<string, Out> values = new Dictionary<string, Out>();
            string baseKey = $@"{sid}\Software\Microsoft\Terminal Server Client\";

            try
            {
                // 当前用户 mstsc 缓存连接记录
                rk = Registry.Users.OpenSubKey(baseKey + "Default");
                if (rk != null)
                {
                    foreach (string mru in rk.GetValueNames())
                    {
                        string port = "";
                        string value = rk.GetValue(mru).ToString();
                        string address = value.Split(':')[0];
                        if (value.Contains(":"))
                        {
                            port = value.Split(':')[1];
                        }
                        if (!values.ContainsKey(address))
                        {
                            values.Add(address, new Out(port, ""));
                        }
                    }
                    rk.Close();
                }


                // 当前用户 cmdkey 缓存记录 
                string[] addresses = { };
                rk = Registry.Users.OpenSubKey(baseKey + "Servers");
                if (rk != null)
                {
                    addresses = rk.GetSubKeyNames();
                    rk.Close();
                }
       
                foreach (string address in addresses)
                {
                    rk = Registry.Users.OpenSubKey($@"{baseKey}Servers\{address}");
                    if (rk != null)
                    {
                        string user = rk.GetValue("UsernameHint").ToString();
                        if (values.ContainsKey(address))
                        {
                            values[address].username = user;
                        }
                        rk.Close();
                    }
     
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"ex: {ex}");
            }

            return values;
        }

        static Dictionary<string, Out> GetRdpFileValues(string file)
        {
            Dictionary<string, Out> values = new Dictionary<string, Out>();
            string line;
            string addressStr = "full address:s:";
            string usernameStr = "username:s:";
            string address = "";
            string username = "";
            string port = "";

            try
            {
                StreamReader sr = new StreamReader(file);
                while (sr.Peek() >= 0)
                {
                    line = sr.ReadLine();
                    if (line.StartsWith(addressStr))
                    {
                        address = line.Replace(addressStr, "");
                    }
                    if (line.StartsWith(usernameStr))
                    {
                        username = line.Replace(usernameStr, "");
                    }
                }

                if (address != "")
                {
                    address = address.Split(':')[0];
                    if (address.Contains(":"))
                    {
                        port = address.Split(':')[1];
                    }
                    values.Add(address, new Out(port, username));
                }
            }
            catch
            {
            }

            return values;
        }

        public static void ListRDPInConnections()
        {
            Logger.TaskHeader("RDP InConnections", 2);
            string logTypeSuccess = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
            string logTypeAll = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";
            string querySuccess = "*[System/EventID=21] or *[System/EventID=25]";
            string queryAll = "*[System/EventID=1149]";

            var historySuccess = ListEventvwrRecords(logTypeSuccess, querySuccess).OrderByDescending(s => s.Value.num).ToDictionary(p => p.Key, p => p.Value);
            var historyAll = ListEventvwrRecords(logTypeAll, queryAll, true).OrderByDescending(s => s.Value.num).ToDictionary(p => p.Key, p => p.Value);

            List<LoginRecord> successfulLogins = new List<LoginRecord>();
            List<LoginRecord> failedLogins = new List<LoginRecord>();

            foreach (var item in historySuccess)
            {
                DateTime localTime = DateTime.Parse(item.Value.lastTime).ToLocalTime();
                successfulLogins.Add(new LoginRecord(localTime.ToString("yyyy-MM-dd HH:mm:ss"), item.Value.num, item.Key.Split('\t')[0], item.Key.Split('\t')[1]));
                historyAll.Remove(item.Key);
            }

            foreach (var item in historyAll)
            {
                DateTime localTime = DateTime.Parse(item.Value.lastTime).ToLocalTime();
                failedLogins.Add(new LoginRecord(localTime.ToString("yyyy-MM-dd HH:mm:ss"), item.Value.num, item.Key.Split('\t')[0], item.Key.Split('\t')[1]));
            }

            if (successfulLogins.Count > 0)
            {
                Logger.WriteLine("[*] Login Successful:\n");
                Logger.PrintTableFromStructs(successfulLogins);
            }

            if (failedLogins.Count > 0)
            {
                Logger.WriteLine("\n[*] Login Failed:\n");
                Logger.PrintTableFromStructs(failedLogins);
            }
        }

        static Dictionary<string, Info> ListEventvwrRecords(string logType, string query, bool flag = false)
        {
            Dictionary<string, Info> values = new Dictionary<string, Info>();

            var elQuery = new EventLogQuery(logType, PathType.LogName, query);
            var elReader = new EventLogReader(elQuery);

            for (EventRecord eventInstance = elReader.ReadEvent(); eventInstance != null; eventInstance = elReader.ReadEvent())
            {
                XmlDocument doc = new XmlDocument();
                doc.LoadXml(eventInstance.ToXml());
                XmlNodeList systemData = doc.FirstChild.FirstChild.ChildNodes;
                XmlNodeList userData = doc.FirstChild.LastChild.FirstChild.ChildNodes;
                string lastTime = systemData[7].Attributes.Item(0).InnerText.Remove(19);
                string user = userData[0].InnerText;
                string address = userData[2].InnerText;

                if (flag == true)
                {
                    string domain = userData[1].InnerText;
                    user = domain + (domain != "" ? "\\" : "") + user;
                }
                string value = $"{address}\t{user}";

                if (address != "本地")
                {
                    if (!values.ContainsKey(value))
                    {
                        values.Add(value, new Info(1, lastTime));
                    }
                    else
                    {
                        values[value].num += 1;
                    }
                }
            }

            return values;
        }
    }
}