using System;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;

namespace SharpHunter.Utils
{
    public class LdapQueryHelper
    {
        public static DirectoryEntry CreateEntry(string ldapPath, string username = null, string password = null)
        {
            return string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password)
                ? new DirectoryEntry(ldapPath)
                : new DirectoryEntry(ldapPath, username, password);
        }

        public static string GetProperty(DirectoryEntry entry, string propertyName)
        {
            if (entry.Properties.Contains(propertyName) && entry.Properties[propertyName].Count > 0)
            {
                return entry.Properties[propertyName][0].ToString();
            }
            return string.Empty;
        }

        public static void AppendPropertyIfExists(StringBuilder stringBuilder, DirectoryEntry entry, string propertyName, string label)
        {
            string propertyValue = GetProperty(entry, propertyName);
            if (!string.IsNullOrEmpty(propertyValue))
            {
                if (stringBuilder.Length > 0)
                {
                    stringBuilder.Append("  ==>>>  ");
                }
                stringBuilder.Append($"{label}{propertyValue}");
            }
        }

        public static void PerformLdapQuery(
            string ldapPath,
            string filter,
            Dictionary<string, string> propertiesWithLabels,
            string title,
            string customMessage = null,
            string username = null,
            string password = null,
            Action<SearchResult> additionalProcessing = null,
            string outputFormat = "list")
        {
            if (title != null)
            {
                Logger.TaskHeader(title, 2);
            }
            try
            {
                DirectoryEntry entry = CreateEntry(ldapPath, username, password);
                DirectorySearcher searcher = new DirectorySearcher(entry) { Filter = filter };

                // Load properties
                var propertiesToLoad = propertiesWithLabels.Keys.ToList();
                foreach (var propName in propertiesToLoad)
                {
                    searcher.PropertiesToLoad.Add(propName);
                }

                SearchResultCollection results = searcher.FindAll();

                if (results.Count == 0)
                {
                    Logger.WriteLine("[-] Not hunted.");
                    Logger.WriteLine(""); // Ensure at least one newline
                    return;
                }

                // 当 customMessage 不为 "No" 时才打印
                if (string.IsNullOrEmpty(customMessage) || !customMessage.Equals("No", StringComparison.OrdinalIgnoreCase))
                {
                    string message = $"[*] Hunted {results.Count} {customMessage ?? title}:\n";
                    Logger.WriteLine(message);
                }

                if (outputFormat == "table")
                {
                    // Print results as a table
                    var rows = new List<List<string>>();
                    var headers = propertiesWithLabels.Values.ToList();
                    foreach (SearchResult result in results)
                    {
                        var row = new List<string>();
                        foreach (var propName in propertiesToLoad)
                        {
                            string propertyValue = GetProperty(result.GetDirectoryEntry(), propName);
                            row.Add(string.IsNullOrEmpty(propertyValue) ? "N/A" : propertyValue);
                        }
                        rows.Add(row);
                    }
                    Logger.PrintTable(headers, rows);
                    Logger.WriteLine("");
                }

                else
                {
                    for (int i = 0; i < results.Count; i++)
                    {
                        SearchResult result = results[i];
                        DirectoryEntry resultEntry = result.GetDirectoryEntry();
                        StringBuilder details = new StringBuilder();

                        foreach (var pair in propertiesWithLabels)
                        {
                            AppendPropertyIfExists(details, resultEntry, pair.Key, pair.Value);
                        }

                        if (additionalProcessing != null)
                        {
                            additionalProcessing.Invoke(result);
                        }
                        else if (details.Length > 0)
                        {
                            Logger.WriteLine($"  [+] {details}");
                        }

                        if (additionalProcessing == null && i == results.Count - 1)
                        {
                            Logger.WriteLine("");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Not hunted: {ex.Message}");
            }
        }

    
        public static void HandleLdapException(Exception ex)
        {
            if (ex is DirectoryServicesCOMException comEx)
            {
                Logger.WriteLine("[-] Error in LDAP query: " + comEx.Message);
            }
            else
            {
                Logger.WriteLine("[-] General error: " + ex.Message);
            }
        }



        public static string GetIPAddress(string dnsHostName)
        {
            try
            {
                var hostEntry = Dns.GetHostEntry(dnsHostName);
                foreach (var ipAddress in hostEntry.AddressList)
                {
                    if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
                    {
                        return ipAddress.ToString();
                    }
                }
                return "[-] No IPv4 address found";
            }
            catch (Exception ex)
            {
                return "[-] Error: " + ex.Message;
            }
        }

        public static string GetLdapAddress()
        {
            try
            {
                Domain domain = Domain.GetCurrentDomain();
                string ldapPath = domain.GetDirectoryEntry().Path;
                return ldapPath;
            }
            catch (ActiveDirectoryObjectNotFoundException)
            {
                Logger.WriteLine("[-] Error: No Active Directory found.");
                return null;
            }
        }

        public static bool TryLdapConnection(string ldapPath, string username, string password)
        {
            try
            {
                using (DirectoryEntry entry = new DirectoryEntry(ldapPath, username, password))
                {
                    object nativeObject = entry.NativeObject;
                    return true; 
                }
            }
            catch (DirectoryServicesCOMException ex)
            {
                Logger.WriteLine("[-] LDAP connection failed: " + ex.Message);
                return false; 
            }
        }

        public static void GetDomainInfo(string ldapPath, string username = null, string password = null)
        {
            try
            {
                int machineAccountQuota = GetMachineAccountQuota(ldapPath, username, password);
                Domain domain = Domain.GetCurrentDomain();

                Logger.TaskHeader("DomainInfo", 1);
                Logger.WriteLine($"[*] Current Domain: {domain.Name}");

                // 获取域的 SID
                DirectoryEntry entry = CreateEntry(ldapPath, username, password);
                DirectorySearcher searcher = new DirectorySearcher(entry)
                {
                    Filter = "(objectClass=domainDNS)",
                };

                SearchResult result = searcher.FindOne();
                if (result.Properties.Contains("objectSid") && result.Properties["objectSid"].Count > 0)
                {
                    byte[] sidBytes = result.Properties["objectSid"][0] as byte[];
                    if (sidBytes != null)
                    {
                        SecurityIdentifier sid = new SecurityIdentifier(sidBytes, 0);
                        string sidString = sid.ToString();
                        Logger.WriteLine($"[*] Domain SID: {sidString}");
                    }
                    else
                    {
                        Logger.WriteLine("[-] Unable to retrieve Domain SID.");
                    }
                }
                else
                {
                    Logger.WriteLine("[-] Domain SID not found in LDAP result.");
                }
                Logger.WriteLine($"[*] ms-DS-MachineAccountQuota: {machineAccountQuota}");
            }
            catch (Exception ex)
            {
                HandleLdapException(ex);
            }
            Logger.WriteLine("");
        }

        public static int GetMachineAccountQuota(string ldapPath, string username = null, string password = null)
        {
            int machineAccountQuota = 0; // 默认值，表示未找到或无法访问

            try
            {
                DirectoryEntry entry = new DirectoryEntry(ldapPath, username, password);
                DirectorySearcher searcher = new DirectorySearcher(entry)
                {
                    Filter = "(objectClass=domainDNS)",
                    SearchScope = SearchScope.Base
                };

                SearchResult result = searcher.FindOne();
                if (result != null && result.Properties.Contains("ms-DS-MachineAccountQuota"))
                {
                    machineAccountQuota = (int)result.Properties["ms-DS-MachineAccountQuota"][0];
                }
                else
                {
                    Logger.WriteLine("[*] Unable to find or access ms-DS-MachineAccountQuota attribute.");
                }
            }
            catch (Exception ex)
            {
                HandleLdapException(ex);
            }

            return machineAccountQuota;
        }
    }
}