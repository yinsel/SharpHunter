using System;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace SharpHunter.Utils
{
    class ADQueryManager
    {
        public static void GetDC(string ldapPath, string username = null, string password = null)
        {
            string filter = "(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))";

            Action<SearchResult> additionalProcessing = result =>
            {
                DirectoryEntry resultEntry = result.GetDirectoryEntry();

                string distinguishedName = LdapQueryHelper.GetProperty(resultEntry, "distinguishedName");
                string dNSHostName = LdapQueryHelper.GetProperty(resultEntry, "dNSHostName");
                string operatingSystem = LdapQueryHelper.GetProperty(resultEntry, "operatingSystem");
                StringBuilder output = new StringBuilder();

                if (!string.IsNullOrEmpty(distinguishedName))
                {
                    var domainParts = distinguishedName.Split(',');
                    var dcParts = domainParts.Where(part => part.TrimStart().StartsWith("DC=")).Select(part => part.Substring(3));
                    string domainName = String.Join(".", dcParts.ToArray());

                    output.AppendLine(dcParts.Count() > 2
                        ? "  [*] This is a Child Domain Controller!"
                        : "  [*] This is a Parent Domain Controller!");
                    output.AppendLine("  [+] Domain: " + domainName);
                }

                if (!string.IsNullOrEmpty(dNSHostName))
                {
                    output.AppendLine("  [+] DC-FQDN: " + dNSHostName);
                    output.AppendLine("  [+] DC-IP: " + LdapQueryHelper.GetIPAddress(dNSHostName));
                }

                if (!string.IsNullOrEmpty(operatingSystem))
                {
                    output.AppendLine("  [+] DC-OS: " + operatingSystem);
                }
                Logger.WriteLine(output.ToString());
            };

            LdapQueryHelper.PerformLdapQuery(ldapPath, filter, new Dictionary<string, string>(), "Domain Controllers", null, username, password, additionalProcessing);
        }
    }
}
