using System;
using System.Collections.Generic;
using System.Net.NetworkInformation;
using SharpHunter.Utils;

namespace SharpHunter.Commands
{
    class DomainInfoCommand : ICommand
    {
        public void Execute(List<string> args)
        {
            try
            {
                IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();
                if (properties.DomainName.Length > 0)
                {
                    string ldapPath = LdapQueryHelper.GetLdapAddress();

                    LdapQueryHelper.GetDomainInfo(ldapPath);
                    ADQueryManager.GetDC(ldapPath);
                }
                else
                {
                    Logger.TaskHeader("DomainInfo", 1);
                    Logger.WriteLine("[-] Only WorkGroup!");
                }
            }
            catch (Exception ex)
            {
                LdapQueryHelper.HandleLdapException(ex);
            }
        }
    }

}