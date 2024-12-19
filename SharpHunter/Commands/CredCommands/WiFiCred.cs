using SharpHunter.Utils;
using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;

namespace SharpHunter.Commands
{
    class WifiCredCommand : ICommand
    {
        public void Execute(List<string> args)
        {
            Logger.TaskHeader("Wi-Fi Credential ", 1);
            try
            {
                string wifi = GetWifiProfile();
                if (!string.IsNullOrEmpty(wifi))
                {
                    Console.WriteLine(wifi);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] An error occurred while hunting Wi-Fi information: " + ex.Message);
            }
        }
        private string GetWifiProfile()
        {
            const int dwClientVersion = 2;  
            IntPtr clientHandle = IntPtr.Zero; 
            IntPtr pInterfaceList = IntPtr.Zero; 
            Win32.WLAN_INTERFACE_INFO_LIST interfaceList;
            Win32.WLAN_PROFILE_INFO_LIST wifiProfileList;
            Guid InterfaceGuid;
            IntPtr profileList = IntPtr.Zero;
            StringBuilder sb = new StringBuilder();

            try
            {
                Win32.WlanOpenHandle(dwClientVersion, IntPtr.Zero, out _, ref clientHandle);
                Win32.WlanEnumInterfaces(clientHandle, IntPtr.Zero, ref pInterfaceList);
                interfaceList = new Win32.WLAN_INTERFACE_INFO_LIST(pInterfaceList);
                InterfaceGuid = interfaceList.InterfaceInfo[0].InterfaceGuid;

                Win32.WlanGetProfileList(clientHandle, InterfaceGuid, IntPtr.Zero, ref profileList);
                wifiProfileList = new Win32.WLAN_PROFILE_INFO_LIST(profileList);
                if (wifiProfileList.dwNumberOfItems <= 0) return null;
                Logger.WriteLine("[+] Hunted " + wifiProfileList.dwNumberOfItems + " Connected Wifi Information: ");

                for (int i = 0; i < wifiProfileList.dwNumberOfItems; i++)
                {
                    try
                    {
                        string profileName = (wifiProfileList.ProfileInfo[i]).strProfileName;
                        int decryptKey = 63;
                        Win32.WlanGetProfile(clientHandle, InterfaceGuid, profileName, IntPtr.Zero, out var wifiXmlProfile, ref decryptKey, out _);

                        XmlDocument xmlProfileXml = new XmlDocument();
                        xmlProfileXml.LoadXml(wifiXmlProfile);

                        XmlNodeList pathToSSID = xmlProfileXml.SelectNodes("//*[name()='WLANProfile']/*[name()='SSIDConfig']/*[name()='SSID']/*[name()='name']");
                        XmlNodeList pathToPassword = xmlProfileXml.SelectNodes("//*[name()='WLANProfile']/*[name()='MSM']/*[name()='security']/*[name()='sharedKey']/*[name()='keyMaterial']");
                        foreach (XmlNode ssid in pathToSSID)
                        {
                            Logger.WriteLine("\n  [*] SSID: " + ssid.InnerText);
                            foreach (XmlNode password in pathToPassword)
                            {
                                Logger.WriteLine("  [*] Password: " + password.InnerText);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.WriteLine("[-] Error retrieving profile: " + ex.Message);
                    }
                }
                Win32.WlanCloseHandle(clientHandle, IntPtr.Zero);
            }
            catch (Exception ex)
            {
                Logger.WriteLine("[-] Error: " + ex.Message);
                Logger.WriteLine("[*] This is probably a virtual machine.");
            }
            return sb.ToString();
        }

    }
}