using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using SharpHunter.Utils;

namespace SharpHunter.Commands
{
    public class NetworkInfoCommand : ICommand
    {
        public void Execute(List<string> args)
        {
            Logger.TaskHeader("Network Info", 1);
            Network.NetworkInterfaces();
            Network.ActiveTCPConnections();
        }
    }

    public class Network
    {
        public static IPGlobalProperties iProperties = IPGlobalProperties.GetIPGlobalProperties();

        public static void NetworkInterfaces()
        {
            NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();
            List<string> ipv4Addresses = CommonUtils.GetValidIPv4Addresses();

            // 打印所有 IPv4 地址
            Logger.WriteLine("[+] Total {0} IPv4 Addresses: {1}", ipv4Addresses.Count, string.Join(" - ", ipv4Addresses.ToArray()));
            Logger.TaskHeader("Network Interface", 2);
            Logger.WriteLine("[+] List {0} NetworkInterfaces:\n", interfaces.Length);
            int i = 0;
            foreach (NetworkInterface adapter in interfaces)
            {
                i++;
                if (adapter.Supports(NetworkInterfaceComponent.IPv4))
                {
                    Logger.WriteLine("  Interface{0} .......: {1} - {2}", i, adapter.Name, adapter.NetworkInterfaceType);

                    IPInterfaceProperties adapterProperties = adapter.GetIPProperties();
                    try
                    {

                        UnicastIPAddressInformationCollection uipAddrs = adapterProperties.UnicastAddresses;
                        IEnumerator uipAddrEnum = uipAddrs.GetEnumerator();

                        Logger.Write("  IP Address .......: ");
                        while (uipAddrEnum.MoveNext())
                        {
                            UnicastIPAddressInformation uipAddr = (UnicastIPAddressInformation)uipAddrEnum.Current;
                            Logger.Write("[" + uipAddr.Address.ToString() + "] ");
                        }
                        Logger.WriteLine("");


                        IPAddressCollection ndsAddrs = adapterProperties.DnsAddresses;
                        IEnumerator ndsAddrEnum = ndsAddrs.GetEnumerator();

                        Logger.Write("  DNS Address ......: ");
                        while (ndsAddrEnum.MoveNext())
                        {
                            IPAddress dnsAddr = (IPAddress)ndsAddrEnum.Current;
                            Logger.Write("[" + dnsAddr.ToString() + "] ");
                        }
                        Logger.WriteLine("\n");

                    }
                    catch (Exception e)
                    {
                        Logger.WriteLine("[-]ERROR: {0}", e);
                    }
                }
            }
        }

        public static void ActiveTCPConnections()
        {
            Logger.TaskHeader("Active TcpConnections", 2);
            foreach (var tcp in iProperties.GetActiveTcpConnections())
            {
                string localAddress = tcp.LocalEndPoint.Address.ToString();
                string remoteAddress = tcp.RemoteEndPoint.Address.ToString();

                if (!CommonUtils.IsIgnoredAddress(localAddress) && !CommonUtils.IsIgnoredAddress(remoteAddress))
                {
                    Logger.WriteLine("  {0}:{1} -- {2}:{3}", localAddress, tcp.LocalEndPoint.Port, remoteAddress, tcp.RemoteEndPoint.Port);
                }
            }
        }
    }
}