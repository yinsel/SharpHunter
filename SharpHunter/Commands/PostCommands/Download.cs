using System;
using System.Collections.Generic;
using System.Net;
using System.IO;
using SharpHunter.Utils;

namespace SharpHunter.Commands
{
    class DownloadFileCommand : ICommand
    {
        public void Execute(List<string> args)
        {
            string address = args[0];
            string fileName = args[1];
            string directory = Path.GetDirectoryName(fileName);
            string fullPath = fileName;
            if (!Path.IsPathRooted(fileName))
            {
                fullPath = Path.Combine(Environment.CurrentDirectory, fileName);
                directory = Path.GetDirectoryName(fullPath);
            }
            Logger.TaskHeader("Download File", 1);
            Logger.WriteLine("[*] Download files remotely from the target server.");
            try
            {
                if (!Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }
                using (WebClient webClient = new WebClient())
                {
                    webClient.DownloadFile(address, fullPath);
                    Logger.WriteLine("Download: " + address);
                    Logger.WriteLine("File Save Path: " + fullPath);
                }
            }
            catch (WebException ex)
            {
                if (ex.Status == WebExceptionStatus.ConnectFailure)
                {
                    Logger.WriteLine("[-] Error: Unable to connect to remote server!");
                    Logger.WriteLine("[*] Eg: SharpHunter.exe down http://xxx/hello.exe hello.txt");
                }
                else
                {
                    Logger.WriteLine("[-] Error: Unable to save file!");
                    Logger.WriteLine("[*] Eg: SharpHunter.exe down http://xxx/hello.exe C:/Users/Public/hello.txt");
                    Logger.WriteLine("Exception Details: " + ex.Message);
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLine("[-] Error: Unexpected error!");
                Logger.WriteLine("Exception Details: " + ex.Message);
            }
        }
    }
}