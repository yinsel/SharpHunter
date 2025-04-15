using System;
using System.Diagnostics;
using SharpHunter.Commands;
using SharpHunter.Utils;

namespace SharpHunter
{
    class Program
    {
        static void RegistrationCommands()
        {
            CommandRegistry.RegisterCommand("all", () => new HuntingAllCommand());
            CommandRegistry.RegisterCommand("sys", () => new SystemInfoCommand());
            CommandRegistry.RegisterCommand("pid", () => new ProcessCommand());
            CommandRegistry.RegisterCommand("net", () => new NetworkInfoCommand());
            CommandRegistry.RegisterCommand("rdp", () => new RDPInfoCommand());
            CommandRegistry.RegisterCommand("soft", () => new SoftwareInfoCommand());
            CommandRegistry.RegisterCommand("file", () => new UserFileInfoCommand());
            CommandRegistry.RegisterCommand("domain", () => new DomainInfoCommand());

            CommandRegistry.RegisterCommand("chrome", () => new ChromiumCredCommand());
            CommandRegistry.RegisterCommand("fshell", () => new FinalShellCredCommand());
            CommandRegistry.RegisterCommand("moba", () => new MobaXtermCredCommand());
            CommandRegistry.RegisterCommand("todesk", () => new ToDeskCredCommand());
            CommandRegistry.RegisterCommand("sunlogin", () => new SunLoginCredCommand());
            CommandRegistry.RegisterCommand("wechat", () => new WeChatCredCommand());
            CommandRegistry.RegisterCommand("wifi", () => new WifiCredCommand());

            CommandRegistry.RegisterCommand("run", () => new ExecuteCmdCommand());
            CommandRegistry.RegisterCommand("screen", () => new ScreenShotPostCommand());
            CommandRegistry.RegisterCommand("adduser", () => new AddUserCommand());
            CommandRegistry.RegisterCommand("enrdp", () => new EnableRDPCommand());
            CommandRegistry.RegisterCommand("down", () => new DownloadFileCommand());
        }
        static void Main(string[] args)
        {
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();

            var commandParsedArgs = CommandLineParser.Parse(args);

            CommonUtils.Banner();


            RegistrationCommands();

            if (args.Length == 0)
            {
                Logger.WriteLine("\n[-] No command provided. Please try again.");
                CommonUtils.DisplayHelp();
                return;
            }

            try
            {
                var command = CommandRegistry.GetCommand(commandParsedArgs.CommandName);
                string commandName = command.GetType().Name; 
                Logger.Initialize(commandParsedArgs.LogEnabled, commandParsedArgs.ZipEnabled, commandName);
                command.Execute(commandParsedArgs.CommandArgs);
            }
            catch (ArgumentException ex)
            {
                Logger.WriteLine($"\n{ex.Message}");
                CommonUtils.DisplayHelp();
            } catch (Exception ex)
            {
                Logger.WriteLine($"\n{ex.Message}");
            }

            if (commandParsedArgs.LogEnabled)
            {
                Logger.WriteLine("[+] LogFilePath: " + Logger.LogFilePath);
            }

            stopwatch.Stop();
            Logger.WriteLine("\n[*] Hunt End: {0} s", stopwatch.Elapsed.TotalSeconds);

            if (commandParsedArgs.ZipEnabled)
            {
                Logger.SetLogToFile();
            }

        }
    }
}