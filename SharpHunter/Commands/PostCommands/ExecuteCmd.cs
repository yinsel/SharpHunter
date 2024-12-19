using SharpHunter.Utils;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace SharpHunter.Commands
{
    class ExecuteCmdCommand : ICommand
    {
        public void Execute(List<string> args)
        {
            Logger.TaskHeader("Attack Mode", 1);
            Logger.WriteLine("[*] Execute commands using the current thread token.");
            Logger.TaskHeader("Run Received", 1);
            RunCommand(args[0]);
        }
        static void Error()
        {
            var error = new Win32Exception(Marshal.GetLastWin32Error()).Message;
            Console.WriteLine(error);
        }
        public static void RunCommand(string cmdline)
        {
            Win32.SECURITY_ATTRIBUTES sa = new Win32.SECURITY_ATTRIBUTES();
            Win32.STARTUPINFO si = new Win32.STARTUPINFO();
            Win32.PROCESS_INFORMATION pi = new Win32.PROCESS_INFORMATION();
            sa.nLength = Marshal.SizeOf(sa);
            sa.lpSecurityDescriptor = IntPtr.Zero;
            sa.bInheritHandle = true;
            IntPtr hRead = IntPtr.Zero;
            IntPtr hWrite = IntPtr.Zero;
            if (!Win32.CreatePipe(out hRead, out hWrite, ref sa, 0))
                return;
            si.cb = Marshal.SizeOf(si);
            si.hStdError = hWrite;
            si.hStdOutput = hWrite;
            si.wShowWindow = Win32.SW_HIDE;
            si.dwFlags = Win32.STARTF_USESHOWWINDOW | Win32.STARTF_USESTDHANDLES;
            var hToken = WindowsIdentity.GetCurrent().Token;
            var hDupedToken = IntPtr.Zero;
            if (!Win32.DuplicateTokenEx(
                hToken,
                Win32.GENERIC_ALL_ACCESS,
                ref sa,
                (int)Win32.SECURITY_IMPERSONATION_LEVEL.SecurityIdentification,
                (int)Win32.TOKEN_TYPE.TokenPrimary,
                ref hDupedToken
            ))
            {
                Error();
                return;
            }
            if (!Win32.CreateProcessAsUser(
                hDupedToken,
                null,
                cmdline,
                ref sa, ref sa,
                true,
                Win32.NORMAL_PRIORITY_CLASS | Win32.CREATE_NO_WINDOW,
                IntPtr.Zero,
                null, ref si, ref pi
            ))
            {
                Error();
                return;
            }
            Win32.CloseHandle(hWrite);
            while (true)
            {
                uint BytesRead = 0;
                byte[] buf = new byte[10240];
                if (!Win32.ReadFile(hRead, buf, (uint)buf.Length, out BytesRead, IntPtr.Zero))
                    break;
                string str = Encoding.Default.GetString(buf, 0, (int)BytesRead);
                Logger.WriteLine(str);
                Thread.Sleep(100);
            }
            Win32.CloseHandle(hRead);
            Win32.CloseHandle(pi.hProcess);
            Win32.CloseHandle(pi.hThread);
        }
    }
}