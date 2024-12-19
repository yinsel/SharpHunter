using System;
using System.Collections.Generic;

namespace SharpHunter.Commands
{
    public static class CommandRegistry
    {
        private static Dictionary<string, Func<ICommand>> commands = new Dictionary<string, Func<ICommand>>();

        public static void RegisterCommand(string commandName, Func<ICommand> commandCreator)
        {
            commands[commandName.ToLower()] = commandCreator;
        }

        public static ICommand GetCommand(string commandName)
        {
            if (commands.TryGetValue(commandName.ToLower(), out var commandCreator))
            {
                return commandCreator();
            }
            else
            {
                throw new ArgumentException($"[-] Unknown command: {commandName}");
            }
        }
    }
}