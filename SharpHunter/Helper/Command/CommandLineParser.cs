using System.Linq;
using System.Collections.Generic;
using SharpHunter.Utils;
using System;

namespace SharpHunter.Commands
{
    public class ParsedArguments
    {
        public string CommandName { get; set; }
        public List<string> CommandArgs { get; set; }
        public bool LogEnabled { get; set; }
        public bool ZipEnabled { get; set; }
    }

    public static class CommandLineParser
    {
        public static ParsedArguments Parse(string[] args)
        {
            var parsed = new ParsedArguments
            {
                CommandArgs = new List<string>()
            };

            if (args.Length > 0)
            {
                parsed.CommandName = args[0];
                parsed.CommandArgs = args.Skip(1).ToList();

                if (parsed.CommandArgs.Contains("-zip"))
                {
                    parsed.ZipEnabled = true;
                    parsed.LogEnabled = true; 
                }
                else if (parsed.CommandArgs.Contains("-log"))
                {
                    parsed.LogEnabled = true;
                }
            }

            return parsed;
        }
    }
}