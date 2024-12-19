using System.Collections.Generic;

namespace SharpHunter.Commands
{
    public interface ICommand
    {
        void Execute(List<string> args);
    }
}