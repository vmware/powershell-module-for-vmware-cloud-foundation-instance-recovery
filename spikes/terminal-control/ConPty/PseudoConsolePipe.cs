using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using static ConPty.Native.PseudoConsoleApi;

namespace ConPty
{
    // Ported from https://github.com/microsoft/terminal/blob/main/samples/ConPTY/GUIConsole/GUIConsole.ConPTY/PseudoConsolePipe.cs
    internal sealed class PseudoConsolePipe : IDisposable
    {
        public readonly SafeFileHandle ReadSide;
        public readonly SafeFileHandle WriteSide;

        public PseudoConsolePipe()
        {
            if (!CreatePipe(out ReadSide, out WriteSide, IntPtr.Zero, 0))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "failed to create pipe");
            }
        }

        public void Dispose()
        {
            ReadSide?.Dispose();
            WriteSide?.Dispose();
        }
    }
}
