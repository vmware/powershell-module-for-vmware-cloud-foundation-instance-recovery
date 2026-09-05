using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace ConPty.Native
{
    // Ported from https://github.com/microsoft/terminal/blob/main/samples/ConPTY/GUIConsole/GUIConsole.ConPTY/Native/PseudoConsoleApi.cs
    // ResizePseudoConsole is not part of the sample; it's the documented counterpart used to
    // handle window/control resize (https://learn.microsoft.com/en-us/windows/console/resizepseudoconsole).
    internal static class PseudoConsoleApi
    {
        internal const uint PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016;

        [StructLayout(LayoutKind.Sequential)]
        internal struct COORD
        {
            public short X;
            public short Y;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int CreatePseudoConsole(COORD size, SafeFileHandle hInput, SafeFileHandle hOutput, uint dwFlags, out IntPtr phPC);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int ResizePseudoConsole(IntPtr hPC, COORD size);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int ClosePseudoConsole(IntPtr hPC);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CreatePipe(out SafeFileHandle hReadPipe, out SafeFileHandle hWritePipe, IntPtr lpPipeAttributes, int nSize);
    }
}
