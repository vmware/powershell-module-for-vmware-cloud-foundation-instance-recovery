using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using static ConPty.Native.PseudoConsoleApi;

namespace ConPty
{
    // Ported from https://github.com/microsoft/terminal/blob/main/samples/ConPTY/GUIConsole/GUIConsole.ConPTY/PseudoConsole.cs
    internal sealed class PseudoConsole : IDisposable
    {
        public static readonly IntPtr PseudoConsoleThreadAttribute = (IntPtr)PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE;

        public IntPtr Handle { get; }

        private PseudoConsole(IntPtr handle)
        {
            Handle = handle;
        }

        internal static PseudoConsole Create(SafeFileHandle inputReadSide, SafeFileHandle outputWriteSide, int width, int height)
        {
            var createResult = CreatePseudoConsole(
                new COORD { X = (short)width, Y = (short)height },
                inputReadSide, outputWriteSide,
                0, out IntPtr hPC);
            if (createResult != 0)
            {
                throw new Win32Exception(createResult, "Could not create pseudo console.");
            }
            return new PseudoConsole(hPC);
        }

        internal void Resize(int width, int height)
        {
            ResizePseudoConsole(Handle, new COORD { X = (short)width, Y = (short)height });
        }

        public void Dispose()
        {
            ClosePseudoConsole(Handle);
        }
    }
}
