using System.Runtime.InteropServices;
using static ConPty.Native.ProcessApi;

namespace ConPty.Processes
{
    // Ported from https://github.com/microsoft/terminal/blob/main/samples/ConPTY/GUIConsole/GUIConsole.ConPTY/Processes/Process.cs
    internal sealed class Process : IDisposable
    {
        public Process(STARTUPINFOEX startupInfo, PROCESS_INFORMATION processInfo)
        {
            StartupInfo = startupInfo;
            ProcessInfo = processInfo;
        }

        public STARTUPINFOEX StartupInfo { get; }
        public PROCESS_INFORMATION ProcessInfo { get; }

        private bool _disposed;

        private void Dispose(bool disposing)
        {
            if (_disposed)
            {
                return;
            }

            if (StartupInfo.lpAttributeList != IntPtr.Zero)
            {
                DeleteProcThreadAttributeList(StartupInfo.lpAttributeList);
                Marshal.FreeHGlobal(StartupInfo.lpAttributeList);
            }

            if (ProcessInfo.hProcess != IntPtr.Zero)
            {
                CloseHandle(ProcessInfo.hProcess);
            }
            if (ProcessInfo.hThread != IntPtr.Zero)
            {
                CloseHandle(ProcessInfo.hThread);
            }

            _disposed = true;
        }

        ~Process()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
