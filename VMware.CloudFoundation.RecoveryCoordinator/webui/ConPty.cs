// Windows pseudo-console (ConPTY) host, loaded with Add-Type only on Windows by
// VCFRecoveryCoordinatorWeb.ps1. On macOS/Linux the server uses script(1) for a PTY instead.
//
// NOT YET RUN ON WINDOWS -- it compiles, but has only been exercised on the author's Mac. Treat the
// Windows path as untested until someone runs it (Win10 1809+ / Server 2019+ required for ConPTY).
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace VCFIR
{
    public sealed class ConPty : IDisposable
    {
        [StructLayout(LayoutKind.Sequential)] private struct COORD { public short X, Y; public COORD(short x, short y) { X = x; Y = y; } }
        [StructLayout(LayoutKind.Sequential)] private struct STARTUPINFO
        {
            public int cb; public IntPtr lpReserved, lpDesktop, lpTitle;
            public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
            public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
        }
        [StructLayout(LayoutKind.Sequential)] private struct STARTUPINFOEX { public STARTUPINFO StartupInfo; public IntPtr lpAttributeList; }
        [StructLayout(LayoutKind.Sequential)] private struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }

        private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private static readonly IntPtr PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = (IntPtr)0x00020016;

        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CreatePipe(out SafeFileHandle r, out SafeFileHandle w, IntPtr attrs, int size);
        [DllImport("kernel32.dll")] private static extern int CreatePseudoConsole(COORD size, SafeFileHandle hInput, SafeFileHandle hOutput, uint flags, out IntPtr phPC);
        [DllImport("kernel32.dll")] private static extern int ResizePseudoConsole(IntPtr hPC, COORD size);
        [DllImport("kernel32.dll")] private static extern void ClosePseudoConsole(IntPtr hPC);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attr, IntPtr value, IntPtr size, IntPtr prev, IntPtr ret);
        [DllImport("kernel32.dll")] private static extern void DeleteProcThreadAttributeList(IntPtr list);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcessW(string app, string cmd, IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr env, string cwd, ref STARTUPINFOEX si, out PROCESS_INFORMATION pi);
        [DllImport("kernel32.dll")] private static extern uint WaitForSingleObject(IntPtr h, uint ms);
        [DllImport("kernel32.dll")] private static extern bool GetExitCodeProcess(IntPtr h, out uint code);
        [DllImport("kernel32.dll")] private static extern bool TerminateProcess(IntPtr h, uint code);
        [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr h);

        private IntPtr _hPC, _hProcess, _attrList;
        private bool _disposed;

        /// <summary>Bytes to type into the console (UTF-8).</summary>
        public Stream Input { get; private set; }
        /// <summary>Raw terminal output (UTF-8 with VT sequences).</summary>
        public Stream Output { get; private set; }
        public int ProcessId { get; private set; }

        public ConPty(string commandLine, string workingDirectory, int cols, int rows)
        {
            SafeFileHandle inRead, inWrite, outRead, outWrite;
            if (!CreatePipe(out inRead, out inWrite, IntPtr.Zero, 0)) throw new Win32Exception();
            if (!CreatePipe(out outRead, out outWrite, IntPtr.Zero, 0)) throw new Win32Exception();

            int hr = CreatePseudoConsole(new COORD((short)cols, (short)rows), inRead, outWrite, 0, out _hPC);
            if (hr != 0) throw new Win32Exception(hr, "CreatePseudoConsole failed (ConPTY needs Windows 10 1809 or later)");
            // The pseudo console owns these ends now.
            inRead.Dispose(); outWrite.Dispose();

            var si = new STARTUPINFOEX();
            si.StartupInfo.cb = Marshal.SizeOf<STARTUPINFOEX>();
            IntPtr size = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
            _attrList = Marshal.AllocHGlobal(size);
            si.lpAttributeList = _attrList;
            if (!InitializeProcThreadAttributeList(_attrList, 1, 0, ref size)) throw new Win32Exception();
            if (!UpdateProcThreadAttribute(_attrList, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, _hPC, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero)) throw new Win32Exception();

            PROCESS_INFORMATION pi;
            if (!CreateProcessW(null, commandLine, IntPtr.Zero, IntPtr.Zero, false, EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT, IntPtr.Zero, workingDirectory, ref si, out pi))
                throw new Win32Exception();
            _hProcess = pi.hProcess;
            ProcessId = pi.dwProcessId;
            CloseHandle(pi.hThread);

            Input = new FileStream(inWrite, FileAccess.Write, 1, false);
            Output = new FileStream(outRead, FileAccess.Read, 1, false);
        }

        public bool HasExited { get { return WaitForSingleObject(_hProcess, 0) == 0; } }
        public int ExitCode { get { uint c; GetExitCodeProcess(_hProcess, out c); return (int)c; } }
        public void Resize(int cols, int rows) { ResizePseudoConsole(_hPC, new COORD((short)cols, (short)rows)); }
        public void Kill() { if (!HasExited) TerminateProcess(_hProcess, 1); }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            try { Kill(); } catch { }
            if (_hPC != IntPtr.Zero) ClosePseudoConsole(_hPC);
            if (_attrList != IntPtr.Zero) { DeleteProcThreadAttributeList(_attrList); Marshal.FreeHGlobal(_attrList); }
            if (_hProcess != IntPtr.Zero) CloseHandle(_hProcess);
        }
    }
}
