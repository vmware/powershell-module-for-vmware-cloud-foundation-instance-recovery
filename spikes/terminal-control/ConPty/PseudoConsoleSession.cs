using ConPty.Processes;
using Microsoft.Win32.SafeHandles;

namespace ConPty
{
    /// <summary>
    /// Spawns a process attached to a Windows ConPTY pseudoconsole and exposes its raw
    /// VT100/xterm output stream for a caller to parse and render, plus a way to write
    /// keystrokes/VT input back to it.
    /// </summary>
    /// <remarks>
    /// Adapted from the non-blocking parts of Microsoft's own sample Terminal.cs
    /// (https://github.com/microsoft/terminal/blob/main/samples/ConPTY/GUIConsole/GUIConsole.ConPTY/Terminal.cs),
    /// but restructured so Start() returns immediately instead of blocking the calling
    /// thread until the child process exits — a WPF app needs to keep pumping its own
    /// message loop while the session runs.
    /// </remarks>
    public sealed class PseudoConsoleSession : IDisposable
    {
        /// <summary>Raised on a background thread when the spawned process exits.</summary>
        public event EventHandler? Exited;

        /// <summary>Raw VT100/xterm-encoded output from the pseudoconsole. Read from any thread.</summary>
        public Stream ConsoleOutStream { get; private set; } = Stream.Null;

        private PseudoConsolePipe? _inputPipe;
        private PseudoConsolePipe? _outputPipe;
        private PseudoConsole? _pseudoConsole;
        private Process? _process;
        private FileStream? _consoleInputStream;
        private Thread? _waitThread;
        private bool _disposed;

        public void Start(string command, int width = 120, int height = 30)
        {
            _inputPipe = new PseudoConsolePipe();
            _outputPipe = new PseudoConsolePipe();
            _pseudoConsole = PseudoConsole.Create(_inputPipe.ReadSide, _outputPipe.WriteSide, width, height);
            _process = ProcessFactory.Start(command, PseudoConsole.PseudoConsoleThreadAttribute, _pseudoConsole.Handle);

            ConsoleOutStream = new FileStream(_outputPipe.ReadSide, FileAccess.Read);
            _consoleInputStream = new FileStream(_inputPipe.WriteSide, FileAccess.Write);

            _waitThread = new Thread(WaitForExit) { IsBackground = true };
            _waitThread.Start();
        }

        /// <summary>Write raw bytes to the pseudoconsole's input (e.g. VT key sequences, terminal query replies).</summary>
        public void Write(byte[] data)
        {
            if (_consoleInputStream is null)
            {
                throw new InvalidOperationException("Call Start() before writing to the session.");
            }
            _consoleInputStream.Write(data, 0, data.Length);
            _consoleInputStream.Flush();
        }

        /// <summary>Write UTF-8 text to the pseudoconsole's input.</summary>
        public void Write(string text) => Write(System.Text.Encoding.UTF8.GetBytes(text));

        public void Resize(int width, int height) => _pseudoConsole?.Resize(width, height);

        private void WaitForExit()
        {
            if (_process is null)
            {
                return;
            }

            using var waitHandle = new AutoResetEvent(false)
            {
                SafeWaitHandle = new SafeWaitHandle(_process.ProcessInfo.hProcess, ownsHandle: false)
            };
            waitHandle.WaitOne(Timeout.Infinite);
            Exited?.Invoke(this, EventArgs.Empty);
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;

            _consoleInputStream?.Dispose();
            ConsoleOutStream.Dispose();
            _process?.Dispose();
            _pseudoConsole?.Dispose();
            _outputPipe?.Dispose();
            _inputPipe?.Dispose();
        }
    }
}
