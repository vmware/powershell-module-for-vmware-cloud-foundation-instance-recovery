# Builds and runs the VCF IBR Orchestrator window. Launched by Start-VCFIBROrchestrator (in the
# module's .psm1) as its own detached pwsh.exe process, not a runspace inside that process, so that
# WPF's one-Application-per-process limit never gets in the way of relaunching: each run of this
# script gets a completely fresh CLR and WPF runtime, so closing the window and running
# Start-VCFIBROrchestrator again always starts over cleanly, with no shared state to worry about.
#
# The console is a second, completely ordinary pwsh.exe process, given a real console window by
# Windows exactly as if it had been launched normally, then reparented (SetParent) into this
# window's layout (see ConsoleHwndHost, below) rather than left as its own separate top-level
# window. Nothing here renders a single character of it or reads a single byte of its output --
# Windows' own console host does all of that, unchanged, exactly as reliably as it already does for
# every other PowerShell session. Typing happens directly in that embedded window; the "Run"/"Run
# All" buttons inject the step's command by simulating real keystrokes into it (WriteConsoleInput),
# indistinguishable from someone typing them.
#
# This replaced two earlier designs, both of which tried to reproduce a terminal ourselves rather
# than reuse the real one: EasyWindowsTerminalControl (a ConPTY-backed control wrapping an
# unpublished CI/beta build of Microsoft's own terminal-hosting layer) caused a crash that needed a
# binary patch and a rendering corruption bug that survived every fix attempted at the PowerShell
# level, both confirmed to be inside that control's own custom rendering; a plain redirected-I/O
# process with our own RichTextBox rendering fixed the corruption but produced a disconnected,
# non-terminal-like two-box UI. Reparenting the real console window avoids both problems at once by
# not reimplementing anything.
#
# Self-contained: has no dependency on the module's own functions (e.g. LogMessage) -- only .NET/WPF.
param(
    [string]$XamlPath,
    [string]$WorkingDirectory
)

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml

$app = New-Object System.Windows.Application

[xml]$xamlDocument = Get-Content -Path $XamlPath -Raw
$xamlReader = New-Object System.Xml.XmlNodeReader $xamlDocument
$window = [System.Windows.Markup.XamlReader]::Load($xamlReader)

$resumeButton = $window.FindName('ResumeButton')
$exitButton = $window.FindName('ExitButton')
$extractRadio = $window.FindName('ExtractBackupRadio')
$browseButton = $window.FindName('BrowseButton')
$filePathTextBox = $window.FindName('FilePathTextBox')
$statusTextBlock = $window.FindName('StatusTextBlock')
$dataSourceDomainsTabControl = $window.FindName('DataSourceDomainsTabControl')
$domainsListBox = $window.FindName('WorkloadDomainsListBox')
$stepsVariablesGroupBox = $window.FindName('StepsVariablesGroupBox')
$stepsVariablesTabControl = $window.FindName('StepsVariablesTabControl')
$managementDomainRestoresStepsListBox = $window.FindName('ManagementDomainRestoresStepsListBox')
$recoverDefaultClusterStepsListBox = $window.FindName('RecoverDefaultClusterStepsListBox')
$runAllManagementDomainRestoresButton = $window.FindName('RunAllManagementDomainRestoresButton')
$runAllRecoverDefaultClusterButton = $window.FindName('RunAllRecoverDefaultClusterButton')
$loadVariablesButton = $window.FindName('LoadVariablesButton')
$loadedVariablesTextBlock = $window.FindName('LoadedVariablesTextBlock')
$variablesItemsPanel = $window.FindName('VariablesItemsPanel')
$consoleHostBorder = $window.FindName('ConsoleHostBorder')

# Populated once a domain is selected (see the SelectionChanged handler below); initialized here
# so Run All never sees $null before that happens.
$global:managementDomainRestoresStepRows = @()
$global:recoverDefaultClusterStepRows = @()
# Path to the last-loaded variable answers file, if any -- tracked separately from the textbox-less
# Load Variables flow so Exit can record it, and Resume can pass it straight back to the same loader.
$global:variablesAnswersFilePath = $null

# Completion tracking, attempt 5: a PowerShell transcript of the console, read from disk. Unaffected
# by the move away from the terminal control -- it never depended on that control's own rendering
# (that was the whole point of using a transcript in the first place: a plain text file that
# PowerShell itself appends to, read back on a timer, confirmed correct even on builds where the
# on-screen rendering was garbled).
#
# Saved in the launch directory (not $env:TEMP) with a timestamp in the name so past runs can be
# told apart and reviewed later instead of being overwritten or left to rot in a temp folder.
$global:transcriptPath = Join-Path $WorkingDirectory "vcfir-transcript-$(Get-Date -Format 'yyyyMMdd-HHmmss')-$PID.log"
# Steps currently being watched for their own "Completed Task <cmdlet>" line, one entry per Run
# click; each is removed (stopping that row's watch) once its text is found. See Add-StepWatch.
$global:activeStepWatches = [System.Collections.Generic.List[object]]::new()

function Protect-SingleQuotes([string]$Value) {
    return $Value.Replace("'", "''")
}

# Native pieces needed to reparent a real console window and to type into it programmatically.
# ConsoleHwndHost never creates or destroys the console window it's given -- that belongs to the
# console process for its entire lifetime; this only relocates it visually into this app's layout.
# WriteConsoleInput needs a handle to the target console's own input buffer, obtained by briefly
# attaching this process to it (AttachConsole/FreeConsole) -- unrelated to, and safe alongside,
# the window having been reparented; reparenting only changes where the window sits on screen, not
# which console session it belongs to.
#
# -ReferencedAssemblies needs the *exact* WindowsBase/PresentationCore DLLs already loaded above
# (by file path), not their simple names: passing simple names lets Add-Type's own resolution pick
# a different-versioned WindowsBase than the one already loaded, which then fails to compile with a
# "higher version than referenced assembly" error -- HwndHost (in PresentationFramework) needs the
# identical WindowsBase the rest of this process is already using.
$wpfAssemblyPaths = foreach ($assemblyName in 'WindowsBase', 'PresentationCore', 'PresentationFramework') {
    ([System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq $assemblyName } | Select-Object -First 1).Location
}
Add-Type -ReferencedAssemblies $wpfAssemblyPaths -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Windows.Interop;

namespace VCFIRConsole {
    // CharSet.Unicode on both structs is required, not cosmetic: a plain C# char field marshals as
    // a single ANSI byte by default, but the native KEY_EVENT_RECORD.uChar.UnicodeChar field is a
    // WCHAR (2 bytes). Without this, every record after the mismatched byte is misaligned, so
    // WriteConsoleInput reports success (Windows accepted the call) while the actual key data inside
    // each record is garbage -- confirmed by testing: it returned true and "wrote" every record, but
    // the target console never actually acted on any of them.
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct KEY_EVENT_RECORD {
        [MarshalAs(UnmanagedType.Bool)] public bool bKeyDown;
        public short wRepeatCount;
        public short wVirtualKeyCode;
        public short wVirtualScanCode;
        public char UnicodeChar;
        public int dwControlKeyState;
    }

    [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Unicode)]
    public struct INPUT_RECORD {
        [FieldOffset(0)] public short EventType;
        [FieldOffset(4)] public KEY_EVENT_RECORD KeyEvent;
    }

    public static class NativeMethods {
        public const int GWL_STYLE = -16;
        public const long WS_CHILD = 0x40000000L;
        public const long WS_CAPTION = 0x00C00000L;
        public const long WS_THICKFRAME = 0x00040000L;
        public const long WS_SYSMENU = 0x00080000L;
        public const long WS_MINIMIZEBOX = 0x00020000L;
        public const long WS_MAXIMIZEBOX = 0x00010000L;
        public const int SW_HIDE = 0;
        public const int SW_SHOW = 5;
        public const int STD_INPUT_HANDLE = -10;

        [DllImport("user32.dll", EntryPoint = "GetWindowLongPtr", SetLastError = true)]
        private static extern IntPtr GetWindowLongPtr64(IntPtr hWnd, int nIndex);
        [DllImport("user32.dll", EntryPoint = "GetWindowLong", SetLastError = true)]
        private static extern IntPtr GetWindowLong32(IntPtr hWnd, int nIndex);
        [DllImport("user32.dll", EntryPoint = "SetWindowLongPtr", SetLastError = true)]
        private static extern IntPtr SetWindowLongPtr64(IntPtr hWnd, int nIndex, IntPtr dwNewLong);
        [DllImport("user32.dll", EntryPoint = "SetWindowLong", SetLastError = true)]
        private static extern IntPtr SetWindowLong32(IntPtr hWnd, int nIndex, IntPtr dwNewLong);

        // 64-bit-only in practice on this platform, but dispatching on IntPtr.Size costs nothing
        // and avoids silently mis-marshaling if that ever stops being true.
        public static IntPtr GetWindowLongPtr(IntPtr hWnd, int nIndex) {
            return IntPtr.Size == 8 ? GetWindowLongPtr64(hWnd, nIndex) : GetWindowLong32(hWnd, nIndex);
        }
        public static IntPtr SetWindowLongPtr(IntPtr hWnd, int nIndex, IntPtr dwNewLong) {
            return IntPtr.Size == 8 ? SetWindowLongPtr64(hWnd, nIndex, dwNewLong) : SetWindowLong32(hWnd, nIndex, dwNewLong);
        }

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr SetParent(IntPtr hWndChild, IntPtr hWndNewParent);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr SetFocus(IntPtr hWnd);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool AttachConsole(uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FreeConsole();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetStdHandle(int nStdHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteConsoleInput(IntPtr hConsoleInput, INPUT_RECORD[] lpBuffer, uint nLength, out uint lpNumberOfEventsWritten);

        // Strips the console window's own title bar/border/system menu so it reads as embedded
        // content rather than a window-within-a-window, and marks it WS_CHILD, which SetParent
        // requires before it will treat this as a child rather than an owned top-level window.
        public static void PrepareForEmbedding(IntPtr hwnd) {
            long style = GetWindowLongPtr(hwnd, GWL_STYLE).ToInt64();
            style &= ~(WS_CAPTION | WS_THICKFRAME | WS_SYSMENU | WS_MINIMIZEBOX | WS_MAXIMIZEBOX);
            style |= WS_CHILD;
            SetWindowLongPtr(hwnd, GWL_STYLE, new IntPtr(style));
        }
    }

    // Hosts an already-existing native window (the real console window) at this element's layout
    // position, rather than rendering anything itself.
    public class ConsoleHwndHost : HwndHost {
        private readonly IntPtr _consoleHwnd;

        public ConsoleHwndHost(IntPtr consoleHwnd) {
            _consoleHwnd = consoleHwnd;
        }

        protected override HandleRef BuildWindowCore(HandleRef hwndParent) {
            NativeMethods.PrepareForEmbedding(_consoleHwnd);
            NativeMethods.SetParent(_consoleHwnd, hwndParent.Handle);
            NativeMethods.ShowWindow(_consoleHwnd, NativeMethods.SW_SHOW);
            return new HandleRef(this, _consoleHwnd);
        }

        protected override void DestroyWindowCore(HandleRef hwnd) {
            // Deliberately empty -- see class comment: the console window is never ours to destroy.
        }
    }
}
'@

# The console process: a completely ordinary pwsh.exe, given a real console window by Windows.
# PSReadLine is removed here -- confirmed by testing, not assumed: WriteConsoleInput reports success
# writing every record regardless, but with PSReadLine active the console never actually acts on any
# of them (an injected "exit`r" left the process running); with PSReadLine removed, the identical
# injection reliably exits it. PSReadLine owns line-editing (history, tab completion, syntax
# coloring) but has nothing to do with output rendering -- that's the console host's job, always
# was, and was never the source of the corruption bugs earlier designs hit. Losing PSReadLine here
# costs those editing niceties for anyone typing directly into the window; it doesn't reintroduce any
# of that risk, and it's the only way the Run/Run All buttons work at all.
# Set-Location and Start-Transcript still run as part of the startup -Command, before anything is
# typed into the console, so neither ever appears as if a user typed them. No -Encoding on
# Start-Transcript: that parameter doesn't exist on every PowerShell version, and Get-Content (used
# to read the transcript back) auto-detects the encoding from its BOM regardless of which default
# Start-Transcript happened to use to write it.
$escapedWorkingDirectory = Protect-SingleQuotes $WorkingDirectory
$escapedTranscriptPath = Protect-SingleQuotes $global:transcriptPath
$consoleStartupCommand = "Set-Location -LiteralPath '$escapedWorkingDirectory'; Remove-Module PSReadLine -Force -ErrorAction SilentlyContinue; Start-Transcript -Path '$escapedTranscriptPath' -Force | Out-Null"

$consoleStartInfo = New-Object System.Diagnostics.ProcessStartInfo
$consoleStartInfo.FileName = (Get-Process -Id $PID).Path   # same pwsh.exe/powershell.exe running this launcher
$consoleStartInfo.ArgumentList.Add('-NoLogo')
$consoleStartInfo.ArgumentList.Add('-NoProfile')
$consoleStartInfo.ArgumentList.Add('-NoExit')
$consoleStartInfo.ArgumentList.Add('-Command')
$consoleStartInfo.ArgumentList.Add($consoleStartupCommand)
$consoleStartInfo.WorkingDirectory = $WorkingDirectory
$consoleStartInfo.UseShellExecute = $false
$consoleStartInfo.CreateNoWindow = $false   # a real, visible console window is exactly the point

$consoleProcess = New-Object System.Diagnostics.Process
$consoleProcess.StartInfo = $consoleStartInfo
[void]$consoleProcess.Start()

# Bounded wait for the console's own window to exist -- this happens well before the main window is
# shown (Application.Run() hasn't been called yet), so blocking briefly here is fine, the same way
# Start-VCFIBROrchestrator briefly waits for this whole process to start. Hidden immediately once
# found, so it never visibly flashes as a free-floating window before ConsoleHwndHost embeds it.
$consoleHwnd = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds(10)
while ((Get-Date) -lt $deadline) {
    $consoleProcess.Refresh()
    if ($consoleProcess.HasExited) {
        $statusTextBlock.Text = "Console process exited before its window appeared."
        break
    }
    $consoleHwnd = $consoleProcess.MainWindowHandle
    if ($consoleHwnd -ne [IntPtr]::Zero) { break }
    Start-Sleep -Milliseconds 50
}
if ($consoleHwnd -ne [IntPtr]::Zero) {
    [VCFIRConsole.NativeMethods]::ShowWindow($consoleHwnd, [VCFIRConsole.NativeMethods]::SW_HIDE) | Out-Null
    $consoleHwndHost = New-Object VCFIRConsole.ConsoleHwndHost($consoleHwnd)
    $consoleHostBorder.Child = $consoleHwndHost
} else {
    $statusTextBlock.Text = "Console window did not appear within 10 seconds."
}

# Kills the console process when the window actually closes, regardless of which path got it there
# (the X button or Exit) -- a plain child process isn't torn down automatically just because this
# process exits, so without this every close would leak an orphaned pwsh.exe. Reparenting doesn't
# change this: the console window being a child of ours now makes it even less discoverable/
# manageable on its own if left behind, not more.
$window.Add_Closed({
    if ($consoleProcess -and -not $consoleProcess.HasExited) {
        try { $consoleProcess.Kill($true) } catch {}
    }
})

# WPF's own default (focus the first focusable control in the visual tree) would land on something
# in the left rail, not the console -- SetFocus puts the initial keyboard focus on the embedded
# console instead, so typing works immediately without clicking into it first.
$window.Add_Loaded({
    if ($consoleHwnd -ne [IntPtr]::Zero) {
        [VCFIRConsole.NativeMethods]::SetFocus($consoleHwnd) | Out-Null
    }
})

# Injects a command by simulating real keystrokes into the embedded console (WriteConsoleInput),
# indistinguishable to PowerShell from someone typing them -- no echo of our own to add, no pipe to
# write to; the real console echoes what's "typed" exactly as it always does, because as far as it
# knows, that's exactly what happened.
function Send-ToConsole([string]$CommandLine) {
    if ($null -eq $consoleProcess -or $consoleProcess.HasExited) {
        $statusTextBlock.Text = "Console process isn't running."
        return
    }
    try {
        [VCFIRConsole.NativeMethods]::FreeConsole() | Out-Null
        if (-not [VCFIRConsole.NativeMethods]::AttachConsole([uint32]$consoleProcess.Id)) {
            throw "AttachConsole failed (Win32 error $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error()))."
        }
        try {
            $inputHandle = [VCFIRConsole.NativeMethods]::GetStdHandle([VCFIRConsole.NativeMethods]::STD_INPUT_HANDLE)
            $records = [System.Collections.Generic.List[VCFIRConsole.INPUT_RECORD]]::new()
            foreach ($character in ($CommandLine + "`r").ToCharArray()) {
                $keyDown = New-Object VCFIRConsole.KEY_EVENT_RECORD
                $keyDown.bKeyDown = $true
                $keyDown.wRepeatCount = 1
                $keyDown.UnicodeChar = $character
                $downRecord = New-Object VCFIRConsole.INPUT_RECORD
                $downRecord.EventType = 1
                $downRecord.KeyEvent = $keyDown
                $records.Add($downRecord)

                $keyUp = New-Object VCFIRConsole.KEY_EVENT_RECORD
                $keyUp.bKeyDown = $false
                $keyUp.wRepeatCount = 1
                $keyUp.UnicodeChar = $character
                $upRecord = New-Object VCFIRConsole.INPUT_RECORD
                $upRecord.EventType = 1
                $upRecord.KeyEvent = $keyUp
                $records.Add($upRecord)
            }
            $recordsArray = $records.ToArray()
            [uint32]$written = 0
            [void][VCFIRConsole.NativeMethods]::WriteConsoleInput($inputHandle, $recordsArray, [uint32]$recordsArray.Length, [ref]$written)
        } finally {
            [VCFIRConsole.NativeMethods]::FreeConsole() | Out-Null
        }
    } catch {
        $statusTextBlock.Text = "Failed to send command: $($_.Exception.Message)"
    }
    if ($consoleHwnd -ne [IntPtr]::Zero) {
        [VCFIRConsole.NativeMethods]::SetFocus($consoleHwnd) | Out-Null
    }
}

# Starts (or restarts) watching the transcript for this row's "Completed Task <cmdlet>" line, from
# whatever the transcript's current length is right now -- so an OLDER completion line already in
# the transcript from a previous run of the same cmdlet can't cause an immediate false-positive
# match on a re-run. Kept as its own function, separate from Invoke-Step, so a future "Run All"
# sequencer can call it the same way an individual Run does when it's ready to wait for step N to
# finish before starting step N+1 (not wired up yet -- Run All still just fires every step's command
# immediately, same as today).
function Add-StepWatch($Button, [string]$CmdletName) {
    $currentText = ''
    if (Test-Path $global:transcriptPath) {
        $currentText = Get-Content -Path $global:transcriptPath -Raw -ErrorAction SilentlyContinue
        if ($null -eq $currentText) { $currentText = '' }
    }
    # Drop any earlier watch for this same button first, rather than stacking duplicates on a re-run.
    # @(...) around the whole pipeline is required, not optional: Where-Object filtering everything
    # out (as it always does on the very first-ever call, since the list starts empty) produces $null,
    # not an empty collection, and List[object]'s constructor throws ArgumentNullException on $null.
    $global:activeStepWatches = [System.Collections.Generic.List[object]]@($global:activeStepWatches | Where-Object { $_.Button -ne $Button })
    $global:activeStepWatches.Add([PSCustomObject]@{
        Button     = $Button
        TargetText = "Completed Task $CmdletName"
        StartOffset = $currentText.Length
    })
}

# Resets a row to its "in progress" look (undoing any earlier Done state -- re-running a step that
# previously completed should stop showing it as done until it completes again) and starts watching
# for its completion.
function Invoke-Step($Dot, $Button, [string]$CmdletName, [string]$CommandLine) {
    $Dot.Fill = [System.Windows.Media.Brushes]::DodgerBlue
    $Button.Content = 'Run'
    $Button.ClearValue([System.Windows.Controls.Control]::BackgroundProperty)
    Add-StepWatch $Button $CmdletName
    Send-ToConsole $CommandLine
}

# Returns [PSCustomObject]@{ Panel; Dot; CommandLine; Button; CmdletName }, not just the row's
# visual Panel -- the other fields are needed separately so a tab's "Run All" button can replay
# every row's Run action, and so Invoke-Step/Add-StepWatch can update the right row's button and
# watch for the right cmdlet name without re-parsing the rendered list.
function New-StepRow([string]$CommandLine) {
    $panel = New-Object System.Windows.Controls.DockPanel
    $panel.Margin = '2,0,2,0'

    $dot = New-Object System.Windows.Shapes.Ellipse
    $dot.Width = 8
    $dot.Height = 8
    $dot.Fill = [System.Windows.Media.Brushes]::LightGray
    $dot.Margin = '0,0,6,0'
    $dot.VerticalAlignment = 'Center'

    # Only the cmdlet name is shown; the full command line (with its parameters) stays in the
    # module and is only ever sent to the console, never rendered in the Steps list. Variable
    # values referenced in it (e.g. $targetFqdn) come from whatever was loaded via "Load
    # Variables..." -- they're already set in the console session by the time Run is clicked.
    $cmdletName = ($CommandLine -split '\s+', 2)[0]

    $runButton = New-Object System.Windows.Controls.Button
    $runButton.Content = 'Run'
    $runButton.Width = 50
    $runButton.Padding = '6,2'
    $runButton.Margin = '6,0,0,0'
    [System.Windows.Controls.DockPanel]::SetDock($runButton, [System.Windows.Controls.Dock]::Right)
    $runButton.Add_Click({
        try {
            Invoke-Step $dot $runButton $cmdletName $CommandLine
        } catch {
            $statusTextBlock.Text = "Run button failed: $($_.Exception.Message)"
        }
    }.GetNewClosure())

    $label = New-Object System.Windows.Controls.TextBlock
    $label.Text = $cmdletName
    $label.FontFamily = New-Object System.Windows.Media.FontFamily('Consolas')
    $label.VerticalAlignment = 'Center'

    [void]$panel.Children.Add($dot)
    [void]$panel.Children.Add($runButton)
    [void]$panel.Children.Add($label)
    return [PSCustomObject]@{ Panel = $panel; Dot = $dot; CommandLine = $CommandLine; Button = $runButton; CmdletName = $cmdletName }
}

# Variable names referenced across $CommandLines (e.g. "$targetFqdn"), in order of first
# appearance, deduplicated. Used to order the Variables panel by when each value is actually
# needed as you work down the Steps list, rather than alphabetically or by answer-file order.
function Get-ReferencedVariableNames([string[]]$CommandLines) {
    $names = [System.Collections.Generic.List[string]]::new()
    $seen = @{}
    foreach ($commandLine in $CommandLines) {
        foreach ($match in [regex]::Matches($commandLine, '\$([A-Za-z_][A-Za-z0-9_]*)')) {
            $name = $match.Groups[1].Value
            if (-not $seen.ContainsKey($name)) {
                $seen[$name] = $true
                [void]$names.Add($name)
            }
        }
    }
    return $names
}

function New-VariableRow([string]$Name, [string]$Value) {
    $panel = New-Object System.Windows.Controls.DockPanel
    $panel.Margin = '0,0,0,3'

    $label = New-Object System.Windows.Controls.TextBlock
    $label.Text = $Name
    $label.FontFamily = New-Object System.Windows.Media.FontFamily('Consolas')
    $label.VerticalAlignment = 'Center'
    $label.Width = 150
    $label.Margin = '0,0,6,0'
    $label.TextTrimming = 'CharacterEllipsis'
    [System.Windows.Controls.DockPanel]::SetDock($label, [System.Windows.Controls.Dock]::Left)

    $valueBox = New-Object System.Windows.Controls.TextBox
    $valueBox.Text = $Value
    $valueBox.Padding = '4,2'

    # Edits only take effect on LostFocus (not per-keystroke) -- re-sends the updated value to the
    # console so a value changed after loading still reaches the running session.
    $valueBox.Add_LostFocus({
        Send-ToConsole "`$$Name = '$(Protect-SingleQuotes $valueBox.Text)'"
    }.GetNewClosure())

    [void]$panel.Children.Add($label)
    [void]$panel.Children.Add($valueBox)
    return $panel
}

# Checks each actively-watched row's slice of the transcript (everything written since its Run was
# clicked) for its own "Completed Task <cmdlet>" line. A row is only in this list between being
# Run and being found Done (see Add-StepWatch) -- once found, it's removed, which is what stops the
# monitor for that row until Run is clicked again.
function Start-StepCompletionWatcher {
    $checkTimer = New-Object System.Windows.Threading.DispatcherTimer
    $checkTimer.Interval = [TimeSpan]::FromMilliseconds(500)
    $checkTimer.Add_Tick({
        if ($global:activeStepWatches.Count -eq 0 -or -not (Test-Path $global:transcriptPath)) { return }
        try {
            $transcriptText = Get-Content -Path $global:transcriptPath -Raw -ErrorAction Stop
        } catch {
            return
        }
        if ($null -eq $transcriptText) { return }
        $stillWatching = [System.Collections.Generic.List[object]]::new()
        foreach ($watch in $global:activeStepWatches) {
            $newText = if ($transcriptText.Length -gt $watch.StartOffset) { $transcriptText.Substring($watch.StartOffset) } else { '' }
            if ($newText.Contains($watch.TargetText)) {
                $watch.Button.Content = 'Done'
                $watch.Button.Background = [System.Windows.Media.Brushes]::Green
            } else {
                $stillWatching.Add($watch)
            }
        }
        $global:activeStepWatches = $stillWatching
    })
    $checkTimer.Start()
}

# Shared by the Browse button and Resume, so both end up driving the exact same domain-listing /
# console-variable-setting logic instead of two copies drifting apart.
function Import-ExtractedSddcDataFile([string]$Path) {
    $domainsListBox.Items.Clear()
    $managementDomainRestoresStepsListBox.Items.Clear()
    $recoverDefaultClusterStepsListBox.Items.Clear()
    $variablesItemsPanel.Children.Clear()
    $loadedVariablesTextBlock.Text = 'No variables loaded yet.'
    $stepsVariablesGroupBox.Visibility = [System.Windows.Visibility]::Collapsed
    $global:allStepCommandLines = @()
    $statusTextBlock.Text = ''

    try {
        $extractedSddcData = Get-Content -Path $Path -Raw | ConvertFrom-Json
    } catch {
        $statusTextBlock.Text = "Failed to load extracted SDDC data: $($_.Exception.Message)"
        return
    }

    if (-not $extractedSddcData.workloadDomains) {
        $statusTextBlock.Text = "No 'workloadDomains' property found in the selected file."
        return
    }

    foreach ($domain in $extractedSddcData.workloadDomains) {
        $item = New-Object System.Windows.Controls.ListBoxItem
        $item.Content = "$($domain.domainName) ($($domain.domainType))"
        $item.Tag = $domain
        [void]$domainsListBox.Items.Add($item)
    }

    # Switch focus to the Workload Domains tab now that there's something to pick from -- saves a
    # manual click back and forth between the two tabs every time a data file is loaded.
    $dataSourceDomainsTabControl.SelectedIndex = 1

    $escapedPath = Protect-SingleQuotes $Path
    Send-ToConsole "Set-ExportedSDDCDataFilePath -Path '$escapedPath'"
}

$browseButton.Add_Click({
    $extracting = $extractRadio.IsChecked -eq $true
    $dialog = New-Object Microsoft.Win32.OpenFileDialog
    if ($extracting) {
        $dialog.Filter = 'All files (*.*)|*.*'
        $dialog.Title = 'Select backup file'
    } else {
        $dialog.Filter = 'JSON files (*.json)|*.json|All files (*.*)|*.*'
        $dialog.Title = 'Select extracted-sddc-data.json'
    }

    if ($dialog.ShowDialog() -ne $true) {
        return
    }

    $filePathTextBox.Text = $dialog.FileName

    if ($extracting) {
        # Extracting a backup file is not implemented yet -- selecting a file here does nothing further.
        return
    }

    Import-ExtractedSddcDataFile $dialog.FileName
}.GetNewClosure())

# Answer file is a flat JSON object, e.g. { "targetFqdn": "sfo-m01-vc02...", "targetAdminPassword": "..." }.
# Parsed here purely to populate the Variables tab's rows in the order they'll be needed (first use
# across the selected domain's steps -- Management Domain Restores, then Recover Default Cluster --
# with anything not referenced by any step appended afterward, in file order, so nothing loaded is
# ever silently dropped from view). The console itself never sees these values directly; it's handed
# the answers file path and reads it itself via Import-RecoveryVariables, below, so every step's Run
# button can reference $targetFqdn etc. directly, the same way $extractedSDDCDataFile already works.
#
# Shared by the Load Variables button and Resume, same reasoning as Import-ExtractedSddcDataFile.
function Import-VariablesAnswersFile([string]$Path) {
    try {
        $answers = Get-Content -Path $Path -Raw | ConvertFrom-Json
        $answerMap = [ordered]@{}
        foreach ($property in $answers.PSObject.Properties) {
            $answerMap[$property.Name] = [string]$property.Value
        }

        # extractedSDDCDataFile comes from the Data Source browse selection, not the answers file --
        # an answer file that happens to also define it must not overwrite that value or show up as
        # an editable row here.
        $answerMap.Remove('extractedSDDCDataFile')

        $variablesItemsPanel.Children.Clear()

        if ($answerMap.Count -eq 0) {
            $loadedVariablesTextBlock.Text = "No variables found in '$Path'."
            return
        }

        $orderedNames = @(Get-ReferencedVariableNames $global:allStepCommandLines | Where-Object { $answerMap.Contains($_) })
        $orderedNames += @($answerMap.Keys | Where-Object { $orderedNames -notcontains $_ })

        foreach ($name in $orderedNames) {
            [void]$variablesItemsPanel.Children.Add((New-VariableRow $name $answerMap[$name]))
        }

        # Import-RecoveryVariables (a real, exported module cmdlet -- see the "Recovery Variables"
        # region) reads the answers file itself and sets each value as a global variable. Sending just
        # this one call, rather than typing "$name = 'value'" once per variable, means none of the
        # values (including plaintext passwords) are ever echoed into the console or the transcript,
        # and it logs via LogMessage the same way every other step does, instead of looking like ad hoc
        # plumbing.
        $escapedAnswersPath = Protect-SingleQuotes $Path
        Send-ToConsole "Import-RecoveryVariables -Path '$escapedAnswersPath'"

        $loadedVariablesTextBlock.Text = "Loaded $($orderedNames.Count) variable(s) from $Path."
        $global:variablesAnswersFilePath = $Path

        # Switch to the Steps tab now that variables are in place -- saves a manual click back and
        # forth, the same way picking a domain switches Setup to the Workload Domains tab.
        $stepsVariablesTabControl.SelectedIndex = 1
    } catch {
        $statusTextBlock.Text = "Load Variables failed: $($_.Exception.Message)"
    }
}

$loadVariablesButton.Add_Click({
    $dialog = New-Object Microsoft.Win32.OpenFileDialog
    $dialog.Filter = 'JSON files (*.json)|*.json|All files (*.*)|*.*'
    $dialog.Title = 'Select variable answers file'
    if ($dialog.ShowDialog() -ne $true) {
        return
    }
    Import-VariablesAnswersFile $dialog.FileName
}.GetNewClosure())

$domainsListBox.Add_SelectionChanged({
  try {
    $managementDomainRestoresStepsListBox.Items.Clear()
    $recoverDefaultClusterStepsListBox.Items.Clear()
    $variablesItemsPanel.Children.Clear()
    $loadedVariablesTextBlock.Text = 'No variables loaded yet.'
    $managementDomainRestoresCommandLines = @()
    $recoverDefaultClusterCommandLines = @()

    $selected = $domainsListBox.SelectedItem
    if ($null -eq $selected) {
        $stepsVariablesGroupBox.Visibility = [System.Windows.Visibility]::Collapsed
        $global:allStepCommandLines = @()
        return
    }
    $stepsVariablesGroupBox.Visibility = [System.Windows.Visibility]::Visible

    if ($selected.Tag.domainType -eq 'MANAGEMENT') {
        $managementDomainRestoresCommandLines = @(
            'New-ExtractDataFromSDDCBackup -vcfBackupFilePath $vcfBackupFilePath -encryptionPassword $encryptionPassword -credentialsFilePath $credentialsFilePath',
            'New-PrepareManagementHostNetworking -extractedSDDCDataFile $extractedSDDCDataFile -mtu 8900',
            'Add-VMKernelsToManagementHosts -extractedSDDCDataFile $extractedSDDCDataFile',
            'New-SingleHostVsanDatastore -extractedSDDCDataFile $extractedSDDCDataFile',
            'New-vCenterOvaDeployment -targetType $targetType -targetFqdn $targetFqdn -targetAdmin $targetAdmin -targetAdminPassword $targetAdminPassword -extractedSDDCDataFile $extractedSDDCDataFile -workloadDomain $workloadDomain -restoredvCenterDeploymentSize $restoredvCenterDeploymentSize -vCenterOvaFile $vCenterOvaFile',
            'New-NSXManagerOvaDeployment -targetType $targetType -targetFqdn $targetFqdn -targetAdmin $targetAdmin -targetAdminPassword $targetAdminPassword -extractedSDDCDataFile $extractedSDDCDataFile -workloadDomain $workloadDomain -restoredNsxManagerDeploymentSize $restoredNsxManagerDeploymentSize -nsxManagerOvaFile $nsxManagerOvaFile',
            'New-SDDCManagerOvaDeployment -targetType $targetType -targetFqdn $targetFqdn -targetAdmin $targetAdmin -targetAdminPassword $targetAdminPassword -extractedSDDCDataFile $extractedSDDCDataFile -sddcManagerOvaFile $sddcManagerOvaFile -rootUserPassword $rootUserPassword -vcfUserPassword $vcfUserPassword -localUserPassword $localUserPassword -basicAuthUserPassword $basicAuthUserPassword',
            'Invoke-vCenterRestore -extractedSDDCDataFile $extractedSDDCDataFile -workloadDomain $workloadDomain -vCenterBackupPath $vCenterBackupPath -locationtype $locationtype -locationUser $locationUser -locationPassword $locationPassword',
            'Invoke-NSXManagerRestore -extractedSDDCDataFile $extractedSDDCDataFile -workloadDomain $workloadDomain -sftpServer $sftpServer -sftpUser $sftpUser -sftpPassword $sftpPassword -sftpServerBackupPath $sftpServerBackupPath -backupPassphrase $nsxBackupPassphrase',
            'New-UploadAndModifySDDCManagerBackup -targetType $targetType -targetFqdn $targetFqdn -targetAdmin $targetAdmin -targetAdminPassword $targetAdminPassword -rootUserPassword $rootUserPassword -vcfUserPassword $vcfUserPassword -backupFilePath $vcfbackupFilePath -encryptionPassword $encryptionPassword -extractedSDDCDataFile $extractedSDDCDataFile',
            'Invoke-SDDCManagerRestore -extractedSDDCDataFile $extractedSDDCDataFile -backupFilePath $vcfbackupFilePath -vcfUserPassword $vcfUserPassword -localUserPassword $localUserPassword -rootUserPassword $rootUserPassword -encryptionPassword $encryptionPassword',
            'Update-ExtractedSDDCData -extractedSDDCDataFile $extractedSDDCDataFile -sddcManagerFQDN $sddcManagerFQDN -sddcManagerAdmin $sddcManagerAdmin -sddcManagerAdminPassword $sddcManagerAdminPassword -vCenterFQDN $restoredVcenterFqdn'
        )

        $recoverDefaultClusterCommandLines = @(
            'Backup-ClusterVMOverrides -clusterName $clusterName',
            'Backup-ClusterVMLocations -clusterName $clusterName',
            'Backup-ClusterDRSGroupsAndRules -clusterName $clusterName',
            'Backup-ClusterVMTags -clusterName $clusterName',
            'Remove-NonResponsiveHosts -vCenterFQDN $restoredVcenterFqdn -vCenterAdmin $restoredVcenterAdmin -vCenterAdminPassword $restoredVcenterAdminPassword -clusterName $clusterName -NsxManagerFQDN $restoredNsxManagerFqdn -NsxManagerAdmin $restoredNsxManagerAdmin -NsxManagerAdminPassword $restoredNsxManagerAdminPassword -NsxManagerRootPassword $restoredNsxManagerRootPassword',
            'Add-HostsToCluster -vCenterFQDN $restoredVcenterFqdn -vCenterAdmin $restoredVcenterAdmin -vCenterAdminPassword $restoredVcenterAdminPassword -clusterName $clusterName -sddcManagerFqdn $sddcManagerFqdn -sddcManagerAdmin $sddcManagerAdmin -sddcManagerAdminPassword $sddcManagerAdminPassword -extractedSDDCDataFile $extractedSDDCDataFile',
            'New-RebuiltVdsConfiguration -vCenterFQDN $restoredVcenterFqdn -vCenterAdmin $restoredVcenterAdmin -vCenterAdminPassword $restoredVcenterAdminPassword -clusterName $clusterName -extractedSDDCDataFile $extractedSDDCDataFile',
            'Watch-NsxHostTransportNodeInstallation -clusterName $clusterName -extractedSDDCDataFile $extractedSDDCDataFile',
            'Add-DiskgroupsToManagementHosts -targetFqdn $restoredVcenterFqdn -targetAdmin $restoredVcenterAdmin -targetAdminPassword $restoredVcenterAdminPassword -clusterName $clusterName -extractedSDDCDataFile $extractedSDDCDataFile',
            'Set-ManagementDatastorePolicy -vCenterFQDN $restoredVcenterFqdn -vCenterAdmin $restoredVcenterAdmin -vCenterAdminPassword $restoredVcenterAdminPassword -clusterName $clusterName -extractedSDDCDataFile $extractedSDDCDataFile',
            'New-ReconfiguredVsanStretchedCluster -vCenterFQDN $restoredVcenterFqdn -vCenterAdmin $restoredVcenterAdmin -vCenterAdminPassword $restoredVcenterAdminPassword -clusterName $clusterName -extractedSDDCDataFile $extractedSDDCDataFile',
            'Clear-vCenterAlarms -vCenterFQDN $restoredVcenterFqdn -vCenterAdmin $restoredVcenterAdmin -vCenterAdminPassword $restoredVcenterAdminPassword',
            'Update-DomainDatastoreID -extractedSDDCDataFile $extractedSDDCDataFile -vCenterFqdn $vCenterFqdn -clusterName $clusterName -VcfUserPassword $VcfUserPassword -RootPassword $RootPassword',
            'Update-ClusterHostSourceIDs -extractedSDDCDataFile $extractedSDDCDataFile -vCenterFqdn $vCenterFqdn -clusterName $clusterName -VcfUserPassword $VcfUserPassword -RootPassword $RootPassword',
            'Invoke-SddcManagerSSHKeyRefresh -vCenterFQDN $restoredVcenterFqdn -vCenterAdmin $restoredVcenterAdmin -vCenterAdminPassword $restoredVcenterAdminPassword -extractedSDDCDataFile $extractedSDDCDataFile -clusterName $clusterName -workloadDomain $workloadDomain -VcfUserPassword $VcfUserPassword',
            'Resolve-PhysicalHostServiceAccounts -targetFQDN $restoredVcenterFqdn -targetAdmin $restoredVcenterAdmin -targetAdminPassword $restoredVcenterAdminPassword -clusterName $clusterName -svcAccountPassword $svcAccountPassword -sddcManagerFqdn $sddcManagerFqdn -sddcManagerAdmin $sddcManagerAdmin -sddcManagerAdminPassword $sddcManagerAdminPassword',
            'Invoke-NSXEdgeClusterRecoverySelective -nsxManagerFqdn $restoredNsxManagerFqdn -nsxManagerAdmin $restoredNsxManagerAdmin -nsxManagerAdminPassword $restoredNsxManagerAdminPassword -vCenterFQDN $restoredVcenterFqdn -vCenterAdmin $restoredvCenterAdmin -vCenterAdminPassword $restoredvCenterAdminPassword -clusterName $clusterName -extractedSDDCDataFile $extractedSDDCDataFile'
        )
    }

    $global:managementDomainRestoresStepRows = @()
    foreach ($commandLine in $managementDomainRestoresCommandLines) {
        $row = New-StepRow $commandLine
        [void]$managementDomainRestoresStepsListBox.Items.Add($row.Panel)
        $global:managementDomainRestoresStepRows += $row
    }
    $global:recoverDefaultClusterStepRows = @()
    foreach ($commandLine in $recoverDefaultClusterCommandLines) {
        $row = New-StepRow $commandLine
        [void]$recoverDefaultClusterStepsListBox.Items.Add($row.Panel)
        $global:recoverDefaultClusterStepRows += $row
    }
    $global:allStepCommandLines = @($managementDomainRestoresCommandLines) + @($recoverDefaultClusterCommandLines)
  } catch {
    $statusTextBlock.Text = "Domain selection handler failed: $($_.Exception.Message)"
  }
}.GetNewClosure())

$runAllManagementDomainRestoresButton.Add_Click({
    try {
        foreach ($row in $global:managementDomainRestoresStepRows) {
            Invoke-Step $row.Dot $row.Button $row.CmdletName $row.CommandLine
        }
    } catch {
        $statusTextBlock.Text = "Run All failed: $($_.Exception.Message)"
    }
}.GetNewClosure())

$runAllRecoverDefaultClusterButton.Add_Click({
    try {
        foreach ($row in $global:recoverDefaultClusterStepRows) {
            Invoke-Step $row.Dot $row.Button $row.CmdletName $row.CommandLine
        }
    } catch {
        $statusTextBlock.Text = "Run All failed: $($_.Exception.Message)"
    }
}.GetNewClosure())

# Saves everything Resume needs to put the window back the way it was: the extracted data file, the
# variable answers file, which domain was selected (by index into the just-reloaded domain list, the
# only stable handle available since domains aren't otherwise named uniquely), and which steps had
# already reached Done. Only the file paths and cmdlet names are saved, never variable values or
# command lines themselves -- Resume re-derives everything else by re-running the exact same loaders
# Browse/Load Variables use.
$exitButton.Add_Click({
    try {
        $allRows = @($global:managementDomainRestoresStepRows) + @($global:recoverDefaultClusterStepRows)
        $completedCmdlets = @($allRows | Where-Object { $_.Button.Content -eq 'Done' } | ForEach-Object { $_.CmdletName })

        $state = [PSCustomObject]@{
            ExtractedDataFilePath    = $filePathTextBox.Text
            VariablesAnswersFilePath = $global:variablesAnswersFilePath
            SelectedDomainIndex      = $domainsListBox.SelectedIndex
            CompletedCmdlets         = $completedCmdlets
        }

        $dialog = New-Object Microsoft.Win32.SaveFileDialog
        $dialog.Filter = 'JSON files (*.json)|*.json|All files (*.*)|*.*'
        $dialog.Title = 'Save orchestrator state'
        $dialog.InitialDirectory = $WorkingDirectory
        $dialog.FileName = "vcfibr-state-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        if ($dialog.ShowDialog() -ne $true) {
            return
        }

        $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $dialog.FileName -Encoding utf8

        Send-ToConsole 'Stop-Transcript | Out-Null'
        # Give Stop-Transcript a moment to actually run inside the console process before it gets
        # killed by closing this window (see $window.Add_Closed, above) -- writing to StandardInput
        # only queues the line, it doesn't wait for the console process to act on it.
        Start-Sleep -Milliseconds 300

        $window.Close()
    } catch {
        $statusTextBlock.Text = "Exit failed: $($_.Exception.Message)"
    }
}.GetNewClosure())

# Replays the same three loaders a manual session would call (Import-ExtractedSddcDataFile, domain
# selection, Import-VariablesAnswersFile), in the same order, then marks whichever steps were Done
# last time as Done again -- without adding them to $global:activeStepWatches, since nothing is being
# (re-)run for them here.
$resumeButton.Add_Click({
    try {
        $dialog = New-Object Microsoft.Win32.OpenFileDialog
        $dialog.Filter = 'JSON files (*.json)|*.json|All files (*.*)|*.*'
        $dialog.Title = 'Select saved orchestrator state'
        if ($dialog.ShowDialog() -ne $true) {
            return
        }

        $state = Get-Content -Path $dialog.FileName -Raw | ConvertFrom-Json

        if ($state.ExtractedDataFilePath) {
            $filePathTextBox.Text = $state.ExtractedDataFilePath
            Import-ExtractedSddcDataFile $state.ExtractedDataFilePath
        }

        if ($null -ne $state.SelectedDomainIndex -and $state.SelectedDomainIndex -ge 0 -and $state.SelectedDomainIndex -lt $domainsListBox.Items.Count) {
            $domainsListBox.SelectedIndex = $state.SelectedDomainIndex
        }

        if ($state.VariablesAnswersFilePath) {
            Import-VariablesAnswersFile $state.VariablesAnswersFilePath
        }

        $completedCmdlets = @($state.CompletedCmdlets)
        $allRows = @($global:managementDomainRestoresStepRows) + @($global:recoverDefaultClusterStepRows)
        foreach ($row in $allRows) {
            if ($completedCmdlets -contains $row.CmdletName) {
                $row.Button.Content = 'Done'
                $row.Button.Background = [System.Windows.Media.Brushes]::Green
            }
        }

        $statusTextBlock.Text = "Resumed state from '$($dialog.FileName)'."
    } catch {
        $statusTextBlock.Text = "Resume failed: $($_.Exception.Message)"
    }
}.GetNewClosure())

Start-ConsoleOutputPump
Start-StepCompletionWatcher

[void]$app.Run($window)
