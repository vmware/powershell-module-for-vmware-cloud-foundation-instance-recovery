# Builds and runs the VCF IBR Orchestrator window. Launched by Start-VCFIBROrchestrator (in the
# module's .psm1) as its own detached pwsh.exe process, not a runspace inside that process, so that
# WPF's one-Application-per-process limit never gets in the way of relaunching: each run of this
# script gets a completely fresh CLR and WPF runtime, so closing the window and running
# Start-VCFIBROrchestrator again always starts over cleanly, with no shared state to worry about.
#
# The console is a plain read-only output pane plus a single-line input box (see the XAML), fed by
# a second pwsh.exe process run with plain redirected stdin/stdout/stderr -- not a ConPTY-backed
# terminal emulator control. That control (EasyWindowsTerminalControl, wrapping an unpublished
# CI/beta build of Microsoft's own terminal-hosting layer) was the source of most of this feature's
# problems: a crash bug that needed a binary patch, and a rendering corruption bug that survived
# every fix attempted at the PowerShell level, confirmed (by running the exact same commands in a
# normal PowerShell console with no corruption) to be in that control's own rendering. This app's
# actual console traffic is entirely line-based -- LogMessage output and single-line Read-Host-style
# prompts -- nothing here ever needed real terminal emulation (cursor positioning, full-screen
# redraws) in the first place.
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
$consoleOutput = $window.FindName('ConsoleOutput')
$consoleInput = $window.FindName('ConsoleInput')

# Every line appended goes into ONE shared Paragraph as Run+LineBreak pairs, rather than one
# Paragraph per line -- RichTextBox's default paragraph spacing would otherwise leave a visible gap
# between every single line, which looks nothing like a console.
$consoleOutputParagraph = New-Object System.Windows.Documents.Paragraph
$consoleOutputParagraph.Margin = '0'
$consoleOutput.Document.Blocks.Clear()
$consoleOutput.Document.Blocks.Add($consoleOutputParagraph)

# Colors matching LogMessage's own ANSI scheme (INFO green, ERROR/EXCEPTION red, WARNING/ADVISORY/
# QUESTION yellow, NOTE/WAIT white) -- applied by us based on the [type] tag in each line, instead of
# interpreting the ANSI escape codes LogMessage actually emits (stripped out entirely, see
# Remove-AnsiCodes). PROMPT is our own pseudo-type for the command-echo lines Send-ToConsole adds.
$logTypeColors = @{
    INFO      = '#3DDC84'
    ERROR     = '#FF5555'
    EXCEPTION = '#FF5555'
    WARNING   = '#FFD866'
    ADVISORY  = '#FFD866'
    QUESTION  = '#FFD866'
    NOTE      = '#FFFFFF'
    WAIT      = '#FFFFFF'
    PROMPT    = '#5DB2FF'
}
$defaultConsoleColor = [System.Windows.Media.ColorConverter]::ConvertFromString('#CCCCCC')

function Remove-AnsiCodes([string]$Text) {
    return $Text -replace "`e\[[0-9;]*m", ''
}

function Get-ConsoleLineColor([string]$CleanText, [string]$ForcedType) {
    $type = $ForcedType
    if (-not $type) {
        $match = [regex]::Match($CleanText, '\[(INFO|ERROR|WARNING|EXCEPTION|ADVISORY|NOTE|QUESTION|WAIT)\]')
        if ($match.Success) { $type = $match.Groups[1].Value }
    }
    if ($type -and $logTypeColors.ContainsKey($type)) {
        return [System.Windows.Media.ColorConverter]::ConvertFromString($logTypeColors[$type])
    }
    return $defaultConsoleColor
}

# Text read from the console process that hasn't reached a newline yet, and the Run currently
# displaying it. Prompts like "Enter the desired number of disk groups...: " or "PS C:\path>" are
# deliberately never newline-terminated -- the answer is meant to continue right after them on the
# same line -- so waiting for a newline before showing them would mean never showing them at all.
# Add-ConsoleChunk displays this partial text immediately and grows it in place as more arrives,
# exactly like a real terminal renders characters as they arrive rather than waiting for whole lines.
$script:consolePendingText = ''
$script:consolePendingRun = $null

# Handles raw text as it arrives from the console process, which may contain zero, one, or several
# newlines and may end mid-line. Complete (newline-terminated) lines are colored and closed off with
# a real line break as soon as they're found; any trailing partial text is shown right away too.
function Add-ConsoleChunk {
    param([string]$Chunk, [string]$ForcedType)

    $remaining = $Chunk
    while ($remaining.Length -gt 0) {
        $newlineIndex = $remaining.IndexOf("`n")
        if ($newlineIndex -lt 0) {
            $piece = $remaining
            $remaining = ''
        } else {
            $piece = $remaining.Substring(0, $newlineIndex).TrimEnd("`r")
            $remaining = $remaining.Substring($newlineIndex + 1)
        }

        $script:consolePendingText += $piece
        if ($null -eq $script:consolePendingRun) {
            $script:consolePendingRun = New-Object System.Windows.Documents.Run
            [void]$consoleOutputParagraph.Inlines.Add($script:consolePendingRun)
        }
        $clean = Remove-AnsiCodes $script:consolePendingText
        $script:consolePendingRun.Text = $clean
        $script:consolePendingRun.Foreground = New-Object System.Windows.Media.SolidColorBrush((Get-ConsoleLineColor $clean $ForcedType))

        if ($newlineIndex -ge 0) {
            [void]$consoleOutputParagraph.Inlines.Add((New-Object System.Windows.Documents.LineBreak))
            $script:consolePendingText = ''
            $script:consolePendingRun = $null
        }
    }
    $consoleOutput.ScrollToEnd()
}

# Adds a complete line we generated ourselves (the command echo, below) -- always its own fresh Run,
# never partial. Closes off anything still pending from the console process's own output first, so
# our line never ends up visually glued onto the end of an unfinished prompt.
function Add-ConsoleLine {
    param([string]$Text, [string]$ForcedType)

    if ($script:consolePendingRun) {
        [void]$consoleOutputParagraph.Inlines.Add((New-Object System.Windows.Documents.LineBreak))
        $script:consolePendingText = ''
        $script:consolePendingRun = $null
    }

    $clean = Remove-AnsiCodes $Text
    $run = New-Object System.Windows.Documents.Run($clean)
    $run.Foreground = New-Object System.Windows.Media.SolidColorBrush((Get-ConsoleLineColor $clean $ForcedType))
    [void]$consoleOutputParagraph.Inlines.Add($run)
    [void]$consoleOutputParagraph.Inlines.Add((New-Object System.Windows.Documents.LineBreak))
    $consoleOutput.ScrollToEnd()
}

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

# The console process: an ordinary pwsh.exe with its stdin/stdout/stderr redirected to us, not a
# ConPTY-backed pseudo-terminal. Set-Location, removing PSReadLine, and Start-Transcript all run as
# part of its own startup -Command, before Send-ToConsole ever writes anything to its stdin, for the
# same reason as before: none of them should appear as if a user typed them. PSReadLine is removed
# defensively -- it should never engage at all against a redirected, non-terminal stdin/stdout, but
# there's no cost to being certain, and it was the confirmed cause of a real corruption bug earlier
# in this feature's life. No -Encoding on Start-Transcript: that parameter doesn't exist on every
# PowerShell version, and Get-Content (used to read the transcript back) auto-detects the encoding
# from its BOM regardless of which default Start-Transcript happened to use to write it.
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
$consoleStartInfo.CreateNoWindow = $true
$consoleStartInfo.RedirectStandardInput = $true
$consoleStartInfo.RedirectStandardOutput = $true
$consoleStartInfo.RedirectStandardError = $true
$consoleStartInfo.StandardOutputEncoding = [System.Text.Encoding]::UTF8
$consoleStartInfo.StandardErrorEncoding = [System.Text.Encoding]::UTF8

$consoleProcess = New-Object System.Diagnostics.Process
$consoleProcess.StartInfo = $consoleStartInfo
[void]$consoleProcess.Start()

# Deliberately not OutputDataReceived/BeginOutputReadLine: that event fires on an arbitrary .NET
# threadpool thread with no PowerShell runspace bound to it at all, and invoking a PowerShell
# scriptblock to handle it -- regardless of what the scriptblock's body does -- needs one. Every
# other .Add_EventName({...}) in this file (Button.Click, Window.Closing, DispatcherTimer.Tick) is
# safe only because WPF itself guarantees those specific events fire on the UI thread; this one
# doesn't. Polled asynchronously instead, entirely from the UI thread via a DispatcherTimer, the same
# proven pattern Start-StepCompletionWatcher already uses.
#
# Reading raw bytes off the BaseStream, not ReadLineAsync(): a line-based read would never return a
# prompt that doesn't end in a newline (every interactive Read-Host-style prompt, and the "PS
# C:\path>" prompt itself, is written exactly that way, since the answer is meant to continue on the
# same line) -- it would just sit there waiting for a newline that's never coming. ReadAsync() on a
# pipe's BaseStream returns as soon as any data at all is available, letting Add-ConsoleChunk display
# partial, not-yet-terminated text immediately. Decoding each chunk independently as UTF8, rather than
# through a stateful incremental decoder, means a multi-byte character split exactly across two reads
# could in principle render as one wrong character; harmless and exceedingly unlikely given this
# app's actual traffic (hostnames, paths, plain English messages), and not worth the extra complexity.
$script:consoleOutputStream = $consoleProcess.StandardOutput.BaseStream
$script:consoleErrorStream = $consoleProcess.StandardError.BaseStream
$script:consoleOutputBuffer = New-Object byte[] 4096
$script:consoleErrorBuffer = New-Object byte[] 4096
$script:pendingConsoleOutputRead = $script:consoleOutputStream.ReadAsync($script:consoleOutputBuffer, 0, $script:consoleOutputBuffer.Length)
$script:pendingConsoleErrorRead = $script:consoleErrorStream.ReadAsync($script:consoleErrorBuffer, 0, $script:consoleErrorBuffer.Length)

function Start-ConsoleOutputPump {
    $pumpTimer = New-Object System.Windows.Threading.DispatcherTimer
    $pumpTimer.Interval = [TimeSpan]::FromMilliseconds(100)
    $pumpTimer.Add_Tick({
        try {
            if ($script:pendingConsoleOutputRead.IsCompleted) {
                $bytesRead = $script:pendingConsoleOutputRead.Result
                if ($bytesRead -gt 0) {
                    Add-ConsoleChunk ([System.Text.Encoding]::UTF8.GetString($script:consoleOutputBuffer, 0, $bytesRead))
                    $script:pendingConsoleOutputRead = $script:consoleOutputStream.ReadAsync($script:consoleOutputBuffer, 0, $script:consoleOutputBuffer.Length)
                }
                # 0 bytes read means the stream hit EOF (the console process's stdout closed) --
                # deliberately not starting another read, since there's never anything more to read.
            }
            if ($script:pendingConsoleErrorRead.IsCompleted) {
                $bytesRead = $script:pendingConsoleErrorRead.Result
                if ($bytesRead -gt 0) {
                    Add-ConsoleChunk ([System.Text.Encoding]::UTF8.GetString($script:consoleErrorBuffer, 0, $bytesRead)) 'ERROR'
                    $script:pendingConsoleErrorRead = $script:consoleErrorStream.ReadAsync($script:consoleErrorBuffer, 0, $script:consoleErrorBuffer.Length)
                }
            }
        } catch {
            # A faulted task (e.g. the console process exiting unexpectedly and disposing its
            # streams) would otherwise re-throw from .Result -- on the UI thread, inside a
            # DispatcherTimer tick, an uncaught exception here would take the whole window down with
            # it. Stop polling rather than let that happen or spin retrying a stream that's gone bad.
            $this.Stop()
        }
    })
    $pumpTimer.Start()
}

# Kills the console process when the window actually closes, regardless of which path got it there
# (the X button or Exit) -- a plain child process isn't torn down automatically just because this
# process exits, so without this every close would leak an orphaned pwsh.exe.
$window.Add_Closed({
    if ($consoleProcess -and -not $consoleProcess.HasExited) {
        try { $consoleProcess.Kill($true) } catch {}
    }
})

# WPF's own default (focus the first focusable control in the visual tree) would land on something
# in the left rail, not the console -- without this, nothing typed goes anywhere until the input box
# is clicked into manually, which is easy to miss now that output and input are two separate controls
# rather than one big terminal area you could click into anywhere.
$window.Add_Loaded({
    [void]$consoleInput.Focus()
})

function Send-ToConsole([string]$CommandLine) {
    if ($null -eq $consoleProcess -or $consoleProcess.HasExited) {
        $statusTextBlock.Text = "Console process isn't running."
        return
    }
    # Echoed ourselves: a redirected pipe, unlike a real terminal, never echoes typed input on its
    # own -- without this, the command actually sent wouldn't be visible anywhere.
    Add-ConsoleLine "PS $WorkingDirectory> $CommandLine" 'PROMPT'
    try {
        $consoleProcess.StandardInput.WriteLine($CommandLine)
    } catch {
        $statusTextBlock.Text = "Failed to send command: $($_.Exception.Message)"
    }
    # Sending a command is exactly when a step or an interactive prompt is about to need typed input
    # next -- without this, focus stays wherever it was (e.g. on the Run button just clicked), and
    # nothing typed goes anywhere until the input box is clicked into manually.
    [void]$consoleInput.Focus()
}

$consoleInput.Add_KeyDown({
    if ($EventArgs.Key -eq [System.Windows.Input.Key]::Enter) {
        $commandText = $consoleInput.Text
        $consoleInput.Clear()
        if ($commandText) {
            Send-ToConsole $commandText
        }
    }
})

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
