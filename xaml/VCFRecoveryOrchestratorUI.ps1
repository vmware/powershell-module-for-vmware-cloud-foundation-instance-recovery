# Builds and runs the VCF IBR Orchestrator window. Launched by Start-VCFRecoveryCoordinator (in the
# module's .psm1) as its own detached pwsh.exe process, not a runspace inside that process, so that
# WPF's one-Application-per-process limit never gets in the way of relaunching: each run of this
# script gets a completely fresh CLR and WPF runtime, so closing the window and running
# Start-VCFRecoveryCoordinator again always starts over cleanly, with no shared state to worry about.
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
    [string]$WorkingDirectory,
    [string]$PlansPath
)

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml

# Without this, Windows groups this window's taskbar button under whatever AppUserModelID pwsh.exe
# itself carries (its own icon and every other running PowerShell window) -- taskbar grouping keys
# off the PROCESS's AppUserModelID, not a window's own Icon property, so setting Window.Icon alone
# (further down) fixes the icon shown but not which group it lands in. Has to run this early --
# before any window of this process is created/shown -- or Windows has already committed to the
# default grouping by the time a later call would take effect.
Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public static class VCFIRTaskbar {
    [DllImport("shell32.dll", SetLastError = true)]
    public static extern int SetCurrentProcessExplicitAppUserModelID([MarshalAs(UnmanagedType.LPWStr)] string AppID);
}
'@
[void][VCFIRTaskbar]::SetCurrentProcessExplicitAppUserModelID('VMware.CloudFoundation.InstanceRecovery.RecoveryCoordinator')

$app = New-Object System.Windows.Application

[xml]$xamlDocument = Get-Content -Path $XamlPath -Raw
$xamlReader = New-Object System.Xml.XmlNodeReader $xamlDocument
$window = [System.Windows.Markup.XamlReader]::Load($xamlReader)

# Without this, the taskbar button for this window shows pwsh.exe's own icon -- Windows uses the
# window's own icon (set here via WM_SETICON, which assigning Window.Icon triggers) for its taskbar
# button, not the hosting process's icon, as long as nothing else overrides the icon association.
# Rendered from the "VmwLogoImage" vector resource (shared with the small header badge below) rather
# than a bundled .ico file, so there's only one definition of the mark to ever keep in sync.
$vmwLogoImage = $window.TryFindResource('VmwLogoImage')
if ($vmwLogoImage) {
    $iconSize = 256
    $iconSourceImage = New-Object System.Windows.Controls.Image
    $iconSourceImage.Source = $vmwLogoImage
    $iconSourceImage.Width = $iconSize
    $iconSourceImage.Height = $iconSize
    $iconSourceImage.Measure((New-Object System.Windows.Size($iconSize, $iconSize)))
    $iconSourceImage.Arrange((New-Object System.Windows.Rect(0, 0, $iconSize, $iconSize)))
    $windowIconBitmap = New-Object System.Windows.Media.Imaging.RenderTargetBitmap($iconSize, $iconSize, 96, 96, [System.Windows.Media.PixelFormats]::Pbgra32)
    $windowIconBitmap.Render($iconSourceImage)
    $windowIconBitmap.Freeze()
    $window.Icon = $windowIconBitmap
}

$resumeButton = $window.FindName('ResumeButton')
$exitButton = $window.FindName('ExitButton')
$ibrRecoveryTypeRadio = $window.FindName('IbrRecoveryTypeRadio')
$fdrRecoveryTypeRadio = $window.FindName('FdrRecoveryTypeRadio')
$dataSourceGroupBox = $window.FindName('DataSourceGroupBox')
$extractRadio = $window.FindName('ExtractBackupRadio')
$browseButton = $window.FindName('BrowseButton')
$filePathTextBox = $window.FindName('FilePathTextBox')
$statusTextBlock = $window.FindName('StatusTextBlock')
$discoveredInfrastructureGroupBox = $window.FindName('DiscoveredInfrastructureGroupBox')
$domainsListBox = $window.FindName('WorkloadDomainsListBox')
$additionalClustersListBox = $window.FindName('AdditionalClustersListBox')
$stepsVariablesGroupBox = $window.FindName('StepsVariablesGroupBox')
$stepsVariablesTabControl = $window.FindName('StepsVariablesTabControl')
$domainRecoveryPanel = $window.FindName('DomainRecoveryPanel')
$additionalClusterRecoveryPanel = $window.FindName('AdditionalClusterRecoveryPanel')
$recoverFleetPanel = $window.FindName('RecoverFleetPanel')
$domainRecoveryStepsListBox = $window.FindName('DomainRecoveryStepsListBox')
$additionalClusterRecoveryStepsListBox = $window.FindName('AdditionalClusterRecoveryStepsListBox')
$recoverFleetStepsListBox = $window.FindName('RecoverFleetStepsListBox')
$runAllDomainRecoveryButton = $window.FindName('RunAllDomainRecoveryButton')
$runAllAdditionalClusterRecoveryButton = $window.FindName('RunAllAdditionalClusterRecoveryButton')
$runAllRecoverFleetButton = $window.FindName('RunAllRecoverFleetButton')
$runAllDomainRecoveryParallelCheckBox = $window.FindName('RunAllDomainRecoveryParallelCheckBox')
$runAllAdditionalClusterRecoveryParallelCheckBox = $window.FindName('RunAllAdditionalClusterRecoveryParallelCheckBox')
$runAllRecoverFleetParallelCheckBox = $window.FindName('RunAllRecoverFleetParallelCheckBox')
$loadVariablesButton = $window.FindName('LoadVariablesButton')
$newVariablesFileButton = $window.FindName('NewVariablesFileButton')
$loadedVariablesTextBlock = $window.FindName('LoadedVariablesTextBlock')
$variablesItemsPanel = $window.FindName('VariablesItemsPanel')
$consoleTabControl = $window.FindName('ConsoleTabControl')

# Populated once a domain is selected (see Sync-DomainSteps below), an additional cluster is picked
# (see Sync-AdditionalClusterSteps), or FDR's own Recover Fleet plan is loaded (see the FDR
# Recovery Type Checked handler); initialized here so Run All never sees $null before that happens.
$global:domainRecoveryStepRows = @()
$global:additionalClusterRecoveryStepRows = @()
$global:recoverFleetStepRows = @()
# The step objects (see Get-RecoveryPlanSteps) currently backing each of the two IBR Steps panels,
# kept separate because Domain Recovery (domain-driven) and Additional Cluster Recovery (Additional
# Clusters-table-driven) are independent, mutually exclusive selections. Update-AllSteps combines
# both into $global:allSteps, which is what the Variables tab actually reads from.
$global:domainRecoverySteps = @()
$global:additionalClusterRecoverySteps = @()
# Facts about the currently selected domain's default cluster or the currently selected additional
# cluster (isStretched, primaryDatastoreType -- see Update-DerivedStepVariables) that a plan's own
# condition can reference (e.g. "$isStretched -eq 't'") without asking the operator to type in
# something the extracted SDDC data already knows. Merged into the answer values before conditions
# are evaluated and before the Variables tab is built, so a referenced fact shows up pre-filled --
# still an ordinary editable row, in case the extracted value is ever wrong or needs overriding.
$global:derivedStepVariables = @{}
# Whether Import-ExtractedSddcDataFile has ever successfully loaded data -- tracked separately
# from Discovered Infrastructure's own Visibility so switching from FDR back to IBR (see the
# Recovery Type Checked handlers) knows whether to reveal it again or leave it collapsed.
$global:extractedDataLoaded = $false
# Path to the last-loaded variable answers file, if any -- tracked separately from the textbox-less
# Load Variables flow so Exit can record it, and Resume can pass it straight back to the same loader.
$global:variablesAnswersFilePath = $null
# Set the instant any step's Run is first clicked (manually, or via Run All/a parallel group -- see
# Invoke-Step) and never cleared for the rest of this process's life. Switching Discovered
# Infrastructure's domain/cluster selection mid-run would leave whatever's already running (or
# already Done) pointed at a target that's no longer the one selected, with no way to tell from the
# UI alone -- Lock-ElementSelection disables both list boxes outright once this flips true, so
# picking a different element requires Exit + a fresh launch instead.
$global:recoveryRunStarted = $false

# Completion tracking, attempt 5: a PowerShell transcript of the console, read from disk. Unaffected
# by the move away from the terminal control -- it never depended on that control's own rendering
# (that was the whole point of using a transcript in the first place: a plain text file that
# PowerShell itself appends to, read back on a timer, confirmed correct even on builds where the
# on-screen rendering was garbled). Every console (Main, and every parallel one Run All spawns --
# see New-EmbeddedConsole) gets its own transcript file, saved in the launch directory (not
# $env:TEMP) with a timestamp and a per-console sequence number in the name, so past runs -- and
# every console within a single run -- can be told apart and reviewed later instead of being
# overwritten or left to rot in a temp folder.
$global:consoleSequence = 0
# Steps currently being watched for their own "Completed Task <cmdlet>" line, one entry per Run
# click; each is removed (stopping that row's watch) once its text is found. See Add-StepWatch.
$global:activeStepWatches = [System.Collections.Generic.List[object]]::new()
# The console this app starts with (see New-EmbeddedConsole), plus zero or more Run All has spawned
# on demand to run a parallel group's non-first members concurrently -- see Invoke-StepGroup. Every
# other console-aware function (Send-ToConsole, Set-ConsoleFocus, Add-StepWatch, Invoke-Step, the
# Exit/Closed handlers) defaults to or iterates these rather than assuming there's only ever one.
$global:mainConsole = $null
$global:parallelConsoles = [System.Collections.Generic.List[object]]::new()

function Protect-SingleQuotes([string]$Value) {
    return $Value.Replace("'", "''")
}

# A small modal prompt for a single secret value -- built directly in code rather than from XAML
# since it's the only place in this app that needs one. Returns the entered password, or $null if
# cancelled (Cancel button, or Escape/the window's own close button, both wired via IsCancel);
# reading $passwordBox.Password after ShowDialog() returns (rather than trying to smuggle it out of
# the OK button's own closure) avoids a scoping trap: a closure can set an outer script-scoped
# variable, but this function's own local variables aren't reachable that way.
function Show-PasswordPromptDialog([string]$Title, [string]$Message) {
    $dialog = New-Object System.Windows.Window
    $dialog.Title = $Title
    $dialog.SizeToContent = 'WidthAndHeight'
    $dialog.Width = 360
    $dialog.WindowStartupLocation = 'CenterOwner'
    $dialog.Owner = $window
    $dialog.ResizeMode = 'NoResize'

    $stack = New-Object System.Windows.Controls.StackPanel
    $stack.Margin = '16'

    $messageBlock = New-Object System.Windows.Controls.TextBlock
    $messageBlock.Text = $Message
    $messageBlock.Margin = '0,0,0,8'
    $messageBlock.TextWrapping = 'Wrap'
    [void]$stack.Children.Add($messageBlock)

    $passwordBox = New-Object System.Windows.Controls.PasswordBox
    $passwordBox.Margin = '0,0,0,12'
    [void]$stack.Children.Add($passwordBox)

    $buttonPanel = New-Object System.Windows.Controls.StackPanel
    $buttonPanel.Orientation = 'Horizontal'
    $buttonPanel.HorizontalAlignment = 'Right'

    $okButton = New-Object System.Windows.Controls.Button
    $okButton.Content = 'OK'
    $okButton.Width = 70
    $okButton.Margin = '0,0,8,0'
    $okButton.IsDefault = $true
    $okButton.Add_Click({ $dialog.DialogResult = $true }.GetNewClosure())
    [void]$buttonPanel.Children.Add($okButton)

    $cancelButton = New-Object System.Windows.Controls.Button
    $cancelButton.Content = 'Cancel'
    $cancelButton.Width = 70
    $cancelButton.IsCancel = $true
    [void]$buttonPanel.Children.Add($cancelButton)

    [void]$stack.Children.Add($buttonPanel)
    $dialog.Content = $stack
    $dialog.Add_Loaded({ $passwordBox.Focus() }.GetNewClosure())

    if ($dialog.ShowDialog() -eq $true) {
        return $passwordBox.Password
    }
    return $null
}

# Reads a plan file fresh from disk every time it's called (no caching) -- the whole point is that
# editing a plan file and re-selecting the domain (or relaunching) picks the change up immediately,
# with no recompiling or restarting anything else. Plan files are a JSON array of step objects:
# [{ "description": "...", "commandLine": "...", "condition": [...], "groupingId": "...",
# "interactive": false }, ...]. description/condition/groupingId/interactive are all optional and
# default to ''/@()/$false when absent or null. condition (empty array = always run) is an array of
# PowerShell boolean expressions, ALL of which must be true for the step to run, each evaluated
# against the currently loaded variable values -- see Test-StepConditions. An array (not a single
# string) is what lets a step depend on more than one fact at once (e.g. isStretched AND
# primaryDatastoreType) without cramming both into one expression. groupingId (empty = must run on
# its own) marks steps that could safely run in parallel with any other step sharing the same
# non-empty groupingId; Run All bundles a CONSECUTIVE run of rows sharing one into a single parallel
# group (see Invoke-StepGroup) -- the same id reappearing later, separated by a different row, starts
# a new group rather than joining the earlier one. interactive (true) marks a step that stops partway
# through to prompt for real keyboard input (a Read-Host confirmation, a menu choice, ...) rather than
# running unattended end to end -- New-StepRow shows this as a trailing "*" on the row so Run All
# doesn't look stalled on something that's actually just waiting on the user. $RecoveryType selects
# the plans\ibr or plans\fdr subfolder.
function Get-RecoveryPlanSteps([string]$RecoveryType, [string]$PlanFileName) {
    $planFilePath = Join-Path (Join-Path $PlansPath $RecoveryType) $PlanFileName
    if (-not (Test-Path -LiteralPath $planFilePath)) {
        return @()
    }
    $rawSteps = @(Get-Content -LiteralPath $planFilePath -Raw | ConvertFrom-Json)
    return @(
        foreach ($rawStep in $rawSteps) {
            [PSCustomObject]@{
                Description = if ($rawStep.description) { [string]$rawStep.description } else { '' }
                CommandLine = [string]$rawStep.commandLine
                Condition   = if ($rawStep.condition) { @($rawStep.condition | ForEach-Object { [string]$_ }) } else { @() }
                GroupingId  = if ($rawStep.groupingId) { [string]$rawStep.groupingId } else { '' }
                Interactive = [bool]$rawStep.interactive
            }
        }
    )
}

# A single condition expression, evaluated with the currently known variable values (from
# Import-VariablesAnswersFile/New-VariablesFile) bound as local variables -- e.g. "$isStretched -eq
# 't'" sees $isStretched exactly as if it had been set with Set-Variable. Runs inside this process
# only, never sent to the console/transcript. A condition that fails to evaluate (typo, references a
# variable nobody supplied yet) fails open -- counts as true, since hiding a real recovery step
# because of a condition bug is worse than showing one that turns out to be unnecessary.
function Test-StepCondition([string]$Condition, [System.Collections.IDictionary]$Variables) {
    try {
        $scriptBlock = [scriptblock]::Create($Condition)
        $variableList = [System.Collections.Generic.List[System.Management.Automation.PSVariable]]::new()
        foreach ($name in $Variables.Keys) {
            $variableList.Add((New-Object System.Management.Automation.PSVariable($name, $Variables[$name])))
        }
        $result = $scriptBlock.InvokeWithContext($null, $variableList)
        return [bool]$result[0]
    } catch {
        return $true
    }
}

# A step's own Condition is an array -- ALL of them must be true (empty array = no conditions = runs
# unconditionally) for the step to be considered applicable.
function Test-StepConditions([string[]]$Conditions, [System.Collections.IDictionary]$Variables) {
    foreach ($condition in $Conditions) {
        if (-not (Test-StepCondition $condition $Variables)) {
            return $false
        }
    }
    return $true
}

# Filters $Steps down to whichever ones currently apply, per Test-StepConditions.
function Get-ApplicableSteps([object[]]$Steps, [System.Collections.IDictionary]$Variables) {
    return @($Steps | Where-Object { Test-StepConditions $_.Condition $Variables })
}

# Every $CommandLine plus every condition expression across $Steps, flattened into one flat string
# array -- used to find every variable name a plan's steps could possibly reference (see
# Get-ReferencedVariableNames), including ones that only ever appear inside a condition. A plain
# `$Steps.Condition` member-access here would collect each step's own condition array as a nested
# element rather than flattening it, so this walks $Steps explicitly instead.
function Get-StepReferenceText([object[]]$Steps) {
    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($step in $Steps) {
        $lines.Add($step.CommandLine)
        foreach ($condition in $step.Condition) {
            $lines.Add($condition)
        }
    }
    return $lines.ToArray()
}

# Shared by every plan's ListBox (Extract Backup, Management Domain Restores, Recover Default
# Cluster) -- clears whatever rows it showed before (a stale row from a previous plan/domain must
# never survive into a new selection) and returns the fresh row objects so Run All can replay them.
# $Steps is expected to already be condition-filtered (see Get-ApplicableSteps) -- this only renders.
function Set-PlanStepsListBox([System.Windows.Controls.ListBox]$ListBox, [object[]]$Steps) {
    $ListBox.Items.Clear()
    $rows = @()
    foreach ($step in $Steps) {
        $row = New-StepRow $step.CommandLine $step.GroupingId $step.Description $step.Interactive
        [void]$ListBox.Items.Add($row.Panel)
        $rows += $row
    }
    return $rows
}

# Maps a cluster's raw primaryDatastoreType (as recorded in the extracted SDDC data, and used
# verbatim in plan conditions like "$primaryDatastoreType -eq 'VSAN'" -- see
# Update-DerivedStepVariables) to a human-friendly label for display only. The raw value itself is
# never touched, so conditions keep matching the real extracted data regardless of this mapping. An
# unrecognized type passes through unchanged rather than disappearing.
function Get-DisplayDatastoreType([string]$RawType) {
    switch ($RawType) {
        'VSAN' { 'HCI (OSA)' }
        'VSAN_ESA' { 'HCI (ESA)' }
        'VSAN_MAX' { 'Storage Cluster' }
        'VSAN_Remote' { 'Compute Cluster' }
        default { $RawType }
    }
}

# What has to be recovered before this additional (non-default) cluster, for the "Dependent On"
# column -- purely informational, shown as a comma-separated list in recovery order:
#   Management domain additional cluster: the management domain itself, then (if a compute
#   cluster) its storage cluster.
#   VI (workload) domain additional cluster: the management domain, then this cluster's own
#   workload domain, then (if a compute cluster) its storage cluster.
# A compute cluster (primaryDatastoreType 'VSAN_Remote', an HCI Mesh consumer with no local vSAN
# datastore of its own) is resolved to its storage cluster by matching primaryDatastoreMoRef
# against every other cluster across every domain: HCI Mesh mounts the exact same underlying vSAN
# datastore object on both the storage cluster and every compute cluster that consumes it, so the
# first non-remote cluster sharing that MoRef is the one actually providing it. Left unresolved
# (silently omitted, not a placeholder) if no such cluster was captured in this extraction.
function Get-ClusterDependencies($Domain, $Cluster, [object[]]$AllDomains) {
    $dependencies = [System.Collections.Generic.List[string]]::new()
    $managementDomain = $AllDomains | Where-Object { $_.domainType -eq 'MANAGEMENT' } | Select-Object -First 1

    if ($Domain.domainType -eq 'MANAGEMENT') {
        if ($Domain.domainName) {
            $dependencies.Add($Domain.domainName)
        }
    } else {
        if ($managementDomain.domainName) {
            $dependencies.Add($managementDomain.domainName)
        }
        if ($Domain.domainName) {
            $dependencies.Add($Domain.domainName)
        }
    }

    if ($Cluster.primaryDatastoreType -eq 'VSAN_Remote' -and $Cluster.primaryDatastoreMoRef) {
        $storageCluster = @(
            foreach ($otherDomain in $AllDomains) {
                foreach ($otherCluster in $otherDomain.vsphereClusterDetails) {
                    if ($otherCluster.primaryDatastoreMoRef -eq $Cluster.primaryDatastoreMoRef -and $otherCluster.primaryDatastoreType -ne 'VSAN_Remote') {
                        $otherCluster
                    }
                }
            }
        ) | Select-Object -First 1
        if ($storageCluster.name) {
            $dependencies.Add($storageCluster.name)
        }
    }

    return ($dependencies -join ', ')
}

# Builds one table row (Workload Domains, Additional Clusters) as a plain Grid of TextBlocks.
# $ColumnGroups must be the same SharedSizeGroup names, in the same order, as the table's own
# static header Grid in the XAML -- that's what keeps a column's width in sync between the header
# and every data row without any data-binding markup. Width="Auto" is what actually makes a column
# hug its own content (Star widths always fill 100% of the row regardless of ratio, so no amount
# of re-weighting alone can "tighten" a Star-based layout). MaxWidth+TextTrimming is a safety net
# against a pathologically long value stretching a column past what the card can hold; ordinary
# values (names, FQDNs) never get close to it.
function New-TableRow([string[]]$Values, [string[]]$ColumnGroups) {
    $grid = New-Object System.Windows.Controls.Grid
    $grid.Margin = '3,2'
    foreach ($group in $ColumnGroups) {
        $columnDefinition = New-Object System.Windows.Controls.ColumnDefinition
        $columnDefinition.Width = [System.Windows.GridLength]::Auto
        $columnDefinition.SharedSizeGroup = $group
        [void]$grid.ColumnDefinitions.Add($columnDefinition)
    }
    for ($i = 0; $i -lt $Values.Count; $i++) {
        $textBlock = New-Object System.Windows.Controls.TextBlock
        $textBlock.Text = $Values[$i]
        $textBlock.MaxWidth = 220
        $textBlock.TextTrimming = 'CharacterEllipsis'
        if ($i -lt $Values.Count - 1) {
            $textBlock.Margin = '0,0,10,0'
        }
        [System.Windows.Controls.Grid]::SetColumn($textBlock, $i)
        [void]$grid.Children.Add($textBlock)
    }
    return $grid
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
        public const uint RDW_INVALIDATE = 0x1;
        public const uint RDW_ERASE = 0x4;
        public const uint RDW_UPDATENOW = 0x100;
        public const uint RDW_ALLCHILDREN = 0x80;

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

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetFocus();

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool RedrawWindow(IntPtr hWnd, IntPtr lprcUpdate, IntPtr hrgnUpdate, uint flags);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint GetWindowThreadProcessId(IntPtr hWnd, IntPtr lpdwProcessId);

        [DllImport("kernel32.dll")]
        public static extern uint GetCurrentThreadId();

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);

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

# Every console (Main, and every parallel one Run All spawns) is a completely ordinary pwsh.exe,
# given a real console window by Windows. PSReadLine is removed here -- confirmed by testing, not
# assumed: WriteConsoleInput reports success writing every record regardless, but with PSReadLine
# active the console never actually acts on any of them (an injected "exit`r" left the process
# running); with PSReadLine removed, the identical injection reliably exits it. PSReadLine owns
# line-editing (history, tab completion, syntax coloring) but has nothing to do with output
# rendering -- that's the console host's job, always was, and was never the source of the corruption
# bugs earlier designs hit. Losing PSReadLine here costs those editing niceties for anyone typing
# directly into the window; it doesn't reintroduce any of that risk, and it's the only way the
# Run/Run All buttons work at all. Set-Location and Start-Transcript still run as part of the
# startup -Command, before anything is typed into the console, so neither ever appears as if a user
# typed them. No -Encoding on Start-Transcript: that parameter doesn't exist on every PowerShell
# version, and Get-Content (used to read the transcript back) auto-detects the encoding from its
# BOM regardless of which default Start-Transcript happened to use to write it.
#
# $Bootstrap (the parallel-console case; Main never passes it) re-sends this new console exactly
# what Main's own session already has -- the extracted-data file path and whatever variables file
# was last loaded/created -- since a brand new pwsh.exe starts with neither, and the whole point of
# spawning it is to run a plan step that likely needs both.
function New-EmbeddedConsole([string]$TabHeader, [switch]$Bootstrap) {
    $global:consoleSequence++
    $transcriptPath = Join-Path $WorkingDirectory "vcfir-transcript-$(Get-Date -Format 'yyyyMMdd-HHmmss')-$PID-$($global:consoleSequence).log"
    $escapedWorkingDirectory = Protect-SingleQuotes $WorkingDirectory
    $escapedTranscriptPath = Protect-SingleQuotes $transcriptPath
    # $ErrorView = 'NormalView' matters, not just cosmetics: PowerShell 7's default, ConciseView,
    # renders an uncaught error as a single terse "<name>: <message>" line with no "+ CategoryInfo"
    # anywhere in it, which is exactly the marker Test-StepTranscriptClean's gate 3 looks for -- on
    # ConciseView a real, uncaught error would silently pass every gate. NormalView is the one that
    # always includes it.
    $consoleStartupCommand = "Set-Location -LiteralPath '$escapedWorkingDirectory'; Remove-Module PSReadLine -Force -ErrorAction SilentlyContinue; `$ErrorView = 'NormalView'; Start-Transcript -Path '$escapedTranscriptPath' -Force | Out-Null"

    # Launched via the Start-Process cmdlet, not System.Diagnostics.ProcessStartInfo + Process.Start().
    # This isn't a style choice -- it's the actual fix for "console window never appears". Confirmed
    # by a direct A/B test: raw ProcessStartInfo+Process.Start() (UseShellExecute=$false,
    # CreateNoWindow=$false, no explicit console-creation flag) makes the child INHERIT this
    # launcher's own console rather than allocate a new one -- MainWindowHandle stays 0 forever
    # (that's why no timeout, however long, ever helped) and the child's output was observed leaking
    # into the parent's own console instead. .NET's base Process API has no public property for the
    # Win32 CREATE_NEW_CONSOLE flag; Start-Process (the cmdlet) reliably allocates a real, separate
    # console window, verified with the exact same arguments. Argument/path quoting with spaces (the
    # original reason this launcher moved off Start-Process) was re-verified separately and is fine
    # here: -Command is a single array element regardless of the spaces inside it.
    $process = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList @('-NoLogo', '-NoProfile', '-NoExit', '-Command', $consoleStartupCommand) -WorkingDirectory $WorkingDirectory -PassThru

    # Bounded wait for the console's own window to exist -- Main's own creation happens well before
    # the main window is shown (Application.Run() hasn't been called yet), so blocking briefly there
    # is fine, the same way Start-VCFRecoveryCoordinator briefly waits for this whole process to
    # start; a parallel console's creation happens on a UI-thread event handler instead, so this
    # briefly blocks the UI too, same trade-off Send-ToConsole already accepts elsewhere. Hidden
    # immediately once found, so it never visibly flashes as a free-floating window before
    # ConsoleHwndHost embeds it.
    $hwnd = [IntPtr]::Zero
    $deadline = (Get-Date).AddSeconds(10)
    while ((Get-Date) -lt $deadline) {
        $process.Refresh()
        if ($process.HasExited) {
            $statusTextBlock.Text = "Console process exited before its window appeared."
            break
        }
        $hwnd = $process.MainWindowHandle
        if ($hwnd -ne [IntPtr]::Zero) { break }
        Start-Sleep -Milliseconds 50
    }

    $tabItem = New-Object System.Windows.Controls.TabItem
    $tabItem.Header = $TabHeader
    $hostBorder = New-Object System.Windows.Controls.Border
    $hostBorder.Background = [System.Windows.Media.Brushes]::Black
    $tabItem.Content = $hostBorder
    [void]$consoleTabControl.Items.Add($tabItem)

    if ($hwnd -ne [IntPtr]::Zero) {
        [VCFIRConsole.NativeMethods]::ShowWindow($hwnd, [VCFIRConsole.NativeMethods]::SW_HIDE) | Out-Null
        $hwndHost = New-Object VCFIRConsole.ConsoleHwndHost($hwnd)
        $hostBorder.Child = $hwndHost
    } else {
        $statusTextBlock.Text = "Console window did not appear within 10 seconds."
    }

    $console = [PSCustomObject]@{
        Process        = $process
        Hwnd           = $hwnd
        TranscriptPath = $transcriptPath
        TabItem        = $tabItem
        HostBorder     = $hostBorder
    }

    # ConsoleHwndHost doesn't implement IKeyboardInputSink, so WPF's own keyboard-focus tracking has
    # no real notion of an embedded console ever "having focus" the way it does for an ordinary WPF
    # control -- a plain click into one otherwise does nothing (WPF's own hit-testing/focus handling
    # can end up owning the click instead of the native child actually receiving real keyboard
    # focus). Every console needs this, not just the one this app starts with.
    $hostBorder.Add_PreviewMouseDown({
            Set-ConsoleFocus
        })

    if ($Bootstrap) {
        Initialize-ConsoleVariables $console
    }

    return $console
}

# Re-sends a freshly spawned parallel console exactly what Main's own session already has -- the
# extracted-data file path and the last-loaded/created variables answers file -- so a plan step run
# there sees the same variables it would if it had been run in Main. Both are conditional on
# something actually having been loaded/created yet in this run of the app; a brand-new console
# started before either happened simply gets neither command, same as Main itself would have none
# to send at that point.
#
# Blocks (bounded) until the last priming command sent actually finishes running, before returning,
# whenever something was sent -- Send-ToConsole only queues keystrokes via WriteConsoleInput, it does
# not wait for the target process to have consumed and run them yet. Invoke-StepGroup calls
# Add-StepWatch immediately after this returns, and Add-StepWatch's baseline offset has to be taken
# from AFTER these priming commands have actually finished executing; captured any earlier, their own
# transcript output would land inside the group step's own watched slice once it does run, and could
# fail that step's clean-transcript gate for something it never did itself.
#
# Both priming commands are real, exported module cmdlets that already log their own "Completed
# Task" line (see LogMessage) -- waiting for whichever was sent LAST to report that confirms
# everything queued before it has finished too, since console input is always processed strictly in
# the order it was queued. This is deliberately not a synthetic marker command of its own (an earlier
# version injected a "Write-Host 'VCFIR-BOOTSTRAP-COMPLETE-...'" for this) -- that line had no purpose
# other than this internal bookkeeping, so every parallel console showed it, uselessly, to anyone
# actually looking at the console pane.
function Initialize-ConsoleVariables($Console) {
    $lastCmdletSent = $null
    if ($global:extractedDataLoaded -and $filePathTextBox.Text) {
        $escapedPath = Protect-SingleQuotes $filePathTextBox.Text
        Send-ToConsole "Set-ExportedSDDCDataFilePath -Path '$escapedPath'" $Console
        $lastCmdletSent = 'Set-ExportedSDDCDataFilePath'
    }
    if ($global:variablesAnswersFilePath) {
        $escapedAnswersPath = Protect-SingleQuotes $global:variablesAnswersFilePath
        Send-ToConsole "Import-RecoveryVariables -Path '$escapedAnswersPath'" $Console
        $lastCmdletSent = 'Import-RecoveryVariables'
    }
    if (-not $lastCmdletSent) {
        return
    }

    $targetText = "Completed Task $lastCmdletSent"
    $deadline = (Get-Date).AddSeconds(10)
    while ((Get-Date) -lt $deadline) {
        $transcriptText = Get-Content -Path $Console.TranscriptPath -Raw -ErrorAction SilentlyContinue
        if ($transcriptText -and $transcriptText.Contains($targetText)) {
            return
        }
        Start-Sleep -Milliseconds 50
    }
    $statusTextBlock.Text = "Console '$($Console.TabItem.Header)' did not confirm its bootstrap variables within 10 seconds."
}

# Resolves to whichever console's tab is currently selected, for the benefit of anything that
# doesn't itself know (or care) which console it's about -- Set-ConsoleFocus, mainly. Falls back to
# Main if nothing matches (e.g. called before any tab has ever been selected).
function Get-ActiveConsole {
    $allConsoles = @($global:mainConsole) + @($global:parallelConsoles)
    $match = $allConsoles | Where-Object { $_.TabItem -eq $consoleTabControl.SelectedItem } | Select-Object -First 1
    if ($match) {
        return $match
    }
    return $global:mainConsole
}

# Kills every console process (Main and every parallel one) when the window actually closes,
# regardless of which path got it there (the X button or Exit) -- a plain child process isn't torn
# down automatically just because this process exits, so without this every close would leak
# orphaned pwsh.exe instances. Reparenting doesn't change this: a console window being a child of
# ours now makes it even less discoverable/manageable on its own if left behind, not more.
$window.Add_Closed({
        foreach ($console in (@($global:mainConsole) + @($global:parallelConsoles))) {
            if ($console -and $console.Process -and -not $console.Process.HasExited) {
                try { $console.Process.Kill($true) } catch {}
            }
        }
    })

# Plain SetFocus is unreliable across a process boundary -- a console is a genuinely separate
# process (and therefore thread) from this one, and Win32 only guarantees a SetFocus call actually
# moves real keyboard focus onto a window owned by another thread if that thread's input queue has
# first been joined to the caller's via AttachThreadInput; otherwise the call can silently do nothing
# even though it reports success. Attached only for the instant it takes to call SetFocus, then
# immediately detached again -- this only needs to be true for that one call, not for the whole
# app's lifetime. Always acts on Get-ActiveConsole (whichever tab is currently selected), never a
# specific console passed in -- switching tabs, clicking a console, the window regaining activation,
# and Send-ToConsole injecting a command should all give focus to whatever's actually on screen,
# never silently steal it onto some other tab.
function Set-ConsoleFocus {
    $console = Get-ActiveConsole
    if ($null -eq $console -or $console.Hwnd -eq [IntPtr]::Zero) {
        return
    }
    # A tab being selected for the very first time (a parallel console's tab, almost always -- Main
    # is selected before the window is even shown) hasn't actually been embedded yet: TabControl only
    # realizes a TabItem's Content -- which is what runs ConsoleHwndHost.BuildWindowCore, the SetParent/
    # ShowWindow call that turns this from a separate hidden top-level window into a true child of our
    # own -- on the next layout pass, not synchronously as part of SelectedItem changing. Called from
    # the SelectionChanged handler (the common case) with no pump in between, SetFocus below would
    # otherwise run against a window that's still a hidden top-level window, silently do nothing useful,
    # and leave every keystroke the user types going nowhere -- confirmed directly: GetParent on the
    # console's hwnd was still Zero, and focus still elsewhere, at that exact point without this call.
    # UpdateLayout is a no-op cost-wise once a tab's content is already realized, so this is always safe.
    $consoleTabControl.UpdateLayout()
    $consoleThreadId = [VCFIRConsole.NativeMethods]::GetWindowThreadProcessId($console.Hwnd, [IntPtr]::Zero)
    $currentThreadId = [VCFIRConsole.NativeMethods]::GetCurrentThreadId()
    $attached = $false
    if ($consoleThreadId -ne 0 -and $consoleThreadId -ne $currentThreadId) {
        $attached = [VCFIRConsole.NativeMethods]::AttachThreadInput($currentThreadId, $consoleThreadId, $true)
    }
    try {
        # SetFocus reporting success doesn't guarantee the target thread actually processed the
        # focus change yet -- if that thread is busy at that exact instant (mid output, mid a
        # network wait finally returning, anything), the change can silently not take, and detaching
        # right after (the very next line, previously) tears down the joined queue before it ever
        # would have. Verified for real: a console that had already taken real keystrokes once
        # stopped accepting them after a long wait, and only started working again once a completely
        # different console's own focus cycle ran -- consistent with exactly this race, not a dead
        # process. GetFocus is only meaningful for OUR OWN thread's queue, which is why this check has
        # to happen here, still attached, rather than after detaching.
        $focusDeadline = (Get-Date).AddMilliseconds(300)
        do {
            [VCFIRConsole.NativeMethods]::SetFocus($console.Hwnd) | Out-Null
            if ([VCFIRConsole.NativeMethods]::GetFocus() -eq $console.Hwnd) {
                break
            }
            Start-Sleep -Milliseconds 20
        } while ((Get-Date) -lt $focusDeadline)
    } finally {
        if ($attached) {
            [VCFIRConsole.NativeMethods]::AttachThreadInput($currentThreadId, $consoleThreadId, $false) | Out-Null
        }
    }
}

$global:mainConsole = New-EmbeddedConsole -TabHeader 'Main'
$consoleTabControl.SelectedIndex = 0

# WPF's own default (focus the first focusable control in the visual tree) would land on something
# in the left rail, not the console -- Set-ConsoleFocus puts the initial keyboard focus on the
# embedded console instead, so typing works immediately without clicking into it first.
$window.Add_Loaded({
        Set-ConsoleFocus
    })

# Window activation and tab switching are the two other moments Set-ConsoleFocus's own comment
# describes as needing an explicit re-assertion -- this window regaining activation after having
# lost it for a while (screen lock, RDP disconnect/reconnect, alt-tabbing away and back), or
# switching to a different console's tab, both leave real OS keyboard focus wherever it already was
# rather than automatically following either. Exactly the kind of gap that would leave a step's own
# interactive prompt (Read-Host) visibly sitting on screen but genuinely unable to receive anything
# typed at it, indefinitely, with nothing to indicate why.
$window.Add_Activated({
        Set-ConsoleFocus
    })

$consoleTabControl.Add_SelectionChanged({
        Set-ConsoleFocus
    })

# The window opens already maximized (see the XAML's WindowState), which means WPF first lays the
# embedded console out at its declared (smaller) design-time size, then the OS applies the maximize
# transform a moment later -- DWM composites a frame of the console mid-transition and never gets
# told to redraw it against the final maximized bounds, leaving a stale strip/duplicate rectangle
# behind until something (e.g. manually unmaximizing and remaximizing) forces a real repaint.
# ContentRendered fires once the window has actually finished rendering at its current size/state,
# which is the right moment to force that repaint ourselves rather than rely on DWM noticing on its
# own. RDW_ALLCHILDREN matters here specifically -- the console is a child HWND (via ConsoleHwndHost),
# not painted by this process, so the redraw has to be told to reach into it, not just this window.
$window.Add_ContentRendered({
        if ($global:mainConsole -and $global:mainConsole.Hwnd -ne [IntPtr]::Zero) {
            $redrawFlags = [VCFIRConsole.NativeMethods]::RDW_INVALIDATE -bor [VCFIRConsole.NativeMethods]::RDW_ERASE -bor [VCFIRConsole.NativeMethods]::RDW_UPDATENOW -bor [VCFIRConsole.NativeMethods]::RDW_ALLCHILDREN
            [VCFIRConsole.NativeMethods]::RedrawWindow($global:mainConsole.Hwnd, [IntPtr]::Zero, [IntPtr]::Zero, $redrawFlags) | Out-Null
        }
    })

# Injects a command by simulating real keystrokes into the embedded console (WriteConsoleInput),
# indistinguishable to PowerShell from someone typing them -- no echo of our own to add, no pipe to
# write to; the real console echoes what's "typed" exactly as it always does, because as far as it
# knows, that's exactly what happened. $Console defaults to Main, so every existing call site (a
# lone Run button, Load Variables, the extraction flow, ...) keeps targeting it without having to
# say so; only Invoke-StepGroup ever passes a specific (parallel) console.
function Send-ToConsole([string]$CommandLine, $Console) {
    if ($null -eq $Console) {
        $Console = $global:mainConsole
    }
    if ($null -eq $Console -or $null -eq $Console.Process -or $Console.Process.HasExited) {
        $statusTextBlock.Text = "Console process isn't running."
        return
    }
    try {
        [VCFIRConsole.NativeMethods]::FreeConsole() | Out-Null
        # A console that was JUST created (New-EmbeddedConsole -Bootstrap calling straight into this,
        # the moment its own window handle first appears) can still fail AttachConsole for a beat
        # afterward -- the window existing doesn't guarantee the process's own console subsystem has
        # finished initializing enough to accept another process attaching to it yet. Retrying a few
        # times a beat apart, rather than failing outright on the first attempt, is what makes a
        # freshly bootstrapped parallel console's very first injected command (typically
        # Set-ExportedSDDCDataFilePath) reliably land instead of silently vanishing -- observed for
        # real: that exact command missing from a parallel console's transcript with no trace of it
        # having ever been typed, while a later command sent moments afterward (once the race window
        # had passed) worked fine. Main is never subject to this since nothing sends it a command
        # this soon after creation.
        $attachDeadline = (Get-Date).AddSeconds(2)
        $attached = $false
        do {
            $attached = [VCFIRConsole.NativeMethods]::AttachConsole([uint32]$Console.Process.Id)
            if (-not $attached) {
                Start-Sleep -Milliseconds 100
            }
        } while (-not $attached -and (Get-Date) -lt $attachDeadline)
        if (-not $attached) {
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
    Set-ConsoleFocus
}

# A step's transcript slice is "unclean" -- even once its own "Completed Task" line has appeared --
# if it contains LogMessage's own [WARNING]/[ERROR]/[EXCEPTION] tags, or "+ CategoryInfo", the one
# near-universal marker of PowerShell's own default terminating-error record formatting (for
# exceptions that were never caught and logged via LogMessage at all -- several cmdlets in the
# module have no try/catch around risky calls). Matched as literal bracketed tags, not bare words,
# so an ordinary INFO message that happens to mention "error" in passing can't false-positive.
# This can never be airtight -- a handful of cmdlets swallow failures with -ErrorAction/
# -WarningAction SilentlyContinue and never display anything at all -- but it catches everything
# that actually reaches the screen, which today includes real failures (e.g. Invoke-vCenterRestore's
# own "Restore failed" branch still logs Completed Task right after its [ERROR] lines).
function Test-StepTranscriptClean([string]$TranscriptSlice) {
    foreach ($marker in '[WARNING]', '[ERROR]', '[EXCEPTION]', '+ CategoryInfo') {
        if ($TranscriptSlice.Contains($marker)) {
            return $false
        }
    }
    return $true
}

# Starts (or restarts) watching a console's transcript for this row's "Completed Task <cmdlet>"
# line, from whatever that transcript's current length is right now -- so an OLDER completion line
# already in it from a previous run of the same cmdlet can't cause an immediate false-positive match
# on a re-run. $OnComplete (optional) is called with one argument -- $isClean, per
# Test-StepTranscriptClean -- once "Completed Task" is found; Invoke-StepChain/Invoke-StepGroup use
# this to gate starting the next step (or continuing past a parallel group) on the previous one(s)
# actually having gone cleanly, not just having finished. $Console defaults to Main.
function Add-StepWatch($Button, [string]$CmdletName, [scriptblock]$OnComplete, $Console) {
    if ($null -eq $Console) {
        $Console = $global:mainConsole
    }
    $currentText = ''
    if (Test-Path $Console.TranscriptPath) {
        $currentText = Get-Content -Path $Console.TranscriptPath -Raw -ErrorAction SilentlyContinue
        if ($null -eq $currentText) { $currentText = '' }
    }
    # Drop any earlier watch for this same button first, rather than stacking duplicates on a re-run.
    # @(...) around the whole pipeline is required, not optional: Where-Object filtering everything
    # out (as it always does on the very first-ever call, since the list starts empty) produces $null,
    # not an empty collection, and List[object]'s constructor throws ArgumentNullException on $null.
    $global:activeStepWatches = [System.Collections.Generic.List[object]]@($global:activeStepWatches | Where-Object { $_.Button -ne $Button })
    $global:activeStepWatches.Add([PSCustomObject]@{
            Button         = $Button
            TargetText     = "Completed Task $CmdletName"
            StartOffset    = $currentText.Length
            OnComplete     = $OnComplete
            TranscriptPath = $Console.TranscriptPath
            Console        = $Console
        })
}

# Same idea as Add-StepWatch, for actions that run immediately rather than through a Steps row --
# there's no Button to flip to Done/Failed, so $OnComplete (called with $isClean, same as
# Add-StepWatch) is the only signal. Used by Invoke-ExtractSDDCManagerBackup to auto-load the
# resulting extracted-sddc-data.json once extraction actually finishes, not as soon as the command
# is sent; that caller ignores $isClean since a failed extraction simply won't produce a loadable
# file. $Console defaults to Main -- extraction only ever runs there.
function Add-CompletionWatch([string]$CmdletName, [scriptblock]$OnComplete, $Console) {
    if ($null -eq $Console) {
        $Console = $global:mainConsole
    }
    $currentText = ''
    if (Test-Path $Console.TranscriptPath) {
        $currentText = Get-Content -Path $Console.TranscriptPath -Raw -ErrorAction SilentlyContinue
        if ($null -eq $currentText) { $currentText = '' }
    }
    $global:activeStepWatches.Add([PSCustomObject]@{
            Button         = $null
            TargetText     = "Completed Task $CmdletName"
            StartOffset    = $currentText.Length
            OnComplete     = $OnComplete
            TranscriptPath = $Console.TranscriptPath
        })
}

# Disables both Discovered Infrastructure list boxes the instant the very first step ever actually
# starts running, regardless of whether that step belongs to a domain or an additional cluster --
# switching which element is selected mid-run would leave whatever's already running (or already
# Done) pointed at a target the UI no longer shows as selected, with no way to tell from looking at
# it. Idempotent (only sets $global:recoveryRunStarted and updates the status text once) since
# Invoke-Step calls this unconditionally on every single Run, not just the first.
function Lock-ElementSelection {
    if ($global:recoveryRunStarted) {
        return
    }
    $global:recoveryRunStarted = $true
    $domainsListBox.IsEnabled = $false
    $additionalClustersListBox.IsEnabled = $false
    $statusTextBlock.Text = 'A run has started -- domain/cluster selection is now locked. Exit and relaunch to recover a different element.'
}

# Resets a row to its "in progress" look (undoing any earlier Done/Failed state -- re-running a step
# that previously completed should stop showing that until it completes again) and starts watching
# for its completion. $OnStepComplete (optional) is threaded straight through to Add-StepWatch --
# see Invoke-StepChain/Invoke-StepGroup. $Console (optional, defaults to Main) is which console the
# command actually runs in -- only a parallel group's non-first members ever pass a different one.
function Invoke-Step($Button, [string]$CmdletName, [string]$CommandLine, [scriptblock]$OnStepComplete, $Console) {
    if ($null -eq $Console) {
        $Console = $global:mainConsole
    }
    Lock-ElementSelection
    $Button.Content = 'Running'
    $Button.Background = [System.Windows.Media.Brushes]::Orange
    Add-StepWatch $Button $CmdletName $OnStepComplete $Console
    Send-ToConsole $CommandLine $Console
}

# Run All's sequencer: runs $Rows one at a time, only starting the next once the previous one has
# passed all three gates -- (1) its own "Completed Task" line found in the transcript, (2) no
# LogMessage [WARNING]/[ERROR]/[EXCEPTION] tag anywhere in its transcript slice, (3) no raw
# PowerShell error record either (see Test-StepTranscriptClean for both). A step that finishes but
# fails any of those stops the whole chain right there instead of sending the next step's command
# into a plan that assumed the previous one actually worked.
#
# A run of two or more consecutive rows sharing the same non-empty GroupingId is dispatched to
# Invoke-StepGroup instead, so they run in parallel (each in its own console) rather than one at a
# time; the chain only continues past the whole group once every member has finished cleanly. Rows
# must be consecutive in the plan file to be bundled -- a GroupingId reappearing later, separated by
# an ungrouped or differently-grouped row, starts a new group rather than joining the earlier one.
# -IgnoreGrouping (driven by each panel's own "Run parallel operations where possible" checkbox --
# unchecked means this) skips that dispatch entirely, running every row one at a time regardless of
# GroupingId; it's threaded through every recursive call so unchecking it stays in effect for the
# rest of that particular Run All run, not just its first row.
function Invoke-StepChain([object[]]$Rows, [switch]$IgnoreGrouping) {
    if ($Rows.Count -eq 0) {
        return
    }
    $row = $Rows[0]
    if ($row.GroupingId -and -not $IgnoreGrouping) {
        $groupEnd = 1
        while ($groupEnd -lt $Rows.Count -and $Rows[$groupEnd].GroupingId -eq $row.GroupingId) {
            $groupEnd++
        }
        if ($groupEnd -gt 1) {
            $groupRows = @($Rows | Select-Object -First $groupEnd)
            $remainingRows = @($Rows | Select-Object -Skip $groupEnd)
            Invoke-StepGroup $groupRows $remainingRows
            return
        }
    }
    $remainingRows = @($Rows | Select-Object -Skip 1)
    Invoke-Step $row.Button $row.CmdletName $row.CommandLine {
        param($isClean)
        if ($isClean) {
            Invoke-StepChain $remainingRows -IgnoreGrouping:$IgnoreGrouping
        } else {
            $statusTextBlock.Text = "Run All stopped: $($row.CmdletName) did not complete cleanly -- check the console/transcript for warnings, errors, or a PowerShell error record before retrying."
        }
    }.GetNewClosure()
}

# Runs every row in $GroupRows at once, each in its own freshly bootstrapped console
# (New-EmbeddedConsole -Bootstrap, which imports the extracted-data path and answers file so the new
# console's session has the same variables as Main) -- none of them run in Main, including the
# first, so Main stays free rather than being tied up by whichever group member happened to be listed
# first in the plan file. Only resumes the chain with $AfterGroupRows once every member has reported
# back. $state is a shared, mutated-in-place hashtable captured by every member's OnComplete closure
# (via .GetNewClosure()) -- safe because it's a reference type and none of the closures ever reassign
# $state itself, only its .Remaining/.AllClean entries. Per the confirmed design, a member finishing
# uncleanly does not attempt to stop its still-running siblings; the chain simply refuses to continue
# once they've all finished if any of them were unclean. Only ever reached with grouping enabled (see
# Invoke-StepChain), so its own continuation into $AfterGroupRows never needs -IgnoreGrouping itself.
function Invoke-StepGroup([object[]]$GroupRows, [object[]]$AfterGroupRows) {
    $state = @{ Remaining = $GroupRows.Count; AllClean = $true }
    $onMemberComplete = {
        param($isClean)
        if (-not $isClean) {
            $state.AllClean = $false
        }
        $state.Remaining--
        if ($state.Remaining -eq 0) {
            if ($state.AllClean) {
                Invoke-StepChain $AfterGroupRows
            } else {
                $statusTextBlock.Text = "Run All stopped: one or more steps in group '$($GroupRows[0].GroupingId)' did not complete cleanly -- check each console/transcript before retrying."
            }
        }
    }.GetNewClosure()

    foreach ($row in $GroupRows) {
        $console = New-EmbeddedConsole -TabHeader $row.CmdletName -Bootstrap
        $global:parallelConsoles.Add($console)
        Invoke-Step $row.Button $row.CmdletName $row.CommandLine $onMemberComplete $console
    }
}

# Returns [PSCustomObject]@{ Panel; CommandLine; Button; CmdletName; GroupingId; Interactive }, not
# just the row's visual Panel -- the other fields are needed separately so a tab's "Run All" button
# can replay every row's Run action, and so Invoke-Step/Add-StepWatch can update the right row's
# button and watch for the right cmdlet name without re-parsing the rendered list.
function New-StepRow([string]$CommandLine, [string]$GroupingId, [string]$Description, [bool]$Interactive) {
    $panel = New-Object System.Windows.Controls.DockPanel
    $panel.Margin = '2,0,2,0'
    if ($Description) {
        $panel.ToolTip = $Description
    }

    # Only the cmdlet name is shown; the full command line (with its parameters) stays in the
    # module and is only ever sent to the console, never rendered in the Steps list. Variable
    # values referenced in it (e.g. $targetFqdn) come from whatever was loaded via "Load
    # Variables..." -- they're already set in the console session by the time Run is clicked. A
    # trailing "*" (see the Steps panel's own legend text in the XAML) is appended here, on the
    # label itself, rather than as some separate badge, since it needs to read as part of the name.
    $cmdletName = ($CommandLine -split '\s+', 2)[0]
    $displayName = if ($Interactive) { "$cmdletName*" } else { $cmdletName }

    $runButton = New-Object System.Windows.Controls.Button
    $runButton.Content = 'Run'
    # Wide enough for 'Running' -- the longest of the states this button ever shows (Run/Running/
    # Done/Failed) -- so it doesn't visibly resize as a step starts and finishes.
    $runButton.Width = 65
    $runButton.Padding = '6,2'
    $runButton.Margin = '6,0,0,0'
    [System.Windows.Controls.DockPanel]::SetDock($runButton, [System.Windows.Controls.Dock]::Right)
    $runButton.Add_Click({
            try {
                Invoke-Step $runButton $cmdletName $CommandLine
            } catch {
                $statusTextBlock.Text = "Run button failed: $($_.Exception.Message)"
            }
        }.GetNewClosure())

    # Run All groups consecutive rows sharing this GroupingId into a parallel batch (see
    # Invoke-StepGroup); manually clicking Run on a single row never does, even if it's grouped.
    if ($GroupingId) {
        $groupBadge = New-Object System.Windows.Controls.TextBlock
        $groupBadge.Text = "[$GroupingId]"
        $groupBadge.Foreground = [System.Windows.Media.Brushes]::Gray
        $groupBadge.FontStyle = 'Italic'
        $groupBadge.VerticalAlignment = 'Center'
        $groupBadge.Margin = '8,0,6,0'
        [System.Windows.Controls.DockPanel]::SetDock($groupBadge, [System.Windows.Controls.Dock]::Right)
    }

    $label = New-Object System.Windows.Controls.TextBlock
    $label.Text = $displayName
    $label.FontFamily = New-Object System.Windows.Media.FontFamily('Consolas')
    $label.VerticalAlignment = 'Center'

    # DockPanel stacks same-side children in the order they're added -- the first Right-docked
    # child added ends up rightmost, and each one after lands just to its left. Adding runButton
    # before groupBadge (rather than after) is what keeps Run pinned to the far-right edge with the
    # group badge immediately to its left, not the other way around.
    [void]$panel.Children.Add($runButton)
    if ($groupBadge) {
        [void]$panel.Children.Add($groupBadge)
    }
    [void]$panel.Children.Add($label)
    return [PSCustomObject]@{ Panel = $panel; CommandLine = $CommandLine; Button = $runButton; CmdletName = $cmdletName; GroupingId = $GroupingId; Interactive = $Interactive }
}

# Variable names referenced across $CommandLines (e.g. "$targetFqdn"), in order of first
# appearance, deduplicated. Used to order the Variables panel by when each value is actually
# needed as you work down the Steps list, rather than alphabetically or by answer-file order.
function Get-ReferencedVariableNames([string[]]$CommandLines) {
    $names = [System.Collections.Generic.List[string]]::new()
    # true/false/null are PowerShell's own automatic variables (e.g. -confirm:$false), not
    # answer-file inputs -- without this, a plan using one produces a nonsensical "true"/"false"/
    # "null" row on the Variables tab asking for a value that was never meant to be supplied.
    $seen = @{ true = $true; false = $true; null = $true }
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

# $OnValueChanged (optional) fires alongside the existing console update below, given the edited
# name/value -- used by New Variables File to persist every field to its chosen file as it's
# filled in, without changing what Load Variables' own rows already do (they pass nothing).
function New-VariableRow([string]$Name, [string]$Value, [scriptblock]$OnValueChanged) {
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
            if ($OnValueChanged) {
                & $OnValueChanged $Name $valueBox.Text
            }
        }.GetNewClosure())

    [void]$panel.Children.Add($label)
    [void]$panel.Children.Add($valueBox)
    return $panel
}

# A parallel console only ever runs one step in its whole lifetime (Invoke-StepGroup spawns a brand
# new one per group member, never reuses one) -- so once that step is done, whether clean or not,
# there's nothing left for that console to do. This relays everything it printed for that step
# ($OutputText -- the same StartOffset-anchored slice Test-StepTranscriptClean already checked) back
# into Main, then tears the console down: Stop-Transcript, kill the process, drop its tab, and drop
# it from $global:parallelConsoles.
#
# The relay goes through a plain temp file rather than embedding $OutputText straight into a typed
# command -- a step's real output can be arbitrarily long and contain quotes, backticks, `$`, anything
# LogMessage or the cmdlet itself printed, none of which is safe to splice into a command line meant
# to run in Main's session. Piping a short, fixed "Get-Content -LiteralPath '...'" command through
# instead sidesteps all of that: the only thing that ever varies is a file path, escaped the same way
# every other Send-ToConsole call in this file already does.
function Close-ParallelConsoleAndFeedBack($Console, [string]$OutputText) {
    try {
        $relayFilePath = Join-Path $WorkingDirectory "vcfir-parallel-output-$(Get-Date -Format 'yyyyMMdd-HHmmss')-$($Console.Process.Id).log"
        Set-Content -LiteralPath $relayFilePath -Value $OutputText -Encoding utf8
        $escapedRelayPath = Protect-SingleQuotes $relayFilePath
        $header = Protect-SingleQuotes "----- Output from parallel console '$($Console.TabItem.Header)' -----"
        $footer = Protect-SingleQuotes "----- End of output from '$($Console.TabItem.Header)' -----"
        Send-ToConsole "Write-Host '$header'; Get-Content -LiteralPath '$escapedRelayPath' -Raw; Write-Host '$footer'"
    } catch {
        $statusTextBlock.Text = "Failed to relay parallel console output to Main: $($_.Exception.Message)"
    }

    try {
        if (-not $Console.Process.HasExited) {
            Send-ToConsole 'Stop-Transcript | Out-Null' $Console
            Start-Sleep -Milliseconds 300
            if (-not $Console.Process.HasExited) {
                Stop-Process -Id $Console.Process.Id -Force -ErrorAction SilentlyContinue
            }
        }
    } catch {}

    [void]$consoleTabControl.Items.Remove($Console.TabItem)
    $global:parallelConsoles = [System.Collections.Generic.List[object]]@($global:parallelConsoles | Where-Object { $_ -ne $Console })
}

# Checks each actively-watched row's slice of ITS OWN console's transcript (everything written
# since its Run was clicked) for its own "Completed Task <cmdlet>" line. A row is only in this list
# between being Run and being found Done (see Add-StepWatch) -- once found, it's removed, which is
# what stops the monitor for that row until Run is clicked again. Watches on different rows can
# share the same TranscriptPath (Main, most of the time) or each have their own (a parallel group's
# non-first members) -- $transcriptCache reads each distinct path at most once per tick regardless
# of how many watches point at it.
function Start-StepCompletionWatcher {
    $checkTimer = New-Object System.Windows.Threading.DispatcherTimer
    $checkTimer.Interval = [TimeSpan]::FromMilliseconds(500)
    $checkTimer.Add_Tick({
            if ($global:activeStepWatches.Count -eq 0) { return }
            $transcriptCache = @{}
            foreach ($path in ($global:activeStepWatches | Select-Object -ExpandProperty TranscriptPath -Unique)) {
                if (-not (Test-Path $path)) { continue }
                try {
                    $text = Get-Content -Path $path -Raw -ErrorAction Stop
                } catch {
                    continue
                }
                if ($null -ne $text) {
                    $transcriptCache[$path] = $text
                }
            }
            if ($transcriptCache.Count -eq 0) { return }
            # Snapshotting which watches are due BEFORE any of them run, then removing each one from
            # whatever $global:activeStepWatches -is- right before invoking its own OnComplete --
            # rather than replacing the whole list wholesale once at the end -- matters because
            # Invoke-StepChain's OnComplete callback calls Add-StepWatch itself to start the next step,
            # which reassigns $global:activeStepWatches to a brand-new list. A wholesale replacement
            # here would silently wipe that reentrant addition out the instant this tick finished,
            # since it was never part of the snapshot this tick started with.
            $dueWatches = @($global:activeStepWatches | Where-Object {
                    $transcriptText = $transcriptCache[$_.TranscriptPath]
                    if ($null -eq $transcriptText) { return $false }
                    $newText = if ($transcriptText.Length -gt $_.StartOffset) { $transcriptText.Substring($_.StartOffset) } else { '' }
                    $newText.Contains($_.TargetText)
                })
            foreach ($watch in $dueWatches) {
                $transcriptText = $transcriptCache[$watch.TranscriptPath]
                $newText = if ($transcriptText.Length -gt $watch.StartOffset) { $transcriptText.Substring($watch.StartOffset) } else { '' }
                $isClean = Test-StepTranscriptClean $newText
                if ($watch.Button) {
                    if ($isClean) {
                        $watch.Button.Content = 'Done'
                        $watch.Button.Background = [System.Windows.Media.Brushes]::Green
                    } else {
                        $watch.Button.Content = 'Failed'
                        $watch.Button.Background = [System.Windows.Media.Brushes]::Firebrick
                    }
                }
                $global:activeStepWatches = [System.Collections.Generic.List[object]]@($global:activeStepWatches | Where-Object { $_ -ne $watch })
                # Only ever a parallel console here -- Main's own watches carry $global:mainConsole,
                # which never gets torn down mid-run. Relaying and closing before OnComplete fires
                # means the tab and its output are already gone/relayed by the time anything reacts
                # to this step finishing (e.g. Invoke-StepGroup deciding whether to continue the chain).
                if ($watch.Console -and $watch.Console -ne $global:mainConsole) {
                    Close-ParallelConsoleAndFeedBack $watch.Console $newText
                }
                if ($watch.OnComplete) {
                    & $watch.OnComplete $isClean
                }
            }
        })
    $checkTimer.Start()
}

# Shared by the Browse button and Resume, so both end up driving the exact same domain-listing /
# console-variable-setting logic instead of two copies drifting apart.
function Import-ExtractedSddcDataFile([string]$Path) {
    $domainsListBox.Items.Clear()
    $additionalClustersListBox.Items.Clear()
    $domainRecoveryStepsListBox.Items.Clear()
    $additionalClusterRecoveryStepsListBox.Items.Clear()
    $variablesItemsPanel.Children.Clear()
    $loadedVariablesTextBlock.Text = 'No variables loaded yet.'
    $stepsVariablesGroupBox.Visibility = [System.Windows.Visibility]::Collapsed
    # Nothing meaningful to show until a load actually succeeds below -- collapsed here covers
    # every early-return failure path (bad JSON, missing workloadDomains) without repeating this
    # line at each one.
    $discoveredInfrastructureGroupBox.Visibility = [System.Windows.Visibility]::Collapsed
    $global:extractedDataLoaded = $false
    $global:domainRecoverySteps = @()
    $global:additionalClusterRecoverySteps = @()
    $global:allSteps = @()
    $global:derivedStepVariables = @{}
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
        $item.Content = New-TableRow -Values @($domain.domainName, $domain.domainType) -ColumnGroups @('WorkloadDomainsCol0', 'WorkloadDomainsCol1')
        $item.Tag = $domain
        [void]$domainsListBox.Items.Add($item)
    }

    # Every domain's own default cluster (isDefault 't') is already the one the Recover Default
    # Cluster plan targets -- anything else (isDefault 'f') is scoped out of that plan entirely, so
    # this is the only place that tells you such a cluster even exists at all. ClusterName can be
    # blank: it's only populated once Update-ExtractedSDDCData resolves it against a live vCenter,
    # which hasn't necessarily happened yet for data that was just extracted or freshly loaded.
    $additionalClusters = @(
        foreach ($domain in $extractedSddcData.workloadDomains) {
            foreach ($cluster in $domain.vsphereClusterDetails) {
                if ($cluster.isDefault -eq 'f') {
                    [PSCustomObject]@{
                        ClusterName          = $cluster.name
                        DomainName           = $domain.domainName
                        PrimaryDatastoreType = $cluster.primaryDatastoreType
                        IsStretched          = $cluster.isStretched
                        DependentOn          = Get-ClusterDependencies $domain $cluster $extractedSddcData.workloadDomains
                    }
                }
            }
        }
    )
    if ($additionalClusters.Count -eq 0) {
        [void]$additionalClustersListBox.Items.Add('No additional clusters detected.')
    } else {
        foreach ($cluster in $additionalClusters) {
            $stretchedText = if ($cluster.IsStretched -eq 't') { 'Y' } else { 'N' }
            $clusterNameText = if ($cluster.ClusterName) { $cluster.ClusterName } else { '(unknown)' }
            $columnGroups = @('AdditionalClustersCol0', 'AdditionalClustersCol1', 'AdditionalClustersCol2', 'AdditionalClustersCol3', 'AdditionalClustersCol4')
            $row = New-TableRow -Values @($clusterNameText, $cluster.DomainName, (Get-DisplayDatastoreType $cluster.PrimaryDatastoreType), $stretchedText, $cluster.DependentOn) -ColumnGroups $columnGroups
            # Wrapped in an explicit ListBoxItem (rather than adding $row directly) so selecting a
            # row is distinguishable from the "No additional clusters detected." placeholder above,
            # which is a plain string -- see Sync-AdditionalClusterSteps's ListBoxItem type check.
            $item = New-Object System.Windows.Controls.ListBoxItem
            $item.Content = $row
            $item.Tag = $cluster
            [void]$additionalClustersListBox.Items.Add($item)
        }
    }

    $global:extractedDataLoaded = $true
    $discoveredInfrastructureGroupBox.Visibility = [System.Windows.Visibility]::Visible

    $escapedPath = Protect-SingleQuotes $Path
    Send-ToConsole "Set-ExportedSDDCDataFilePath -Path '$escapedPath'"
}

# IBR is domain-driven: Data Source/Discovered Infrastructure come back, and Domain Restores /
# Recover Default Cluster / Recover Additional Cluster replace Recover Fleet on the Steps tab strip.
# Sync-DomainSteps/Sync-AdditionalClusterSteps own their own tabs' visibility (each shows only when
# its own selection is real, and the two selections are mutually exclusive), so this handler doesn't
# force any of the three visible/collapsed itself -- it only re-runs both syncs to re-derive
# Execution's state from whatever's currently selected in Discovered Infrastructure (re-picking the
# same domain/cluster wouldn't refire SelectionChanged, so this can't just rely on that).
$ibrRecoveryTypeRadio.Add_Checked({
        $dataSourceGroupBox.Visibility = [System.Windows.Visibility]::Visible
        # Only reveal Discovered Infrastructure if data was actually loaded before switching away to
        # FDR -- not unconditionally, since nothing may have been loaded at all yet.
        $discoveredInfrastructureGroupBox.Visibility = if ($global:extractedDataLoaded) { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
        $recoverFleetPanel.Visibility = [System.Windows.Visibility]::Collapsed
        $global:recoverFleetStepRows = Set-PlanStepsListBox $recoverFleetStepsListBox @()
        Sync-DomainSteps
        Sync-AdditionalClusterSteps
    })

# FDR has one whole-fleet plan (plans/fdr/fdr-failover-plan.json) with no domain to select, so Data
# Source/Discovered Infrastructure are irrelevant to it -- collapsing both (rather than covering
# them with a placeholder) lets Recovery Tasks' Auto-height rows collapse to zero and the row below
# take the freed space automatically. Loads and shows the plan immediately, same as picking
# Extract SDDC Manager Backup runs immediately rather than waiting for a further action. No variable
# values are known yet at this point, so conditional steps fail open (see Test-StepCondition) and
# show unconditionally until Load Variables/New Variables File re-filters them for real.
$fdrRecoveryTypeRadio.Add_Checked({
        $dataSourceGroupBox.Visibility = [System.Windows.Visibility]::Collapsed
        $discoveredInfrastructureGroupBox.Visibility = [System.Windows.Visibility]::Collapsed
        $domainRecoveryPanel.Visibility = [System.Windows.Visibility]::Collapsed
        $additionalClusterRecoveryPanel.Visibility = [System.Windows.Visibility]::Collapsed
        $global:additionalClusterRecoveryStepRows = Set-PlanStepsListBox $additionalClusterRecoveryStepsListBox @()
        $recoverFleetPanel.Visibility = [System.Windows.Visibility]::Visible

        $variablesItemsPanel.Children.Clear()
        $loadedVariablesTextBlock.Text = 'No variables loaded yet.'

        $recoverFleetSteps = Get-ApplicableSteps (Get-RecoveryPlanSteps 'fdr' 'fdr-failover-plan.json') @{}
        $global:recoverFleetStepRows = Set-PlanStepsListBox $recoverFleetStepsListBox $recoverFleetSteps
        $global:allSteps = @($recoverFleetSteps)

        $stepsVariablesGroupBox.Visibility = [System.Windows.Visibility]::Visible
        $stepsVariablesTabControl.SelectedIndex = 1   # "Steps"
    })

# Extracting a backup isn't a plan with steps to sequence -- it's one action, run immediately from
# Browse below (see Invoke-ExtractSDDCManagerBackup). Picking this radio just clears any stale
# Domain Recovery rows left over from a previously selected domain, the same "nothing to show yet"
# state a fresh launch starts in.
$extractRadio.Add_Checked({
        $global:domainRecoveryStepRows = Set-PlanStepsListBox $domainRecoveryStepsListBox @()
        $global:additionalClusterRecoveryStepRows = Set-PlanStepsListBox $additionalClusterRecoveryStepsListBox @()
        $variablesItemsPanel.Children.Clear()
        $loadedVariablesTextBlock.Text = 'No variables loaded yet.'
        $stepsVariablesGroupBox.Visibility = [System.Windows.Visibility]::Collapsed
        $global:domainRecoverySteps = @()
        $global:additionalClusterRecoverySteps = @()
        $global:allSteps = @()
        $global:derivedStepVariables = @{}
    })

# Prompts for the backup's credentials file and encryption password right here (rather than via
# the Variables tab -- there's no plan/Execution context for this action at all) and runs it
# immediately. Cancelling either prompt aborts without sending anything to the console.
function Invoke-ExtractSDDCManagerBackup([string]$BackupFilePath) {
    $credentialsDialog = New-Object Microsoft.Win32.OpenFileDialog
    $credentialsDialog.Filter = 'All files (*.*)|*.*'
    $credentialsDialog.Title = 'Select credentials file'
    if ($credentialsDialog.ShowDialog() -ne $true) {
        return
    }

    $encryptionPassword = Show-PasswordPromptDialog -Title 'Encryption Password' -Message 'Enter the backup encryption password:'
    if ($null -eq $encryptionPassword) {
        return
    }

    $escapedBackupFilePath = Protect-SingleQuotes $BackupFilePath
    $escapedCredentialsFilePath = Protect-SingleQuotes $credentialsDialog.FileName
    $escapedEncryptionPassword = Protect-SingleQuotes $encryptionPassword
    Send-ToConsole "New-ExtractDataFromSDDCBackup -vcfBackupFilePath '$escapedBackupFilePath' -encryptionPassword '$escapedEncryptionPassword' -credentialsFilePath '$escapedCredentialsFilePath'"

    # New-ExtractDataFromSDDCBackup always writes extracted-sddc-data.json next to the backup file
    # it read -- computed here rather than asked for, since it's fully determined by BackupFilePath.
    # Waiting for its own "Completed Task" line (the same signal Steps rows watch for) means this
    # loads the real output once extraction has actually finished, not a stale/nonexistent file the
    # moment the command is merely sent.
    $extractedDataFilePath = Join-Path (Split-Path -Path $BackupFilePath -Parent) 'extracted-sddc-data.json'
    Add-CompletionWatch -CmdletName 'New-ExtractDataFromSDDCBackup' -OnComplete {
        $filePathTextBox.Text = $extractedDataFilePath
        Import-ExtractedSddcDataFile $extractedDataFilePath
    }.GetNewClosure()
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
            Invoke-ExtractSDDCManagerBackup $dialog.FileName
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

        # Facts the extracted SDDC data already knows (isStretched, primaryDatastoreType -- see
        # Update-DerivedStepVariables/Sync-DomainSteps/Sync-AdditionalClusterSteps) fill in any of
        # these names the answer file doesn't already define -- an explicit value in the answer file
        # always wins, since that's an intentional operator override.
        foreach ($name in $global:derivedStepVariables.Keys) {
            if (-not $answerMap.Contains($name)) {
                $answerMap[$name] = [string]$global:derivedStepVariables[$name]
            }
        }

        $variablesItemsPanel.Children.Clear()

        if ($answerMap.Count -eq 0) {
            $loadedVariablesTextBlock.Text = "No variables found in '$Path'."
            return
        }

        $orderedNames = @(Get-ReferencedVariableNames (Get-StepReferenceText $global:allSteps) | Where-Object { $answerMap.Contains($_) })
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

        # Steps are only ever populated here or in New-VariablesFile -- selecting a domain/cluster
        # alone never puts Run buttons in front of anyone before values exist for them to use.
        # $answerMap doubles as the condition-evaluation context (see Test-StepCondition), so a step
        # gated on e.g. "$isStretched -eq 't'" is only shown once that value is actually known.
        Update-RevealedSteps $answerMap

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

# Starts from whatever variables the currently-loaded plan(s) actually reference -- the same
# Get-ReferencedVariableNames call Import-VariablesAnswersFile already uses to order its rows --
# rather than a specific template file, so it's always right for IBR (domain-specific) or FDR
# (Recover Fleet) alike without having to know which plan file(s) are behind it. The chosen file is
# created empty immediately (so it exists on disk right away, not only once something's typed) and
# rewritten in full every time a field loses focus -- no separate "Save" action to remember.
function New-VariablesFile([string]$Path) {
    $variableNames = @(Get-ReferencedVariableNames (Get-StepReferenceText $global:allSteps))
    if ($variableNames.Count -eq 0) {
        $statusTextBlock.Text = 'No steps are currently loaded, so there are no variables to create a file for.'
        return
    }

    # Facts the extracted SDDC data already knows (isStretched, primaryDatastoreType) start pre-filled
    # from $global:derivedStepVariables rather than blank -- same override precedence as
    # Import-VariablesAnswersFile: still an ordinary editable row, just not empty when there's no
    # real reason to make someone retype something already known.
    $values = [ordered]@{}
    foreach ($name in $variableNames) {
        $values[$name] = if ($global:derivedStepVariables.Contains($name)) { [string]$global:derivedStepVariables[$name] } else { '' }
    }
    $values | ConvertTo-Json | Set-Content -LiteralPath $Path -Encoding utf8

    $variablesItemsPanel.Children.Clear()
    foreach ($name in $variableNames) {
        $onValueChanged = {
            param($changedName, $changedValue)
            $values[$changedName] = $changedValue
            $values | ConvertTo-Json | Set-Content -LiteralPath $Path -Encoding utf8
            # Re-filters Steps by condition every time a field changes, not only once at creation --
            # a step gated on e.g. "$isStretched -eq 't'" starts pre-filled from extracted data when
            # known (see above), but should still react live if it's edited or was genuinely blank.
            Update-RevealedSteps $values
        }.GetNewClosure()
        [void]$variablesItemsPanel.Children.Add((New-VariableRow $name $values[$name] $onValueChanged))
    }

    $loadedVariablesTextBlock.Text = "Creating '$Path' -- values save automatically as you fill them in."
    $global:variablesAnswersFilePath = $Path

    # Reveals Steps in the background (see Update-RevealedSteps) even though every value here still
    # starts blank -- each field is already wired to push its value to the console the moment it's
    # filled in (New-VariableRow's LostFocus handler), the same mechanism Import-VariablesAnswersFile
    # uses, so this is the same "variables are now in play" moment for this flow too.
    Update-RevealedSteps $values

    # Stays on the Variables tab (unlike Import-VariablesAnswersFile, which switches to Steps) --
    # there's nothing to run yet here, only fields still waiting to be filled in.
    $stepsVariablesTabControl.SelectedIndex = 0
}

$newVariablesFileButton.Add_Click({
        # Checked here too, before showing a dialog only to fail right after picking a location --
        # New-VariablesFile also checks on its own, so it's still safe if ever called another way.
        if (@(Get-ReferencedVariableNames (Get-StepReferenceText $global:allSteps)).Count -eq 0) {
            $statusTextBlock.Text = 'No steps are currently loaded, so there are no variables to create a file for.'
            return
        }
        $dialog = New-Object Microsoft.Win32.SaveFileDialog
        $dialog.Filter = 'JSON files (*.json)|*.json|All files (*.*)|*.*'
        $dialog.Title = 'Save new variables file'
        $dialog.FileName = 'variables.json'
        if ($dialog.ShowDialog() -ne $true) {
            return
        }
        New-VariablesFile $dialog.FileName
    }.GetNewClosure())

# Shared by the domain SelectionChanged handler and by switching back to IBR from FDR (see the
# Recovery Type Checked handlers below) -- re-selecting the same domain doesn't refire
# SelectionChanged, so switching recovery type has to be able to re-derive Execution's state from
# whatever's currently selected on its own, not only react to an actual selection change.
# Recomputes $global:allSteps as the union of every currently-populated IBR Steps panel (Domain
# Recovery, Additional Cluster Recovery) -- these are two independent, mutually exclusive
# selections (a domain, or separately an additional cluster), so the Variables tab needs to see
# whichever one is currently populated.
function Update-AllSteps {
    $global:allSteps = @($global:domainRecoverySteps) + @($global:additionalClusterRecoverySteps)
}

# Recovery Tasks has to stay visible if EITHER a domain or an additional cluster is currently
# selected -- neither selection's own handler can safely collapse it just because it has nothing
# selected, since the other one might.
function Update-ExecutionVisibility {
    $hasDomainSelected = $null -ne $domainsListBox.SelectedItem
    $hasClusterSelected = $additionalClustersListBox.SelectedItem -is [System.Windows.Controls.ListBoxItem]
    $stepsVariablesGroupBox.Visibility = if ($hasDomainSelected -or $hasClusterSelected) { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
}

# Populates the Domain Recovery/Additional Cluster Recovery ListBoxes from whatever
# Sync-DomainSteps/Sync-AdditionalClusterSteps already resolved into $global:domainRecoverySteps
# etc, filtered by each step's own condition against $Variables -- called only once variables have
# actually been loaded or created (Import-VariablesAnswersFile/New-VariablesFile), never from
# selection alone. Selecting a domain or cluster still resolves which plan applies (so Variables can
# list the right names), but must not itself put Run buttons in front of anyone before values exist
# for them to use.
function Update-RevealedSteps([System.Collections.IDictionary]$Variables) {
    $global:domainRecoveryStepRows = Set-PlanStepsListBox $domainRecoveryStepsListBox (Get-ApplicableSteps $global:domainRecoverySteps $Variables)
    $global:additionalClusterRecoveryStepRows = Set-PlanStepsListBox $additionalClusterRecoveryStepsListBox (Get-ApplicableSteps $global:additionalClusterRecoverySteps $Variables)
}

function Sync-DomainSteps {
    $domainRecoveryStepsListBox.Items.Clear()
    $variablesItemsPanel.Children.Clear()
    $loadedVariablesTextBlock.Text = 'No variables loaded yet.'
    $global:domainRecoverySteps = @()

    $selected = $domainsListBox.SelectedItem
    if ($null -ne $selected) {
        # A domain and an additional cluster are mutually exclusive selections -- picking a domain
        # always deselects whichever additional cluster was picked before, which (via
        # Sync-AdditionalClusterSteps) collapses its panel so only the domain's own panel shows.
        if ($null -ne $additionalClustersListBox.SelectedItem) {
            $additionalClustersListBox.SelectedItem = $null
        }
        $domainRecoveryPanel.Visibility = [System.Windows.Visibility]::Visible

        # Same plan for both domain types -- only which file backs it changes. The former separate
        # "restore" and "recover default cluster" plans are concatenated into one combined plan per
        # domain type (management-domain-recovery-plan.json / workload-domain-recovery-plan.json),
        # since restoring components and then recovering the default cluster is always exactly one
        # sequence, never two independently-runnable ones.
        if ($selected.Tag.domainType -eq 'MANAGEMENT') {
            $global:domainRecoverySteps = Get-RecoveryPlanSteps 'ibr' 'management-domain-recovery-plan.json'
        } else {
            $global:domainRecoverySteps = Get-RecoveryPlanSteps 'ibr' 'workload-domain-recovery-plan.json'
        }

        # The default-cluster-recovery portion of the combined plan runs against the domain's
        # default cluster (isDefault 't'), not any of the "additional" ones -- see
        # Sync-AdditionalClusterSteps for the other half of this same mechanism.
        $defaultCluster = $selected.Tag.vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' } | Select-Object -First 1
        $global:derivedStepVariables = @{
            isStretched          = [string]$defaultCluster.isStretched
            primaryDatastoreType = [string]$defaultCluster.primaryDatastoreType
        }
    } else {
        $domainRecoveryPanel.Visibility = [System.Windows.Visibility]::Collapsed
        $global:derivedStepVariables = @{}
    }

    # Deliberately not populated here -- Update-RevealedSteps does that, only once variables have
    # actually been loaded or created for this selection (see its own comment). The ListBox was
    # already cleared above, so a domain change with no variables loaded yet leaves Steps empty.
    $global:domainRecoveryStepRows = @()
    Update-AllSteps
    Update-ExecutionVisibility
}

$domainsListBox.Add_SelectionChanged({
        try {
            Sync-DomainSteps
        } catch {
            $statusTextBlock.Text = "Domain selection handler failed: $($_.Exception.Message)"
        }
    }.GetNewClosure())

# Mutually exclusive with a domain selection above -- picking a real additional cluster always
# deselects whichever domain was picked before, which (via Sync-DomainSteps) collapses its panel so
# only Recover Additional Cluster shows. The "No additional clusters detected." placeholder row (a
# plain string, not a ListBoxItem -- see Import-ExtractedSddcDataFile) is deliberately not treated
# as a real selection here.
function Sync-AdditionalClusterSteps {
    $additionalClusterRecoveryStepsListBox.Items.Clear()
    $variablesItemsPanel.Children.Clear()
    $loadedVariablesTextBlock.Text = 'No variables loaded yet.'
    $global:additionalClusterRecoverySteps = @()

    $selected = $additionalClustersListBox.SelectedItem
    $isRealClusterSelected = $selected -is [System.Windows.Controls.ListBoxItem]
    if ($isRealClusterSelected) {
        if ($null -ne $domainsListBox.SelectedItem) {
            $domainsListBox.SelectedItem = $null
        }
        $additionalClusterRecoveryPanel.Visibility = [System.Windows.Visibility]::Visible
        $global:additionalClusterRecoverySteps = Get-RecoveryPlanSteps 'ibr' 'additional-cluster-recovery-plan.json'
        # See the matching comment in Sync-DomainSteps -- $selected.Tag here is the cluster
        # PSCustomObject built in Import-ExtractedSddcDataFile, not a raw domain object, so no
        # isDefault lookup is needed: this row already IS the one cluster in question.
        $global:derivedStepVariables = @{
            isStretched          = [string]$selected.Tag.IsStretched
            primaryDatastoreType = [string]$selected.Tag.PrimaryDatastoreType
        }
    } else {
        $additionalClusterRecoveryPanel.Visibility = [System.Windows.Visibility]::Collapsed
        $global:derivedStepVariables = @{}
    }

    # Deliberately not populated here -- see the matching comment in Sync-DomainSteps.
    $global:additionalClusterRecoveryStepRows = @()
    Update-AllSteps
    Update-ExecutionVisibility
}

$additionalClustersListBox.Add_SelectionChanged({
        try {
            Sync-AdditionalClusterSteps
        } catch {
            $statusTextBlock.Text = "Additional cluster selection handler failed: $($_.Exception.Message)"
        }
    }.GetNewClosure())

$runAllDomainRecoveryButton.Add_Click({
        try {
            Invoke-StepChain $global:domainRecoveryStepRows -IgnoreGrouping:(-not $runAllDomainRecoveryParallelCheckBox.IsChecked)
        } catch {
            $statusTextBlock.Text = "Run All failed: $($_.Exception.Message)"
        }
    }.GetNewClosure())

$runAllAdditionalClusterRecoveryButton.Add_Click({
        try {
            Invoke-StepChain $global:additionalClusterRecoveryStepRows -IgnoreGrouping:(-not $runAllAdditionalClusterRecoveryParallelCheckBox.IsChecked)
        } catch {
            $statusTextBlock.Text = "Run All failed: $($_.Exception.Message)"
        }
    }.GetNewClosure())

$runAllRecoverFleetButton.Add_Click({
        try {
            Invoke-StepChain $global:recoverFleetStepRows -IgnoreGrouping:(-not $runAllRecoverFleetParallelCheckBox.IsChecked)
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
            $allRows = @($global:domainRecoveryStepRows) + @($global:additionalClusterRecoveryStepRows) + @($global:recoverFleetStepRows)
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

            # Every console has its own transcript running, not just Main -- any parallel consoles
            # spawned by a Run All group need Stop-Transcript too, or their log stays unflushed/open.
            foreach ($console in (@($global:mainConsole) + @($global:parallelConsoles))) {
                Send-ToConsole 'Stop-Transcript | Out-Null' $console
            }
            # Give Stop-Transcript a moment to actually run inside each console process before they get
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
            $allRows = @($global:domainRecoveryStepRows) + @($global:additionalClusterRecoveryStepRows) + @($global:recoverFleetStepRows)
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

Start-StepCompletionWatcher

[void]$app.Run($window)
