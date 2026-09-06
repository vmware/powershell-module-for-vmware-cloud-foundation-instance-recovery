# Builds and runs the VCF IBR Orchestrator window. Launched by Start-VCFIBROrchestrator (in the
# module's .psm1) as its own detached pwsh.exe process -- not a runspace inside that process -- so
# that WPF's one-Application-per-process limit never gets in the way of relaunching: each run of
# this script gets a completely fresh CLR and WPF runtime, so closing the window and running
# Start-VCFIBROrchestrator again always starts over cleanly, with no shared state to worry about.
#
# Self-contained: has no dependency on the module's own functions (e.g. LogMessage) -- only .NET/WPF
# and the vendored terminal control, since a separate process wouldn't have the module imported
# anyway.
param(
    [string]$XamlPath,
    [string]$LibPath,
    [string]$WorkingDirectory
)

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml

# Prepend the vendored folder to the native search path -- EasyWindowsTerminalControl wraps native
# C++/DirectX rendering components that need to resolve alongside its managed assembly.
$env:PATH = "$LibPath;$env:PATH"
Get-ChildItem -Path $LibPath -Filter '*.dll' | ForEach-Object {
    try {
        Add-Type -Path $_.FullName -ErrorAction Stop
    } catch {
        Write-Warning "Failed to load $($_.FullName): $($_.Exception.Message)"
    }
}

# EasyWindowsTerminalControl's native rendering/ConPTY session appears to need
# Application.Current to already exist by the time the control is constructed -- a normal
# compiled WPF app's generated Main() always does "new Application(); app.Run();" before its
# StartupUri window (and therefore any control inside it) is ever built. XamlReader.Load()
# below constructs the Term control immediately, so the Application must be created first.
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
$term = $window.FindName('Term')

# EasyTerminalControl.FontSizeWhenSettingTheme is a no-op by itself -- it's only ever read inside
# SetTheme(), which the control skips entirely whenever its Theme property is null (the default,
# since XAML never sets one). So the font size must be applied together with an explicit Theme;
# otherwise the "smaller font" request silently does nothing. Colors below are the standard
# Windows Terminal "Campbell" default scheme, matching what the control already renders without a
# Theme, so this changes only the font size, not the look.
$campbellColors = @(
    '#0C0C0C', '#C50F1F', '#13A10E', '#C19C00', '#0037DA', '#881798', '#3A96DD', '#CCCCCC',
    '#767676', '#E74856', '#16C60C', '#F9F1A5', '#3B78FF', '#B4009E', '#61D6D6', '#F2F2F2'
)
$toColorVal = { param([string]$Hex) [EasyWindowsTerminalControl.EasyTerminalControl]::ColorToVal([System.Windows.Media.ColorConverter]::ConvertFromString($Hex)) }
$terminalTheme = New-Object Microsoft.Terminal.Wpf.TerminalTheme
$terminalTheme.DefaultBackground = & $toColorVal '#0C0C0C'
$terminalTheme.DefaultForeground = & $toColorVal '#CCCCCC'
$terminalTheme.DefaultSelectionBackground = & $toColorVal '#FFFFFF'
$terminalTheme.ColorTable = [uint32[]]($campbellColors | ForEach-Object { & $toColorVal $_ })
$term.FontSizeWhenSettingTheme = 11
$term.Theme = $terminalTheme

# Populated once a domain is selected (see the SelectionChanged handler below); initialized here
# so Run All never sees $null before that happens.
$global:managementDomainRestoresStepRows = @()
$global:recoverDefaultClusterStepRows = @()
# Path to the last-loaded variable answers file, if any -- tracked separately from the textbox-less
# Load Variables flow so Exit can record it, and Resume can pass it straight back to the same loader.
$global:variablesAnswersFilePath = $null

# Completion tracking, attempt 5: a PowerShell transcript of the embedded console, read from disk.
# This is fully decoupled from the terminal control itself -- no event subscription (confirmed to
# collide with the control's own rendering), no reading the control's rendered text back. Just a
# plain text file that PowerShell itself appends to, and a plain file read on a timer.
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

# Set here, not in the XAML, since it needs to embed values computed above/passed in (the launch
# directory, the per-launch transcript path). The Set-Location, PSReadLine prediction fix, and
# Start-Transcript all run as part of the console's own process startup (-Command), before the
# interactive session ever begins -- so none of them are ever "typed" into the visible console, the
# way sending them afterward via WriteToTerm would be. Start-Transcript's own confirmation output is
# piped to Out-Null so launching it leaves no trace in the console at all.
$escapedWorkingDirectory = Protect-SingleQuotes $WorkingDirectory
$escapedTranscriptPath = Protect-SingleQuotes $global:transcriptPath
$term.StartupCommandLine = "pwsh.exe -NoLogo -NoExit -Command `"Set-Location -LiteralPath '$escapedWorkingDirectory'; Remove-Module PSReadLine -Force -ErrorAction SilentlyContinue; Start-Transcript -Path '$escapedTranscriptPath' -Force | Out-Null`""

function Send-ToConsole([string]$CommandLine) {
    if ($null -eq $term.ConPTYTerm) {
        $statusTextBlock.Text = "Console isn't ready yet (ConPTYTerm is null) -- try again in a moment."
        return
    }
    try {
        $term.ConPTYTerm.WriteToTerm("$CommandLine`r")
    } catch {
        $statusTextBlock.Text = "WriteToTerm failed: $($_.Exception.Message)"
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

function Start-TerminalReadyWatcher {
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(200)
    $script:terminalReadyAttempts = 0
    $timer.Add_Tick({
        # $this, not $timer -- by the time this fires, Start-TerminalReadyWatcher has already
        # returned, so its local $timer variable is out of scope and resolves to $null here.
        # $this is bound to the DispatcherTimer instance automatically by Add_Tick.
        #
        # No command is sent to the console once it's ready: the module is installed on
        # $env:PSModulePath, so PowerShell auto-loads it the first time a Step's cmdlet actually
        # runs -- an explicit Import-Module here would just be a redundant, race-prone extra step.
        # (The transcript now starts as part of the console's own process startup command line, not
        # here -- see where $term.StartupCommandLine is set, above.)
        #
        # Gating on ConPTYTerm alone would not be enough to safely WriteToTerm here if this branch
        # ever needs to send something in the future: ConPTYTerm is non-null from the moment the
        # control is constructed, well before the real child process has actually started -- calling
        # WriteToTerm that early throws internally ("Object reference not set..."). TermProcIsStarted
        # only becomes true once the process has actually started.
        $script:terminalReadyAttempts++
        if ($null -ne $term.ConPTYTerm -and $term.ConPTYTerm.TermProcIsStarted) {
            $this.Stop()
        } elseif ($script:terminalReadyAttempts -gt 50) {
            $this.Stop()
            $statusTextBlock.Text = 'Embedded console did not start in time.'
        }
    })
    $timer.Start()
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
        # Give Stop-Transcript a moment to actually run inside the console's own process before this
        # window (and the console with it) is hidden -- WriteToTerm only queues keystrokes, it doesn't
        # wait for them to be processed.
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

Start-TerminalReadyWatcher
Start-StepCompletionWatcher

[void]$app.Run($window)
