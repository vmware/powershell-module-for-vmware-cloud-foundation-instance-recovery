# Cross-platform (Windows / macOS / Linux) front end for the VCF Recovery Coordinator -- SPIKE.
#
# A single-threaded localhost web server (System.Net.HttpListener) that serves webui\index.html and a
# small JSON + WebSocket API over the SAME plan catalog / plan files the WPF UI
# (xaml\VCFRecoveryCoordinatorUI.ps1) uses. Nothing here touches WPF or Win32 UI APIs.
#
# Same model as the WPF UI, minus the Win32 window reparenting:
#   * A "console" is a long-lived, ordinary interactive pwsh running on a real pseudo-terminal
#     (ConPTY on Windows, script(1) on macOS/Linux), shown in the page with xterm.js. You type into it
#     directly; Run buttons type a step's command line into it for you.
#   * Step completion is detected by watching the console's transcript for "Completed Task <cmdlet>"
#     and applying the same cleanliness gate (Test-StepTranscriptClean), exactly like the WPF UI.
#   * Run All uses one console per threadId, like the WPF UI.
#
# Security model: the server types commands taken from plan files into a shell, so it is locked down --
# loopback only, a random per-launch token on every API/WebSocket request, Host/Origin checks
# (DNS-rebinding and cross-site protection), and /api/step/run only accepts a plan id + step index
# (never a command line). Only the browser tab holding the token can type into a console.
param(
    [Parameter(Mandatory)][string]$PlansPath,
    [Parameter(Mandatory)][string]$Token,
    [int]$Port = 0,
    [string]$WorkingDirectory = (Get-Location).Path,
    # Module files the consoles import (the dev repo is usually not on PSModulePath).
    [string]$CoordinatorModulePath,
    [string]$InstanceRecoveryModulePath
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- state
$script:htmlPath = Join-Path $PSScriptRoot 'index.html'
$script:vendorPath = Join-Path $PSScriptRoot 'vendor'
$script:vendorFiles = @{ 'xterm.js' = 'text/javascript; charset=utf-8'; 'xterm.css' = 'text/css; charset=utf-8'; 'addon-fit.js' = 'text/javascript; charset=utf-8' }
$script:catalog = Get-Content -LiteralPath (Join-Path $PlansPath 'recovery-plan-catalog.json') -Raw | ConvertFrom-Json
$script:vars = [ordered]@{}            # name -> string value, shared by every console
$script:consoles = [ordered]@{}        # id -> console session
$script:consoleSeq = 0
$script:watches = @{}                  # watchId -> step watch
$script:watchSeq = 0
$script:stepLedger = @{}               # step id -> Success | Failed | Skipped (feeds "stepStatus" conditions)
$script:wsClients = [System.Collections.Generic.List[object]]::new()
$script:pendingAccepts = [System.Collections.Generic.List[object]]::new()
$script:shutdown = $false
$script:extracted = $null              # parsed extracted-sddc-data.json
$script:extractedPath = ''
$script:allDomains = @()
$script:selection = $null              # @{ kind = 'domain'|'cluster'; domain; cluster }
$script:conditionContext = @{}         # what "dataPath" step conditions resolve against (selectedDomain / selectedCluster)
$script:varsFilePath = ''
$script:uiMode = 'User'
$script:engineeringUnlocked = $false
# Variables the operator never types: they come from the Data Source / the infrastructure selection (as in the
# WPF UI, where an answers file's values for them are ignored so a stale file can't retarget a run).
$script:readonlyVariables = @('extractedSDDCDataFile', 'workloadDomain', 'clusterName')
$script:pwshPath = (Get-Process -Id $PID).Path
$script:ignoredVariableNames = @('true', 'false', 'null', '_', 'env', 'PSScriptRoot', 'PSItem', 'args', 'input')
$script:defaultCols = 120
$script:defaultRows = 30

if ($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop') {
    Add-Type -Path (Join-Path $PSScriptRoot 'ConPty.cs')
}

# ---------------------------------------------------------------- plan / condition logic
# (Ported from the WPF script: Get-RecoveryPlanSteps, Test-ConditionOperator, Test-StepCondition,
#  Test-StepStatusGate. dataPath conditions need the extracted-data context the WPF UI builds; not
#  ported yet, so they fail open exactly like the WPF code does for anything it can't evaluate.)
function Get-CatalogEntry([string]$PlanId) {
    return $script:catalog.recoveryPlans | Where-Object { $_.id -eq $PlanId } | Select-Object -First 1
}

function Get-PlanSteps($Entry) {
    $path = Join-Path (Join-Path $PlansPath $Entry.planFolder) $Entry.planFile
    if (-not (Test-Path -LiteralPath $path)) { return @() }
    $index = 0
    $steps = foreach ($raw in @(Get-Content -LiteralPath $path -Raw | ConvertFrom-Json)) {
        $visible = if ($raw.PSObject.Properties.Name -contains 'visible') { [bool]$raw.visible } else { $true }
        [PSCustomObject]@{
            Index       = $index++
            Id          = if ($raw.id) { [string]$raw.id } else { '' }
            DisplayName = if ($raw.displayName) { [string]$raw.displayName } else { ([string]$raw.commandLine -split '\s+', 2)[0] }
            Description = [string]$raw.description
            CommandLine = [string]$raw.commandLine
            Condition   = @($raw.condition)
            ThreadId    = [string]$raw.threadId
            Interactive = [bool]$raw.interactive
            Visible     = $visible
        }
    }
    return @($steps)
}

function Test-ConditionOperator([string]$Operator, $Actual, $Expected) {
    switch ($Operator) {
        'eq' { return [string]$Actual -eq [string]$Expected }
        'ne' { return [string]$Actual -ne [string]$Expected }
        'in' { return @($Expected) -contains $Actual }
        'notIn' { return -not (@($Expected) -contains $Actual) }
        'exists' { return -not [string]::IsNullOrEmpty($Actual) }
        'notExists' { return [string]::IsNullOrEmpty($Actual) }
        'match' { return $Actual -match $Expected }
        default { return $true }
    }
}

function Resolve-ConditionDataPath([string]$Path, $Root) {
    $current = $Root
    foreach ($segment in ($Path -split '\.')) {
        if ($null -eq $current) { return $null }
        $current = if ($current -is [System.Collections.IDictionary]) { $current[$segment] } else { $current.$segment }
    }
    return $current
}

function Test-StepApplicable($Step) {
    foreach ($c in $Step.Condition) {
        if ($null -eq $c -or $c -is [string]) { continue }
        try {
            if ($c.type -eq 'variable') {
                $actual = if ($script:vars.Contains($c.name)) { $script:vars[$c.name] } else { $null }
                if (-not (Test-ConditionOperator $c.operator $actual $c.value)) { return $false }
            } elseif ($c.type -eq 'dataPath') {
                # An explicit value typed into a variable named like the path's last segment wins over the data.
                $leaf = ($c.path -split '\.')[-1]
                $override = if ($script:vars.Contains($leaf)) { $script:vars[$leaf] } else { $null }
                $actual = if (-not [string]::IsNullOrEmpty($override)) { $override } else { Resolve-ConditionDataPath $c.path $script:conditionContext }
                if (-not (Test-ConditionOperator $c.operator $actual $c.value)) { return $false }
            }
        } catch { }   # fail open, as the WPF UI does
    }
    return $true
}

# Execution-time gate only (never used for display filtering) -- see Test-StepStatusGate in the WPF UI.
function Test-StepStatusGate($Step) {
    foreach ($c in $Step.Condition) {
        if ($null -ne $c -and $c -isnot [string] -and $c.type -eq 'stepStatus') {
            $actual = if ($script:stepLedger.ContainsKey($c.stepId)) { $script:stepLedger[$c.stepId] } else { 'NotRun' }
            if (-not (Test-ConditionOperator $c.operator $actual $c.value)) { return $false }
        }
    }
    return $true
}

function Get-ReferencedVariableNames([string[]]$CommandLines) {
    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($commandLine in $CommandLines) {
        foreach ($m in [regex]::Matches($commandLine, '\$([A-Za-z_][A-Za-z0-9_]*)')) {
            $n = $m.Groups[1].Value
            if ($n -notin $script:ignoredVariableNames -and -not $names.Contains($n)) { [void]$names.Add($n) }
        }
    }
    return , $names
}

function Import-VariablesTemplate($Entry) {
    # Seed (never overwrite) the shared variable store with the plan's template keys.
    if (-not $Entry.variablesFile) { return }
    $path = Join-Path (Join-Path $PlansPath $Entry.planFolder) $Entry.variablesFile
    if (-not (Test-Path -LiteralPath $path)) { return }
    $template = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -AsHashtable
    foreach ($k in $template.Keys) {
        if (-not $script:vars.Contains($k)) { $script:vars[$k] = if ($null -eq $template[$k]) { '' } else { [string]$template[$k] } }
    }
}

function Get-PlanPayload([string]$PlanId) {
    $entry = Get-CatalogEntry $PlanId
    if (-not $entry) { throw "Unknown plan '$PlanId'" }
    Import-VariablesTemplate $entry
    $steps = @(Get-PlanSteps $entry | Where-Object { $_.Visible })
    $names = Get-ReferencedVariableNames @($steps.CommandLine)
    return @{
        plan      = $entry
        steps     = @($steps | ForEach-Object {
                @{ index = $_.Index; id = $_.Id; name = $_.DisplayName; description = $_.Description; commandLine = $_.CommandLine
                    threadId = $_.ThreadId; interactive = $_.Interactive; applicable = (Test-StepApplicable $_) }
            })
        variables = @($names | ForEach-Object {
                @{ name = $_; value = $(if ($script:vars.Contains($_)) { $script:vars[$_] } else { '' }); secret = ($_ -match 'password|passphrase'); readonly = ($_ -in $script:readonlyVariables) }
            })
        mode      = $script:uiMode
        infrastructure = (Get-InfrastructurePayload $entry)
        varsFile  = $script:varsFilePath
    }
}

# ---------------------------------------------------------------- extracted data / infrastructure / selection
# (Ported from the WPF UI: Import-ExtractedSddcDataFile, Get-ClusterDependencies, Get-DisplayDatastoreType,
#  Sync-DomainSteps, Sync-AdditionalClusterSteps.)
function Get-DisplayDatastoreType([string]$RawType) {
    switch ($RawType) {
        'VSAN' { 'HCI (OSA)' }
        'VSAN_ESA' { 'HCI (ESA)' }
        'VSAN_MAX' { 'Storage Cluster' }
        'VSAN_Remote' { 'Compute Cluster' }
        default { $RawType }
    }
}

# What has to be recovered before this additional cluster, in recovery order (informational).
function Get-ClusterDependencies($Domain, $Cluster, [object[]]$AllDomains) {
    $dependencies = [System.Collections.Generic.List[string]]::new()
    $managementDomain = $AllDomains | Where-Object { $_.domainType -eq 'MANAGEMENT' } | Select-Object -First 1
    if ($Domain.domainType -eq 'MANAGEMENT') {
        if ($Domain.domainName) { $dependencies.Add($Domain.domainName) }
    } else {
        if ($managementDomain.domainName) { $dependencies.Add($managementDomain.domainName) }
        if ($Domain.domainName) { $dependencies.Add($Domain.domainName) }
    }
    if ($Cluster.primaryDatastoreType -eq 'VSAN_Remote' -and $Cluster.primaryDatastoreMoRef) {
        # A compute cluster (HCI Mesh consumer) depends on whichever non-remote cluster provides the same datastore.
        $storageCluster = @(
            foreach ($otherDomain in $AllDomains) {
                foreach ($otherCluster in $otherDomain.vsphereClusterDetails) {
                    if ($otherCluster.primaryDatastoreMoRef -eq $Cluster.primaryDatastoreMoRef -and $otherCluster.primaryDatastoreType -ne 'VSAN_Remote') { $otherCluster }
                }
            }
        ) | Select-Object -First 1
        if ($storageCluster.name) { $dependencies.Add($storageCluster.name) }
    }
    return ($dependencies -join ', ')
}

function Import-ExtractedData([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'No file path was entered.' }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "File not found on the machine running this server: $Path" }
    $data = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if (-not $data.workloadDomains) { throw "No 'workloadDomains' property found in the selected file." }
    $script:extracted = $data
    $script:extractedPath = $Path
    $script:allDomains = @($data.workloadDomains)
    $script:selection = $null
    $script:conditionContext = @{}
    $script:stepLedger = @{}
    $script:vars['extractedSDDCDataFile'] = $Path
    $script:vars['workloadDomain'] = ''
    $script:vars['clusterName'] = ''
}

function Get-InfrastructurePayload($Entry) {
    if (-not $script:extracted) { return @{ loaded = $false } }
    $filter = if ($Entry) { [string]$Entry.domainFilter } else { '' }
    $domains = @($script:allDomains | Where-Object {
            if ($filter -eq 'MANAGEMENT') { $_.domainType -eq 'MANAGEMENT' }
            elseif ($filter -eq 'NOT_MANAGEMENT') { $_.domainType -ne 'MANAGEMENT' }
            else { $true }
        } | ForEach-Object { @{ name = $_.domainName; type = $_.domainType } })
    $clusters = @(
        foreach ($domain in $script:allDomains) {
            foreach ($cluster in $domain.vsphereClusterDetails) {
                if ($cluster.isDefault -eq 'f') {
                    @{
                        name        = $(if ($cluster.name) { $cluster.name } else { '(unknown)' })
                        domain      = $domain.domainName
                        storage     = (Get-DisplayDatastoreType $cluster.primaryDatastoreType)
                        stretched   = $(if ($cluster.isStretched -eq 't') { 'Y' } else { 'N' })
                        dependentOn = (Get-ClusterDependencies $domain $cluster $script:allDomains)
                    }
                }
            }
        }
    )
    return @{
        loaded              = $true
        file                = $script:extractedPath
        runsFleetComponents = (@($script:extracted.vcfManagementComponents.ComponentType) -contains 'FLEET_LCM')
        domains             = $domains
        clusters            = $clusters
        selection           = $script:selection
    }
}

# Selecting a domain targets its default cluster; selecting an additional cluster targets that cluster in its own
# domain. Either way $workloadDomain/$clusterName are set from the selection (never typed), step status resets,
# and "dataPath" conditions resolve against the normalized shape below.
function Set-InfrastructureSelection([string]$Kind, [string]$DomainName, [string]$ClusterName) {
    $script:stepLedger = @{}
    $script:selection = $null
    $script:conditionContext = @{}
    $script:vars['workloadDomain'] = ''
    $script:vars['clusterName'] = ''
    $domain = $script:allDomains | Where-Object { $_.domainName -eq $DomainName } | Select-Object -First 1
    if (-not $domain -or $Kind -notin 'domain', 'cluster') { return }
    if ($Kind -eq 'domain') {
        $cluster = $domain.vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' } | Select-Object -First 1
        $script:conditionContext = @{
            selectedDomain  = $domain
            selectedCluster = [PSCustomObject]@{ name = $cluster.name; isDefault = $cluster.isDefault; isStretched = $cluster.isStretched; primaryDatastoreType = $cluster.primaryDatastoreType; domainName = $domain.domainName }
        }
        $script:selection = @{ kind = 'domain'; domain = $domain.domainName }
    } else {
        $cluster = $domain.vsphereClusterDetails | Where-Object { $_.name -eq $ClusterName } | Select-Object -First 1
        if (-not $cluster) { return }
        $script:conditionContext = @{
            selectedDomain  = $null
            selectedCluster = [PSCustomObject]@{ name = $cluster.name; isDefault = 'f'; isStretched = $cluster.isStretched; primaryDatastoreType = $cluster.primaryDatastoreType; domainName = $domain.domainName }
        }
        $script:selection = @{ kind = 'cluster'; domain = $domain.domainName; cluster = $cluster.name }
    }
    $script:vars['workloadDomain'] = [string]$domain.domainName
    $script:vars['clusterName'] = [string]$cluster.name
}

function Import-VariablesFile([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'No file path was entered.' }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "File not found on the machine running this server: $Path" }
    $file = (Resolve-Path -LiteralPath $Path).Path
    $loaded = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json -AsHashtable
    foreach ($k in $loaded.Keys) {
        $v = $loaded[$k]
        # Scalars only (string/number/bool/null); nested objects aren't variables. Selection/Data-Source-driven names are ignored.
        if ($k -match '^[A-Za-z_][A-Za-z0-9_]*$' -and $k -notin $script:readonlyVariables -and ($null -eq $v -or $v -is [string] -or $v -is [ValueType])) {
            $script:vars[$k] = if ($null -eq $v) { '' } else { [string]$v }
        }
    }
    $script:varsFilePath = $file
    return @{ file = $file; count = $loaded.Count }
}

# Same obfuscated check as the WPF UI (Test-EngineeringModePassword) -- a speed bump against accidents, not security.
function Test-EngineeringModePassword([string]$Candidate) {
    $expected = -join ((116, 104, 105, 115, 105, 115, 117, 110, 115, 97, 102, 101) | ForEach-Object { [char]$_ })
    return $Candidate -ceq $expected
}

# ---------------------------------------------------------------- folder listing (the in-page Browse dialog)
# A browser can't give a web page a file's full path, and the native OS dialogs proved unreliable to drive from here
# (focus, screen grabbing, permission prompts). So the page has its own file browser, backed by this listing. Plain .NET
# calls only, so it behaves the same on Windows, macOS and Linux. It returns names, sizes and dates -- never file
# contents -- for folders the server's own account can already read, behind the same token as everything else.
function Get-BrowseRoots {
    $home_ = [Environment]::GetFolderPath('UserProfile')
    $roots = [System.Collections.Generic.List[object]]::new()
    $roots.Add(@{ name = 'Launch folder'; path = $WorkingDirectory })
    if ($home_) { $roots.Add(@{ name = 'Home'; path = $home_ }) }
    foreach ($n in 'Desktop', 'Documents', 'Downloads') {
        $p = if ($home_) { Join-Path $home_ $n }
        if ($p -and (Test-Path -LiteralPath $p -PathType Container)) { $roots.Add(@{ name = $n; path = $p }) }
    }
    if ($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop') {
        foreach ($d in [IO.DriveInfo]::GetDrives()) { if ($d.IsReady) { $roots.Add(@{ name = $d.Name; path = $d.Name }) } }
    } else {
        $roots.Add(@{ name = '/'; path = '/' })
        foreach ($m in '/Volumes', '/mnt', '/media') { if (Test-Path -LiteralPath $m -PathType Container) { $roots.Add(@{ name = $m; path = $m }) } }
    }
    return , $roots.ToArray()
}

function Get-DirectoryListing([string]$Path, [string]$Filter, [bool]$ShowHidden) {
    # The browser always opens in the launch (working) directory -- where the transcripts, state files and the files
    # a recovery produces live -- rather than remembering wherever it was last left or defaulting to the home folder.
    if ([string]::IsNullOrWhiteSpace($Path)) { $Path = $WorkingDirectory }
    $full = [IO.Path]::GetFullPath($Path)
    $selected = $null
    if (Test-Path -LiteralPath $full -PathType Leaf) {        # a file path was typed: list its folder and report the file
        $selected = $full
        $full = [IO.Path]::GetDirectoryName($full)
    }
    if (-not (Test-Path -LiteralPath $full -PathType Container)) { throw "Folder not found: $full" }
    $parentInfo = [IO.Directory]::GetParent($full)
    $result = @{ path = $full; parent = $(if ($parentInfo) { $parentInfo.FullName } else { $null }); roots = (Get-BrowseRoots); selected = $selected }
    try { $items = @(Get-ChildItem -LiteralPath $full -Force -ErrorAction Stop) }
    catch { $result.entries = @(); $result.error = "Cannot read this folder: $($_.Exception.Message)"; return $result }
    $onWindows = $IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop'
    $entries = foreach ($item in $items) {
        $hidden = if ($onWindows) { [bool]($item.Attributes -band [IO.FileAttributes]::Hidden) } else { $item.Name.StartsWith('.') }
        if ($hidden -and -not $ShowHidden) { continue }
        $isDir = [bool]$item.PSIsContainer
        if (-not $isDir -and $Filter -eq 'json' -and $item.Extension -ne '.json') { continue }
        @{ name = $item.Name; path = $item.FullName; dir = $isDir; size = $(if ($isDir) { $null } else { $item.Length }); modified = $item.LastWriteTime.ToString('s') }
    }
    $sorted = @($entries | Sort-Object -Property @{ Expression = { -not $_.dir } }, @{ Expression = { $_.name.ToLowerInvariant() } })
    $result.truncated = $sorted.Count -gt 2000
    $result.entries = @($sorted | Select-Object -First 2000)
    return $result
}

# ---------------------------------------------------------------- PTY
function Protect-SingleQuotes([string]$Value) { return $Value.Replace("'", "''") }

# Returns @{ Input; Output; IsExited; Kill; Resize } for one interactive pwsh on a real pseudo-terminal.
function New-PtyProcess([string]$StartupScript, [int]$Cols, [int]$Rows) {
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($StartupScript))

    if ($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop') {
        $pty = [VCFIR.ConPty]::new("`"$script:pwshPath`" -NoLogo -NoProfile -EncodedCommand $encoded", $WorkingDirectory, $Cols, $Rows)
        return @{
            Input    = $pty.Input
            Output   = $pty.Output
            IsExited = { $pty.HasExited }.GetNewClosure()
            Kill     = { $pty.Dispose() }.GetNewClosure()
            Resize   = { param($c, $r) $pty.Resize($c, $r) }.GetNewClosure()
        }
    }

    # macOS / Linux: script(1) allocates the pty and runs a tiny sh wrapper that records the tty's
    # device name (so we can resize it later with stty) and sets the initial size before exec'ing pwsh.
    $scriptExe = (Get-Command script -ErrorAction Stop).Source
    $ttyFile = Join-Path ([IO.Path]::GetTempPath()) ("vcfir-tty-{0}-{1}" -f $PID, [guid]::NewGuid().ToString('N'))
    $pwshQuoted = "'" + $script:pwshPath.Replace("'", "'\''") + "'"
    $inner = "tty > '$ttyFile'; stty rows $Rows cols $Cols; exec $pwshQuoted -NoLogo -NoProfile -EncodedCommand $encoded"
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $scriptExe
    $argList = if ($IsMacOS) { @('-q', '/dev/null', '/bin/sh', '-c', $inner) } else { @('-qfec', $inner, '/dev/null') }
    foreach ($a in $argList) { $psi.ArgumentList.Add($a) }
    $psi.WorkingDirectory = $WorkingDirectory
    $psi.Environment['TERM'] = 'xterm-256color'
    $psi.Environment['COLORTERM'] = 'truecolor'
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::Start($psi)
    $sttyFlag = if ($IsMacOS) { '-f' } else { '-F' }
    return @{
        Input    = $process.StandardInput.BaseStream
        Output   = $process.StandardOutput.BaseStream
        IsExited = { $process.HasExited }.GetNewClosure()
        Kill     = { try { $process.Kill($true) } catch { }; Remove-Item -LiteralPath $ttyFile -Force -ErrorAction SilentlyContinue }.GetNewClosure()
        Resize   = {
            param($c, $r)
            $tty = if (Test-Path -LiteralPath $ttyFile) { (Get-Content -LiteralPath $ttyFile -TotalCount 1) } else { $null }
            if ($tty) { & stty $sttyFlag $tty rows $r cols $c 2>$null }
        }.GetNewClosure()
    }
}

# ---------------------------------------------------------------- consoles
function New-ConsoleSession([string]$Id, [string]$Label) {
    $script:consoleSeq++
    $transcript = Join-Path $WorkingDirectory ("vcfir-web-transcript-{0}-{1}-{2}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'), $PID, $script:consoleSeq)
    # Step commands (and the variables they need, which may be secrets) reach the console through this private
    # directory, never through its stdin -- see console-repl.ps1 for why.
    $queueDir = Join-Path ([IO.Path]::GetTempPath()) ("vcfir-q-{0}" -f [guid]::NewGuid().ToString('N'))
    if ($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop') { [void][IO.Directory]::CreateDirectory($queueDir) }
    else { [void][IO.Directory]::CreateDirectory($queueDir, [IO.UnixFileMode]'UserRead,UserWrite,UserExecute') }
    # Each step announces itself BEFORE it starts, so a blank console is never ambiguous: no text at all means the
    # pseudo-terminal output isn't reaching the page; "Loading ..." with nothing after it means a module import is slow
    # (importing InstanceRecovery pulls in PowerCLI and others, which can take a long time on a cold start).
    $startup = @(
        "[Console]::WriteLine('Starting console...')"
        "Set-Location -LiteralPath '$(Protect-SingleQuotes $WorkingDirectory)'"
        $(if ($InstanceRecoveryModulePath) { "[Console]::WriteLine('Loading VMware.CloudFoundation.InstanceRecovery (this can take a minute)...'); Import-Module -Force '$(Protect-SingleQuotes $InstanceRecoveryModulePath)'" })
        $(if ($CoordinatorModulePath) { "[Console]::WriteLine('Loading VMware.CloudFoundation.RecoveryCoordinator...'); Import-Module -Force '$(Protect-SingleQuotes $CoordinatorModulePath)'" })
        "Start-Transcript -Path '$(Protect-SingleQuotes $transcript)' | Out-Null"
        ". '$(Protect-SingleQuotes (Join-Path $PSScriptRoot 'console-repl.ps1'))' -QueueDir '$(Protect-SingleQuotes $queueDir)'"
    ) -join '; '
    $pty = New-PtyProcess $startup $script:defaultCols $script:defaultRows
    $c = @{
        Id = $Id; Label = $Label; Pty = $pty; Transcript = $transcript; QueueDir = $queueDir
        Out = [System.Collections.Generic.List[byte]]::new(); Base = [long]0
        Buf = [byte[]]::new(8192); ReadTask = $null; Exited = $false; SentVars = @{}
        InBuf = [System.Collections.Generic.List[byte]]::new(); EverAttached = $false
    }
    $c.ReadTask = $pty.Output.ReadAsync($c.Buf, 0, $c.Buf.Length)
    $script:consoles[$Id] = $c
    return $c
}

function Get-ConsoleLabel([string]$Id) { if ($Id -eq 'main') { 'Main' } else { 'Thread ' + $Id.Substring('thread-'.Length) } }

function Get-OrNewConsole([string]$Id) {
    if ($Id -notmatch '^(main|thread-[A-Za-z0-9_-]+)$') { throw "Invalid console id '$Id'" }
    if ($script:consoles.Contains($Id)) { return $script:consoles[$Id] }
    return New-ConsoleSession $Id (Get-ConsoleLabel $Id)
}

# Input is queued and fed to the pty in small chunks by Update-Consoles, never as one big write: pwsh's own
# terminal-input reader (it also reads the terminal's cursor-position replies from the same stdin) corrupts
# the tail of a long burst -- observed with a 233-byte line arriving as "...-Force<garbage>". A browser paste
# is one big burst too, so everything typed goes through this queue.
function Send-ConsoleBytes($Console, [byte[]]$Bytes) {
    if ($Console.Exited) { return }
    $Console.InBuf.AddRange($Bytes)
}
function Write-ConsoleInputChunk($Console) {
    if ($Console.Exited -or $Console.InBuf.Count -eq 0) { return }
    $n = [Math]::Min(48, $Console.InBuf.Count)
    # don't split a multi-byte UTF-8 character across two writes
    while ($n -lt $Console.InBuf.Count -and $n -gt 1 -and ($Console.InBuf[$n] -band 0xC0) -eq 0x80) { $n-- }
    $chunk = $Console.InBuf.GetRange(0, $n).ToArray()
    $Console.InBuf.RemoveRange(0, $n)
    try { $Console.Pty.Input.Write($chunk, 0, $n); $Console.Pty.Input.Flush() } catch { }
}
function Send-ConsoleLine($Console, [string]$Text) { Send-ConsoleBytes $Console ([Text.Encoding]::UTF8.GetBytes($Text + "`r")) }

function Submit-ConsoleCommand($Console, [string]$Init, [string]$Command, [string]$Id = '') {
    $seq = '{0:D10}' -f ([DateTime]::UtcNow.Ticks)
    $tmp = Join-Path $Console.QueueDir "$seq.tmp"
    [IO.File]::Create($tmp).Dispose()
    if (-not ($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop')) { [IO.File]::SetUnixFileMode($tmp, [IO.UnixFileMode]'UserRead,UserWrite') }
    [IO.File]::WriteAllText($tmp, (@{ init = $Init; command = $Command; id = $Id } | ConvertTo-Json -Compress), [System.Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $tmp -Destination (Join-Path $Console.QueueDir "$seq.json")
}

function Update-Consoles {
    foreach ($c in $script:consoles.Values) {
        Write-ConsoleInputChunk $c
        while ($c.ReadTask -and $c.ReadTask.IsCompleted) {
            $n = if ($c.ReadTask.IsFaulted) { 0 } else { $c.ReadTask.Result }
            if ($n -le 0) { $c.ReadTask = $null; break }
            $chunk = [byte[]]::new($n)
            [Array]::Copy($c.Buf, $chunk, $n)
            $c.Out.AddRange($chunk)
            if ($c.Out.Count -gt 8MB) { $c.Out.RemoveRange(0, 4MB); $c.Base += 4MB }   # scrollback cap
            $c.ReadTask = $c.Pty.Output.ReadAsync($c.Buf, 0, $c.Buf.Length)
        }
        if (-not $c.Exited -and -not $c.ReadTask -and (& $c.Pty.IsExited)) { $c.Exited = $true }
    }
}

# ---------------------------------------------------------------- variable injection
# Returns the assignments this step needs that the console doesn't already hold, as script text for the queue's
# silent "init" slot (so values, including secrets, never appear on screen or in the transcript).
function Get-VariableInit($Console, $Step) {
    $lines = [System.Collections.Generic.List[string]]::new()
    $pending = @{}
    foreach ($name in (Get-ReferencedVariableNames @($Step.CommandLine))) {
        if (-not $script:vars.Contains($name) -or [string]::IsNullOrEmpty($script:vars[$name])) { continue }
        $value = $script:vars[$name]
        if ($Console.SentVars.ContainsKey($name) -and $Console.SentVars[$name] -ceq $value) { continue }
        $q = Protect-SingleQuotes $value
        if ($name -eq 'secureEncryptionPassword') { [void]$lines.Add("`$global:$name = ConvertTo-SecureString '$q' -AsPlainText -Force") }
        else { [void]$lines.Add("`$global:$name = '$q'") }
        $pending[$name] = $value
    }
    return @{ Script = ($lines -join "`n"); Pending = $pending }
}

# ---------------------------------------------------------------- step watches (transcript based)
function Test-StepTranscriptClean([string]$Slice) {
    foreach ($marker in '[WARNING]', '[ERROR]', '[EXCEPTION]', '+ CategoryInfo') { if ($Slice.Contains($marker)) { return $false } }
    return $true
}

function Get-TranscriptLength([string]$Path) {
    if (Test-Path -LiteralPath $Path) { return (Get-Item -LiteralPath $Path).Length }
    return 0
}

function Read-TranscriptFrom([string]$Path, [long]$Offset) {
    if (-not (Test-Path -LiteralPath $Path)) { return '' }
    $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        if ($fs.Length -le $Offset) { return '' }
        [void]$fs.Seek($Offset, [IO.SeekOrigin]::Begin)
        $bytes = [byte[]]::new($fs.Length - $Offset)
        $read = 0
        while ($read -lt $bytes.Length) { $got = $fs.Read($bytes, $read, $bytes.Length - $read); if ($got -le 0) { break }; $read += $got }
        return [Text.Encoding]::UTF8.GetString($bytes, 0, $read)
    } finally { $fs.Dispose() }
}

function Complete-Watch($Watch, [string]$Status, $Clean, [string]$Slice) {
    $Watch.Status = $Status
    $Watch.Clean = $Clean
    if ($Watch.StepId) { $script:stepLedger[$Watch.StepId] = if ($Status -eq 'Done') { 'Success' } else { 'Failed' } }
    if ($Status -eq 'Done' -and $Watch.Cmdlet -eq 'New-RetrieveVCFCredentials') {
        # Same hand-off the WPF UI does (Get-CredentialsFilePathFromTranscript): remember the file the step wrote.
        $m = [regex]::Matches($Slice, 'Credentials file written to: (?<path>[^\r\n\x1b]+)')
        if ($m.Count -gt 0) { $script:vars['credentialsFilePath'] = $m[$m.Count - 1].Groups['path'].Value.Trim() }
    }
}

function Update-Watches {
    foreach ($w in @($script:watches.Values | Where-Object { $_.Status -eq 'Running' })) {
        $c = $script:consoles[$w.ConsoleId]
        $text = Read-TranscriptFrom $c.Transcript $w.Offset
        $i = $text.IndexOf($w.Target)
        if ($i -ge 0) {
            $eol = $text.IndexOf("`n", $i)
            $slice = if ($eol -ge 0) { $text.Substring(0, $eol) } else { $text }
            $clean = Test-StepTranscriptClean $slice
            Complete-Watch $w $(if ($clean) { 'Done' } else { 'Failed' }) $clean $slice
        } elseif ($c.Exited) {
            Complete-Watch $w 'Failed' $false $text
        } elseif (Test-Path -LiteralPath (Join-Path $c.QueueDir "$($w.Id).done")) {
            # The command returned but its "Completed Task" line is not in the transcript. Give the transcript a moment
            # to flush before concluding it never will be written.
            if (-not $w.ReturnedAt) { $w.ReturnedAt = [DateTime]::UtcNow }
            elseif (([DateTime]::UtcNow - $w.ReturnedAt).TotalSeconds -ge 2) { Complete-Watch $w 'Failed' $false $text }
        }
    }
}

function Start-Step([string]$PlanId, [int]$StepIndex, [string]$ConsoleId) {
    $entry = Get-CatalogEntry $PlanId
    if (-not $entry) { throw "Unknown plan '$PlanId'" }
    $step = Get-PlanSteps $entry | Where-Object { $_.Index -eq $StepIndex } | Select-Object -First 1
    if (-not $step) { throw "Unknown step $StepIndex in plan '$PlanId'" }

    if (-not (Test-StepStatusGate $step)) {
        if ($step.Id) { $script:stepLedger[$step.Id] = 'Skipped' }
        return @{ skipped = $true }
    }
    # "New-Advisory '...'" is a UI-only pseudo-command (it only exists in the WPF window); resolve it here.
    $adv = [regex]::Match($step.CommandLine, "^New-Advisory\s+'(.*)'\s*$", [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if ($adv.Success) {
        if ($step.Id) { $script:stepLedger[$step.Id] = 'Success' }
        return @{ advisory = ($adv.Groups[1].Value -replace "''", "'") }
    }

    # Same fallback as the WPF UI: with no credentials path remembered, use the newest one the Retrieve step left behind.
    if ($step.CommandLine -match '\$credentialsFilePath\b' -and [string]::IsNullOrEmpty($script:vars['credentialsFilePath'])) {
        $latest = Get-ChildItem -LiteralPath $WorkingDirectory -Filter 'vcf-credentials-*.json' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($latest) { $script:vars['credentialsFilePath'] = $latest.FullName }
    }

    $console = Get-OrNewConsole $ConsoleId
    if ($console.Exited) { throw "Console '$ConsoleId' has exited; restart it first." }
    $init = Get-VariableInit $console $step
    $cmdlet = ($step.CommandLine -split '\s+', 2)[0]
    $script:watchSeq++
    $id = [string]$script:watchSeq
    $script:watches[$id] = @{
        Id = $id; ConsoleId = $ConsoleId; StepId = $step.Id; Cmdlet = $cmdlet; Target = "Completed Task $cmdlet"
        Offset = (Get-TranscriptLength $console.Transcript); Status = 'Running'; Clean = $null
    }
    Submit-ConsoleCommand $console $init.Script $step.CommandLine $id
    foreach ($k in $init.Pending.Keys) { $console.SentVars[$k] = $init.Pending[$k] }
    return @{ watchId = $id; consoleId = $ConsoleId }
}

# ---------------------------------------------------------------- WebSocket clients (one per open console tab)
function Add-WsAccept($Context, [string]$ConsoleId) {
    # [NullString]::Value, not $null: PowerShell converts a $null argument to "" for a [string] parameter, and
    # AcceptWebSocketAsync rejects an empty subprotocol (ArgumentException) -- the upgrade then never completes.
    [void]$script:pendingAccepts.Add(@{ Task = $Context.AcceptWebSocketAsync([NullString]::Value); ConsoleId = $ConsoleId })
}

function Invoke-ClientMessage($Client, [string]$Text) {
    if ([string]::IsNullOrEmpty($Text)) { return }
    $console = $script:consoles[$Client.ConsoleId]
    switch ($Text[0]) {
        'i' { Send-ConsoleBytes $console ([Text.Encoding]::UTF8.GetBytes($Text.Substring(1))) }
        'r' {
            $p = $Text.Substring(1).Split(',')
            $cols = [int]$p[0]; $rows = [int]$p[1]
            if ($cols -ge 20 -and $cols -le 500 -and $rows -ge 5 -and $rows -le 200 -and -not $console.Exited) { & $console.Pty.Resize $cols $rows }
        }
    }
}

function Update-Clients {
    foreach ($a in @($script:pendingAccepts | Where-Object { $_.Task.IsCompleted })) {
        [void]$script:pendingAccepts.Remove($a)
        if ($a.Task.IsFaulted) { continue }
        $ws = $a.Task.Result.WebSocket
        $c = $script:consoles[$a.ConsoleId]
        $client = @{
            Ws = $ws; ConsoleId = $a.ConsoleId; RecvBuf = [byte[]]::new(8192); Msg = [System.IO.MemoryStream]::new()
            Sent = $c.Base; SendTask = $null; RecvTask = $null
        }
        $client.RecvSeg = [ArraySegment[byte]]::new($client.RecvBuf)
        $client.RecvTask = $ws.ReceiveAsync($client.RecvSeg, [Threading.CancellationToken]::None)
        # Tell the page how much scrollback is a REPLAY, so it can ignore the terminal's own replies (cursor-
        # position reports etc.) to old queries inside it instead of typing them into the prompt.
        # The FIRST attach to a console is not a replay: pwsh asks the terminal for the cursor position at
        # startup and stalls until something answers, and nothing could answer before a browser attached.
        # That backlog must be answered, so it is presented as live output (replay = 0).
        $replayBytes = if ($c.EverAttached) { [long]$c.Out.Count } else { [long]0 }
        $c.EverAttached = $true
        $hello = [Text.Encoding]::UTF8.GetBytes((@{ replay = $replayBytes } | ConvertTo-Json -Compress))
        $client.SendTask = $ws.SendAsync([ArraySegment[byte]]::new($hello), [System.Net.WebSockets.WebSocketMessageType]::Text, $true, [Threading.CancellationToken]::None)
        [void]$script:wsClients.Add($client)
    }
    foreach ($client in @($script:wsClients)) {
        try {
            $ws = $client.Ws
            if ($ws.State -ne [System.Net.WebSockets.WebSocketState]::Open) { [void]$script:wsClients.Remove($client); continue }
            if ($client.RecvTask.IsCompleted) {
                $r = $client.RecvTask.Result      # throws if faulted -> client dropped below
                if ($r.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Close) {
                    try { [void]$ws.CloseOutputAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, '', [Threading.CancellationToken]::None).Wait(500) } catch { }
                    [void]$script:wsClients.Remove($client); continue
                }
                $client.Msg.Write($client.RecvBuf, 0, $r.Count)
                if ($r.EndOfMessage) {
                    $text = [Text.Encoding]::UTF8.GetString($client.Msg.ToArray())
                    $client.Msg.SetLength(0)
                    Invoke-ClientMessage $client $text
                }
                $client.RecvTask = $ws.ReceiveAsync($client.RecvSeg, [Threading.CancellationToken]::None)
            }
            if ($client.SendTask -and -not $client.SendTask.IsCompleted) { continue }
            if ($client.SendTask -and $client.SendTask.IsFaulted) { [void]$script:wsClients.Remove($client); continue }
            $c = $script:consoles[$client.ConsoleId]
            $end = $c.Base + $c.Out.Count
            if ($client.Sent -lt $c.Base) { $client.Sent = $c.Base }
            if ($client.Sent -lt $end) {
                $n = [int][Math]::Min(32768, $end - $client.Sent)
                $chunk = $c.Out.GetRange([int]($client.Sent - $c.Base), $n).ToArray()
                $client.SendTask = $ws.SendAsync([ArraySegment[byte]]::new($chunk), [System.Net.WebSockets.WebSocketMessageType]::Binary, $true, [Threading.CancellationToken]::None)
                $client.Sent += $n
            }
        } catch {
            [void]$script:wsClients.Remove($client)
        }
    }
}

# ---------------------------------------------------------------- HTTP plumbing
function Send-Response($Context, [byte[]]$Bytes, [string]$ContentType, [int]$Code = 200) {
    $r = $Context.Response
    $r.StatusCode = $Code
    $r.ContentType = $ContentType
    $r.Headers['Cache-Control'] = 'no-store'
    $r.Headers['X-Content-Type-Options'] = 'nosniff'
    # 'unsafe-inline' only because the page keeps its script/style inline (no build step); everything is same-origin.
    $r.Headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self' ws://127.0.0.1:$script:listenPort ws://localhost:$script:listenPort; img-src 'self' data:"
    $r.ContentLength64 = $Bytes.Length
    $r.OutputStream.Write($Bytes, 0, $Bytes.Length)
    $r.Close()
}

function Send-Json($Context, $Object, [int]$Code = 200) {
    $json = ConvertTo-Json -InputObject $Object -Depth 20 -Compress
    Send-Response $Context ([Text.Encoding]::UTF8.GetBytes($json)) 'application/json; charset=utf-8' $Code
}

function Read-JsonBody($Context) {
    $reader = [System.IO.StreamReader]::new($Context.Request.InputStream, [Text.Encoding]::UTF8)
    try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
    if ([string]::IsNullOrWhiteSpace($text)) { return @{} }
    return ($text | ConvertFrom-Json -AsHashtable)
}

function Test-RequestAllowed($Context) {
    $req = $Context.Request
    $path = $req.Url.AbsolutePath
    $allowedHosts = @("127.0.0.1:$script:listenPort", "localhost:$script:listenPort")
    if ($req.Headers['Host'] -notin $allowedHosts) { return $false }                       # DNS rebinding
    $origin = $req.Headers['Origin']
    if ($origin -and ($origin -notin @("http://127.0.0.1:$script:listenPort", "http://localhost:$script:listenPort"))) { return $false }   # cross-site (incl. cross-site WebSocket)
    if ($req.HttpMethod -eq 'GET' -and $path.StartsWith('/vendor/')) { return $true }       # public static libraries only (allow-listed in Invoke-Route)
    # The page itself and the WebSocket carry the token in the query string (neither can set headers); the JSON API uses a header.
    $supplied = if ($path -eq '/' -or $path -eq '/ws') { $req.QueryString['t'] } else { $req.Headers['X-VCFIR-Token'] }
    return ($supplied -and $supplied -ceq $Token)
}

function Invoke-Route($Context) {
    $req = $Context.Request
    $path = $req.Url.AbsolutePath
    $method = $req.HttpMethod

    if ($path -eq '/ws' -and $req.IsWebSocketRequest) {
        $id = [string]$req.QueryString['console']
        if (-not $script:consoles.Contains($id)) { Send-Json $Context @{ error = 'unknown console' } 404; return }
        Add-WsAccept $Context $id
        return
    }
    if ($method -eq 'GET' -and $path.StartsWith('/vendor/')) {
        $name = $path.Substring('/vendor/'.Length)
        if (-not $script:vendorFiles.ContainsKey($name)) { Send-Json $Context @{ error = 'not found' } 404; return }
        Send-Response $Context ([IO.File]::ReadAllBytes((Join-Path $script:vendorPath $name))) $script:vendorFiles[$name]
        return
    }

    switch ("$method $path") {
        'GET /' { Send-Response $Context ([IO.File]::ReadAllBytes($script:htmlPath)) 'text/html; charset=utf-8' }
        'GET /api/catalog' { Send-Json $Context $script:catalog }
        'GET /api/plan' { Send-Json $Context (Get-PlanPayload $req.QueryString['id']) }
        'GET /api/consoles' {
            Send-Json $Context @{ consoles = @($script:consoles.Values | ForEach-Object { @{ id = $_.Id; label = $_.Label; exited = $_.Exited } }) }
        }
        'POST /api/console/restart' {
            $id = [string](Read-JsonBody $Context).id
            if ($script:consoles.Contains($id)) {
                $old = $script:consoles[$id]
                & $old.Pty.Kill
                Remove-Item -LiteralPath $old.QueueDir -Recurse -Force -ErrorAction SilentlyContinue
                foreach ($cl in @($script:wsClients | Where-Object { $_.ConsoleId -eq $id })) { try { $cl.Ws.Abort() } catch { }; [void]$script:wsClients.Remove($cl) }
                $script:consoles.Remove($id)
                [void](New-ConsoleSession $id (Get-ConsoleLabel $id))
            }
            Send-Json $Context @{ ok = $true }
        }
        'POST /api/console/interrupt' {
            # Ctrl+C into the console, and stop waiting on whatever step was running there.
            $body = Read-JsonBody $Context
            $id = [string]$body.id
            if ($script:consoles.Contains($id)) {
                # notifyOnly: the user already pressed Ctrl+C in the terminal itself -- don't send a second one.
                if (-not $body.notifyOnly) { $script:consoles[$id].InBuf.Clear(); Send-ConsoleBytes $script:consoles[$id] ([byte[]](3)) }
                foreach ($w in @($script:watches.Values | Where-Object { $_.ConsoleId -eq $id -and $_.Status -eq 'Running' })) { Complete-Watch $w 'Stopped' $false '' }
            }
            Send-Json $Context @{ ok = $true }
        }
        'POST /api/variables' {
            $body = Read-JsonBody $Context
            foreach ($k in $body.values.Keys) {
                if ($k -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') { throw "Invalid variable name '$k'" }
                $script:vars[$k] = [string]$body.values[$k]
            }
            Send-Json $Context @{ ok = $true }
        }
        'POST /api/variables/load' {
            $body = Read-JsonBody $Context
            $r = Import-VariablesFile ([string]$body.path)
            Send-Json $Context @{ ok = $true; count = $r.count; file = $r.file }
        }
        'POST /api/datasource' {
            # Stand-in for the WPF Data Source panel. "Load Extracted SDDC Data" parses the file (domains, clusters,
            # selection context); "Extract SDDC Manager Backup" just remembers the backup path for the plan's variables.
            $body = Read-JsonBody $Context
            if ([string]::IsNullOrWhiteSpace([string]$body.path)) { throw 'No file path was entered.' }
            if (-not (Test-Path -LiteralPath ([string]$body.path) -PathType Leaf)) { throw "File not found on the machine running this server: $($body.path)" }
            $file = (Resolve-Path -LiteralPath ([string]$body.path)).Path
            switch ([string]$body.kind) {
                'LoadExtractedData' { Import-ExtractedData $file; Send-Json $Context @{ ok = $true; variable = 'extractedSDDCDataFile'; file = $file } }
                'ExtractBackup' { $script:vars['vcfbackupFilePath'] = $file; Send-Json $Context @{ ok = $true; variable = 'vcfbackupFilePath'; file = $file } }
                default { throw "Unknown data source '$($body.kind)'" }
            }
        }
        'GET /api/fs' {
            Send-Json $Context (Get-DirectoryListing $req.QueryString['path'] $req.QueryString['filter'] ($req.QueryString['hidden'] -eq '1'))
        }
        'POST /api/extract' {
            # Same as the WPF "Extract SDDC Manager Backup" data source: the encryption password goes to the Main console
            # (silently, via the private queue -- never echoed or logged) and New-ExtractDataFromSDDCBackup runs there. It
            # always writes extracted-sddc-data.json next to the backup, so the page loads that once the step completes.
            $body = Read-JsonBody $Context
            $backup = [string]$body.path
            if (-not (Test-Path -LiteralPath $backup -PathType Leaf)) { throw "File not found on the machine running this server: $backup" }
            if ([string]::IsNullOrEmpty([string]$body.password)) { throw 'No encryption password was entered.' }
            $backup = (Resolve-Path -LiteralPath $backup).Path
            $console = Get-OrNewConsole 'main'
            if ($console.Exited) { throw "Console 'main' has exited; restart it first." }
            $script:vars['secureEncryptionPassword'] = [string]$body.password
            $script:vars['vcfbackupFilePath'] = $backup
            $init = "`$global:secureEncryptionPassword = ConvertTo-SecureString '$(Protect-SingleQuotes ([string]$body.password))' -AsPlainText -Force"
            $console.SentVars['secureEncryptionPassword'] = [string]$body.password
            $script:watchSeq++
            $id = [string]$script:watchSeq
            $script:watches[$id] = @{ Id = $id; ConsoleId = 'main'; StepId = ''; Cmdlet = 'New-ExtractDataFromSDDCBackup'; Target = 'Completed Task New-ExtractDataFromSDDCBackup'
                Offset = (Get-TranscriptLength $console.Transcript); Status = 'Running'; Clean = $null }
            Submit-ConsoleCommand $console $init -Id $id -Command ("New-ExtractDataFromSDDCBackup -vcfBackupFilePath '$(Protect-SingleQuotes $backup)' -secureEncryptionPassword `$secureEncryptionPassword")
            Send-Json $Context @{ watchId = $id; consoleId = 'main'; extractedFile = (Join-Path (Split-Path $backup -Parent) 'extracted-sddc-data.json') }
        }
        'POST /api/select' {
            $body = Read-JsonBody $Context
            Set-InfrastructureSelection ([string]$body.kind) ([string]$body.domain) ([string]$body.cluster)
            Send-Json $Context @{ ok = $true; selection = $script:selection }
        }
        'POST /api/mode' {
            $body = Read-JsonBody $Context
            $mode = [string]$body.mode
            if ($mode -eq 'Engineering' -and -not $script:engineeringUnlocked) {
                if (-not (Test-EngineeringModePassword ([string]$body.password))) { Send-Json $Context @{ error = 'Incorrect engineering mode password.' } 403; return }
                $script:engineeringUnlocked = $true
            }
            if ($mode -in 'User', 'Engineering') { $script:uiMode = $mode }
            Send-Json $Context @{ mode = $script:uiMode }
        }
        'POST /api/state/save' {
            # Same content as the WPF Save & Exit state: file paths, the selection, and which steps were Done -- never
            # variable values. Written to the launch directory (a browser can't show a native save dialog).
            $body = Read-JsonBody $Context
            $state = [ordered]@{
                ExtractedDataFilePath    = $script:extractedPath
                RecoveryPlanId           = [string]$body.planId
                VariablesAnswersFilePath = $script:varsFilePath
                CredentialsFilePath      = $(if ($script:vars.Contains('credentialsFilePath')) { $script:vars['credentialsFilePath'] } else { '' })
                Selection                = $script:selection
                CompletedSteps           = @($body.completed)
            }
            $file = Join-Path $WorkingDirectory ("vcfibr-state-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
            $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $file -Encoding utf8
            Send-Json $Context @{ ok = $true; file = $file }
        }
        'GET /api/states' {
            $files = @(Get-ChildItem -LiteralPath $WorkingDirectory -Filter 'vcfibr-state-*.json' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending |
                    ForEach-Object { @{ name = $_.Name; path = $_.FullName; modified = $_.LastWriteTime.ToString('s') } })
            Send-Json $Context @{ states = $files }
        }
        'POST /api/state/resume' {
            # Replays the loaders a manual session would use (data file, variables file, selection), then reports which
            # saved-Done steps still line up with the plan file (position AND command line, so an edited plan can't
            # mark the wrong row Done).
            $body = Read-JsonBody $Context
            $path = (Resolve-Path -LiteralPath ([string]$body.path)).Path
            if ((Split-Path $path -Parent) -ne (Resolve-Path -LiteralPath $WorkingDirectory).Path -or (Split-Path $path -Leaf) -notlike 'vcfibr-state-*.json') { throw 'Only vcfibr-state-*.json files in the launch directory can be resumed.' }
            $state = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            if ($state.ExtractedDataFilePath) { Import-ExtractedData ([string]$state.ExtractedDataFilePath) }
            if ($state.VariablesAnswersFilePath) { [void](Import-VariablesFile ([string]$state.VariablesAnswersFilePath)) }
            if ($state.CredentialsFilePath) { $script:vars['credentialsFilePath'] = [string]$state.CredentialsFilePath }
            if ($state.Selection) { Set-InfrastructureSelection ([string]$state.Selection.kind) ([string]$state.Selection.domain) ([string]$state.Selection.cluster) }
            $entry = Get-CatalogEntry ([string]$state.RecoveryPlanId)
            $completed = @()
            if ($entry) {
                $steps = Get-PlanSteps $entry
                foreach ($c in @($state.CompletedSteps)) {
                    $step = $steps | Where-Object { $_.Index -eq [int]$c.Index } | Select-Object -First 1
                    if ($step -and $step.CommandLine -eq [string]$c.CommandLine) {
                        $completed += [int]$c.Index
                        if ($step.Id) { $script:stepLedger[$step.Id] = 'Success' }
                    }
                }
            }
            Send-Json $Context @{ ok = $true; planId = [string]$state.RecoveryPlanId; completed = $completed; file = $path }
        }
        'POST /api/step/run' {
            $body = Read-JsonBody $Context
            Send-Json $Context (Start-Step ([string]$body.planId) ([int]$body.index) ([string]$body.consoleId))
        }
        'GET /api/step' {
            $w = $script:watches[$req.QueryString['id']]
            if (-not $w) { Send-Json $Context @{ error = 'unknown step run' } 404; return }
            Send-Json $Context @{ status = $w.Status; clean = $w.Clean; consoleId = $w.ConsoleId }
        }
        'POST /api/shutdown' {
            Send-Json $Context @{ ok = $true }
            $script:shutdown = $true
        }
        default { Send-Json $Context @{ error = 'not found' } 404 }
    }
}

# ---------------------------------------------------------------- main
if ($Port -eq 0) {
    $probe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $probe.Start(); $Port = $probe.LocalEndpoint.Port; $probe.Stop()
}
$script:listenPort = $Port
$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://127.0.0.1:$Port/")
$listener.Start()

try {
    [void](New-ConsoleSession 'main' 'Main')
    $pending = $listener.GetContextAsync()
    while (-not $script:shutdown) {
        $got = try { $pending.Wait(25) } catch { break }
        if ($got) {
            $context = $pending.Result
            $pending = $listener.GetContextAsync()
            try {
                if (-not (Test-RequestAllowed $context)) {
                    Send-Json $context @{ error = 'forbidden' } 403
                } else {
                    Invoke-Route $context
                }
            } catch {
                try { Send-Json $context @{ error = $_.Exception.Message } 500 } catch { }
            }
        }
        Update-Consoles
        Update-Watches
        Update-Clients
    }
} finally {
    foreach ($c in $script:consoles.Values) { try { & $c.Pty.Kill } catch { }; Remove-Item -LiteralPath $c.QueueDir -Recurse -Force -ErrorAction SilentlyContinue }
    $listener.Stop()
    $listener.Close()
}
