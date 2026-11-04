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
    [string]$InstanceRecoveryModulePath,
    # How each console's pwsh is hosted. Pty = a real pseudo-terminal (script(1) on macOS/Linux, ConPTY on Windows);
    # Pipe = a plain pwsh with redirected stdin/stdout/stderr, which is all the queue-driven console needs (steps arrive
    # through a file queue and the only input is answers to prompts) and has no native dependencies. Auto picks Pipe on
    # Windows (the ConPTY code has never been run there) and Pty elsewhere.
    [ValidateSet('Auto', 'Pty', 'Pipe')][string]$ConsoleBackend = 'Auto',
    # "Name|Installed|Latest|Repository" (or "...|ERROR|message") results from Get-VCFIRModuleUpdateStatus, computed by
    # Start-VCFRecoveryCoordinatorWeb before this server starts -- same hand-off the WPF UI uses for its update banner.
    [string]$CoordinatorUpdateStatus,
    [string]$InstanceRecoveryUpdateStatus,
    # The server lives and dies with its window, like the WPF UI: once a page has been opened, the server exits (ending every
    # console and anything still running) this many seconds after it last heard from a window. The page polls every 0.7 s and
    # keeps a WebSocket open, so this only has to outlast a delayed poll or a console reconnecting -- not a person's actions.
    [double]$CloseGraceSeconds = 3,
    # If no page is ever opened (-NoBrowser, or the browser failed to start), exit after this many minutes. 0 disables it.
    [double]$IdleTimeoutMinutes = 10,
    # Refuse commands typed into the console between steps (the page then shows no command line). The token and
    # loopback-only limits apply either way; this switch is for sites that want the server to accept only plan steps.
    [switch]$DisableCommandLine
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
$script:typedSeq = 0
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
$script:answerMap = $null                # ordered name -> value of the ACTIVE variables file ($null until one is loaded/created)
$script:interactiveAnswerFile = $null    # the "use answer file for interactive tasks" file, per Import-VCFIRAnswerFile
$script:lastClientSeen = [DateTime]::UtcNow
$script:lastTick = [DateTime]::UtcNow
# What the PAGE used to hold and now lives here, so a closed or reloaded window loses nothing: step statuses, the pause point,
# the Advisories log, the Run Plan timer and the Run Plan itself (which the server drives, so it survives the window).
$script:ui = @{
    planId = ''; recoveryType = ''; dataSource = ''; useThreads = $true; pausePointAfter = $null; toggles = @{}
    statuses = @{}                                                   # step key ("0", "1", ... or "bp") -> Running/Done/Failed/Skipped/Stopped
    advisories = [System.Collections.Generic.List[object]]::new()
    run = $null; runStartedAt = $null; runFinishedAt = $null
    needPassword = $false; pw = $null
    focusSeq = 0; focusConsole = ''
}
# One window at a time: the first page to talk to the server owns it (its random client id). Another page is refused while the
# owner is alive -- it has a console WebSocket open, or it made a request within the last few seconds.
$script:activeClient = @{ Id = ''; LastSeen = [DateTime]::MinValue }
$script:pageSeen = $false              # a page has been served at least once (the server then follows that window's life)
# Names the operator never types (they come from the Data Source / the selection / a password prompt): the WPF UI drops
# them from answers files and never lists them on the Variables tab.
$script:selectionDriven = @('extractedSDDCDataFile', 'workloadDomain', 'clusterName', 'secureEncryptionPassword')
$script:uiMode = 'User'
$script:engineeringUnlocked = $false
$script:pwshPath = (Get-Process -Id $PID).Path
$script:ignoredVariableNames = @('true', 'false', 'null', '_', 'env', 'PSScriptRoot', 'PSItem', 'args', 'input')
$script:defaultCols = 120
$script:defaultRows = 30

$script:onWindows = [bool]($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop')
$script:consoleBackend = switch ($ConsoleBackend) { 'Auto' { if ($script:onWindows) { 'Pipe' } else { 'Pty' } } default { $ConsoleBackend } }
if ($script:onWindows -and $script:consoleBackend -eq 'Pty') {
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
    # PowerShell variable names are case-insensitive ($sddcManagerFqdn and $sddcManagerFQDN are one variable), so a name
    # seen again in a different case must not become a second row.
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($commandLine in $CommandLines) {
        foreach ($m in [regex]::Matches($commandLine, '\$([A-Za-z_][A-Za-z0-9_]*)')) {
            $n = $m.Groups[1].Value
            if ($n -notin $script:ignoredVariableNames -and $seen.Add($n)) { [void]$names.Add($n) }
        }
    }
    return $names.ToArray()
}

# Every command line plus a '$name' fragment for each "variable" condition, so a variable that only ever appears in a
# condition still gets a row (Get-StepReferenceText in the WPF UI).
function Get-StepReferenceText($Steps) {
    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($step in $Steps) {
        $lines.Add($step.CommandLine)
        foreach ($c in $step.Condition) { if ($null -ne $c -and $c -isnot [string] -and $c.type -eq 'variable') { $lines.Add('$' + [string]$c.name) } }
    }
    return , $lines.ToArray()
}

function Get-VariablesTemplateKeys($Entry) {
    if (-not $Entry -or -not $Entry.variablesFile) { return $null }
    $path = Join-Path (Join-Path $PlansPath $Entry.planFolder) $Entry.variablesFile
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    return @((Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).PSObject.Properties.Name)
}

function Get-VariablesStructureMismatch([string[]]$AnswerMapKeys, [string[]]$TemplateKeys) {
    $missing = @($TemplateKeys | Where-Object { $_ -notin $AnswerMapKeys })
    $extra = @($AnswerMapKeys | Where-Object { $_ -notin $TemplateKeys })
    if ($missing.Count -eq 0 -and $extra.Count -eq 0) { return $null }
    $parts = @()
    if ($missing.Count -gt 0) { $parts += "missing $($missing -join ', ')" }
    if ($extra.Count -gt 0) { $parts += "unexpected $($extra -join ', ')" }
    return $parts -join '; '
}

function Test-PlanAllowed($Entry) {
    if ($Entry.engineeringOnly -and -not $script:engineeringUnlocked) { throw "'$($Entry.label)' is engineering-only: unlock engineering mode first." }
}

# Which interactive steps the interactive answer file already covers ("Auto Answered" vs "Requires Input"), counting each
# cmdlet's occurrences in plan order exactly the way Get-VCFIRAnswerSet dequeues them (Update-StepRowAutoAnsweredBadges).
function Get-AutoAnsweredIndexes($Steps) {
    $covered = [System.Collections.Generic.HashSet[int]]::new()
    if (-not $script:interactiveAnswerFile -or -not (Test-Path -LiteralPath $script:interactiveAnswerFile)) { return , $covered }
    $counts = $null; $preApproved = $null
    try {
        $answers = Get-Content -LiteralPath $script:interactiveAnswerFile -Raw | ConvertFrom-Json
        $counts = @{}
        foreach ($property in $answers.PSObject.Properties) { $counts[$property.Name] = @($property.Value).Count }
        if ($answers.PSObject.Properties.Name -contains 'Confirm-ManualStep') { $preApproved = @($answers.'Confirm-ManualStep') }
    } catch { return , $covered }
    $seen = @{}
    foreach ($step in $Steps) {
        if (-not $step.Interactive) { continue }
        $cmdlet = ($step.CommandLine -split '\s+', 2)[0]
        if ($cmdlet -eq 'Confirm-ManualStep') {
            $m = [regex]::Match($step.CommandLine, "-AnswerKey\s+'([^']*)'")
            $auto = $m.Success -and $preApproved -and ($preApproved -contains $m.Groups[1].Value)
        } else {
            $seen[$cmdlet] = 1 + [int]$seen[$cmdlet]
            $auto = $counts.ContainsKey($cmdlet) -and ($seen[$cmdlet] -le $counts[$cmdlet])
        }
        if ($auto) { [void]$covered.Add([int]$step.Index) }
    }
    return , $covered
}

function Get-PlanPayload([string]$PlanId) {
    $entry = Get-CatalogEntry $PlanId
    if (-not $entry) { throw "Unknown plan '$PlanId'" }
    Test-PlanAllowed $entry
    $steps = @(Get-PlanSteps $entry | Where-Object { $_.Visible })
    $applicable = @($steps | Where-Object { Test-StepApplicable $_ })
    $autoAnswered = Get-AutoAnsweredIndexes $applicable
    # The Variables tab lists only the active variables file's own names (none until one is loaded or created), ordered
    # like the WPF UI: names the steps reference first, then whatever else the file holds.
    $rows = @()
    if ($script:answerMap) {
        $referenced = @(@(Get-ReferencedVariableNames (Get-StepReferenceText $steps)) | Where-Object { $script:answerMap.Contains($_) })
        $rows = @($referenced) + @($script:answerMap.Keys | Where-Object { $referenced -notcontains $_ })
    }
    return @{
        plan      = $entry
        steps     = @($steps | ForEach-Object {
                @{ index = $_.Index; id = $_.Id; name = $_.DisplayName; description = $_.Description; commandLine = $_.CommandLine
                    threadId = $_.ThreadId; interactive = $_.Interactive; applicable = (Test-StepApplicable $_); autoAnswered = $autoAnswered.Contains([int]$_.Index) }
            })
        variables = @($rows | ForEach-Object { @{ name = $_; value = $(if ($script:vars.Contains($_)) { $script:vars[$_] } else { '' }); secret = ($_ -match 'password|passphrase') } })
        variablesLoaded = [bool]$script:answerMap
        mode      = $script:uiMode
        unlocked  = $script:engineeringUnlocked
        answerFile = $script:interactiveAnswerFile
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

# A new data file, plan or selection starts a fresh plan context: no variables file, no interactive answer file
# (Reset-CurrentRecoveryPlanContext in the WPF UI).
function Reset-PlanContext {
    $script:answerMap = $null
    $script:varsFilePath = ''
    $script:interactiveAnswerFile = $null
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
    Reset-PlanContext
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
    Reset-PlanContext
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

function Import-VariablesFile([string]$Path, $Entry) {
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'No file path was entered.' }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "File not found on the machine running this server: $Path" }
    $file = (Resolve-Path -LiteralPath $Path).Path
    $loaded = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
    $map = [ordered]@{}
    foreach ($property in $loaded.PSObject.Properties) {
        $v = $property.Value
        # Scalars only (string/number/bool/null); nested objects aren't variables.
        if ($property.Name -match '^[A-Za-z_][A-Za-z0-9_]*$' -and ($null -eq $v -or $v -is [string] -or $v -is [ValueType])) { $map[$property.Name] = if ($null -eq $v) { '' } else { [string]$v } }
    }
    foreach ($owned in $script:selectionDriven) { $map.Remove($owned) }
    $templateKeys = Get-VariablesTemplateKeys $Entry
    if ($null -ne $templateKeys) {
        $mismatch = Get-VariablesStructureMismatch @($map.Keys) $templateKeys
        if ($null -ne $mismatch) { throw "Load Variables failed: '$file' does not match the selected plan's variables structure ($mismatch)." }
    }
    if ($map.Count -eq 0) { return @{ file = $file; count = 0 } }
    foreach ($k in $map.Keys) { $script:vars[$k] = $map[$k] }
    $script:answerMap = $map
    $script:varsFilePath = $file
    $script:interactiveAnswerFile = $null          # Reset-AnswerFileToggle: a new variables file starts without an answer file
    return @{ file = $file; count = $map.Count }
}

# New Variables File: starts from the variables the current plan's steps reference (so it is always in sync with the task
# list), blank, and every later edit is written straight back to the file (Set-VariablesFromPage).
function New-VariablesFile([string]$Path, $Entry, [bool]$Overwrite) {
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'No file path was entered.' }
    $steps = @(Get-PlanSteps $Entry | Where-Object { $_.Visible })
    $excluded = @($script:selectionDriven) + @(if ($Entry.extraToggles) { @($Entry.extraToggles.id) } else { @() })
    $names = @(@(Get-ReferencedVariableNames (Get-StepReferenceText $steps)) | Where-Object { $_ -notin $excluded })
    if ($names.Count -eq 0) { throw 'No steps are currently loaded, so there are no variables to create a file for.' }
    if ((Test-Path -LiteralPath $Path) -and -not $Overwrite) { throw "EXISTS:$Path" }
    $dir = Split-Path -Path $Path -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir -PathType Container)) { throw "Folder not found: $dir" }
    $map = [ordered]@{}
    foreach ($n in $names) { $map[$n] = ''; $script:vars[$n] = '' }
    $map | ConvertTo-Json | Set-Content -LiteralPath $Path -Encoding utf8
    $script:answerMap = $map
    $script:varsFilePath = (Resolve-Path -LiteralPath $Path).Path
    $script:interactiveAnswerFile = $null
    return @{ file = $script:varsFilePath; count = $map.Count }
}

# Values typed on the Variables tab: held for the session AND, for names the active variables file owns, written back to
# that file immediately (the WPF UI saves on every edit).
function Set-VariablesFromPage($Values) {
    $dirty = $false
    foreach ($k in $Values.Keys) {
        if ($k -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') { throw "Invalid variable name '$k'" }
        $script:vars[$k] = [string]$Values[$k]
        if ($script:answerMap -and $script:answerMap.Contains($k) -and $script:answerMap[$k] -cne [string]$Values[$k]) { $script:answerMap[$k] = [string]$Values[$k]; $dirty = $true }
    }
    if ($dirty -and $script:varsFilePath) { $script:answerMap | ConvertTo-Json | Set-Content -LiteralPath $script:varsFilePath -Encoding utf8 }
}

function Set-InteractiveAnswerFile([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { $script:interactiveAnswerFile = $null; return }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "File not found on the machine running this server: $Path" }
    $file = (Resolve-Path -LiteralPath $Path).Path
    [void](Get-Content -LiteralPath $file -Raw | ConvertFrom-Json)       # must at least be valid JSON
    $script:interactiveAnswerFile = $file
}

# After Update-ExtractedSDDCData the cluster name is resolved against live vCenter and written back to the data file:
# re-read it so $clusterName (and the dataPath context) stop being stale (Update-SelectedClusterNameFromDisk).
function Update-SelectedClusterNameFromDisk {
    if (-not $script:extractedPath -or -not $script:selection -or $script:selection.kind -ne 'domain') { return }
    try { $fresh = Get-Content -LiteralPath $script:extractedPath -Raw | ConvertFrom-Json } catch { return }
    $domainName = [string]$script:selection.domain
    $freshDomain = $fresh.workloadDomains | Where-Object { $_.domainName -eq $domainName } | Select-Object -First 1
    $freshDefault = $freshDomain.vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' } | Select-Object -First 1
    if ($null -eq $freshDefault -or [string]::IsNullOrWhiteSpace($freshDefault.name)) { return }
    $stale = ($script:allDomains | Where-Object { $_.domainName -eq $domainName } | Select-Object -First 1).vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' } | Select-Object -First 1
    if ($stale) { $stale.name = $freshDefault.name }
    if ($script:conditionContext.selectedCluster) { $script:conditionContext.selectedCluster.name = $freshDefault.name }
    $script:vars['clusterName'] = [string]$freshDefault.name
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
    $result = @{ path = $full; parent = $(if ($parentInfo) { $parentInfo.FullName } else { $null }); roots = (Get-BrowseRoots); selected = $selected; sep = [string][IO.Path]::DirectorySeparatorChar }
    try { $items = @(Get-ChildItem -LiteralPath $full -Force -ErrorAction Stop) }
    catch { $result.entries = @(); $result.error = "Cannot read this folder: $($_.Exception.Message)"; return $result }
    $onWindows = $IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop'
    $entries = foreach ($item in $items) {
        $hidden = if ($onWindows) { [bool]($item.Attributes -band [IO.FileAttributes]::Hidden) } else { $item.Name.StartsWith('.') }
        if ($hidden -and -not $ShowHidden) { continue }
        $isDir = [bool]$item.PSIsContainer
        if (-not $isDir -and $Filter -eq 'json' -and $item.Extension -ne '.json') { continue }
        if (-not $isDir -and $Filter -eq 'backup' -and -not $item.Name.EndsWith('.tar.gz', [StringComparison]::OrdinalIgnoreCase)) { continue }
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
# A plain pwsh with redirected stdin/stdout/stderr (no terminal). Output is forwarded as raw bytes; stderr is returned as a
# second stream because there is no terminal to merge it into.
function New-PipeProcess([string]$Encoded) {
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $script:pwshPath
    # -OutputFormat/-InputFormat Text: with redirected streams and -EncodedCommand, pwsh otherwise serialises its streams as
    # CLIXML ("<Objs ...>") instead of plain text, and would read stdin as CLIXML too.
    foreach ($a in '-NoLogo', '-NoProfile', '-OutputFormat', 'Text', '-InputFormat', 'Text', '-EncodedCommand', $Encoded) { $psi.ArgumentList.Add($a) }
    $psi.WorkingDirectory = $WorkingDirectory
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::Start($psi)
    return @{
        Input    = $process.StandardInput.BaseStream
        Output   = $process.StandardOutput.BaseStream
        Error    = $process.StandardError.BaseStream
        IsExited = { $process.HasExited }.GetNewClosure()
        Kill     = { try { $process.Kill($true) } catch { } }.GetNewClosure()
        Resize   = { param($c, $r) }.GetNewClosure()
    }
}

function New-PtyProcess([string]$StartupScript, [int]$Cols, [int]$Rows) {
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($StartupScript))
    if ($script:consoleBackend -eq 'Pipe') { return New-PipeProcess $encoded }

    if ($script:onWindows) {
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
        $(if ($script:consoleBackend -eq 'Pipe') { '[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false); [Console]::InputEncoding = [Text.UTF8Encoding]::new($false); $OutputEncoding = [Console]::OutputEncoding' })
        "[Console]::WriteLine('Starting console...')"
        "Set-Location -LiteralPath '$(Protect-SingleQuotes $WorkingDirectory)'"
        $(if ($InstanceRecoveryModulePath) { "[Console]::WriteLine('Loading VMware.CloudFoundation.InstanceRecovery (this can take a minute)...'); Import-Module -Force '$(Protect-SingleQuotes $InstanceRecoveryModulePath)'" })
        $(if ($CoordinatorModulePath) { "[Console]::WriteLine('Loading VMware.CloudFoundation.RecoveryCoordinator...'); Import-Module -Force '$(Protect-SingleQuotes $CoordinatorModulePath)'" })
        "Start-Transcript -Path '$(Protect-SingleQuotes $transcript)' | Out-Null"
        ". '$(Protect-SingleQuotes (Join-Path $PSScriptRoot 'console-repl.ps1'))' -QueueDir '$(Protect-SingleQuotes $queueDir)'$(if ($script:consoleBackend -eq 'Pipe') { ' -HostShims' })$(if ($DisableCommandLine) { ' -NoCommandLine' })"
    ) -join '; '
    $pty = New-PtyProcess $startup $script:defaultCols $script:defaultRows
    $c = @{
        Id = $Id; Label = $Label; Pty = $pty; Transcript = $transcript; QueueDir = $queueDir
        Out = [System.Collections.Generic.List[byte]]::new(); Base = [long]0
        Buf = [byte[]]::new(8192); ReadTask = $null; Exited = $false; SentVars = @{}
        InBuf = [System.Collections.Generic.List[byte]]::new(); EverAttached = $false
        ErrBuf = [byte[]]::new(8192); ErrTask = $null; AnswerFileSent = $null
        Pending = [System.Collections.Generic.HashSet[string]]::new(); Ready = $false; LastOutputAt = [DateTime]::UtcNow
    }
    $c.ReadTask = $pty.Output.ReadAsync($c.Buf, 0, $c.Buf.Length)
    if ($pty.Error) { $c.ErrTask = $pty.Error.ReadAsync($c.ErrBuf, 0, $c.ErrBuf.Length) }
    $script:consoles[$Id] = $c
    return $c
}

function Get-ConsoleLabel([string]$Id) { if ($Id -eq 'main') { 'Main Thread' } else { 'Thread ' + $Id.Substring('thread-'.Length) } }

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
    if ($Id) { [void]$Console.Pending.Add($Id) }                  # the console is busy until its "<id>.done" marker appears
}

function Update-Consoles {
    foreach ($c in $script:consoles.Values) {
        Write-ConsoleInputChunk $c
        while ($c.ReadTask -and $c.ReadTask.IsCompleted) {
            $n = if ($c.ReadTask.IsFaulted) { 0 } else { $c.ReadTask.Result }
            if ($n -le 0) { $c.ReadTask = $null; break }
            $chunk = [byte[]]::new($n)
            [Array]::Copy($c.Buf, $chunk, $n)
            $c.Out.AddRange($chunk); $c.LastOutputAt = [DateTime]::UtcNow
            if ($c.Out.Count -gt 8MB) { $c.Out.RemoveRange(0, 4MB); $c.Base += 4MB }   # scrollback cap
            $c.ReadTask = $c.Pty.Output.ReadAsync($c.Buf, 0, $c.Buf.Length)
        }
        while ($c.ErrTask -and $c.ErrTask.IsCompleted) {      # stderr (pipe backend only)
            $n = if ($c.ErrTask.IsFaulted) { 0 } else { $c.ErrTask.Result }
            if ($n -le 0) { $c.ErrTask = $null; break }
            $chunk = [byte[]]::new($n)
            [Array]::Copy($c.ErrBuf, $chunk, $n)
            $c.Out.AddRange($chunk); $c.LastOutputAt = [DateTime]::UtcNow
            $c.ErrTask = $c.Pty.Error.ReadAsync($c.ErrBuf, 0, $c.ErrBuf.Length)
        }
        if (-not $c.Ready -and (Test-Path -LiteralPath (Join-Path $c.QueueDir 'ready'))) { $c.Ready = $true }
        foreach ($pendingId in @($c.Pending)) { if (Test-Path -LiteralPath (Join-Path $c.QueueDir "$pendingId.done")) { [void]$c.Pending.Remove($pendingId) } }
        if (-not $c.Exited -and -not $c.ReadTask -and -not $c.ErrTask -and (& $c.Pty.IsExited)) { $c.Exited = $true }
    }
}

# Idle = the console has finished starting, has no queued or running command, and has been quiet for a moment (so the prompt
# the page draws can never land in the middle of a command's own output). cwd comes from the console loop itself.
function Get-ConsoleState($Console) {
    $quiet = ([DateTime]::UtcNow - $Console.LastOutputAt).TotalMilliseconds -gt 150
    if ($Console.Exited -or -not $Console.Ready -or $Console.Pending.Count -gt 0 -or -not $quiet) { return @{ idle = $false; cwd = '' } }
    $cwd = try { (Get-Content -LiteralPath (Join-Path $Console.QueueDir 'cwd') -Raw -ErrorAction Stop).Trim() } catch { '' }
    return @{ idle = $true; cwd = $cwd }
}

# Everything the loaded variables file and the selection define, for a command typed between steps: the WPF UI sends all of
# these to the console as soon as they are loaded, so `$workloadDomain` or `$targetFqdn` are there to inspect. (Steps only
# inject the names they reference.) Only values the console does not already hold are sent.
function Get-VariableInitAll($Console) {
    $names = @(if ($script:answerMap) { $script:answerMap.Keys }) + @($script:selectionDriven) + @('credentialsFilePath')
    $lines = [System.Collections.Generic.List[string]]::new(); $pending = @{}
    foreach ($name in ($names | Select-Object -Unique)) {
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
    if ($Watch.UiKey) { Set-UiStatus $Watch.UiKey $Status }
    if ($Watch.StepId) { $script:stepLedger[$Watch.StepId] = if ($Status -eq 'Done') { 'Success' } else { 'Failed' } }
    if ($Status -eq 'Done' -and $Watch.Cmdlet -eq 'Update-ExtractedSDDCData') { Update-SelectedClusterNameFromDisk }
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

# Makes the console's copy of the interactive answer file match the current one (Import-VCFIRAnswerFile / Clear-VCFIRAnswerFile),
# like Sync-InteractiveAnswerFiles does for every console before a run.
function Get-AnswerFileSync($Console) {
    if ($script:interactiveAnswerFile -eq $Console.AnswerFileSent) { return $null }
    if ($script:interactiveAnswerFile) { return "Import-VCFIRAnswerFile -Path '$(Protect-SingleQuotes $script:interactiveAnswerFile)'" }
    return 'Clear-VCFIRAnswerFile'
}

function Start-Step([string]$PlanId, [int]$StepIndex, [string]$ConsoleId, [bool]$Breakpoint = $false) {
    $entry = Get-CatalogEntry $PlanId
    if (-not $entry) { throw "Unknown plan '$PlanId'" }
    Test-PlanAllowed $entry
    if ($Breakpoint) {
        # The synthetic pause point (Add-EngineeringBreakPointStep): a manual go/no-go gate, Engineering mode only.
        if ($script:uiMode -ne 'Engineering') { throw 'Breakpoints are only available in Engineering mode.' }
        $step = [PSCustomObject]@{ Index = -1; Id = ''; DisplayName = 'Engineering Break Point'; CommandLine = "Confirm-ManualStep -Message 'Press Enter to Continue'"; Condition = @(); ThreadId = ''; Interactive = $true }
    } else {
        $step = Get-PlanSteps $entry | Where-Object { $_.Index -eq $StepIndex } | Select-Object -First 1
        if (-not $step) { throw "Unknown step $StepIndex in plan '$PlanId'" }
    }

    if (-not (Test-StepStatusGate $step)) {
        if ($step.Id) { $script:stepLedger[$step.Id] = 'Skipped' }
        Set-UiStatus $(if ($Breakpoint) { 'bp' } else { $StepIndex }) 'Skipped'
        return @{ skipped = $true }
    }
    # "New-Advisory '...'" is a UI-only pseudo-command (it only exists in the WPF window); resolve it here.
    $adv = [regex]::Match($step.CommandLine, "^New-Advisory\s+'(.*)'\s*$", [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if ($adv.Success) {
        if ($step.Id) { $script:stepLedger[$step.Id] = 'Success' }
        Add-UiAdvisory ($adv.Groups[1].Value -replace "''", "'")
        Set-UiStatus $StepIndex 'Done'
        return @{ advisory = ($adv.Groups[1].Value -replace "''", "'") }
    }

    # A step that references $secureEncryptionPassword needs the backup password; ask for it (once) if we don't hold it.
    if ($step.CommandLine -match '\$secureEncryptionPassword\b' -and [string]::IsNullOrEmpty($script:vars['secureEncryptionPassword'])) {
        return @{ needPassword = $true }
    }

    # Same fallback as the WPF UI: with no credentials path remembered, use the newest one the Retrieve step left behind.
    if ($step.CommandLine -match '\$credentialsFilePath\b' -and [string]::IsNullOrEmpty($script:vars['credentialsFilePath'])) {
        $latest = Get-ChildItem -LiteralPath $WorkingDirectory -Filter 'vcf-credentials-*.json' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($latest) { $script:vars['credentialsFilePath'] = $latest.FullName }
    }

    $console = Get-OrNewConsole $ConsoleId
    if ($console.Exited) { throw "Console '$ConsoleId' has exited; restart it first." }
    $init = Get-VariableInit $console $step
    $answerSync = Get-AnswerFileSync $console
    $initScript = (@($init.Script, $answerSync) | Where-Object { $_ }) -join "`n"
    $cmdlet = ($step.CommandLine -split '\s+', 2)[0]
    $script:watchSeq++
    $id = [string]$script:watchSeq
    $script:watches[$id] = @{
        Id = $id; ConsoleId = $ConsoleId; StepId = $step.Id; Cmdlet = $cmdlet; Target = "Completed Task $cmdlet"
        Offset = (Get-TranscriptLength $console.Transcript); Status = 'Running'; Clean = $null
        UiKey = $(if ($Breakpoint) { 'bp' } else { [string]$StepIndex })
    }
    Set-UiStatus $script:watches[$id].UiKey 'Running'
    Submit-ConsoleCommand $console $initScript $step.CommandLine $id
    foreach ($k in $init.Pending.Keys) { $console.SentVars[$k] = $init.Pending[$k] }
    $console.AnswerFileSent = $script:interactiveAnswerFile
    return @{ watchId = $id; consoleId = $ConsoleId }
}

# ---------------------------------------------------------------- UI session state + Run Plan (server-driven)
function Add-UiAdvisory([string]$Text, [bool]$Failure = $false) {
    [void]$script:ui.advisories.Add(@{ ms = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds(); text = $Text; failure = $Failure })
}
function Set-UiStatus($Key, [string]$Status) { $script:ui.statuses[[string]$Key] = $Status }
function Reset-UiRun { $script:ui.statuses = @{}; $script:ui.pausePointAfter = $null }
function Test-UiBusy {
    if ($script:ui.run -and $script:ui.run.Active) { return $true }
    return (@($script:watches.Values | Where-Object { $_.Status -eq 'Running' -and $_.UiKey }).Count -gt 0)
}
function Set-UiFocus([string]$ConsoleId) { $script:ui.focusSeq++; $script:ui.focusConsole = $ConsoleId }
function New-RunThread([string]$Id) {
    return @{ Id = $Id; ConsoleId = $(if ($Id) { "thread-$Id" } else { 'main' }); List = [System.Collections.Generic.List[object]]::new(); Pos = 0; WatchId = ''; Failed = $null; Done = $false }
}

# Mirrors the page's old runAll: the visible, applicable steps (plus the pause point), consecutive rows that carry a threadId
# form a block whose threads run concurrently, leading steps that are already Done are skipped.
function Start-UiRun([string]$PlanId, [bool]$UseThreads) {
    if (Test-UiBusy) { throw 'A run is already in progress.' }
    $entry = Get-CatalogEntry $PlanId
    if (-not $entry) { throw "Unknown plan '$PlanId'" }
    Test-PlanAllowed $entry
    $items = [System.Collections.Generic.List[object]]::new()
    foreach ($s in @(Get-PlanSteps $entry | Where-Object { $_.Visible -and (Test-StepApplicable $_) })) {
        $items.Add(@{ Index = [int]$s.Index; Key = [string]$s.Index; Name = $s.DisplayName; CommandLine = $s.CommandLine; ThreadId = $s.ThreadId; Interactive = $s.Interactive; Breakpoint = $false })
        if ($null -ne $script:ui.pausePointAfter -and [int]$s.Index -eq [int]$script:ui.pausePointAfter) {
            $items.Add(@{ Index = -1; Key = 'bp'; Name = 'Engineering Break Point'; CommandLine = "Confirm-ManualStep -Message 'Press Enter to Continue'"; ThreadId = ''; Interactive = $true; Breakpoint = $true })
        }
    }
    while ($items.Count -gt 0 -and $script:ui.statuses[$items[0].Key] -eq 'Done') { $items.RemoveAt(0) }
    $blocks = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $items) {
        if (-not $UseThreads -or -not $item.ThreadId) {
            $t = New-RunThread ''; $t.List.Add($item)
            $blocks.Add(@{ Threaded = $false; Threads = @($t) }); continue
        }
        $last = if ($blocks.Count -gt 0) { $blocks[$blocks.Count - 1] } else { $null }
        if (-not ($last -and $last.Threaded)) { $last = @{ Threaded = $true; Threads = [System.Collections.Generic.List[object]]::new() }; $blocks.Add($last) }
        $t = $last.Threads | Where-Object { $_.Id -eq $item.ThreadId } | Select-Object -First 1
        if (-not $t) { $t = New-RunThread $item.ThreadId; $last.Threads.Add($t) }
        $t.List.Add($item)
    }
    $script:ui.run = @{ Active = $true; PlanId = $PlanId; Blocks = $blocks; BlockPos = 0 }
    $script:ui.runStartedAt = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds(); $script:ui.runFinishedAt = $null
    Add-UiAdvisory 'Run Started. Navigation to other domains/clusters disabled.'
}
function Stop-UiRun {
    $script:ui.run.Active = $false
    $script:ui.runFinishedAt = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    Add-UiAdvisory 'Run Finished. Navigation to other domains/clusters re-enabled.'
}
# Advances one thread as far as it can without waiting: finished step -> next step; a step that returns at once (skipped,
# advisory) -> the one after it. Mirrors runThread/runStep.
function Step-RunThread($Run, $Thread) {
    while ($true) {
        if ($Thread.WatchId) {
            $w = $script:watches[$Thread.WatchId]
            if ($w.Status -eq 'Running') { return }
            $Thread.WatchId = ''
            if ($w.Status -ne 'Done') { $Thread.Failed = $Thread.List[$Thread.Pos]; $Thread.Done = $true; return }
            $Thread.Pos++
        }
        if ($Thread.Pos -ge $Thread.List.Count) { $Thread.Done = $true; return }
        $item = $Thread.List[$Thread.Pos]
        try { $r = Start-Step $Run.PlanId $item.Index $Thread.ConsoleId $item.Breakpoint }
        catch {
            Set-UiStatus $item.Key 'Failed'
            Add-UiAdvisory "$($item.Name) was not run: $($_.Exception.Message)" $true
            $Thread.Failed = $item; $Thread.Done = $true; return
        }
        if ($r.needPassword) {                      # the page asks the person; /api/secret clears the flag and this retries
            Set-UiStatus $item.Key 'Running'
            $script:ui.needPassword = $true; $script:ui.pw = @{ Thread = $Thread; Item = $item }
            return
        }
        if ($r.skipped -or $r.advisory) { $Thread.Pos++; continue }
        $Thread.WatchId = $r.watchId
        if ($item.Interactive) { Set-UiFocus $r.consoleId }        # bring the prompt in front, like the WPF UI
        return
    }
}
function Update-Run {
    $run = $script:ui.run
    if (-not $run -or -not $run.Active -or $script:ui.needPassword) { return }
    if ($run.BlockPos -ge $run.Blocks.Count) { Stop-UiRun; return }          # nothing (left) to run, e.g. every step is already Done
    $block = $run.Blocks[$run.BlockPos]
    foreach ($t in @($block.Threads)) {
        if (-not $t.Done) { Step-RunThread $run $t }
        if ($script:ui.needPassword) { return }
    }
    if (@($block.Threads | Where-Object { -not $_.Done }).Count -gt 0) { return }
    $failed = @($block.Threads | Where-Object { $_.Failed })
    if ($failed.Count -gt 0) {
        $cmdlet = ($failed[0].Failed.CommandLine -split '\s+', 2)[0]
        Add-UiAdvisory $(if ($block.Threaded) { 'Run All stopped: one or more threads did not complete cleanly -- check each console/transcript before retrying.' }
                         else { "Run All stopped: $cmdlet did not complete cleanly -- check the console/transcript for warnings, errors, or a PowerShell error record before retrying." }) $true
        Stop-UiRun; return
    }
    if ($block.Threaded) { Set-UiFocus 'main' }
    $run.BlockPos++
    if ($run.BlockPos -ge $run.Blocks.Count) { Stop-UiRun }
}
function Get-UiPayload([int]$Since) {
    $adv = @($script:ui.advisories | Select-Object -Skip $Since)
    return @{
        planId = $script:ui.planId; recoveryType = $script:ui.recoveryType; dataSource = $script:ui.dataSource
        useThreads = $script:ui.useThreads; pausePointAfter = $script:ui.pausePointAfter; toggles = $script:ui.toggles
        extractedPath = $script:extractedPath
        statuses = $script:ui.statuses
        advisories = $adv; advisoryCount = $script:ui.advisories.Count
        busy = (Test-UiBusy)
        runActive = [bool]($script:ui.run -and $script:ui.run.Active)
        runStartedAt = $script:ui.runStartedAt; runFinishedAt = $script:ui.runFinishedAt
        now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        needPassword = $script:ui.needPassword
        focusSeq = $script:ui.focusSeq; focusConsole = $script:ui.focusConsole
    }
}

# ---------------------------------------------------------------- WebSocket clients (one per open console tab)
function Test-ActiveClientLive {
    if (-not $script:activeClient.Id) { return $false }
    if (@($script:wsClients | Where-Object { $_.ClientId -eq $script:activeClient.Id }).Count -gt 0) { return $true }
    return (([DateTime]::UtcNow - $script:activeClient.LastSeen).TotalSeconds -lt 3)
}
function Test-ClientAllowed([string]$ClientId) {
    if (-not $ClientId) { return $true }            # not a page (a script holding the token): never claims or blocks the window
    if ($script:activeClient.Id -eq $ClientId -or -not (Test-ActiveClientLive)) {
        $script:activeClient.Id = $ClientId; $script:activeClient.LastSeen = [DateTime]::UtcNow
        return $true
    }
    return $false
}
function Add-WsAccept($Context, [string]$ConsoleId) {
    # [NullString]::Value, not $null: PowerShell converts a $null argument to "" for a [string] parameter, and
    # AcceptWebSocketAsync rejects an empty subprotocol (ArgumentException) -- the upgrade then never completes.
    [void]$script:pendingAccepts.Add(@{ Task = $Context.AcceptWebSocketAsync([NullString]::Value); ConsoleId = $ConsoleId; ClientId = [string]$Context.Request.QueryString['client'] })
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
            Ws = $ws; ConsoleId = $a.ConsoleId; ClientId = $a.ClientId; RecvBuf = [byte[]]::new(8192); Msg = [System.IO.MemoryStream]::new()
            Sent = $c.Base; SendTask = $null; RecvTask = $null; StateSent = $null
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
        $hello = [Text.Encoding]::UTF8.GetBytes((@{ replay = $replayBytes; backend = $script:consoleBackend.ToLowerInvariant(); commandLine = (-not $DisableCommandLine) } | ConvertTo-Json -Compress))
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
            } else {
                # Caught up with the console's output: tell the page whether the console is idle (and where) or busy. Sent only
                # now so the page draws its prompt after everything the previous command printed.
                $state = Get-ConsoleState $c
                $sig = if ($state.idle) { 'idle|' + $state.cwd } else { 'busy' }
                if ($client.StateSent -cne $sig) {
                    $msg = [Text.Encoding]::UTF8.GetBytes((@{ state = $(if ($state.idle) { 'idle' } else { 'busy' }); cwd = $state.cwd } | ConvertTo-Json -Compress))
                    $client.SendTask = $ws.SendAsync([ArraySegment[byte]]::new($msg), [System.Net.WebSockets.WebSocketMessageType]::Text, $true, [Threading.CancellationToken]::None)
                    $client.StateSent = $sig
                }
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

# The page and its WebSockets identify themselves (X-VCFIR-Client header / client= query). The page itself, the public vendor files
# are exempt, so a second window can load far enough to say why it is refused.
function Test-PageOwner($Context) {
    $req = $Context.Request; $path = $req.Url.AbsolutePath
    if ($path -eq '/' -or $path.StartsWith('/vendor/')) { return $true }
    $id = if ($path -eq '/ws') { [string]$req.QueryString['client'] } else { [string]$req.Headers['X-VCFIR-Client'] }
    return (Test-ClientAllowed $id)
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
        'GET /' { $script:pageSeen = $true; Send-Response $Context ([IO.File]::ReadAllBytes($script:htmlPath)) 'text/html; charset=utf-8' }
        'GET /api/catalog' { Send-Json $Context $script:catalog }
        'GET /api/plan' { Send-Json $Context (Get-PlanPayload $req.QueryString['id']) }
        'GET /api/info' {
            # Lets the page (and a screenshot of it) say exactly which build, OS and console backend is running.
            Send-Json $Context @{
                build   = ((Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.Substring(0, 8))
                os      = [Runtime.InteropServices.RuntimeInformation]::OSDescription
                pwsh    = $PSVersionTable.PSVersion.ToString()
                backend = $script:consoleBackend
                workingDirectory = $WorkingDirectory
                unlocked = $script:engineeringUnlocked
                commandLine = (-not $DisableCommandLine)
                updates  = @(@($CoordinatorUpdateStatus, $InstanceRecoveryUpdateStatus) | Where-Object { $_ })
            }
        }
        'GET /api/consoles' {
            Send-Json $Context @{ consoles = @($script:consoles.Values | ForEach-Object { @{ id = $_.Id; label = $_.Label; exited = $_.Exited; bytes = ($_.Base + $_.Out.Count) } }) }
        }
        'POST /api/console/exec' {
            # A command typed in the page's command line while the console is idle. It runs in the console's own session (so
            # variables, modules and connections are all there) and is echoed like a step. Refused while the console is busy.
            if ($DisableCommandLine) { Send-Json $Context @{ error = 'The command line is disabled (-DisableCommandLine).' } 403; return }
            $body = Read-JsonBody $Context
            $id = [string]$body.id
            if (-not $script:consoles.Contains($id)) { Send-Json $Context @{ error = 'unknown console' } 404; return }
            $console = $script:consoles[$id]
            $command = [string]$body.command
            if ([string]::IsNullOrWhiteSpace($command)) { Send-Json $Context @{ ok = $true }; return }
            if ($command.Length -gt 20000) { throw 'That command is too long.' }
            if (-not (Get-ConsoleState $console).idle) { Send-Json $Context @{ error = 'The console is busy.' } 409; return }
            $init = Get-VariableInitAll $console
            $script:typedSeq++
            Submit-ConsoleCommand $console $init.Script $command ('t' + $script:typedSeq)
            foreach ($k in $init.Pending.Keys) { $console.SentVars[$k] = $init.Pending[$k] }
            Send-Json $Context @{ ok = $true }
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
                if ($script:consoleBackend -eq 'Pipe') {
                    # No terminal, so Ctrl+C can't be delivered as a signal: end the console; the page restarts it.
                    & $script:consoles[$id].Pty.Kill
                } elseif (-not $body.notifyOnly) { $script:consoles[$id].InBuf.Clear(); Send-ConsoleBytes $script:consoles[$id] ([byte[]](3)) }
                foreach ($w in @($script:watches.Values | Where-Object { $_.ConsoleId -eq $id -and $_.Status -eq 'Running' })) { Complete-Watch $w 'Stopped' $false '' }
            }
            Send-Json $Context @{ ok = $true }
        }
        'POST /api/variables' {
            Set-VariablesFromPage (Read-JsonBody $Context).values
            Send-Json $Context @{ ok = $true }
        }
        'POST /api/variables/load' {
            $body = Read-JsonBody $Context
            $r = Import-VariablesFile ([string]$body.path) (Get-CatalogEntry ([string]$body.planId))
            Send-Json $Context @{ ok = $true; count = $r.count; file = $r.file }
        }
        'POST /api/variables/new' {
            $body = Read-JsonBody $Context
            try { $r = New-VariablesFile ([string]$body.path) (Get-CatalogEntry ([string]$body.planId)) ([bool]$body.overwrite) }
            catch { if ($_.Exception.Message -like 'EXISTS:*') { Send-Json $Context @{ exists = $true; file = $_.Exception.Message.Substring(7) }; return }; throw }
            Send-Json $Context @{ ok = $true; count = $r.count; file = $r.file }
        }
        'POST /api/answerfile' {
            Set-InteractiveAnswerFile ([string](Read-JsonBody $Context).path)
            Send-Json $Context @{ ok = $true; file = $script:interactiveAnswerFile }
        }
        'POST /api/secret' {
            # The backup encryption password, asked for by the page the first time a step needs it. Held in memory only.
            $value = [string](Read-JsonBody $Context).value
            if ([string]::IsNullOrEmpty($value)) { throw 'No encryption password was entered.' }
            $script:vars['secureEncryptionPassword'] = $value
            $script:ui.needPassword = $false; $script:ui.pw = $null          # a Run Plan waiting for it retries on its next tick
            Send-Json $Context @{ ok = $true }
        }
        'POST /api/unlock' {
            if (-not (Test-EngineeringModePassword ([string](Read-JsonBody $Context).password))) { Send-Json $Context @{ error = 'Incorrect engineering mode password.' } 403; return }
            $script:engineeringUnlocked = $true
            Send-Json $Context @{ unlocked = $true }
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
                InteractiveAnswerFilePath = $script:interactiveAnswerFile
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
            $entry = Get-CatalogEntry ([string]$state.RecoveryPlanId)
            $warnings = [System.Collections.Generic.List[string]]::new()
            if ($state.ExtractedDataFilePath) { Import-ExtractedData ([string]$state.ExtractedDataFilePath) }
            if ($state.Selection) { Set-InfrastructureSelection ([string]$state.Selection.kind) ([string]$state.Selection.domain) ([string]$state.Selection.cluster) }
            if ($state.VariablesAnswersFilePath) {
                try { [void](Import-VariablesFile ([string]$state.VariablesAnswersFilePath) $entry) } catch { $warnings.Add($_.Exception.Message) }
            }
            if ($state.InteractiveAnswerFilePath) {
                if (Test-Path -LiteralPath ([string]$state.InteractiveAnswerFilePath)) { Set-InteractiveAnswerFile ([string]$state.InteractiveAnswerFilePath) }
                else { $warnings.Add("The interactive answer file '$($state.InteractiveAnswerFilePath)' from the saved state no longer exists -- re-select it with the answer file toggle.") }
            }
            if ($state.CredentialsFilePath) {
                if (Test-Path -LiteralPath ([string]$state.CredentialsFilePath)) { $script:vars['credentialsFilePath'] = [string]$state.CredentialsFilePath }
                else { $warnings.Add("The credentials file '$($state.CredentialsFilePath)' from the saved state no longer exists -- re-run Retrieve SDDC Credentials Payload.") }
            }
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
            Send-Json $Context @{ ok = $true; planId = [string]$state.RecoveryPlanId; completed = $completed; file = $path; warnings = @($warnings) }
        }
        'POST /api/step/run' {
            $body = Read-JsonBody $Context
            Send-Json $Context (Start-Step ([string]$body.planId) ([int]$body.index) ([string]$body.consoleId) ([bool]$body.breakpoint))
        }
        'GET /api/ui' {
            $since = 0; [void][int]::TryParse([string]$req.QueryString['since'], [ref]$since)
            Send-Json $Context (Get-UiPayload $since)
        }
        'POST /api/ui' {
            $body = Read-JsonBody $Context                                  # a hashtable (ConvertFrom-Json -AsHashtable)
            if ($body.ContainsKey('reset') -and $body['reset']) { Reset-UiRun }
            if ($body.ContainsKey('planId')) { $script:ui.planId = [string]$body['planId'] }
            if ($body.ContainsKey('recoveryType')) { $script:ui.recoveryType = [string]$body['recoveryType'] }
            if ($body.ContainsKey('dataSource')) { $script:ui.dataSource = [string]$body['dataSource'] }
            if ($body.ContainsKey('useThreads')) { $script:ui.useThreads = [bool]$body['useThreads'] }
            if ($body.ContainsKey('pausePointAfter')) { $script:ui.pausePointAfter = $(if ($null -eq $body['pausePointAfter']) { $null } else { [int]$body['pausePointAfter'] }) }
            if ($body.ContainsKey('toggles')) { $t = @{}; foreach ($k in $body['toggles'].Keys) { $t[[string]$k] = [bool]$body['toggles'][$k] }; $script:ui.toggles = $t }
            if ($body.ContainsKey('status')) { foreach ($k in $body['status'].Keys) { Set-UiStatus $k ([string]$body['status'][$k]) } }
            if ($body.ContainsKey('statuses')) { $st = @{}; foreach ($k in $body['statuses'].Keys) { $st[[string]$k] = [string]$body['statuses'][$k] }; $script:ui.statuses = $st }
            Send-Json $Context @{ ok = $true }
        }
        'POST /api/ui/advisory' {
            $body = Read-JsonBody $Context
            Add-UiAdvisory ([string]$body.text) ([bool]$body.failure)
            Send-Json $Context @{ ok = $true }
        }
        'POST /api/run/start' {
            $body = Read-JsonBody $Context
            $script:ui.useThreads = [bool]$body.useThreads
            Start-UiRun ([string]$body.planId) ([bool]$body.useThreads)
            Send-Json $Context @{ ok = $true }
        }
        'POST /api/run/passwordcancel' {
            $pw = $script:ui.pw
            if ($script:ui.needPassword -and $pw) {
                $script:ui.needPassword = $false; $script:ui.pw = $null
                Set-UiStatus $pw.Item.Key 'Failed'
                Add-UiAdvisory "$(($pw.Item.CommandLine -split '\s+', 2)[0]) was not run: no encryption password was entered." $true
                $pw.Thread.Failed = $pw.Item; $pw.Thread.Done = $true
            }
            Send-Json $Context @{ ok = $true }
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
    [void](New-ConsoleSession 'main' 'Main Thread')
    $pending = $listener.GetContextAsync()
    while (-not $script:shutdown) {
        $got = try { $pending.Wait(25) } catch { break }
        if ($got) {
            $script:lastClientSeen = [DateTime]::UtcNow
            $context = $pending.Result
            $pending = $listener.GetContextAsync()
            try {
                if (-not (Test-RequestAllowed $context)) {
                    Send-Json $context @{ error = 'forbidden' } 403
                } elseif (-not (Test-PageOwner $context)) {
                    Send-Json $context @{ error = 'This Recovery Coordinator is already open in another window.'; busyElsewhere = $true } 409
                } else {
                    Invoke-Route $context
                }
            } catch {
                try { Send-Json $context @{ error = $_.Exception.Message } 500 } catch { }
            }
        }
        Update-Consoles
        Update-Watches
        try { Update-Run }
        catch {                                    # a fault in the engine must end the run, not the server
            Add-UiAdvisory "Run stopped on an internal error: $($_.Exception.Message) [$($_.ScriptStackTrace -replace '\r?\n', ' | ')]" $true
            if ($script:ui.run) { Stop-UiRun }
            $script:ui.needPassword = $false
        }
        Update-Clients
        if ($script:wsClients.Count -gt 0) { $script:lastClientSeen = [DateTime]::UtcNow }       # a connected window counts as "seen"
        # A jump in the loop's own clock means the machine slept: the window could not have spoken while it was suspended.
        if (([DateTime]::UtcNow - $script:lastTick).TotalSeconds -gt 5) { $script:lastClientSeen = [DateTime]::UtcNow }
        $script:lastTick = [DateTime]::UtcNow
        $quiet = ([DateTime]::UtcNow - $script:lastClientSeen).TotalSeconds
        if ($script:pageSeen) { if ($quiet -ge $CloseGraceSeconds) { $script:shutdown = $true } }      # the window was closed: so is everything it was running
        elseif ($IdleTimeoutMinutes -gt 0 -and $quiet -ge ($IdleTimeoutMinutes * 60)) { $script:shutdown = $true }
    }
} finally {
    foreach ($c in $script:consoles.Values) { try { & $c.Pty.Kill } catch { }; Remove-Item -LiteralPath $c.QueueDir -Recurse -Force -ErrorAction SilentlyContinue }
    $listener.Stop()
    $listener.Close()
}
