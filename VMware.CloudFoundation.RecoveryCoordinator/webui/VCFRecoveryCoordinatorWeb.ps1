# Cross-platform (Windows / macOS / Linux) front end for the VCF Recovery Coordinator -- SPIKE.
#
# A single-threaded localhost web server (System.Net.HttpListener) that serves webui\index.html and a
# small JSON API over the SAME plan catalog / plan files the WPF UI (xaml\VCFRecoveryCoordinatorUI.ps1)
# uses. Nothing here touches WPF or Win32, so it runs anywhere PowerShell 7 does.
#
# Differences from the WPF UI that matter (see webui\README.md for the full list):
#   * Each step runs in its OWN fresh pwsh child process (redirected stdin/stdout/stderr), not in a
#     long-lived embedded console. Variables are re-injected as assignments at the top of every step.
#   * Output is a plain text stream (ANSI colours rendered by the page), not a terminal emulator.
#   * Read-Host style prompts are answered through an input box that writes to the child's stdin.
#
# Security model: the server executes commands taken from plan files, so it is locked down --
# loopback only, a random per-launch token on every request, Host/Origin checks (DNS-rebinding and
# cross-site protection), and /api/run only accepts a plan id + step index (never a command line).
param(
    [Parameter(Mandatory)][string]$PlansPath,
    [Parameter(Mandatory)][string]$Token,
    [int]$Port = 0,
    [string]$WorkingDirectory = (Get-Location).Path,
    # Module files the child consoles import (the dev repo is usually not on PSModulePath).
    [string]$CoordinatorModulePath,
    [string]$InstanceRecoveryModulePath
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- state
$script:htmlPath = Join-Path $PSScriptRoot 'index.html'
$script:catalog = Get-Content -LiteralPath (Join-Path $PlansPath 'recovery-plan-catalog.json') -Raw | ConvertFrom-Json
$script:vars = [ordered]@{}            # name -> string value, shared by every step (like a console's session variables)
$script:runs = @{}                     # runId -> run record
$script:runSequence = 0
$script:shutdown = $false
$script:pwshPath = (Get-Process -Id $PID).Path
$script:ignoredVariableNames = @('true', 'false', 'null', '_', 'env', 'PSScriptRoot', 'PSItem', 'args', 'input')

# ---------------------------------------------------------------- plan / condition logic
# (Ported from the WPF script: Get-RecoveryPlanSteps, Test-ConditionOperator, Test-StepCondition.
#  dataPath conditions need the extracted-data context the WPF UI builds; not ported yet, so they
#  fail open exactly like the WPF code does for anything it can't evaluate.)
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

function Test-StepApplicable($Step) {
    foreach ($c in $Step.Condition) {
        if ($null -eq $c -or $c -is [string]) { continue }
        try {
            if ($c.type -eq 'variable') {
                $actual = if ($script:vars.Contains($c.name)) { $script:vars[$c.name] } else { $null }
                if (-not (Test-ConditionOperator $c.operator $actual $c.value)) { return $false }
            }
        } catch { }   # fail open, as the WPF UI does
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
                @{ name = $_; value = $(if ($script:vars.Contains($_)) { $script:vars[$_] } else { '' }); secret = ($_ -match 'password|passphrase') }
            })
    }
}

# ---------------------------------------------------------------- runs (one pwsh child per step)
function Protect-SingleQuotes([string]$Value) { return $Value.Replace("'", "''") }

function New-StepScript($Step) {
    $lines = [System.Collections.Generic.List[string]]::new()
    [void]$lines.Add('$ErrorView = ''NormalView''')   # keeps "+ CategoryInfo" in uncaught errors (completion gate relies on it)
    [void]$lines.Add("Set-Location -LiteralPath '$(Protect-SingleQuotes $WorkingDirectory)'")
    if ($InstanceRecoveryModulePath) { [void]$lines.Add("Import-Module -Force '$(Protect-SingleQuotes $InstanceRecoveryModulePath)'") }
    if ($CoordinatorModulePath) { [void]$lines.Add("Import-Module -Force '$(Protect-SingleQuotes $CoordinatorModulePath)'") }
    foreach ($name in (Get-ReferencedVariableNames @($Step.CommandLine))) {
        if (-not $script:vars.Contains($name) -or [string]::IsNullOrEmpty($script:vars[$name])) { continue }
        $value = Protect-SingleQuotes $script:vars[$name]
        if ($name -eq 'secureEncryptionPassword') {
            [void]$lines.Add("`$$name = ConvertTo-SecureString '$value' -AsPlainText -Force")
        } else {
            [void]$lines.Add("`$$name = '$value'")
        }
    }
    [void]$lines.Add($Step.CommandLine)
    return ($lines -join "`n")
}

function Start-StepRun([string]$PlanId, [int]$StepIndex) {
    $entry = Get-CatalogEntry $PlanId
    if (-not $entry) { throw "Unknown plan '$PlanId'" }
    $step = Get-PlanSteps $entry | Where-Object { $_.Index -eq $StepIndex } | Select-Object -First 1
    if (-not $step) { throw "Unknown step $StepIndex in plan '$PlanId'" }

    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes((New-StepScript $step)))
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $script:pwshPath
    # -OutputFormat/-InputFormat Text: with -EncodedCommand and redirected streams pwsh otherwise serializes
    # errors/output as CLIXML ("#< CLIXML ...") instead of plain text.
    foreach ($a in '-NoLogo', '-NoProfile', '-OutputFormat', 'Text', '-InputFormat', 'Text', '-EncodedCommand', $encoded) { $psi.ArgumentList.Add($a) }
    $psi.WorkingDirectory = $WorkingDirectory
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [Text.Encoding]::UTF8
    $process = [System.Diagnostics.Process]::Start($psi)

    $script:runSequence++
    $id = [string]$script:runSequence
    $logPath = Join-Path $WorkingDirectory ("vcfir-web-{0}-{1}-{2}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'), $PID, $id)
    $newStream = { param($reader) @{ Reader = $reader; Buf = [char[]]::new(4096); Task = $null } }
    $run = @{
        Id = $id; Name = $step.DisplayName; Process = $process; Output = [System.Text.StringBuilder]::new()
        Status = 'Running'; Clean = $null; ExitCode = $null; LogPath = $logPath; Streams = @()
    }
    foreach ($reader in $process.StandardOutput, $process.StandardError) {
        $s = & $newStream $reader
        $s.Task = $s.Reader.ReadAsync($s.Buf, 0, $s.Buf.Length)
        $run.Streams += , $s
    }
    $script:runs[$id] = $run
    return $id
}

# Called from the main loop every ~100ms. Everything is polled on the one server thread, so no
# event handlers / runspaces / locks are needed.
function Update-Runs {
    foreach ($run in @($script:runs.Values | Where-Object { $_.Status -eq 'Running' })) {
        foreach ($s in $run.Streams) {
            while ($s.Task -and $s.Task.IsCompleted) {
                $n = if ($s.Task.IsFaulted) { 0 } else { $s.Task.Result }
                if ($n -le 0) { $s.Task = $null; break }
                $chunk = [string]::new($s.Buf, 0, $n)
                [void]$run.Output.Append($chunk)
                [System.IO.File]::AppendAllText($run.LogPath, $chunk)
                $s.Task = $s.Reader.ReadAsync($s.Buf, 0, $s.Buf.Length)
            }
        }
        $streamsDone = -not ($run.Streams | Where-Object { $_.Task })
        if ($streamsDone -and $run.Process.HasExited) {
            $run.ExitCode = $run.Process.ExitCode
            $text = $run.Output.ToString()
            # Same gate as Test-StepTranscriptClean in the WPF UI.
            $run.Clean = -not ($text.Contains('[WARNING]') -or $text.Contains('[ERROR]') -or $text.Contains('[EXCEPTION]') -or $text.Contains('+ CategoryInfo'))
            $run.Status = if ($run.ExitCode -ne 0) { 'Failed' } elseif ($run.Clean) { 'Done' } else { 'Attention' }
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
    $r.Headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline'"
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
    $allowedHosts = @("127.0.0.1:$script:listenPort", "localhost:$script:listenPort")
    if ($req.Headers['Host'] -notin $allowedHosts) { return $false }                       # DNS rebinding
    $origin = $req.Headers['Origin']
    if ($origin -and ($origin -notin @("http://127.0.0.1:$script:listenPort", "http://localhost:$script:listenPort"))) { return $false }   # cross-site
    $supplied = if ($req.Url.AbsolutePath -eq '/') { $req.QueryString['t'] } else { $req.Headers['X-VCFIR-Token'] }
    return ($supplied -and $supplied -ceq $Token)
}

function Invoke-Route($Context) {
    $req = $Context.Request
    $path = $req.Url.AbsolutePath
    $method = $req.HttpMethod
    switch ("$method $path") {
        'GET /' {
            Send-Response $Context ([System.IO.File]::ReadAllBytes($script:htmlPath)) 'text/html; charset=utf-8'
        }
        'GET /api/catalog' { Send-Json $Context $script:catalog }
        'GET /api/plan' { Send-Json $Context (Get-PlanPayload $req.QueryString['id']) }
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
            $file = (Resolve-Path -LiteralPath ([string]$body.path)).Path
            $loaded = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json -AsHashtable
            foreach ($k in $loaded.Keys) {
                $v = $loaded[$k]
                # Scalars only (string/number/bool/null); nested objects aren't variables.
                if ($k -match '^[A-Za-z_][A-Za-z0-9_]*$' -and ($null -eq $v -or $v -is [string] -or $v -is [ValueType])) {
                    $script:vars[$k] = if ($null -eq $v) { '' } else { [string]$v }
                }
            }
            Send-Json $Context @{ ok = $true; count = $loaded.Count }
        }
        'POST /api/run' {
            $body = Read-JsonBody $Context
            Send-Json $Context @{ runId = (Start-StepRun ([string]$body.planId) ([int]$body.index)) }
        }
        'GET /api/run' {
            $run = $script:runs[$req.QueryString['id']]
            if (-not $run) { Send-Json $Context @{ error = 'unknown run' } 404; return }
            $from = [int]$req.QueryString['from']
            $len = $run.Output.Length
            if ($from -gt $len) { $from = $len }
            Send-Json $Context @{ status = $run.Status; clean = $run.Clean; exitCode = $run.ExitCode; length = $len; text = $run.Output.ToString($from, $len - $from); name = $run.Name; logPath = $run.LogPath }
        }
        'POST /api/input' {
            $body = Read-JsonBody $Context
            $run = $script:runs[[string]$body.runId]
            if ($run -and $run.Status -eq 'Running') { $run.Process.StandardInput.WriteLine([string]$body.text); $run.Process.StandardInput.Flush() }
            Send-Json $Context @{ ok = [bool]$run }
        }
        'POST /api/stop' {
            $body = Read-JsonBody $Context
            $run = $script:runs[[string]$body.runId]
            if ($run -and $run.Status -eq 'Running') { $run.Status = 'Stopped'; try { $run.Process.Kill($true) } catch { } }
            Send-Json $Context @{ ok = [bool]$run }
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
    $pending = $listener.GetContextAsync()
    while (-not $script:shutdown) {
        $got = try { $pending.Wait(100) } catch { break }
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
        Update-Runs
    }
} finally {
    foreach ($run in $script:runs.Values) {
        if ($run.Status -eq 'Running') { try { $run.Process.Kill($true) } catch { } }
    }
    $listener.Stop()
    $listener.Close()
}
