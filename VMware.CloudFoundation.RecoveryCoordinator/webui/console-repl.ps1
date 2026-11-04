# The body of every Recovery Coordinator web console. Dot-sourced (so it runs in the console's GLOBAL scope)
# by the startup command the web server gives each console's pwsh.
#
# Why this exists instead of typing commands into an interactive prompt: pwsh on a pseudo-terminal asks
# the terminal for the cursor position (and PSReadLine does so repeatedly); the terminal's replies arrive on
# stdin, and any text injected at the same moment gets interleaved with them, which corrupted commands.
# Here nothing is ever injected. The server drops each step into a queue directory as a small JSON file;
# this loop picks it up, echoes it, and runs it in the SAME session (so variables, loaded modules, and
# connections persist from step to step, like the WPF console). While a command runs, stdin belongs to the
# command alone, so a Read-Host prompt reads exactly what the person types into the terminal.
#
# Trade-off, deliberately accepted: at the idle moment between steps nothing reads stdin, so this console
# answers prompts but is not a free-typing shell. Ctrl+C ends this process; the page restarts the console.
param([Parameter(Mandatory)][string]$QueueDir, [switch]$HostShims, [switch]$NoCommandLine)

# Pipe backend only (stdin/stdout are redirected, there is no terminal). Two things a real console host does that a redirected
# pwsh does not, both needed to look and behave like the WPF console:
#   * Write-Host -ForegroundColor/-BackgroundColor: a redirected host drops the colour, so the module's yellow prompts
#     ("Enter the ID of the Manager ...") would come out plain. This stand-in turns the colours into ANSI codes, which the
#     page's terminal renders. (Functions defined here are global, so the module's own Write-Host calls resolve to it.)
#   * Read-Host: with redirected input, the real one echoes the line it read back to the output, so an answer would appear
#     twice (the page already shows what you type). This one reads a line without echoing it.
if ($HostShims) {
    function global:Write-Host {
        [CmdletBinding()]
        param(
            [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromRemainingArguments = $true)][object[]]$Object,
            [switch]$NoNewline, [object]$Separator, [ConsoleColor]$ForegroundColor, [ConsoleColor]$BackgroundColor
        )
        process {
            $sep = if ($PSBoundParameters.ContainsKey('Separator')) { [string]$Separator } else { ' ' }
            $text = (@($Object) | ForEach-Object { if ($null -eq $_) { '' } else { "$_" } }) -join $sep
            $ansi = @(30, 34, 32, 36, 31, 35, 33, 37, 90, 94, 92, 96, 91, 95, 93, 97)       # ConsoleColor 0..15 -> SGR foreground
            $esc = [char]27; $prefix = ''
            if ($PSBoundParameters.ContainsKey('ForegroundColor')) { $prefix += "$esc[$($ansi[[int]$ForegroundColor])m" }
            if ($PSBoundParameters.ContainsKey('BackgroundColor')) { $prefix += "$esc[$($ansi[[int]$BackgroundColor] + 10)m" }
            if ($prefix) { $text = $prefix + $text + "$esc[0m" }
            Microsoft.PowerShell.Utility\Write-Host -Object $text -NoNewline:$NoNewline
        }
    }
    function global:Read-Host {
        [CmdletBinding()]
        param([Parameter(Position = 0)][object]$Prompt, [switch]$AsSecureString, [switch]$MaskInput)
        if ($null -ne $Prompt -and "$Prompt" -ne '') { Microsoft.PowerShell.Utility\Write-Host -Object ("$Prompt" + ': ') -NoNewline }
        $line = [Console]::In.ReadLine()
        if ($null -eq $line) { $line = '' }
        if ($AsSecureString) { return (ConvertTo-SecureString -String $line -AsPlainText -Force) }
        return $line
    }
}

$ErrorView = 'NormalView'          # keeps "+ CategoryInfo" in error output (the step cleanliness gate looks for it)
$ErrorActionPreference = 'Continue'

if ($NoCommandLine) { Write-Host 'Recovery Coordinator console ready. Steps you Run appear here; type here only to answer a prompt.' }
else { Write-Host 'Recovery Coordinator console ready. Steps you Run appear here; between steps you can type commands at the prompt.' }

# Tells the server when this console is idle and where it is, so the page can offer a command line between steps: `cwd`
# is rewritten after every command (a typed `Set-Location` changes it), and `ready` appears once, just before the loop.
$__vcfirSent = $false                  # has this console run a step yet (the first one gets no leading blank prompt line)
$__vcfirPublish = { [IO.File]::WriteAllText((Join-Path $QueueDir 'cwd'), (Get-Location).Path) }
& $__vcfirPublish
[IO.File]::WriteAllText((Join-Path $QueueDir 'ready'), '')

while ($true) {
    $__vcfirItem = Get-ChildItem -LiteralPath $QueueDir -Filter '*.json' -File -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -First 1
    if (-not $__vcfirItem) { Start-Sleep -Milliseconds 100; continue }
    $__vcfirJob = Get-Content -LiteralPath $__vcfirItem.FullName -Raw | ConvertFrom-Json
    Remove-Item -LiteralPath $__vcfirItem.FullName -Force

    # "init" (variable assignments, possibly secrets) runs silently and is never echoed or logged.
    if ($__vcfirJob.init) {
        try { . ([scriptblock]::Create($__vcfirJob.init)) } catch { Write-Error -ErrorRecord $_ }
    }
    # Like the WPF console, which types a blank Enter ahead of every command but a console's first: an empty prompt line is the
    # visual delimiter between one task's output and the next. Steps only -- a command typed at the idle prompt (id "t<n>") is
    # not preceded by one, just as typing there in the WPF console isn't.
    if ($__vcfirSent -and $__vcfirJob.id -match '^\d+$') { Write-Host ("PS {0}> " -f (Get-Location).Path) }
    if ($__vcfirJob.id -match '^\d+$') { $__vcfirSent = $true }
    Write-Host ("PS {0}> {1}" -f (Get-Location).Path, $__vcfirJob.command)
    try { . ([scriptblock]::Create($__vcfirJob.command)) } catch { Write-Error -ErrorRecord $_ }
    # Tell the server this command has RETURNED (however it ended). A step normally signals success by logging its own
    # "Completed Task <cmdlet>" line; if the command ends without having logged one (it crashed, say), the server sees
    # this marker and reports the step as failed instead of waiting for a line that will never come.
    & $__vcfirPublish                                  # the (possibly changed) folder first ...
    if ($__vcfirJob.id) { [IO.File]::WriteAllText((Join-Path $QueueDir "$($__vcfirJob.id).done"), '') }   # ... then "finished"
}
