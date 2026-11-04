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
param([Parameter(Mandatory)][string]$QueueDir)

$ErrorView = 'NormalView'          # keeps "+ CategoryInfo" in error output (the step cleanliness gate looks for it)
$ErrorActionPreference = 'Continue'

Write-Host 'Recovery Coordinator console ready. Steps you Run appear here; type here only to answer a prompt.'

while ($true) {
    $__vcfirItem = Get-ChildItem -LiteralPath $QueueDir -Filter '*.json' -File -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -First 1
    if (-not $__vcfirItem) { Start-Sleep -Milliseconds 100; continue }
    $__vcfirJob = Get-Content -LiteralPath $__vcfirItem.FullName -Raw | ConvertFrom-Json
    Remove-Item -LiteralPath $__vcfirItem.FullName -Force

    # "init" (variable assignments, possibly secrets) runs silently and is never echoed or logged.
    if ($__vcfirJob.init) {
        try { . ([scriptblock]::Create($__vcfirJob.init)) } catch { Write-Error -ErrorRecord $_ }
    }
    Write-Host ("PS {0}> {1}" -f (Get-Location).Path, $__vcfirJob.command)
    try { . ([scriptblock]::Create($__vcfirJob.command)) } catch { Write-Error -ErrorRecord $_ }
    # Tell the server this command has RETURNED (however it ended). A step normally signals success by logging its own
    # "Completed Task <cmdlet>" line; if the command ends without having logged one (it crashed, say), the server sees
    # this marker and reports the step as failed instead of waiting for a line that will never come.
    if ($__vcfirJob.id) { [IO.File]::WriteAllText((Join-Path $QueueDir "$($__vcfirJob.id).done"), '') }
}
