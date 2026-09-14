# Copyright 2025 Broadcom. All Rights Reserved.
# SPDX-License-Identifier: BSD-2

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# This module is the UI-facing counterpart to VMware.CloudFoundation.InstanceRecovery: it launches
# the VCF Recovery Coordinator window (Start-VCFRecoveryCoordinator) and provides the small set of
# session-variable cmdlets that window's own embedded console relies on
# (Import-RecoveryVariables/Set-ExportedSDDCDataFilePath/Set-SelectedRecoveryTarget). It has no
# instance-recovery logic of its own -- every actual recovery cmdlet a plan step calls remains in
# VMware.CloudFoundation.InstanceRecovery, declared as a required module below.
#
# LogMessage itself is deliberately a LOCAL COPY (see Supporting Functions below), not left to
# resolve via that dependency, even though InstanceRecovery exports its own copy too: this module's
# whole purpose is spawning a brand-new console process on demand (see Start-VCFRecoveryCoordinator),
# and every function here needs to be able to write output to screen on its own from the very first
# call, without depending on module load order or a transitive RequiredModules auto-load succeeding
# first. A function defined in a module always resolves an unqualified call to another function of
# the same name against ITS OWN module's internal copy first, regardless of what else is imported --
# so this local copy is what every cmdlet in this file actually uses.

#Region Supporting Functions

Function LogMessage {
    Param (
        [Parameter (Mandatory = $true)] [AllowEmptyString()] [String]$message,
        [Parameter (Mandatory = $false)] [Switch]$nonewline,
        [Parameter (Mandatory = $false)] [ValidateSet("INFO", "ERROR", "WARNING", "EXCEPTION", "ADVISORY", "NOTE", "QUESTION", "WAIT")] [String]$type = "INFO"
    )

    If (!$colour) {
        $colour = "92m" #Green
    }

    If ($type -eq "INFO") {
        $messageColour = "92m" #Green
    } elseIf ($type -in "ERROR", "EXCEPTION") {
        $messageColour = "91m" # Red
    } elseIf ($type -in "WARNING", "ADVISORY", "QUESTION") {
        $messageColour = "93m" #Yellow
    } elseIf ($type -in "NOTE", "WAIT") {
        $messageColour = "97m" # White
    }

    <#
    Reference Colours
    31m Red
    32m Green
    33m Yellow
    36m Cyan
    37m White
    91m Bright Red
    92m Bright Green
    93m Bright Yellow
    95m Bright Magenta
    96m Bright Cyan
    97m Bright White
    #>
    $ESC = [char]0x1b
    $timeStamp = Get-Date -Format "MM-dd-yyyy_HH:mm:ss"
    $timestampColour = "97m"

    If ($nonewline) {
        Write-Host "$ESC[${timestampcolour} [$timestamp]$ESC[${messageColour} [$type] $message$ESC[0m" -NoNewline
    } else {
        Write-Host "$ESC[${timestampcolour} [$timestamp]$ESC[${messageColour} [$type] $message$ESC[0m"
    }
}

#EndRegion Supporting Functions

#Region Recovery Variables

Function Import-RecoveryVariables {
    <#
    .SYNOPSIS
    Loads a flat JSON answers file into the current session as variables

    .DESCRIPTION
    The Import-RecoveryVariables cmdlet reads a flat JSON object (e.g. { "targetFqdn": "...",
    "targetAdminPassword": "..." }) and sets each property as a variable in the caller's session, so
    the other Instance Recovery cmdlets in this module can reference them directly (e.g. $targetFqdn)
    without every value having to be passed explicitly on the command line.

    .PARAMETER Path
    Path to the JSON variable answers file.

    .EXAMPLE
    Import-RecoveryVariables -Path 'C:\VCFIR\answers.json'
    #>
    Param(
        [Parameter (Mandatory = $true)][String] $Path
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()

    LogMessage -type INFO -message "[$jumpboxName] Loading variables from '$Path'"
    $answers = Get-Content -Path $Path -Raw | ConvertFrom-Json
    foreach ($property in $answers.PSObject.Properties) {
        # extractedSDDCDataFile comes from the orchestrator UI's own Data Source selection, and
        # workloadDomain/clusterName from its domain/cluster selection -- not the answers file. An
        # answer file that happens to also define any of them (e.g. one saved before these became
        # selection-driven) must never overwrite the live selection, or a step would silently run
        # against the wrong domain or cluster.
        if ($property.Name -in @('extractedSDDCDataFile', 'workloadDomain', 'clusterName')) {
            continue
        }
        Set-Variable -Name $property.Name -Value ([string]$property.Value) -Scope Global
    }

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Import-RecoveryVariables

Function Set-ExportedSDDCDataFilePath {
    <#
    .SYNOPSIS
    Sets $extractedSDDCDataFile in the current session

    .DESCRIPTION
    The Set-ExportedSDDCDataFilePath cmdlet sets $extractedSDDCDataFile to the given path, so the
    other Instance Recovery cmdlets in this module can reference it directly without it needing to be
    passed explicitly on the command line every time.

    .PARAMETER Path
    Path to the extracted SDDC data JSON file.

    .EXAMPLE
    Set-ExportedSDDCDataFilePath -Path 'C:\VCFIR\extracted-sddc-data.json'
    #>
    Param(
        [Parameter (Mandatory = $true)][String] $Path
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()

    LogMessage -type INFO -message "[$jumpboxName] Setting extracted SDDC data file path to '$Path'"
    Set-Variable -Name 'extractedSDDCDataFile' -Value $Path -Scope Global

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Set-ExportedSDDCDataFilePath

Function Set-SelectedRecoveryTarget {
    <#
    .SYNOPSIS
    Sets $workloadDomain and/or $clusterName in the current session

    .DESCRIPTION
    The Set-SelectedRecoveryTarget cmdlet sets $workloadDomain and $clusterName, so the other
    Instance Recovery cmdlets in this module can reference them directly without either needing to be
    passed explicitly on the command line every time. The orchestrator UI calls this whenever a
    domain or cluster is selected, which is the single source of truth for what the plan's steps act
    on -- both values come from one selection, so they are set together in a single call rather than
    one call each.

    Import-RecoveryVariables deliberately ignores workloadDomain and clusterName found in an answers
    file, so a stale file can never point the steps at a different domain or cluster than the one
    selected on screen.

    .PARAMETER WorkloadDomain
    Name of the selected workload domain.

    .PARAMETER ClusterName
    Name of the selected vSphere cluster. For a domain selection this is that domain's default
    cluster; for an additional-cluster selection it is the cluster that was picked.

    .EXAMPLE
    Set-SelectedRecoveryTarget -WorkloadDomain 'sfo-w02' -ClusterName 'sfo-w02-cl02'

    .EXAMPLE
    Set-SelectedRecoveryTarget -ClusterName 'sfo-w02-cl02'
    #>
    Param(
        [Parameter (Mandatory = $false)][String] $WorkloadDomain,
        [Parameter (Mandatory = $false)][String] $ClusterName
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()

    if ($PSBoundParameters.ContainsKey('WorkloadDomain')) {
        LogMessage -type INFO -message "[$jumpboxName] Setting selected workload domain to '$WorkloadDomain'"
        Set-Variable -Name 'workloadDomain' -Value $WorkloadDomain -Scope Global
    }
    if ($PSBoundParameters.ContainsKey('ClusterName')) {
        LogMessage -type INFO -message "[$jumpboxName] Setting selected cluster name to '$ClusterName'"
        Set-Variable -Name 'clusterName' -Value $ClusterName -Scope Global
    }
    if (-not $PSBoundParameters.ContainsKey('WorkloadDomain') -and -not $PSBoundParameters.ContainsKey('ClusterName')) {
        LogMessage -type WARNING -message "[$jumpboxName] Neither -WorkloadDomain nor -ClusterName was supplied; nothing was set."
    }

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Set-SelectedRecoveryTarget

#EndRegion Recovery Variables

#Region UI Orchestrator

Function Start-VCFRecoveryCoordinator {
    <#
    .SYNOPSIS
    Launches the VCF Recovery Coordinator UI

    .DESCRIPTION
    The Start-VCFRecoveryCoordinator cmdlet opens a WPF window -- built by a standalone script
    (xaml\VCFRecoveryOrchestratorUI.ps1) that lets you pick an extracted-sddc-data.json file,
    lists the workload domains it contains, and runs the recovery steps for the selected domain in an
    embedded console. That console is a plain read-only output pane plus a single-line input box fed
    by a second, ordinary pwsh.exe process with redirected stdin/stdout/stderr -- not a terminal
    emulator control. This app's console traffic is entirely line-based (LogMessage output and
    single-line Read-Host-style prompts), so it never needed real terminal emulation in the first
    place, and the vendored terminal control that used to provide it was the source of most of this
    feature's problems (a crash bug, and a rendering corruption bug confirmed to be in that control's
    own rendering, not in PowerShell or anything this module does).

    The UI script runs as its own separate, detached pwsh.exe process, not a runspace inside this one.
    That's deliberate: WPF allows only one Application object (and one Dispatcher/message loop) per
    process, and once that shuts down -- which happens automatically the moment its last window truly
    closes -- it can never run again for the rest of that process's life. Running the UI in-process
    meant the first launch worked, but every later one in the same PowerShell session silently did
    nothing at all: the Application constructor threw on a background thread nothing was watching, so
    the cmdlet still reported success even though nothing was ever going to appear. A separate process
    has no such constraint -- closing the window ends that process cleanly, and the next launch starts
    a genuinely fresh one, every time.

    This cmdlet returns control to your console immediately. Each call starts a genuinely new,
    separate instance -- calling it again while an earlier window is still open opens another one
    alongside it rather than reusing or focusing the existing window.

    .EXAMPLE
    Start-VCFRecoveryCoordinator
    #>

    Param()

    $moduleRoot = $PSScriptRoot
    $xamlPath = Join-Path $moduleRoot 'xaml\VCFRecoveryOrchestratorUI.xaml'
    $uiScriptPath = Join-Path $moduleRoot 'xaml\VCFRecoveryOrchestratorUI.ps1'
    # Recovery plans (Management Domain Restores, Recover Default Cluster, etc) live here as a JSON
    # array of step objects (commandLine/condition/threadId) per plan file -- see
    # Get-RecoveryPlanSteps in the UI script. Kept outside both the .psm1 and the UI script so
    # editing a plan never requires recompiling the module or restarting anything: the UI script
    # re-reads these files every time a domain is (re)selected.
    $plansPath = Join-Path $moduleRoot 'plans'
    # Captured here, not inside the UI script: that runs in a separate process which has no notion
    # of "the caller's current directory" of its own. The console process is started with this as
    # its own working directory (see Set-Location in the UI script), and transcripts are written
    # here too, so both land wherever the user ran this cmdlet from.
    $launchDirectory = (Get-Location).Path

    if (-not (Test-Path $xamlPath)) {
        LogMessage -type ERROR -message "Cannot find UI resource '$xamlPath'."
        return
    }
    if (-not (Test-Path $uiScriptPath)) {
        LogMessage -type ERROR -message "Cannot find UI script '$uiScriptPath'."
        return
    }
    if (-not (Test-Path $plansPath)) {
        LogMessage -type ERROR -message "Cannot find plans folder '$plansPath'."
        return
    }

    $pwshPath = (Get-Process -Id $PID).Path   # same pwsh.exe/powershell.exe build this session is running under

    # ProcessStartInfo.ArgumentList, not Start-Process's own -ArgumentList: the cmdlet's version just
    # joins array elements with spaces and does not quote ones that themselves contain spaces, which
    # breaks the moment the module is installed under a path like "C:\Program Files\..." -- pwsh.exe's
    # own command-line parser then splits that path at the space and can't find a script file at all.
    # ArgumentList.Add() here quotes each argument correctly regardless of what it contains.
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $pwshPath
    # pwsh.exe is a console-subsystem executable, so launching it this way would otherwise open a
    # visible console window behind the WPF one -- the in-process runspace this used to run in never
    # showed one, and the orchestrator window is the only thing meant to be visible.
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    # -STA must come before -File: anything after -File's own value is passed through as an argument
    # to the script itself, not interpreted as a pwsh.exe switch. WPF requires an STA thread, and
    # pwsh.exe's own usage text lists both -STA and -MTA as real switches -- meaning the apartment
    # state a plain launch ends up with isn't something to assume. Without this, Application.Run()
    # throws right after the window is constructed, which is invisible with CreateNoWindow set above:
    # the whole process just exits, and the window vanishes with no error shown anywhere.
    $startInfo.ArgumentList.Add('-STA')
    $startInfo.ArgumentList.Add('-NoProfile')
    $startInfo.ArgumentList.Add('-File')
    $startInfo.ArgumentList.Add($uiScriptPath)
    $startInfo.ArgumentList.Add('-XamlPath')
    $startInfo.ArgumentList.Add($xamlPath)
    $startInfo.ArgumentList.Add('-WorkingDirectory')
    $startInfo.ArgumentList.Add($launchDirectory)
    $startInfo.ArgumentList.Add('-PlansPath')
    $startInfo.ArgumentList.Add($plansPath)

    # Redirected only so a fast, unhandled failure (e.g. an exception thrown before Application.Run()
    # ever starts pumping messages) has somewhere to be read back from below -- not read from at all
    # while the process is still running, since that would block once its stderr's pipe buffer filled.
    $startInfo.RedirectStandardError = $true

    $process = [System.Diagnostics.Process]::Start($startInfo)

    # A real launch stays open indefinitely; this is only long enough to catch a launch that failed
    # outright, so this cmdlet reports what actually happened instead of claiming success regardless,
    # the way it used to when the old in-process approach's background-thread exceptions went unread.
    Start-Sleep -Milliseconds 750
    $process.Refresh()
    if ($process.HasExited) {
        $errorOutput = $process.StandardError.ReadToEnd()
        LogMessage -type ERROR -message "VCF Recovery Coordinator UI exited immediately (exit code $($process.ExitCode)). $errorOutput"
        return
    }

    LogMessage -type NOTE -message "VCF Recovery Coordinator UI launched (PID $($process.Id))."
}
Export-ModuleMember -Function Start-VCFRecoveryCoordinator

#EndRegion UI Orchestrator
