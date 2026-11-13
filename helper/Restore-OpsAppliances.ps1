#Requires -Version 7.0
# Veeam: rescan vCenter, restore OpsAppliances to a new location (powered on), wait for VCF Ops.
#   Default:           full restore (waits for each restore to finish before waiting for VCF Ops).
#   -InstantRecovery:  Veeam Instant Recovery (VMs run from the backup via vPower NFS), then, once VCF Ops
#                      is available, starts migrating the VMs to production storage in the background.
[CmdletBinding()]
Param (
    [Parameter(Mandatory = $false)] [Switch]$InstantRecovery
)

$ErrorActionPreference = 'Stop'
# No progress bars: when this runs as a child of the Recovery Coordinator its output is piped to the
# console, and progress-bar escape sequences (e.g. from Rescan-VBREntity -Wait) can erase lines.
$ProgressPreference = 'SilentlyContinue'

$vbrServer   = 'localhost'
$vbrUser     = 'Administrator'
$vbrPassword = 'Adamant1um1!'
$vcenterName = 'sfo-m01-vc01.sfo.rainpole.io'
$backupName  = 'OpsAppliances'
$nameSuffix  = ''     # set e.g. '-restored' if the original VMs still exist in vCenter
$opsFqdn     = 'flt-ops01a.rainpole.io'
$opsUser     = 'admin'
$opsPassword = 'VMw@re1!VMw@re1!'
$opsTimeoutMinutes = 60

$jumpboxName = hostname

Function Write-LogMessage {
    Param (
        [Parameter(Mandatory = $true)] [String]$Message,
        [Parameter(Mandatory = $false)] [ValidateSet('INFO', 'NOTE', 'WARNING', 'ERROR', 'SUCCESS')] [String]$Type = 'INFO'
    )
    # ANSI colour codes (same as the module's LogMessage) rather than -ForegroundColor: when this script
    # runs as a child of the Recovery Coordinator its output is piped, so host colours would be lost.
    $colour = switch ($Type) {
        'INFO'    { '92m' }   # Green
        'NOTE'    { '97m' }   # White
        'WARNING' { '93m' }   # Yellow
        'ERROR'   { '91m' }   # Red
        'SUCCESS' { '92m' }   # Green
    }
    $timestamp = Get-Date -Format 'MM-dd-yyyy_HH:mm:ss'
    # Timestamp in bright white, then type + message in the type's colour -- same layout as the module's LogMessage.
    $esc = [char]27
    Write-Host "$esc[97m [$timestamp]$esc[$colour [$Type] [$jumpboxName] $Message$esc[0m"
}

# Any terminating error: log it as ERROR and exit non-zero, so a caller (e.g. the Recovery Coordinator's
# Invoke-UserOpsRestoreScript) can tell this script failed. Success exits 0 at the end of the script.
trap {
    Write-LogMessage -Type ERROR -Message $_.Exception.Message
    exit 1
}

Import-Module Veeam.Backup.PowerShell -DisableNameChecking -WarningAction SilentlyContinue -ErrorAction SilentlyContinue

try {
    Connect-VBRServer -Server $vbrServer -User $vbrUser -Password $vbrPassword

    # 1. Refresh the vCenter
    Write-LogMessage -Type INFO -Message "Rescanning vCenter $vcenterName"
    $vc = Get-VBRServer -Name $vcenterName
    if (-not $vc) { throw "vCenter $vcenterName is not registered in Veeam." }
    Rescan-VBREntity -Entity $vc -Wait | Out-Null
    Write-LogMessage -Type INFO -Message "Rescan of vCenter $vcenterName complete"

    # 2. Latest restore point per VM in the backup
    $backup = Get-VBRBackup -Name $backupName
    if (-not $backup) { throw "Backup '$backupName' not found." }

    $restorePoints = Get-VBRRestorePoint -Backup $backup |
        Sort-Object CreationTime -Descending |
        Group-Object Name |
        ForEach-Object { $_.Group[0] }

    # 3. Restore each VM to another location, defaulting everything to the original placement.
    $mode = if ($InstantRecovery) { 'instant recovery' } else { 'full restore' }
    Write-LogMessage -Type INFO -Message "Restore mode: $mode"
    $recovered = @()
    $sessions  = @()
    foreach ($rp in $restorePoints) {
        # Target host: the original VM's host if it still exists, otherwise the first ESXi host
        $orig = Find-VBRViEntity -Server $vc -Name $rp.Name | Select-Object -First 1
        $esx  = $null
        if ($orig -and $orig.VmHostName) { $esx = Get-VBRServer -Type ESXi -Name $orig.VmHostName }
        if (-not $esx) { $esx = Get-VBRServer -Type ESXi | Select-Object -First 1 }
        if (-not $esx) { throw "No ESXi host found for restore of $($rp.Name)." }

        # Resource pool: Find-VBRViResourcePool returns nothing for this cluster, so try the
        # inventory (-ResourcePools); if still nothing, omit it (the parameter is optional).
        $rpool = Find-VBRViResourcePool -Server $esx | Select-Object -First 1
        if (-not $rpool) {
            $rpool = Find-VBRViEntity -Server $vc -ResourcePools |
                Where-Object { $_.Path -like "*$($esx.Name)*" -or $_.Path -like '*\sfo-m01-cl01\*' } |
                Select-Object -First 1
        }

        $ds = Find-VBRViDatastore -Server $esx | Sort-Object FreeSpace -Descending | Select-Object -First 1
        if (-not $ds) {
            $ds = Find-VBRViDatastore -Server $vc | Sort-Object FreeSpace -Descending | Select-Object -First 1
        }
        if (-not $ds) { throw "No datastore found on $($esx.Name) or $vcenterName." }

        $restoreArgs = @{
            RestorePoint = $rp
            Server       = $esx
            Datastore    = $ds       # Instant Recovery: holds the redo logs until the migration in step 5
            VMName       = "$($rp.Name)$nameSuffix"
            PowerUp      = $true
            NICsEnabled  = $true
            Reason       = 'Automated OpsAppliances recovery'
        }
        if ($rpool) { $restoreArgs.ResourcePool = $rpool }

        if ($InstantRecovery) {
            Write-LogMessage -Type INFO -Message "Instant recovery of $($rp.Name) to $($esx.Name) / $($ds.Name)"
            # Blocks until the VM is mounted and powered on (seconds to minutes, not the length of a full restore)
            $ir = Start-VBRInstantRecovery @restoreArgs
            if (-not $ir) { throw "Instant recovery of $($rp.Name) did not return a session." }
            $recovered += [pscustomobject]@{ Name = $rp.Name; Session = $ir; Server = $esx; Datastore = $ds; ResourcePool = $rpool }
        } else {
            Write-LogMessage -Type INFO -Message "Restoring $($rp.Name) to $($esx.Name) / $($ds.Name)"
            # -RunAsync returns immediately so all VMs restore in parallel
            $sessions += Start-VBRRestoreVM @restoreArgs -RunAsync
        }
    }

    if ($InstantRecovery) {
        Write-LogMessage -Type INFO -Message "$($recovered.Count) VM(s) recovered and powered on"
    } else {
        # Wait for every restore session to finish
        Write-LogMessage -Type INFO -Message "Waiting for $($sessions.Count) restore(s) to complete"
        do {
            Start-Sleep -Seconds 15
            $current = @(Get-VBRRestoreSession | Where-Object { $_.Id -in $sessions.Id })
            $running = @($current | Where-Object { $_.State -ne 'Stopped' })
        } while ($running.Count -gt 0)

        $failed = @($current | Where-Object { $_.Result -ne 'Success' -and $_.Result -ne 'Warning' })
        foreach ($f in $failed) { Write-LogMessage -Type ERROR -Message "Restore of $($f.Name): $($f.Result)" }
        if ($failed) { throw "Restore failed for: $($failed.Name -join ', ')" }
        Write-LogMessage -Type INFO -Message 'Restores complete, VMs powered on'
    }

    # 4. Wait for VCF Operations
    Write-LogMessage -Type INFO -Message "Waiting for VCF Operations at https://$opsFqdn"
    $deadline = (Get-Date).AddMinutes($opsTimeoutMinutes)
    $body = @{ username = $opsUser; password = $opsPassword } | ConvertTo-Json
    $ready = $false
    while ((Get-Date) -lt $deadline -and -not $ready) {
        try {
            $r = Invoke-RestMethod -Uri "https://$opsFqdn/suite-api/api/auth/token/acquire" -Method Post `
                -Body $body -ContentType 'application/json' -Headers @{ Accept = 'application/json' } `
                -SkipCertificateCheck -TimeoutSec 30
            if ($r.token) { $ready = $true }
        } catch {
            Start-Sleep -Seconds 30
        }
    }
    if (-not $ready) { throw "VCF Operations did not become available within $opsTimeoutMinutes minutes." }
    Write-LogMessage -Type INFO -Message "VCF Operations is available at https://$opsFqdn"

    # 5. Instant Recovery only: start migrating every VM from the backup to production storage in the
    #    background (-RunAsync), then exit. The migrations carry on server-side in Veeam; this script does
    #    not wait for them.
    if ($InstantRecovery) {
        foreach ($vm in $recovered) {
            $migrationArgs = @{
                InstantRecovery = $vm.Session
                Server          = $vm.Server
                Datastore       = $vm.Datastore
                RunAsync        = $true
            }
            if ($vm.ResourcePool) { $migrationArgs.ResourcePool = $vm.ResourcePool }
            Write-LogMessage -Type INFO -Message "Starting background migration of $($vm.Name) to $($vm.Datastore.Name)"
            Start-VBRViInstantRecoveryMigration @migrationArgs | Out-Null
        }
    }
}
finally {
    Disconnect-VBRServer -ErrorAction SilentlyContinue
}
exit 0
