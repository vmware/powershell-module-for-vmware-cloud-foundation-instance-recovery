<#
.SYNOPSIS
Unregisters an existing vSAN Witness host from vCenter, then deploys a new vSAN Witness appliance and registers it.

.DESCRIPTION
Standalone script intended to be run by Invoke-UserScript (child pwsh process, no parameters, exit code 0 = success).
Modelled on Platform Tools workload menu item 34 (Get-VSANWitnessOVA / New-VSANWitnessDeployment).

  1. Connects to the managed vCenter and removes the old witness host from inventory.
  2. (Optional) Connects to the infrastructure vCenter and deletes the old witness VM.
  3. Deploys the witness OVA with ovftool into the infrastructure vCenter.
  4. Waits for VMware Tools, sets the management VLAN and enables SSH via VMware Tools guest operations.
  5. Adds the new witness to the managed vCenter, removes vmk1 / secondarySwitch, starts SSH, configures NTP.

Safe to re-run. If the old witness is registered in the managed vCenter and is not disconnected, it is healthy and
the script exits 0 without doing anything. If it is disconnected it is removed, and if it is already gone the script
simply carries on, so a missing old host or VM never causes a failure.
#>

# ======================================================================================
# VARIABLES TO SET - replace every <placeholder> before running
# ======================================================================================

# --- vCenter that manages the witness host (where the witness is registered / stretched cluster lives)
$managedVcenterFqdn      = 'sfo-w02-vc01.sfo.rainpole.io'
$managedVcenterUser      = 'administrator@sfo-w02.local'
$managedVcenterPassword  = 'VMw@re1!VMw@re1!'
$managedDatacenterName   = 'sfo-w02-dc'       # Datacenter the witness host is added to

# --- vCenter hosting the witness appliance VM (infrastructure vCenter)
$infraVcenterFqdn        = 'vcf-pd-vc01.lvn.broadcom.net'
$infraVcenterUser        = 'breakglass@vsphere.local'
$infraVcenterPassword    = 'VMw@re1!VMw@re1!'
$infraDatacenterName     = 'vcf-pd-dc01'
$infraClusterName        = 'vcf-pd-cl02'
$infraDatastoreName      = 'vcf-pd-vcf-pd-cl02-vsan01'
$infraVmFolder           = 'ken-912c4-ibr'      # e.g. owner-environment

# --- Old witness (to unregister)
$oldWitnessFqdn          = 'sfo-w02-cl01-vsw01.sfo.rainpole.io'              # Name it is registered under in the managed vCenter
$deleteOldWitnessVm      = $true                             # Also delete the old witness VM from the infrastructure vCenter
$oldWitnessVmName        = 'ken-912c4-ibr-sfo-w02-cl01-vsw01'           # Only used if $deleteOldWitnessVm is $true

# --- New witness
$newWitnessFqdn          = 'sfo-w02-cl01-vsw01.sfo.rainpole.io'
$newWitnessVmName        = 'ken-912c4-ibr-sfo-w02-cl01-vsw01'
$newWitnessIp            = '10.21.10.220'
$newWitnessNetmask       = '255.255.255.0'
$newWitnessGateway       = '10.21.10.1'
$newWitnessVlanId        = '2110'
$witnessPortgroupName    = 'ken-912c4-ibr-isolated-segment'   # Used for both "Management Network" and "Secondary Network"
$witnessRootPassword     = 'VMw@re1!'         # Also used as the ESXi password when adding to vCenter
$witnessEsxiUsername     = 'root'

# --- Network services
$dnsServers              = '10.11.10.4,10.11.10.4'
$dnsDomain               = 'sfo.rainpole.io'
$ntpServers              = 'ntp0.sfo.rainpole.io,ntp1.sfo.rainpole.io'

# --- Files / tools
$witnessOvaPath          = 'F:\PlatformTools\binaries\VMware-vSAN-ESA-Witness-9.1.2.0.25886086.ova'      # e.g. F:\binaries\VMware-VirtualSAN-Witness-<build>.ova
$ovfToolPath             = 'C:\Program Files\VMware\VMware OVF Tool\ovftool.exe'
$vsanNetworkName         = 'Management'                      # guestinfo.vsannetwork value used by Platform Tools

# ======================================================================================
# SCRIPT BODY
# ======================================================================================

$ErrorActionPreference = 'Stop'

# Same look as the module's LogMessage (timestamp, coloured type tag). Use ERROR only for a real failure -
# Invoke-UserScript treats an [ERROR] line as a failed task - and INFO for anything expected.
Function LogMessage {
    Param (
        [Parameter(Mandatory = $true)] [AllowEmptyString()] [String]$message,
        [Parameter(Mandatory = $false)] [Switch]$nonewline,
        [Parameter(Mandatory = $false)] [ValidateSet("INFO", "ERROR", "WARNING", "EXCEPTION", "ADVISORY", "NOTE", "QUESTION", "WAIT")] [String]$type = "INFO"
    )
    If ($type -eq "INFO") {
        $messageColour = "92m" #Green
    } elseIf ($type -in "ERROR", "EXCEPTION") {
        $messageColour = "91m" # Red
    } elseIf ($type -in "WARNING", "ADVISORY", "QUESTION") {
        $messageColour = "93m" #Yellow
    } elseIf ($type -in "NOTE", "WAIT") {
        $messageColour = "97m" # White
    }
    $ESC = [char]0x1b
    $timeStamp = Get-Date -Format "MM-dd-yyyy_HH:mm:ss"
    $timestampColour = "97m"
    If ($nonewline) {
        Write-Host "$ESC[${timestampcolour} [$timestamp]$ESC[${messageColour} [$type] $message$ESC[0m" -NoNewline
    } else {
        Write-Host "$ESC[${timestampcolour} [$timestamp]$ESC[${messageColour} [$type] $message$ESC[0m"
    }
}

Function Test-Placeholders {
    $unset = Get-Variable -Scope Script | Where-Object { $_.Value -is [string] -and $_.Value -match '<[^>]+>' -and $_.Name -notin 'MyInvocation' } | Select-Object -ExpandProperty Name
    If ($unset) {
        Throw "These variables still contain placeholders: $($unset -join ', ')"
    }
}

# Runs a program inside the witness appliance via VMware Tools guest operations. The witness is ESXi, so there is no
# bash and Invoke-VMScript cannot be used. Same approach as Platform Tools' Invoke-VMGuestCommand, but this waits for
# the program to finish and returns its exit code.
Function Invoke-WitnessGuestProgram {
    Param(
        [Parameter(Mandatory)] $Server,
        [Parameter(Mandatory)] $VM,
        [Parameter(Mandatory)] [string]$GuestUser,
        [Parameter(Mandatory)] [string]$GuestPassword,
        [Parameter(Mandatory)] [string]$ProgramPath,
        [Parameter(Mandatory)] [string]$Arguments,
        [int]$TimeoutSeconds = 120
    )
    $guestOpMgr = Get-View $Server.ExtensionData.Content.GuestOperationsManager -Server $Server
    $procMgr = Get-View $guestOpMgr.ProcessManager -Server $Server

    $auth = New-Object VMware.Vim.NamePasswordAuthentication
    $auth.Username = $GuestUser
    $auth.Password = $GuestPassword
    $auth.InteractiveSession = $false

    $progSpec = New-Object VMware.Vim.GuestProgramSpec
    $progSpec.ProgramPath = $ProgramPath
    $progSpec.WorkingDirectory = '/tmp'
    # "++group=host/vim/tmp" is required for ESXi to run the process
    $progSpec.Arguments = "++group=host/vim/tmp $Arguments"

    $guestPid = $procMgr.StartProgramInGuest($VM.ExtensionData.MoRef, $auth, $progSpec)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    Do {
        Start-Sleep -Seconds 2
        $proc = $procMgr.ListProcessesInGuest($VM.ExtensionData.MoRef, $auth, @($guestPid)) | Select-Object -First 1
    } Until ($proc.EndTime -or (Get-Date) -gt $deadline)
    If (-not $proc.EndTime) {
        Throw "Guest program '$ProgramPath $Arguments' did not finish within $TimeoutSeconds seconds"
    }
    Return [int]$proc.ExitCode
}

# Sends one line of ovftool output through LogMessage, dropping the noise (certificate dump, the harmless
# "Unsupported value ... ExtraConfig" warnings, per-percent task progress) and reporting disk progress every 10%.
# $State carries the filter state between lines: @{ InCert = $false; LastDisk = 0 }
Function Write-OvfToolLine {
    Param([string]$Line, [hashtable]$State, [string]$Tag)
    $Line = $Line.TrimEnd()
    If ([string]::IsNullOrWhiteSpace($Line)) {
        Return
    }
    If ($Line -match '^Source is signed') {
        $State.InCert = $true
    }
    If ($State.InCert) {
        If ($Line -match 'END CERTIFICATE') {
            $State.InCert = $false
        }
        Return
    }
    If ($Line -like 'Task progress*' -or $Line -eq 'Warning:' -or $Line -match "Unsupported value '.*' for attribute 'key' on element 'ExtraConfig'") {
        Return
    }
    If ($Line -match '^Disk progress: (\d+)%') {
        $bucket = [Math]::Floor([int]$Matches[1] / 10) * 10
        If ($bucket -gt $State.LastDisk) {
            $State.LastDisk = $bucket
            LogMessage -type INFO -message "$Tag $Line"
        }
        Return
    }
    If ($Line -match '^Error' -or $Line -eq 'Completed with errors') {
        LogMessage -type ERROR -message "$Tag $Line"
    } else {
        LogMessage -type INFO -message "$Tag $Line"
    }
}

# Runs ovftool and returns @{ ExitCode; Lines }. Like the module's OVA deployments, ovftool runs in a background job
# and this session only polls it, so LogMessage never writes while a native program is running in this session's
# console (which prints the colour codes as literal text). Output is streamed through Write-OvfToolLine unless
# -Quiet, in which case it is only collected (so a caller can replay it through Write-OvfToolLine if the run fails).
Function Invoke-OvfTool {
    Param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string[]]$Arguments,
        [Parameter(Mandatory)] [string]$Tag,
        [switch]$Quiet,
        [int]$PollSeconds = 5
    )
    $state = @{ InCert = $false; LastDisk = 0 }
    $collected = [System.Collections.Generic.List[string]]::new()
    $exitMarker = '__OVFTOOL_EXIT__:'
    $exitCode = $null

    $scriptBlock = {
        Param($ovfPath, $ovfArguments, $marker)
        & $ovfPath @ovfArguments 2>&1 | ForEach-Object { "$_" }
        "$marker$LASTEXITCODE"
    }
    $job = Start-Job -ScriptBlock $scriptBlock -ArgumentList $Path, $Arguments, $exitMarker

    $processLines = {
        Param($lines)
        ForEach ($line in $lines) {
            If ($line -like "$exitMarker*") {
                $script:ovfExit = [int]($line.Substring($exitMarker.Length))
                Continue
            }
            $collected.Add($line)
            If (-not $Quiet) {
                Write-OvfToolLine -Line $line -State $state -Tag $Tag
            }
        }
    }
    $script:ovfExit = $null
    Try {
        Do {
            Start-Sleep -Seconds $PollSeconds
            $jobState = $job.State
            & $processLines @(Receive-Job -Job $job -ErrorAction SilentlyContinue)
        } While ($jobState -eq 'Running')
        & $processLines @(Receive-Job -Job $job -ErrorAction SilentlyContinue)
        If ($job.State -eq 'Failed') {
            Throw "ovftool job failed: $($job.ChildJobs[0].JobStateInfo.Reason.Message)"
        }
        $exitCode = $script:ovfExit
    } Finally {
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }
    If ($null -eq $exitCode) {
        Throw 'ovftool did not report an exit code'
    }
    Return @{ ExitCode = $exitCode; Lines = $collected }
}

Try {
    Test-Placeholders
    If (-not (Test-Path -LiteralPath $witnessOvaPath -PathType Leaf)) {
        Throw "Witness OVA '$witnessOvaPath' not found"
    }
    If (-not (Test-Path -LiteralPath $ovfToolPath -PathType Leaf)) {
        Throw "ovftool '$ovfToolPath' not found"
    }
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope Session | Out-Null

    $tag = "[$newWitnessVmName]"
    LogMessage -type INFO -message "$tag Connecting to managed vCenter $managedVcenterFqdn and infrastructure vCenter $infraVcenterFqdn"
    $managedVi = Connect-VIServer -Server $managedVcenterFqdn -User $managedVcenterUser -Password $managedVcenterPassword
    $infraVi = Connect-VIServer -Server $infraVcenterFqdn -User $infraVcenterUser -Password $infraVcenterPassword

    # ---------------- 1. Unregister the old witness from the managed vCenter ----------------
    $oldHost = Get-VMHost -Name $oldWitnessFqdn -Server $managedVi -ErrorAction SilentlyContinue
    If ($oldHost -and $oldHost.ConnectionState -notin 'Disconnected', 'NotResponding') {
        LogMessage -type INFO -message "$tag Witness host $oldWitnessFqdn is $($oldHost.ConnectionState) in $managedVcenterFqdn - nothing to do"
        Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
        Exit 0
    }
    If ($oldHost) {
        LogMessage -type INFO -message "$tag Removing disconnected witness host $oldWitnessFqdn from vCenter inventory"
        Remove-VMHost -VMHost $oldHost -Confirm:$false
    } else {
        LogMessage -type INFO -message "$tag Witness host $oldWitnessFqdn is not registered in $managedVcenterFqdn - nothing to unregister"
    }

    # ---------------- 2. Delete the old witness VM (optional) ----------------
    If ($deleteOldWitnessVm) {
        $oldVm = Get-VM -Name $oldWitnessVmName -Server $infraVi -ErrorAction SilentlyContinue
        If ($oldVm) {
            LogMessage -type INFO -message "$tag Deleting old witness VM $oldWitnessVmName"
            If ($oldVm.PowerState -eq 'PoweredOn') {
                Stop-VM -VM $oldVm -Confirm:$false | Out-Null
            }
            Remove-VM -VM $oldVm -DeletePermanently -Confirm:$false
        } else {
            LogMessage -type INFO -message "$tag Old witness VM $oldWitnessVmName not found - nothing to delete"
        }
    }

    # ---------------- 3. Deploy the new witness with ovftool ----------------
    $hostname = $newWitnessFqdn.Split('.')[0]
    $target = 'vi://{0}:{1}@{2}/{3}/host/{4}/' -f [uri]::EscapeDataString($infraVcenterUser), [uri]::EscapeDataString($infraVcenterPassword), $infraVcenterFqdn, $infraDatacenterName, $infraClusterName
    $ovfArgs = @(
        '--noSSLVerify', '--acceptAllEulas', '--allowAllExtraConfig', '--diskMode=thin', '--powerOn',
        "--name=$newWitnessVmName",
        "--vmFolder=$infraVmFolder",
        "--net:Management Network=$witnessPortgroupName",
        "--net:Secondary Network=$witnessPortgroupName",
        "--datastore=$infraDatastoreName",
        '--X:injectOvfEnv',
        "--prop:guestinfo.hostname=$hostname",
        "--prop:guestinfo.ipaddress0=$newWitnessIp",
        "--prop:guestinfo.netmask0=$newWitnessNetmask",
        "--prop:guestinfo.gateway0=$newWitnessGateway",
        "--prop:guestinfo.dns=$dnsServers",
        "--prop:guestinfo.dnsDomain=$dnsDomain",
        "--prop:guestinfo.ntp=$ntpServers",
        "--prop:guestinfo.passwd=$witnessRootPassword",
        "--prop:guestinfo.vsannetwork=$vsanNetworkName"
    )

    # ovftool resolves --vmFolder as a top-level VM folder of the datacenter and only says "Invalid VM folder specified"
    $dc = Get-Datacenter -Name $infraDatacenterName -Server $infraVi
    $vmFolderObjects = @(Get-Folder -Type VM -Location $dc -Server $infraVi -ErrorAction SilentlyContinue)
    $topLevelFolders = @($vmFolderObjects | Where-Object { $_.ParentId -eq $dc.ExtensionData.VmFolder.ToString() } | Select-Object -ExpandProperty Name)
    If ($infraVmFolder -cnotin $topLevelFolders) {
        $nested = @($vmFolderObjects | Where-Object { $_.Name -ceq $infraVmFolder })
        If ($nested.Count -gt 0) {
            Throw "VM folder '$infraVmFolder' exists in $infraDatacenterName but is not at the top level, which ovftool requires. Top-level folders: $($topLevelFolders -join ', ')"
        }
        Throw "VM folder '$infraVmFolder' was not found in datacenter $infraDatacenterName on $infraVcenterFqdn. Top-level VM folders: $($topLevelFolders -join ', ')"
    }

    LogMessage -type INFO -message "$tag Pre-validating witness deployment"
    $verify = Invoke-OvfTool -Path $ovfToolPath -Arguments (@('--verifyOnly') + $ovfArgs + @($witnessOvaPath, $target)) -Tag $tag -Quiet
    If ($verify.ExitCode -ne 0 -or $verify.Lines[-1] -notmatch 'Completed successfully') {
        $verifyState = @{ InCert = $false; LastDisk = 0 }
        ForEach ($line in $verify.Lines) {
            Write-OvfToolLine -Line $line -State $verifyState -Tag $tag
        }
        Throw 'ovftool pre-validation failed. Check the OVA, datastore, portgroup and credentials.'
    }

    LogMessage -type INFO -message "$tag Deploying witness appliance (this can take several minutes)"
    $deploy = Invoke-OvfTool -Path $ovfToolPath -Arguments ($ovfArgs + @($witnessOvaPath, $target)) -Tag $tag
    If ($deploy.ExitCode -ne 0) {
        Throw "ovftool deployment failed (exit code $($deploy.ExitCode))"
    }

    # ---------------- 4. Configure management VLAN / SSH via guest operations ----------------
    $newVm = Get-VM -Name $newWitnessVmName -Server $infraVi
    If ($newVm.PowerState -ne 'PoweredOn') {
        LogMessage -type INFO -message "$tag Powering on witness appliance"
        Start-VM -VM $newVm -Confirm:$false | Out-Null
    }
    LogMessage -type WAIT -message "$tag Waiting for VMware Tools to start"
    $deadline = (Get-Date).AddMinutes(15)
    Do {
        Start-Sleep -Seconds 10
        $toolsStatus = (Get-VM -Name $newWitnessVmName -Server $infraVi).ExtensionData.Guest.ToolsStatus
    } Until (($toolsStatus -in 'toolsOld', 'toolsOk') -or (Get-Date) -gt $deadline)
    If ($toolsStatus -notin 'toolsOld', 'toolsOk') {
        Throw "VMware Tools did not start on $newWitnessVmName within 15 minutes"
    }
    Start-Sleep -Seconds 60   # Let the appliance finish booting

    $newVm = Get-VM -Name $newWitnessVmName -Server $infraVi
    LogMessage -type INFO -message "$tag Configuring management VLAN $newWitnessVlanId"
    $exitCode = Invoke-WitnessGuestProgram -Server $infraVi -VM $newVm -GuestUser $witnessEsxiUsername -GuestPassword $witnessRootPassword `
        -ProgramPath '/bin/python' -Arguments "/bin/esxcli.py network vswitch standard portgroup set -p `"Management Network`" -v $newWitnessVlanId"
    If ($exitCode -ne 0) {
        Throw "Setting the management VLAN on the witness failed (exit code $exitCode)"
    }

    # Best effort only - SSH is started again through vCenter in step 5, so a failure here is not fatal
    LogMessage -type INFO -message "$tag Ensuring SSH is running"
    ForEach ($sshCmd in 'hostsvc/start_ssh', 'hostsvc/enable_ssh') {
        Try {
            Invoke-WitnessGuestProgram -Server $infraVi -VM $newVm -GuestUser $witnessEsxiUsername -GuestPassword $witnessRootPassword `
                -ProgramPath '/bin/vim-cmd' -Arguments $sshCmd | Out-Null
        } Catch {
            LogMessage -type INFO -message "$tag vim-cmd $sshCmd did not complete ($($_.Exception.Message)) - SSH is handled again once the host is in vCenter"
        }
    }

    # ---------------- 5. Register the new witness in the managed vCenter ----------------
    LogMessage -type WAIT -message "$tag Waiting for $newWitnessIp to become reachable"
    Do {
        Start-Sleep -Seconds 10
    } Until (Test-Connection -ComputerName $newWitnessIp -Count 1 -Quiet)

    LogMessage -type INFO -message "$tag Adding $newWitnessFqdn to vCenter"
    $location = Get-Datacenter -Name $managedDatacenterName -Server $managedVi
    Add-VMHost -Name $newWitnessFqdn -Location $location -User $witnessEsxiUsername -Password $witnessRootPassword -Force -Server $managedVi | Out-Null
    LogMessage -type WAIT -message "$tag Allowing vCenter inventory to synchronize"
    Start-Sleep -Seconds 90

    $newHost = Get-VMHost -Name $newWitnessFqdn -Server $managedVi

    $vmk1 = $newHost | Get-VMHostNetworkAdapter -Name vmk1 -ErrorAction SilentlyContinue
    If ($vmk1) {
        LogMessage -type INFO -message "$tag Removing vmk1"
        $vmk1 | Remove-VMHostNetworkAdapter -Confirm:$false
    } else {
        LogMessage -type INFO -message "$tag vmk1 is already removed"
    }
    $secondarySwitch = $newHost | Get-VirtualSwitch -Name 'secondarySwitch' -ErrorAction SilentlyContinue
    If ($secondarySwitch) {
        LogMessage -type INFO -message "$tag Removing secondarySwitch"
        $secondarySwitch | Remove-VirtualSwitch -Confirm:$false
    } else {
        LogMessage -type INFO -message "$tag secondarySwitch is already removed"
    }

    $sshService = $newHost | Get-VMHostService | Where-Object { $_.Key -eq 'TSM-SSH' }
    If ($sshService -and -not $sshService.Running) {
        LogMessage -type INFO -message "$tag Starting SSH"
        $sshService | Start-VMHostService -Confirm:$false | Out-Null
    }

    $desiredNtp = @($ntpServers.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $currentNtp = @(Get-VMHostNtpServer -VMHost $newHost)
    $missingNtp = @($desiredNtp | Where-Object { $_ -notin $currentNtp })
    $ntpd = $newHost | Get-VMHostService | Where-Object { $_.Key -eq 'ntpd' }
    If ($missingNtp.Count -gt 0) {
        LogMessage -type INFO -message "$tag Adding NTP server(s) $($missingNtp -join ', ')"
        Add-VMHostNtpServer -VMHost $newHost -NtpServer $missingNtp | Out-Null
    }
    If ($ntpd.Policy -ne 'on') {
        $ntpd | Set-VMHostService -Policy On | Out-Null
    }
    If ($missingNtp.Count -gt 0 -or -not $ntpd.Running) {
        LogMessage -type INFO -message "$tag Starting NTP service"
        If ($ntpd.Running) {
            $ntpd | Restart-VMHostService -Confirm:$false | Out-Null
        } else {
            $ntpd | Start-VMHostService -Confirm:$false | Out-Null
        }
    } else {
        LogMessage -type INFO -message "$tag NTP is already configured"
    }

    Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
    LogMessage -type INFO -message "$tag vSAN Witness $newWitnessFqdn is deployed and registered in $managedVcenterFqdn"
    Exit 0
} Catch {
    LogMessage -type ERROR -message "$($_.Exception.Message)"
    Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null
    Exit 1
}
