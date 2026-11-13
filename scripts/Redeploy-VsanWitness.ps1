<#
.SYNOPSIS
Unregisters an existing vSAN Witness host from vCenter, then deploys a new vSAN Witness appliance and registers it.

.DESCRIPTION
Standalone script intended to be run by Invoke-UserScript (child pwsh process, no parameters, exit code 0 = success).
Modelled on Platform Tools workload menu item 34 (Get-VSANWitnessOVA / New-VSANWitnessDeployment).

  1. Connects to the managed vCenter and removes the old witness host from inventory.
  2. (Optional) Connects to the infrastructure vCenter and deletes the old witness VM.
  3. Deploys the witness OVA with ovftool into the infrastructure vCenter.
  4. Waits for VMware Tools, sets the management VLAN and enables SSH via guest operations.
  5. Adds the new witness to the managed vCenter, removes vmk1 / secondarySwitch, starts SSH, configures NTP.

Requires: VCF.PowerCLI / VMware.PowerCLI, and VMware OVF Tool on the machine running the script.
#>

# ======================================================================================
# VARIABLES TO SET - replace every <placeholder> before running
# ======================================================================================

# --- vCenter that manages the witness host (where the witness is registered / stretched cluster lives)
$managedVcenterFqdn      = '<managed-vcenter-fqdn>'
$managedVcenterUser      = '<administrator@vsphere.local>'
$managedVcenterPassword  = '<managed-vcenter-password>'
$managedDatacenterName   = '<managed-datacenter-name>'       # Datacenter the witness host is added to

# --- vCenter hosting the witness appliance VM (infrastructure vCenter)
$infraVcenterFqdn        = '<infrastructure-vcenter-fqdn>'
$infraVcenterUser        = '<administrator@vsphere.local>'
$infraVcenterPassword    = '<infrastructure-vcenter-password>'
$infraDatacenterName     = '<infrastructure-datacenter-name>'
$infraClusterName        = '<infrastructure-cluster-name>'
$infraDatastoreName      = '<infrastructure-datastore-name>'
$infraVmFolder           = '<infrastructure-vm-folder>'      # e.g. owner-environment

# --- Old witness (to unregister)
$oldWitnessFqdn          = '<old-witness-fqdn>'              # Name it is registered under in the managed vCenter
$deleteOldWitnessVm      = $true                             # Also delete the old witness VM from the infrastructure vCenter
$oldWitnessVmName        = '<old-witness-vm-name>'           # Only used if $deleteOldWitnessVm is $true

# --- New witness
$newWitnessFqdn          = '<new-witness-fqdn>'
$newWitnessVmName        = '<new-witness-vm-name>'
$newWitnessIp            = '<new-witness-mgmt-ip>'
$newWitnessNetmask       = '<new-witness-netmask>'
$newWitnessGateway       = '<new-witness-gateway>'
$newWitnessVlanId        = '<new-witness-mgmt-vlan-id>'
$witnessPortgroupName    = '<portgroup-for-witness-vm-networks>'   # Used for both "Management Network" and "Secondary Network"
$witnessRootPassword     = '<witness-root-password>'         # Also used as the ESXi password when adding to vCenter
$witnessEsxiUsername     = 'root'

# --- Network services
$dnsServers              = '<dns1>,<dns2>'
$dnsDomain               = '<dns-domain>'
$ntpServers              = '<ntp1>,<ntp2>'

# --- Files / tools
$witnessOvaPath          = '<full-path-to-witness.ova>'      # e.g. F:\binaries\VMware-VirtualSAN-Witness-<build>.ova
$ovfToolPath             = 'C:\Program Files\VMware\VMware OVF Tool\ovftool.exe'
$vsanNetworkName         = 'Management'                      # guestinfo.vsannetwork value used by Platform Tools

# ======================================================================================
# SCRIPT BODY
# ======================================================================================
$ErrorActionPreference = 'Stop'

Function Write-Step {
    Param([string]$Message, [string]$Type = 'INFO')
    Write-Host ("[{0}] [{1}] {2}" -f (Get-Date -Format 'HH:mm:ss'), $Type, $Message)
}

Function Test-Placeholders {
    $unset = Get-Variable -Scope Script | Where-Object { $_.Value -is [string] -and $_.Value -match '<[^>]+>' -and $_.Name -notin 'MyInvocation' } | Select-Object -ExpandProperty Name
    If ($unset) { Throw "These variables still contain placeholders: $($unset -join ', ')" }
}

Try {
    Test-Placeholders
    If (-not (Test-Path -LiteralPath $witnessOvaPath -PathType Leaf)) { Throw "Witness OVA '$witnessOvaPath' not found" }
    If (-not (Test-Path -LiteralPath $ovfToolPath -PathType Leaf)) { Throw "ovftool '$ovfToolPath' not found" }

    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope Session | Out-Null

    # ---------------- 1. Unregister the old witness from the managed vCenter ----------------
    Write-Step "Connecting to managed vCenter $managedVcenterFqdn"
    Connect-VIServer -Server $managedVcenterFqdn -User $managedVcenterUser -Password $managedVcenterPassword | Out-Null

    $oldHost = Get-VMHost -Name $oldWitnessFqdn -ErrorAction SilentlyContinue
    If ($oldHost) {
        Write-Step "Removing witness host $oldWitnessFqdn from vCenter inventory"
        If ($oldHost.ConnectionState -eq 'Connected') {
            Set-VMHost -VMHost $oldHost -State Maintenance -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        }
        Remove-VMHost -VMHost $oldHost -Confirm:$false
        Write-Step "Witness host $oldWitnessFqdn removed from inventory"
    } Else {
        Write-Step "Witness host $oldWitnessFqdn is not registered in $managedVcenterFqdn - nothing to unregister" 'WARNING'
    }
    Disconnect-VIServer -Server $managedVcenterFqdn -Force -Confirm:$false | Out-Null

    # ---------------- 2. Delete the old witness VM (optional) ----------------
    Write-Step "Connecting to infrastructure vCenter $infraVcenterFqdn"
    Connect-VIServer -Server $infraVcenterFqdn -User $infraVcenterUser -Password $infraVcenterPassword | Out-Null

    If ($deleteOldWitnessVm) {
        $oldVm = Get-VM -Name $oldWitnessVmName -ErrorAction SilentlyContinue
        If ($oldVm) {
            Write-Step "Deleting old witness VM $oldWitnessVmName"
            If ($oldVm.PowerState -eq 'PoweredOn') { Stop-VM -VM $oldVm -Confirm:$false | Out-Null }
            Remove-VM -VM $oldVm -DeletePermanently -Confirm:$false
        } Else {
            Write-Step "Old witness VM $oldWitnessVmName not found - skipping delete" 'WARNING'
        }
    }
    Disconnect-VIServer -Server $infraVcenterFqdn -Force -Confirm:$false | Out-Null

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

    Write-Step "Pre-validating witness deployment"
    $verifyOutput = & $ovfToolPath '--verifyOnly' @ovfArgs $witnessOvaPath $target 2>&1
    If ($verifyOutput[-1] -notmatch 'Completed successfully') {
        $verifyOutput | ForEach-Object { Write-Host $_ }
        Throw 'ovftool pre-validation failed. Check the OVA, datastore, portgroup and credentials.'
    }

    Write-Step "Deploying witness appliance $newWitnessVmName (this can take several minutes)"
    & $ovfToolPath @ovfArgs $witnessOvaPath $target 2>&1 | ForEach-Object { Write-Host $_ }
    If ($LASTEXITCODE -ne 0) { Throw "ovftool deployment failed (exit code $LASTEXITCODE)" }

    # ---------------- 4. Configure management VLAN / SSH via guest operations ----------------
    Connect-VIServer -Server $infraVcenterFqdn -User $infraVcenterUser -Password $infraVcenterPassword | Out-Null
    Write-Step "Waiting for VMware Tools on $newWitnessVmName"
    Do {
        Start-Sleep -Seconds 10
        $toolsStatus = (Get-VM -Name $newWitnessVmName).ExtensionData.Guest.ToolsStatus
    } Until ($toolsStatus -in 'toolsOld', 'toolsOk')
    Start-Sleep -Seconds 60

    # NOTE: guest commands mirror Platform Tools (python /bin/esxcli.py ...). Invoke-VMScript behaviour against the
    # witness appliance has not been verified here - confirm on first run.
    $vm = Get-VM -Name $newWitnessVmName
    $guestCommands = @(
        "/bin/python /bin/esxcli.py network vswitch standard portgroup set -p 'Management Network' -v $newWitnessVlanId",
        '/bin/python /bin/vim-cmd hostsvc/start_ssh',
        '/bin/python /bin/vim-cmd hostsvc/enable_ssh'
    )
    Write-Step "Configuring management VLAN $newWitnessVlanId and enabling SSH"
    ForEach ($cmd in $guestCommands) {
        Invoke-VMScript -VM $vm -ScriptType Bash -ScriptText $cmd -GuestUser $witnessEsxiUsername -GuestPassword $witnessRootPassword | Out-Null
    }
    Disconnect-VIServer -Server $infraVcenterFqdn -Force -Confirm:$false | Out-Null

    # ---------------- 5. Register the new witness in the managed vCenter ----------------
    Write-Step "Waiting for $newWitnessIp to become reachable"
    Do { Start-Sleep -Seconds 10 } Until (Test-Connection -ComputerName $newWitnessIp -Count 1 -Quiet)

    Connect-VIServer -Server $managedVcenterFqdn -User $managedVcenterUser -Password $managedVcenterPassword | Out-Null
    Write-Step "Adding $newWitnessFqdn to vCenter"
    $location = Get-Datacenter -Name $managedDatacenterName
    Add-VMHost -Name $newWitnessFqdn -Location $location -User $witnessEsxiUsername -Password $witnessRootPassword -Force | Out-Null
    Write-Step "Allowing vCenter inventory to synchronise" 'WAIT'
    Start-Sleep -Seconds 90

    Write-Step "Removing vmk1 and secondarySwitch"
    Get-VMHost -Name $newWitnessFqdn | Get-VMHostNetworkAdapter -Name vmk1 | Remove-VMHostNetworkAdapter -Confirm:$false
    Get-VMHost -Name $newWitnessFqdn | Get-VirtualSwitch -Name 'secondarySwitch' | Remove-VirtualSwitch -Confirm:$false

    Write-Step "Starting SSH and configuring NTP"
    $newHost = Get-VMHost -Name $newWitnessFqdn
    $newHost | Get-VMHostService | Where-Object { $_.Label -eq 'SSH' } | Start-VMHostService | Out-Null
    $ntpList = $ntpServers.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    Add-VMHostNtpServer -VMHost $newHost -NtpServer $ntpList -ErrorAction SilentlyContinue | Out-Null
    $ntpd = $newHost | Get-VMHostService | Where-Object { $_.Key -eq 'ntpd' }
    $ntpd | Set-VMHostService -Policy On | Out-Null
    $ntpd | Restart-VMHostService -Confirm:$false | Out-Null
    Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null

    Write-Step "vSAN Witness $newWitnessFqdn redeployed and registered successfully"
    Exit 0
} Catch {
    Write-Step $_.Exception.Message 'ERROR'
    Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null
    Exit 1
}
