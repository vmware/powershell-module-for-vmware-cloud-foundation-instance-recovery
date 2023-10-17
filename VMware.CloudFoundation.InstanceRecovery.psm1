#Module to Assist in VCF Full Instance Recovery
If ($PSEdition -eq 'Core') {
    $Script:PSDefaultParameterValues = @{
        "invoke-restmethod:SkipCertificateCheck" = $true
        "invoke-webrequest:SkipCertificateCheck" = $true
    }
}
else
{
	Add-Type @"
		using System.Net;
		using System.Security.Cryptography.X509Certificates;
		public class TrustAllCertsPolicy : ICertificatePolicy {
			public bool CheckValidationResult(
				ServicePoint srvPoint, X509Certificate certificate,
				WebRequest request, int certificateProblem) {
				return true;
			}
		}
"@

	[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}

$is7Zip4PowerShellInstalled = Get-InstalledModule -name 7Zip4PowerShell -ErrorAction SilentlyContinue
If (!$is7Zip4PowerShellInstalled)
{
    Write-Output "Installing 7Zip4PowerShell Module"
    Install-Module 7Zip4PowerShell -Scope AllUsers
} 

#Region Data Gathering

Function New-GatherDataFromSDDCBackup
{
    Param(
        [Parameter (Mandatory = $true)][String] $backupFilePath,
        [Parameter (Mandatory = $true)][String] $encryptionPassword
    )
    $backupFilePath = (Resolve-Path -Path $backupFilePath).path
    $backupFileName = (Get-ChildItem -path $backupFilePath).name
    $parentFolder = Split-Path -Path $backupFilePath
    $extractedBackupFolder = ($backupFileName -Split(".tar.gz"))[0]
    
    #Decrypt Backup
    Write-Output "Decrypting Backup"
    $command = "openssl enc -d -aes-256-cbc -md sha256 -in $backupFilePath -pass pass:`"$encryptionPassword`" -out `"$parentFolder\decrypted-sddc-manager-backup.tar.gz`""
    Invoke-Expression "& $command" *>$null

    #Extract Backup
    Write-Output "Extracting Backup"
    Expand-7Zip -ArchiveFileName "$parentFolder\decrypted-sddc-manager-backup.tar.gz" -TargetPath $parentFolder
    Expand-7Zip -ArchiveFileName "$parentFolder\decrypted-sddc-manager-backup.tar" -TargetPath $parentFolder

    #Get Content of Password Vault
    Write-Output "Reading Password Vault"
    $passwordVaultJson = Get-Content "$parentFolder\$extractedBackupFolder\security_password_vault.json" | ConvertFrom-JSON
    $passwordVaultObject = @()
    Foreach ($object in $passwordVaultJson)
    {
        $passwordVaultObject += [pscustomobject]@{
            'entityId'   = $object.entityId
            'entityName' = $object.entityName
            'entityType'     = $object.entityType
            'credentialType'   = $object.credentialType
            'entityIpAddress'   = $object.entityIpAddress
            'username'   = $object.username
            'domainName'   = $object.domainName
            'password'   = $object.password
        }
    }

    Write-Output "Retrieving Management Component Detail"
    $mgmtDomainName = ($passwordVaultObject | Where-Object {$_.entityType -eq "BACKUP"}).domainName
    $mgmtComponentObject = @()
    $mgmtComponentObject += [pscustomobject]@{
        'sddcManagerFqdn' = ($passwordVaultObject | Where-Object {$_.entityType -eq "BACKUP"}).entityName
        'sddcManagerVmname' = ((($passwordVaultObject | Where-Object {$_.entityType -eq "BACKUP"}).entityName).split("."))[0]
        'mgmtDomainName'   = $mgmtDomainName
        'mgmtvCenterFqdn'   = ($passwordVaultObject | Where-Object {($_.entityType -eq "VCENTER") -and ($_.domainName -eq $mgmtDomainName) -and ($_.credentialType -eq "SSO")}).entityName
    }
    
    Write-Output "Retrieving NSX Manager Details"
    $psqlContent = Get-Content "$extractedBackupFolder\database\sddc-postgres.bkp"

    #Get All NSX Manager Clusters
    $nsxManagerstartingLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.nsxt (id" | Select Line,LineNumber).LineNumber
    $nsxManagerlineIndex = $nsxManagerstartingLineNumber
    $nsxtManagerClusters = @()
    Do 
    {
        $lineContent = $psqlContent | Select-Object -Index $nsxManagerlineIndex
        If ($lineContent -ne '\.')
        {
            $nodeContent = (($lineContent.split("`t")[9]).replace("\n","")) | ConvertFrom-Json
            $nodeIPs = ($nodeContent.managerIpsFqdnMap | Get-Member -type NoteProperty).name
            $nsxNodes = @()
            Foreach ($nodeIP in $nodeIPs)
            {
                $hostname = $nodeContent.managerIpsFqdnMap.$($nodeIP)
                $nsxNodes += [pscustomobject]@{
                    'hostname' = $hostname
                    'ip' =  $nodeIP
                }
            }
            $nsxtManagerClusters += [pscustomobject]@{
                'domainIDs' = $nodeContent.domainIds
                'nsxNodes' = $nsxNodes
            }
        }
        $nsxManagerlineIndex++
    }
    Until ($lineContent -eq '\.')


    #GetDomainDetails
    $domainsStartingLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.domain (id" | Select Line,LineNumber).LineNumber
    $domainLineIndex = $domainsStartingLineNumber
    $workloadDomains = @()
    Do 
    {
        $lineContent = $psqlContent | Select-Object -Index $domainLineIndex
        If ($lineContent -ne '\.')
        {
            $domainId = $lineContent.split("`t")[0]
            $domainName = $lineContent.split("`t")[3]
            $domainType = $lineContent.split("`t")[6]
            $workloadDomains += [pscustomobject]@{
                'domainName' = $domainName
                'domainID' = $domainID
                'domainType' = $domainType
                'nsxNodeDetails' = ($nsxtManagerClusters | Where-Object {$_.domainIDs -contains $domainId}).nsxNodes
            }
        }
        $domainLineIndex++
    } Until ($lineContent -eq '\.')

    Write-Output "Creating extracted-sddc-data.json"
    $sddcDataObject = New-Object -TypeName psobject
    $sddcDataObject | Add-Member -notepropertyname 'mgmtComponents' -notepropertyvalue $mgmtComponentObject
    $sddcDataObject | Add-Member -notepropertyname 'workloadDomains' -notepropertyvalue $workloadDomains
    $sddcDataObject | Add-Member -notepropertyname 'passwords' -notepropertyvalue $passwordVaultObject
    $sddcDataObject | ConvertTo-Json -Depth 10 | Out-File "$parentFolder\extracted-sddc-data.json"
}

Function New-UploadAndModifySDDCManagerBackup
{
    Param(
        [Parameter (Mandatory = $true)][String] $rootUserPassword,
        [Parameter (Mandatory = $true)][String] $vcfUserPassword,
        [Parameter (Mandatory = $true)][String] $backupFilePath,
        [Parameter (Mandatory = $true)][String] $encryptionPassword,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $true)][String] $tempvCenterFQDN,
        [Parameter (Mandatory = $true)][String] $tempvCenterAdmin,
        [Parameter (Mandatory = $true)][String] $tempvCenterAdminPassword
    )
    Write-Output "Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $mgmtVcenterFqdn = $extractedSddcData.mgmtComponents.mgmtVcenterFqdn
    $sddcManagerFQDN = $extractedSddcData.mgmtComponents.sddcManagerFQDN
    $sddcManagerVmName = $extractedSddcData.mgmtComponents.sddcManagerVmName
    $backupFilePath = (Resolve-Path -Path $backupFilePath).path
    $backupFileName = (Get-ChildItem -path $backupFilePath).name
    $extractedBackupFolder = ($backupFileName -Split(".tar.gz"))[0]
    
    #Establish SSH Connection to SDDC Manager
    Write-Output "Establishing Connection to SDDC Manager Appliance"
    $SecurePassword = ConvertTo-SecureString -String $vcfUserPassword -AsPlainText -Force
    $mycreds = New-Object System.Management.Automation.PSCredential ("vcf", $SecurePassword)
    Get-SSHTrustedHost | Remove-SSHTrustedHost
    $inmem = New-SSHMemoryKnownHost
    New-SSHTrustedHost -KnownHostStore $inmem -HostName $sddcManagerFQDN -FingerPrint ((Get-SSHHostKey -ComputerName $sddcManagerFQDN).fingerprint) | Out-Null
    Do
    {
        $sshSession = New-SSHSession -computername $sddcManagerFQDN -Credential $mycreds -KnownHost $inmem
    } Until ($sshSession)

    #Perform KeyScan
    Write-Output "Performing Keyscan on SDDC Manager Appliance"
    $result = (Invoke-SSHCommand -timeout 30 -sessionid $sshSession.SessionId -command "ssh-keyscan $mgmtVcenterFqdn").output
    
    #Determine new SSH Keys
    $newNistKey = '"' + (($result | Where-Object {$_ -like "*ecdsa-sha2-nistp256*"}).split("ecdsa-sha2-nistp256 "))[1] + '"'
    If ($newNistKey) { Write-Output "New ecdsa-sha2-nistp256 key for $mgmtVcenterFqdn retrieved" }
    $newRSAKey = '"' + (($result | Where-Object {$_ -like "*ssh-rsa*"}).split("ssh-rsa "))[1] + '"'
    If ($newRSAKey) { Write-Output "New ssh-rsa key for $mgmtVcenterFqdn retrieved" }

    #Upload Backup
    $vCenterConnection = Connect-VIServer -server $tempvCenterFQDN -user $tempvCenterAdmin -password $tempvCenterAdminPassword
    Write-Output "Uploading Backup File to SDDC Manager Appliance"
    $copyFile = Copy-VMGuestFile -Source $backupFilePath -Destination "/tmp/$backupFileName" -LocalToGuest -VM $sddcManagerVmName -GuestUser "root" -GuestPassword $rootUserPassword -Force -WarningAction SilentlyContinue -WarningVariable WarnMsg

    #Decrypt/Extract Backup
    Write-Output "Decrypting Backup on SDDC Manager Appliance"
    #$command = "cd /tmp; OPENSSL_FIPS=1 openssl enc -d -aes-256-cbc -md sha256 -in /tmp/$backupFileName -pass pass:`'$encryptionPassword`' | tar -xz"
    $command = "cd /tmp; echo `'$encryptionPassword`' | OPENSSL_FIPS=1 openssl enc -d -aes-256-cbc -md sha256 -in /tmp/$backupFileName -pass stdin | tar -xz"
    $result = ((Invoke-VMScript -ScriptText $command -VM $sddcManagerVmName -GuestUser 'root' -GuestPassword $rootUserPassword).ScriptOutput) -replace "(`n|`r)"

    #Modfiy JSON file  
    #Existing Nist Key
    Write-Output "Parsing Backup on SDDC Manager Appliance for original ecdsa-sha2-nistp256 key for $mgmtVcenterFqdn"
    $command = "cat /tmp/$extractedBackupFolder/appliancemanager_ssh_knownHosts.json  | jq `'.knownHosts[] | select(.host==`"$mgmtVcenterFqdn`") | select(.keyType==`"ecdsa-sha2-nistp256`")| .key`'"
    $oldNistKey = ((Invoke-VMScript -ScriptText $command -VM $sddcManagerVmName -GuestUser 'root' -GuestPassword $rootUserPassword).ScriptOutput) -replace "(`n|`r)"

    #Existing rsa Key
    Write-Output "Parsing Backup on SDDC Manager Appliance for original ssh-rsa key for $mgmtVcenterFqdn"
    $command = "cat /tmp/$extractedBackupFolder/appliancemanager_ssh_knownHosts.json  | jq `'.knownHosts[] | select(.host==`"$mgmtVcenterFqdn`") | select(.keyType==`"ssh-rsa`")| .key`'"
    $oldRSAKey = ((Invoke-VMScript -ScriptText $command -VM $sddcManagerVmName -GuestUser 'root' -GuestPassword $rootUserPassword).ScriptOutput) -replace "(`n|`r)"

    #Sed File
    Write-Output "Replacing ecdsa-sha2-nistp256 and ssh-rsa keys and re-encrypting the SDDC Manager Backup"
    $command = "sed -i `'s@$oldNistKey@$newNistKey@`' /tmp/$extractedBackupFolder/appliancemanager_ssh_knownHosts.json; sed -i `'s@$oldRSAKey@$newRSAKey@`' /tmp/$extractedBackupFolder/appliancemanager_ssh_knownHosts.json; mv /tmp/$backupFileName /tmp/$backupFileName.original; export encryptionPassword='$encryptionPassword'; cd /tmp; tar -cz $extractedBackupFolder | OPENSSL_FIPS=1 openssl enc -aes-256-cbc -md sha256 -out /tmp/$backupFileName -pass env:encryptionPassword"
    $result = ((Invoke-VMScript -ScriptText $command -VM $sddcManagerVmName -GuestUser 'root' -GuestPassword $rootUserPassword).ScriptOutput) -replace "(`n|`r)"

    #Disconnect from vCenter
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
}
#EndRegion Data Gathering

#Region vCenter Functions
Function Add-ClusterHostsToVds {
    Param(
        [Parameter (Mandatory = $true)][String] $restoredvCenterFQDN,
        [Parameter (Mandatory = $true)][String] $restoredvCenterAdmin,
        [Parameter (Mandatory = $true)][String] $restoredvCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $restoredclusterName,
        [Parameter (Mandatory = $true)][String] $esxiRootPassword,
        [Parameter (Mandatory = $true)][String] $restoredVdsName
    )
    $esxiHosts = get-cluster -name $restoredclusterName | get-vmhost
    Foreach ($esxiHost in $esxiHosts) {
        Write-Host "[$esxiHost] Adding to $restoredVdsName"
        Get-VDSwitch -Name $restoredVdsName | Add-VDSwitchVMHost -VMHost $esxiHost | Out-null
        $vmNicToAdd = Get-VMHostNetworkAdapter -Physical -Name vmnic0
        Get-VDSwitch $restoredVdsName | Add-VDSwitchPhysicalNetworkAdapter -VMHostNetworkAdapter $vmNicToAdd -Confirm:$false | Out-Null
    }
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
}


Function Move-ClusterHostsToRestoredVcenter {
    Param(
        [Parameter (Mandatory = $true)][String] $tempvCenterFQDN,
        [Parameter (Mandatory = $true)][String] $tempvCenterAdmin,
        [Parameter (Mandatory = $true)][String] $tempvCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $tempclusterName,
        [Parameter (Mandatory = $true)][String] $restoredvCenterFQDN,
        [Parameter (Mandatory = $true)][String] $restoredvCenterAdmin,
        [Parameter (Mandatory = $true)][String] $restoredvCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $restoredclusterName,
        [Parameter (Mandatory = $true)][String] $esxiRootPassword
    )
    $tempvCenterConnection = connect-viserver $tempvCenterFQDN -user $tempvCenterAdmin -password $tempvCenterAdminPassword
    $esxiHosts = get-cluster -name $tempclusterName | get-vmhost
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
    $restoredvCenterConnection = connect-viserver $restoredvCenterFQDN -user $restoredvCenterAdmin -password $restoredvCenterAdminPassword
    Foreach ($esxiHost in $esxiHosts) {
        Add-VMHost -Name $esxiHost.Name -Location $restoredclusterName -User root -Password $esxiRootPassword -Force -Confirm:$false | Out-Null
    }
}

Function Remove-ClusterHostsFromVds {
    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $vdsName
    )
    $vCenterConnection = connect-viserver $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    $esxiHosts = get-cluster -name $clusterName | get-vmhost
    Foreach ($esxiHost in $esxiHosts) {
        Get-VDSwitch -Name $vdsName | Get-VMHostNetworkAdapter -VMHost $esxiHost -Physical | Remove-VDSwitchPhysicalNetworkAdapter -Confirm:$false | Out-Null
        Get-VDSwitch -Name $vdsName | Remove-VDSwitchVMHost -VMHost $esxiHost -Confirm:$false | Out-Null
    }
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
}

Function Move-MgmtVmsToTempPg {
    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName
    )
    $vCenterConnection = connect-viserver $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    $vmsTomove = get-cluster -name $clusterName | get-vm | ? { $_.Name -notlike "*vCLS*" }
    foreach ($vmToMove in $vmsTomove) {
        Get-VM -Name $vmToMove | Get-NetworkAdapter | Set-NetworkAdapter -NetworkName "mgmt_temp" -confirm:$false | Out-Null
    }
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
}

Function Move-ClusterHostNetworkingTovSS {
    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $vdsName,
        [Parameter (Mandatory = $true)][String] $mtu,
        [Parameter (Mandatory = $true)][String] $vmnic,
        [Parameter (Mandatory = $true)][String] $mgmtVlanId,
        [Parameter (Mandatory = $true)][String] $vMotionVlanId,
        [Parameter (Mandatory = $true)][String] $vSanVlanId

    )
    
    $vCenterConnection = connect-viserver $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword

    $vmhost_array = get-cluster -name $clusterName | get-vmhost

    # VDS to migrate from
    $vds = Get-VDSwitch -Name $vdsName

    # VSS to migrate to
    $vss_name = "vSwitch0"

    # Name of portgroups to create on VSS
    $mgmt_name = "Management"
    $vmotion_name = "vMotion"
    $storage_name = "vSAN"

    foreach ($vmhost in $vmhost_array) {
        <# Write-Host "[$vmhost] Entering Maintenance Mode" 
        Get-VMHost -Name $vmhost | set-vmhost -State Maintenance -VsanDataMigrationMode NoDataMigration | Out-Null
 #>
        Get-VMHostNetworkAdapter -VMHost $vmhost -Physical -Name $vmnic | Remove-VDSwitchPhysicalNetworkAdapter -Confirm:$false | Out-Null
        New-VirtualSwitch -VMHost $vmhost -Name vSwitch0 -mtu $mtu | Out-Null
        New-VirtualPortGroup -VirtualSwitch (Get-VirtualSwitch -VMHost $vmhost -Name "vSwitch0") -Name "mgmt_temp" -VLanId $mgmtVlanId | Out-Null

        # pNICs to migrate to VSS
        Write-Host "[$vmhost] Retrieving pNIC info for vmnic1"
        $vmnicToMove = Get-VMHostNetworkAdapter -VMHost $vmhost -Name $vmnic

        # Array of pNICs to migrate to VSS
        $pnic_array = @($vmnicToMove)

        # vSwitch to migrate to
        $vss = Get-VMHost -Name $vmhost | Get-VirtualSwitch -Name $vss_name

        # Create destination portgroups
        Write-Host "[$vmhost] Creating $mgmt_name portrgroup on $vss_name"
        $mgmt_pg = New-VirtualPortGroup -VirtualSwitch $vss -Name $mgmt_name -VLanId $mgmtVlanId

        Write-Host "[$vmhost] Creating $vmotion_name portrgroup on $vss_name"
        $vmotion_pg = New-VirtualPortGroup -VirtualSwitch $vss -Name $vmotion_name -VLanId $vMotionVlanId

        Write-Host "[$vmhost] Creating $storage_name Network portrgroup on $vss_name"
        $storage_pg = New-VirtualPortGroup -VirtualSwitch $vss -Name $storage_name -VLanId $vSanVlanId

        # Array of portgroups to map VMkernel interfaces (order matters!)
        $pg_array = @($mgmt_pg, $vmotion_pg, $storage_pg)

        # VMkernel interfaces to migrate to VSS
        $mgmt_vmk = Get-VMHostNetworkAdapter -VMHost $vmhost -Name "vmk0"
        $vmotion_vmk = Get-VMHostNetworkAdapter -VMHost $vmhost -Name "vmk1"
        $storage_vmk = Get-VMHostNetworkAdapter -VMHost $vmhost -Name "vmk2"

        # Array of VMkernel interfaces to migrate to VSS (order matters!)
        $vmk_array = @($mgmt_vmk, $vmotion_vmk, $storage_vmk)

        # Perform the migration
        Write-Host "[$vmhost] Migrating from $vdsName to $vss_name"
        Add-VirtualSwitchPhysicalNetworkAdapter -VirtualSwitch $vss -VMHostPhysicalNic $pnic_array -VMHostVirtualNic $vmk_array -VirtualNicPortgroup $pg_array  -Confirm:$false
       <#  Write-Host "[$vmhost] Exiting Maintenance Mode" 
        Get-VMHost -Name $vmhost | set-vmhost -State Connected | Out-Null #>
        Start-Sleep 5
    }
}

Function Move-ClusterVmnicTovSwitch {
    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $mtu,
        [Parameter (Mandatory = $true)][String] $VLanId,
        [Parameter (Mandatory = $true)][String] $vmnic
    )

    $vCenterConnection = connect-viserver $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    $esxiHosts = get-cluster -name $clusterName | get-vmhost
    Foreach ($esxiHost in $esxiHosts) {
        Write-Host "[$esxiHost] Migrating `'$vmnic`' from vDS to vSwitch0"
        Get-VMHostNetworkAdapter -VMHost $esxiHost -Physical -Name $vmnic | Remove-VDSwitchPhysicalNetworkAdapter -Confirm:$false | Out-Null
        New-VirtualSwitch -VMHost $esxiHost -Name vSwitch0 -nic $vmnic -mtu $mtu | Out-Null
        New-VirtualPortGroup -VirtualSwitch (Get-VirtualSwitch -VMHost $esxiHost -Name "vSwitch0") -Name "mgmt_temp" -VLanId $VLanId | Out-Null
    }
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
}

Function Set-ClusterHostsvSanIgnoreClusterMemberList {
    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $esxiRootPassword,
        [Parameter (Mandatory = $true)][ValidateSet("enable", "disable")][String] $setting
    )
    # prepare ESXi hosts for cluster migration - Tested
    $vCenterConnection = connect-viserver $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    Get-Cluster -name $clusterName | Get-VMHost | Get-VMHostService | Where-Object { $_.label -eq "SSH" } | Start-VMHostService | Out-Null
    $esxiHosts = get-cluster -name $clusterName | get-vmhost
    if ($setting -eq "enable") {
        $value = 1
    }
    else {
        $value = 0
    }
    $esxCommand = "esxcli system settings advanced set --int-value=$value --option=/VSAN/IgnoreClusterMemberListUpdates"
    $password = ConvertTo-SecureString $esxiRootPassword -AsPlainText -Force
    $mycreds = New-Object System.Management.Automation.PSCredential ("root", $password)
    foreach ($esxiHost in $esxiHosts) {
        Get-SSHTrustedHost -HostName $esxiHost | Remove-SSHTrustedHost | Out-Null
        Write-Host "Setting vSAN Ignore Cluster Member to `'$setting`' for $esxiHost"
        $sshSession = New-SSHSession -computername $esxiHost -credential $mycreds -AcceptKey
        Invoke-SSHCommand -timeout 30 -sessionid $sshSession.SessionId -command $esxCommand | Out-Null
    }
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
}

Function Move-ClusterVMsToFirstHost {
    Param(
       <#  [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword, #>
        [Parameter (Mandatory = $true)][String] $clusterName
        
    )
    #$vCenterConnection = connect-viserver $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    $vms = Get-Cluster -Name $clusterName | Get-VM | Where-Object { $_.Name -notlike "vCLS*" } | Select-Object Name, VMhost
    $firstHost = ((Get-cluster -name $clusterName | Get-VMHost | Sort-Object -property Name)[0]).Name
    Foreach ($vm in $vms) {
        if ($vm.vmHost.Name -ne $firstHost) {
            Get-VM -Name $vm.name | Move-VM -Location $firstHost -Runasync | Out-Null
            Write-Host "Moving $($vm.name) to $firstHost"
        }
    }
    Do {
        $runningTasks = Get-Task | Where-Object { ($_.Name -eq "RelocateVM_Task") -and ($_.State -eq "running") } 
        Sleep 5
    } Until (!$runningTasks)
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
}

Function Resolve-PhysicalHostServiceAccounts {
    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $svcAccountPassword,
        [Parameter (Mandatory = $true)][String] $sddcManagerFQDN,
        [Parameter (Mandatory = $true)][String] $sddcManagerUser,
        [Parameter (Mandatory = $true)][String] $sddcManagerPassword
    )
    $vCenterConnection = Connect-VIServer -server $vCenterFQDN -username $vCenterAdmin -password $vCenterAdminPassword
    $clusterHosts = Get-Cluster -name $clusterName | Get-VMHost
    Disconnect-VIServer * -confirm:$false
    $tokenRequest = Request-VCFToken -fqdn $sddcManagerFQDN -username $sddcManagerUser -password $sddcManagerPassword
    #verify SDDC Manager credential API state
    $credentialAPILastTask = ((Get-VCFCredentialTask | Sort-Object -Property creationTimeStamp)[-1]).status
    if ($credentialAPILastTask -eq "FAILED")
    {
        Write-Host "Failed credential operation detected. Please resolve in SDDC Manager and try again" ; break
    }

    Foreach ($hostInstance in $clusterHosts) {
        $esxiRootPassword = [String](Get-VCFCredential | ? {$_.resource.resourceName -eq $hostInstance.name}).password
        $esxiConnection = Connect-VIServer -Server $hostInstance.name -User root -Password $esxiRootPassword.Trim() | Out-Null
        $esxiHostName = $hostInstance.name.Split(".")[0]
        $svcAccountName = "svc-vcf-$esxiHostName"
        $accountExists = Get-VMHostAccount -Server $esxiConnection -User $svcAccountName -erroraction SilentlyContinue
        If (!$accountExists) {
            Write-Host "[$($hostInstance.name)] VCF Service Account Not Found: Creating"
            New-VMHostAccount -Id $svcAccountName -Password $svcAccountPassword -Description "ESXi User" | Out-Null
            New-VIPermission -Entity (Get-Folder root) -Principal $svcAccountName -Role Admin | Out-Null
            Disconnect-VIServer $hostInstance.name -confirm:$false | Out-Null
        }
        else
        {
            Write-Host "[$($hostInstance.name)] VCF Service Account Found: Setting Password"
            Set-VMHostAccount -UserAccount $svcAccountName -Password $svcAccountPassword | Out-Null
        }
    }

    Foreach ($hostInstance in $clusterHosts) {
        Remove-Variable credentialsObject -ErrorAction SilentlyContinue
        Remove-Variable elementsObject -ErrorAction SilentlyContinue
        Remove-Variable esxHostObject -ErrorAction SilentlyContinue

        $esxiHostName = $hostInstance.name.Split(".")[0]
        $svcAccountName = "svc-vcf-$esxiHostName"
        
        $credentialsObject += [pscustomobject]@{
            'username' = $svcAccountName
            'password' = $svcAccountPassword
        }
        
        $elementsObject += [pscustomobject]@{
            'resourceName' = $hostInstance.name
            'resourceType' = 'ESXI'
            'credentials'  = @($credentialsObject)
        }

        $esxHostObject += [pscustomobject]@{
            'operationType' = 'REMEDIATE'
            'elements'      = @($elementsObject)
        }

        $esxiHostJson = $esxHostObject | Convertto-Json -depth 10
        Write-Host "[$($hostInstance.name)] Remediating VCF Service Account Password: " -nonewline
        $taskID = (Set-VCFCredential -json $esxiHostJson).id
        Do {
            Sleep 5
            $taskStatus = (Get-VCFCredentialTask -id $taskID).status
        } Until ($taskStatus -ne "IN_PROGRESS")
        Write-Output "$taskStatus"
    }
}

Function Set-PhysicalHostServiceAccountPasswords {
    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $svcAccountPassword,
        [Parameter (Mandatory = $true)][String] $esxiRootPassword
        
    )
    $vCenterConnection = Connect-VIServer -server $vCenterFQDN -username $vCenterAdmin -password $vCenterAdminPassword
    $clusterHosts = Get-Cluster -name $clusterName | Get-VMHost
    Disconnect-VIServer * -confirm:$false
    Foreach ($hostInstance in $clusterHosts) {
        Connect-VIServer -Server $hostInstance.name -User root -Password $esxiRootPassword | Out-Null
        $esxiHostName = $hostInstance.name.Split(".")[0]
        $svcAccountName = "svc-vcf-$esxiHostName"
        Set-VMHostAccount -UserAccount $svcAccountName -Password $svcAccountPassword -confirm:$false | Out-Null
        Disconnect-VIServer $hostInstance.name -confirm:$false
    }
}

Function Set-ClusterDRSLevel {
    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $DrsAutomationLevel
        
    )
    $vCenterConnection = connect-viserver $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    set-cluster -cluster $clusterName -DrsAutomationLevel $DrsAutomationLevel -confirm:$false
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
}

Function Remove-NonResponsiveHosts {
    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName
        
    )
    $vCenterConnection = connect-viserver $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    $nonResponsiveHosts = get-cluster -name $clusterName | get-vmhost | Where-Object { $_.ConnectionState -eq "NotResponding" }
    foreach ($nonResponsiveHost in $nonResponsiveHosts) {
        Get-VMHost | Where-Object { $_.Name -eq $nonResponsiveHost.Name } | Remove-VMHost -Confirm:$false
    }
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
}

Function Add-HostsToCluster {
    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $esxiRootPassword,
        [Parameter (Mandatory = $true)][String] $sddcManagerFQDN,
        [Parameter (Mandatory = $true)][String] $sddcManagerUser,
        [Parameter (Mandatory = $true)][String] $sddcManagerPassword
    )
    $tokenRequest = Request-VCFToken -fqdn $sddcManagerFQDN -username $sddcManagerUser -password $sddcManagerPassword
    $newHosts = (get-vcfhost | where-object { $_.id -in ((get-vcfcluster -name $clusterName).hosts.id) }).fqdn
    $vCenterConnection = connect-viserver $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    foreach ($newHost in $newHosts) {
        $vmHosts = (Get-cluster -name $clusterName | Get-VMHost).Name
        if ($newHost -notin $vmHosts) {
            $esxiConnection = connect-viserver $newHost -user root -password $esxiRootPassword
            if ($esxiConnection) {
                Write-Output "Adding $newHost to cluster $clusterName"
                Add-VMHost $newHost -username root -password $esxiRootPassword -Location $clusterName -Force -Confirm:$false | Out-Null
            }
            else {
                Write-Error "Unable to connect to $newHost. Host will not be added to the cluster"
            }
        }
        else {
            Write-Output "$newHost is already part of $clusterName. Skipping"
        }
    }
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
}

<# Function Add-HostsToVDS
{
    Param(
        [Parameter (Mandatory=$true)][String] $vCenterFQDN,
        [Parameter (Mandatory=$true)][String] $vCenterAdmin,
        [Parameter (Mandatory=$true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory=$true)][String] $clusterName,
        [Parameter (Mandatory=$true)][String] $sddcManagerFQDN,
        [Parameter (Mandatory=$true)][String] $sddcManagerUser,
        [Parameter (Mandatory=$true)][String] $sddcManagerPassword
        )
    $vCenterConnection = connect-viserver $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    $vmHosts = (Get-cluster -name $clusterName | Get-VMHost).Name
    $tokenRequest = Request-VCFToken -fqdn $sddcManagerFQDN -username $sddcManagerUser -password $sddcManagerPassword
    $vdsName = ((get-vcfCluster -name $clusterName -vdses) | ? {$_.portGroups.transportType -contains "MANAGEMENT"}).name
    # Put Host in Maintenance Mode
    foreach ($vmhost in $vmHosts) 
    {
    Write-Output "`nEntering Maintenance Mode for" $vmhost
    Get-VMHost -Name $vmhost | set-vmhost -State Maintenance -VsanDataMigrationMode NoDataMigration | Out-Null
    # Add host to VDS
    Write-Output "`nAdding $vmhost to $vdsName " 
    $vds = Get-VDSwitch -Name $vdsName | Add-VDSwitchVMHost -VMHost $vmhost
    $vmhostNetworkAdapter = Get-VMHost $vmhost | Get-VMHostNetworkAdapter -Physical -Name vmnic1
    $vds | Add-VDSwitchPhysicalNetworkAdapter -VMHostNetworkAdapter $vmhostNetworkAdapter -Confirm:$false
    }
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
} #>

Function Remove-StandardSwitch {
    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName
    )
    $vCenterConnection = connect-viserver $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    $vmHosts = (Get-cluster -name $clusterName | Get-VMHost).Name
    foreach ($vmhost in $vmHosts) {
        Write-Output "Removing standard vSwitch from $vmhost" 
        Get-VMHost -Name $vmhost | Get-VirtualSwitch -Name "vSwitch0" | Remove-VirtualSwitch -Confirm:$false | Out-Null
    }
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
}

Function Add-VMKernelsToHost {
    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $sddcManagerFQDN,
        [Parameter (Mandatory = $true)][String] $sddcManagerUser,
        [Parameter (Mandatory = $true)][String] $sddcManagerPassword
    )
    $tokenRequest = Request-VCFToken -fqdn $sddcManagerFQDN -username $sddcManagerUser -password $sddcManagerPassword
    
    $vCenterConnection = connect-viserver $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    $vmHosts = (Get-cluster -name $clusterName | Get-VMHost).Name
    foreach ($vmhost in $vmHosts) { 
        $vmotionPG = ((get-vcfCluster -name $clusterName -vdses).portGroups | ? { $_.transportType -eq "VMOTION" }).name
        $vmotionVDSName = ((get-vcfCluster -name $clusterName -vdses) | ? { $_.portGroups.transportType -contains "VMOTION" }).name
        $vmotionIP = (((Get-VCFHost | Where-Object { $_.fqdn -eq $vmhost }).ipAddresses) | ? { $_.type -eq "VMOTION" }).ipAddress
        $vmotionMask = (Get-VCFNetworkIPPool -id ((Get-VCFHost | Where-Object { $_.fqdn -eq $vmhost }).networkPool.id) | ? { $_.type -eq "VMOTION" }).mask
        $vmotionMTU = (Get-VCFNetworkIPPool -id ((Get-VCFHost | Where-Object { $_.fqdn -eq $vmhost }).networkPool.id) | ? { $_.type -eq "VMOTION" }).mtu
        $vmotionGW = (Get-VCFNetworkIPPool -id ((Get-VCFHost | Where-Object { $_.fqdn -eq $vmhost }).networkPool.id) | ? { $_.type -eq "VMOTION" }).gateway
        $vsanPG = ((get-vcfCluster -name $clusterName -vdses).portGroups | ? { $_.transportType -eq "VSAN" }).name
        $vsanVDSName = ((get-vcfCluster -name $clusterName -vdses) | ? { $_.portGroups.transportType -contains "VSAN" }).name
        $vsanIP = (((Get-VCFHost | Where-Object { $_.fqdn -eq $vmhost }).ipAddresses) | ? { $_.type -eq "VSAN" }).ipAddress
        $vsanMask = (Get-VCFNetworkIPPool -id ((Get-VCFHost | Where-Object { $_.fqdn -eq $vmhost }).networkPool.id) | ? { $_.type -eq "VSAN" }).mask
        $vsanMTU = (Get-VCFNetworkIPPool -id ((Get-VCFHost | Where-Object { $_.fqdn -eq $vmhost }).networkPool.id) | ? { $_.type -eq "VSAN" }).mtu
        $vsanGW = (Get-VCFNetworkIPPool -id ((Get-VCFHost | Where-Object { $_.fqdn -eq $vmhost }).networkPool.id) | ? { $_.type -eq "VSAN" }).gateway

        Write-Output "Creating vMotion vMK on $vmHost"
        $dvportgroup = Get-VDPortgroup -name $vmotionPG -VDSwitch $vmotionVDSName
        $vmk = New-VMHostNetworkAdapter -VMHost $vmhost -VirtualSwitch $vmotionVDSName -mtu $vmotionMTU -PortGroup $dvportgroup -ip $vmotionIP -SubnetMask $vmotionMask -NetworkStack (Get-VMHostNetworkStack -vmhost $vmhost | Where-Object { $_.id -eq "vmotion" })
        Write-Output "Setting vMotion Gateway on $vmHost"
        $vmkName = 'vmk1'
        $esx = Get-VMHost -Name $vmHost
        $esxcli = Get-EsxCli -VMHost $esx -V2
        $interface = $esxcli.network.ip.interface.ipv4.get.Invoke(@{interfacename = $vmkName })
        $interfaceArg = @{
            netmask       = $interface[0].IPv4Netmask
            type          = $interface[0].AddressType.ToLower()
            ipv4          = $interface[0].IPv4Address
            interfacename = $interface[0].Name
            gateway       = $vmotionGW
        }
        $esxcli.network.ip.interface.ipv4.set.Invoke($interfaceArg) *>$null

        Write-Output "Creating vSAN vMK on $vmHost"
        $dvportgroup = Get-VDPortgroup -name $vsanPG -VDSwitch $vsanVDSName
        $vmk = New-VMHostNetworkAdapter -VMHost $vmhost -VirtualSwitch $vsanVDSName -mtu $vsanMTU -PortGroup $dvportgroup -ip $vsanIP -SubnetMask $vsanMask -VsanTrafficEnabled:$true

        Write-Host "Setting vSAN Gateway on $vmHost"
        $vmkName = 'vmk2'
        $esx = Get-VMHost -Name $vmHost
        $esxcli = Get-EsxCli -VMHost $esx -V2
        $interface = $esxcli.network.ip.interface.ipv4.get.Invoke(@{interfacename = $vmkName })
        $interfaceArg = @{
            netmask       = $interface[0].IPv4Netmask
            type          = $interface[0].AddressType.ToLower()
            ipv4          = $interface[0].IPv4Address
            interfacename = $interface[0].Name
            gateway       = $vsanGW
        }
        $esxcli.network.ip.interface.ipv4.set.Invoke($interfaceArg) *>$null
    }
}

Function Backup-ClusterVMOverrides {
    <#
    .SYNOPSIS
        Retrieves and saves configured VM Overrides.

    .DESCRIPTION
        Saves details for configured VM Overrides for the passed cluster to a JSON file

    .EXAMPLE
        Backup-ClusterVMOverrides -clusterName 'sfo-m01-cl01'
    #>
    Param(
        [Parameter(Mandatory = $true)]
        [String]$clusterName
    )
    $cluster = Get-Cluster -Name $clusterName
    #$overRiddenVMs = $cluster.ExtensionData.ConfigurationEx.DrsVmConfig
    $clusterVMs = Get-Cluster -name $clusterName | Get-VM | Select-Object Name, id, DrsAutomationLevel
    $overRiddenData = @()
    Foreach ($clusterVM in $clusterVMs) {
        $vmMonitoringSettings = ($cluster.ExtensionData.Configuration.DasVmConfig | Where-Object { $_.Key -eq $clusterVM.id }).DasSettings
        $vmVmReadinessSettings = ($cluster.ExtensionData.ConfigurationEx.VmOrchestration | Where-Object { $_.vm -eq $clusterVM.id }).VmReadiness
        $overRiddenData += [pscustomobject]@{ 
            #VM Basic Settings
            'name'                      = $clusterVM.name
            'id'                        = $clusterVM.id
            #DRS Automation Settings
            'drsAutomationLevel'        = [STRING]$clusterVM.DrsAutomationLevel
            #VM Monitoring Settings
            'VmMonitoring'              = $vmMonitoringSettings.VmToolsMonitoringSettings.VmMonitoring
            'ClusterSettings'           = $vmMonitoringSettings.VmToolsMonitoringSettings.ClusterSettings
            'FailureInterval'           = $vmMonitoringSettings.VmToolsMonitoringSettings.FailureInterval
            'MinUpTime'                 = $vmMonitoringSettings.VmToolsMonitoringSettings.MinUpTime
            'MaxFailures'               = $vmMonitoringSettings.VmToolsMonitoringSettings.MaxFailures
            'MaxFailureWindow'          = $vmMonitoringSettings.VmToolsMonitoringSettings.MaxFailureWindow
            #vSphereHASettings
            'RestartPriorityTimeout'    = $vmMonitoringSettings.RestartPriorityTimeout
            'RestartPriority'           = $vmMonitoringSettings.RestartPriority
            'IsolationResponse'         = $vmMonitoringSettings.IsolationResponse
            'ReadyCondition'            = $vmVmReadinessSettings.ReadyCondition
            'PostReadyDelay'            = $vmVmReadinessSettings.PostReadyDelay
            #APD
            'VmStorageProtectionForAPD' = $vmMonitoringSettings.VmComponentProtectionSettings.VmStorageProtectionForAPD
            'VmTerminateDelayForAPDSec' = $vmMonitoringSettings.VmComponentProtectionSettings.VmTerminateDelayForAPDSec
            'VmReactionOnAPDCleared' = $vmMonitoringSettings.VmComponentProtectionSettings.VmReactionOnAPDCleared
            #PDL
            'VmStorageProtectionForPDL' = $vmMonitoringSettings.VmComponentProtectionSettings.VmStorageProtectionForPDL
        }
    }
    $overRiddenData | ConvertTo-Json -depth 10 | Out-File "$clusterName-vmOverrides.json"
}

Function Backup-ClusterVMLocations {
    <#
    .SYNOPSIS
        Retrieves the folder and resource pool settings.

    .DESCRIPTION
        Saves the folder and resource pool settings for the passed cluster to a JSON file

    .EXAMPLE
        Backup-ClusterVMLocations -clusterName 'sfo-m01-cl01'
    #>
    Param(
        [Parameter(Mandatory = $true)]
        [String]$clusterName
    )
    Try {

        $clusterVMs = Get-Cluster -Name $clusterName | Get-VM | Select-Object Name, id, folder, resourcePool    
        $allVMs = @()
        Foreach ($vm in $clusterVMs) {
            $vmSettings = @()
            $vmSettings += [pscustomobject]@{
                'name'         = $vm.name
                'id'           = $vm.id
                'folder'       = $vm.folder.name
                'resourcePool' = $vm.resourcePool.name
            }
            $allVMs += $vmSettings
        }
        $allVMs | ConvertTo-Json -depth 10 | Out-File "$clusterName-vmLocations.json"
    }
    Catch {
        catchWriter -object $_
    }
}

Function Backup-ClusterDRSGroupsAndRules {
    <#
    .SYNOPSIS
        Retrieves the DRS Groups And Rules for a Cluster

    .DESCRIPTION
        Saves the DRS Group and Rule settings for the passed cluster to a JSON file 

    .EXAMPLE
        Backup-ClusterDRSGroupsAndRules -clusterName 'sfo-m01-cl01'
    #>
    Param(
        [Parameter(Mandatory = $true)]
        [PSObject]$clusterName
    )
    Try {
        $retrievedVmDrsGroups = Get-DrsClusterGroup -cluster $clusterName
        $drsGroupsObject = @()
        Foreach ($drsGroup in $retrievedVmDrsGroups) {
            $drsGroupsObject += [pscustomobject]@{
                'name'    = $drsGroup.name
                'type'    = [STRING]$drsGroup.GroupType
                'members' = $drsGroup.Member.name
            }
        }
        
        #$drsGroupsObject | ConvertTo-Json -depth 10

        $retrievedDrsRules = Get-DrsRule -Cluster $clusterName
        $vmAffinityRulesObject = @()
        Foreach ($drsRule in $retrievedDrsRules) {
            $members = @()
            Foreach ($vmId in $drsRule.vmids) {
                $vmName = (Get-Cluster -name $clusterName | Get-VM | Where-Object { $_.id -eq $vmId }).name
                $members += $vmName    
            }
            $vmAffinityRulesObject += [pscustomobject]@{
                'name'         = $drsrule.name
                'type'         = [String]$drsRule.type
                'keepTogether' = $drsRule.keepTogether
                'members'      = $members
            }
        }
        #$vmAffinityRulesObject | ConvertTo-Json -depth 10

        $retrievedDrsRules = Get-DrsRule -type VMHostAffinity -Cluster $clusterName
        $VMHostAffinityRulesObject = @()
        Foreach ($drsRule in $retrievedDrsRules) {
            $vmNames = @()
            Foreach ($vmId in $drsRule.vmids) {
                $vmName = (Get-Cluster -name $clusterName | Get-VM | Where-Object { $_.id -eq $vmId }).name
                $vmNames += $vmName    
            }
            $vmNames = $vmNames -join (",")
            $VMHostAffinityRulesObject += [pscustomobject]@{
                'name'          = $drsrule.name
                'variant'       = If ($drsRule.ExtensionData.Mandatory -eq $true) { If ($drsRule.ExtensionData.AffineHostGroupName) { "MustRunOn" } else { "MustNotRunOn" } } else { If ($drsRule.ExtensionData.AffineHostGroupName) { "ShouldRunOn" } else { "ShouldNotRunOn" } }
                'vmGroupName'   = $drsRule.ExtensionData.VmGroupName
                'hostGroupName' = If ($drsRule.ExtensionData.AffineHostGroupName) { $drsRule.ExtensionData.AffineHostGroupName } else { $drsRule.ExtensionData.AntiAffineHostGroupName }
            }
        }
        #$VMHostAffinityRulesObject | ConvertTo-Json -depth 10

        $dependencyRules = (Get-Cluster -Name $clusterName).ExtensionData.Configuration.Rule | Where-Object { $_.DependsOnVmGroup }
        $vmToVmDependencyRulesObject = @()
        Foreach ($dependencyRule in $dependencyRules) {
            $vmToVmDependencyRulesObject += [pscustomobject]@{
                'name'             = $dependencyRule.name
                'vmGroup'          = $dependencyRule.vmGroup
                'DependsOnVmGroup' = $dependencyRule.DependsOnVmGroup
                'mandatory'        = $dependencyRule.mandatory
            }
        }
        #$vmToVmDependencyRulesObject | ConvertTo-Json -depth 10

        $drsBackup += [pscustomobject]@{
            'vmDrsGroups'           = $drsGroupsObject
            'vmAffinityRules'       = $vmAffinityRulesObject
            'vmHostAffinityRules'   = $VMHostAffinityRulesObject
            'vmToVmDependencyRules' = $vmToVmDependencyRulesObject

        }
        $drsBackup | ConvertTo-Json -depth 10 | Out-File "$clusterName-drsConfiguration.json"
    }
    Catch {
        catchWriter -object $_
    }
}

Function Restore-ClusterVMOverrides {
    <#
    .SYNOPSIS
        Restores previously saved configured VM Overrides for a cluster

    .DESCRIPTION
        Restores VM Overrides for the passed cluster from a JSON file

    .EXAMPLE
        Restore-ClusterVMOverrides -clusterName 'sfo-m01-cl01' -jsonfile .\sfo-m01-cl01-vmOverrides.json
    #>
    Param(
        [Parameter(Mandatory = $true)][String]$clusterName,
        [Parameter(Mandatory = $true)][String]$jsonFile
    )
    try {
        If (Test-Path -path $jsonFile) {
            $vmOverRideInstances = Get-Content -path $jsonFile | ConvertFrom-Json
            Foreach ($vmOverRideInstance in $vmOverRideInstances)
            {
                If ($vmOverRideInstance.name -notlike "vCLS*")
                {
                    Write-Output "[$($vmOverRideInstance.name)] Restoring VM Overide Settings"
                    $dasVmConfigSpecRequired = $false
                    $drsVmConfigSpecRequired = $false
                    $vmOverRideInstanceOrchestrationSpecRequired = $false
                    $dasVmConfigSpecSettings = @("VmMonitoring","ClusterSettings","FailureInterval","MinUpTime","MaxFailures","MaxFailureWindow","VmStorageProtectionForAPD","VmTerminateDelayForAPDSec","VmReactionOnAPDCleared","VmStorageProtectionForPDL","RestartPriority","RestartPriorityTimeout","IsolationResponse")
                    $vmOverRideInstanceOrchestrationSpecSettings = @("readyCondition","PostReadyDelay")
                    
                    Foreach ($dasVmConfigSpecSetting in $dasVmConfigSpecSettings)
                    {
                        If ($vmOverRideInstance.$dasVmConfigSpecSetting -ne $null) {$dasVmConfigSpecRequired = $true}
                    }
                    If (($vmOverRideInstance.DrsAutomationLevel -ne $null) -and ($vmOverRideInstance.DrsAutomationLevel -ne 'AsSpecifiedByCluster')) 
                    {
                        $drsVmConfigSpecRequired = $true
                    }
                    Foreach ($vmOverRideInstanceOrchestrationSpecSetting in $vmOverRideInstanceOrchestrationSpecSettings)
                    {
                        If ($vmOverRideInstance.$vmOverRideInstanceOrchestrationSpecSetting -ne $null) {$vmOverRideInstanceOrchestrationSpecRequired = $true}
                    }
                    $cluster = Get-Cluster -Name $clusterName
                    $vm = Get-VM $vmOverRideInstance.name
                    $spec = New-Object VMware.Vim.ClusterConfigSpecEx
                    If ($dasVmConfigSpecRequired)
                    {
                        $spec.dasVmConfigSpec = New-Object VMware.Vim.ClusterDasVmConfigSpec[] (1)
                        $spec.dasVmConfigSpec[0] = New-Object VMware.Vim.ClusterDasVmConfigSpec
                        $spec.dasVmConfigSpec[0].operation = "add"
                        $spec.dasVmConfigSpec[0].info = New-Object VMware.Vim.ClusterDasVmConfigInfo
                        $spec.dasVmConfigSpec[0].info.key = New-Object VMware.Vim.ManagedObjectReference
                        $spec.dasVmConfigSpec[0].info.key.type = "VirtualMachine"
                        $spec.dasVmConfigSpec[0].info.key.value = $vm.ExtensionData.MoRef.Value
                        $spec.dasVmConfigSpec[0].info.dasSettings = New-Object VMware.Vim.ClusterDasVmSettings    
                    }
                    If ($drsVmConfigSpecRequired)
                    {
                        $spec.drsVmConfigSpec = New-Object VMware.Vim.ClusterDrsVmConfigSpec[] (1)
                        $spec.drsVmConfigSpec[0] = New-Object VMware.Vim.ClusterDrsVmConfigSpec
                        $spec.drsVmConfigSpec[0].operation = "add"
                        $spec.drsVmConfigSpec[0].info = New-Object VMware.Vim.ClusterDrsVmConfigInfo
                        $spec.drsVmConfigSpec[0].info.key = New-Object VMware.Vim.ManagedObjectReference
                        $spec.drsVmConfigSpec[0].info.key.type = "VirtualMachine"
                        $spec.drsVmConfigSpec[0].info.key.value = $vm.ExtensionData.MoRef.Value    
                    }
                    If ($vmOverRideInstanceOrchestrationSpecRequired)
                    {
                        $spec.vmOrchestrationSpec = New-Object VMware.Vim.ClusterVmOrchestrationSpec[] (1)
                        $spec.vmOrchestrationSpec[0] = New-Object VMware.Vim.ClusterVmOrchestrationSpec
                        $spec.vmOrchestrationSpec[0].operation = "add"
                        $spec.vmOrchestrationSpec[0].info = New-Object VMware.Vim.ClusterVmOrchestrationInfo
                        $spec.vmOrchestrationSpec[0].info.vm = New-Object VMware.Vim.ManagedObjectReference
                        $spec.vmOrchestrationSpec[0].info.vm.type = "VirtualMachine"
                        $spec.vmOrchestrationSpec[0].info.vm.value = $vm.ExtensionData.MoRef.Value
                    }
                
                    #Set VM Monitoring settings [Done]
                    $vmOverRideInstanceMonitoringSettings = @("VmMonitoring","ClusterSettings","FailureInterval","MinUpTime","MaxFailures","MaxFailureWindow")
                    $vmOverRideInstanceMonitoringRequired = $false
                    Foreach ($vmOverRideInstanceMonitoringSetting in $vmOverRideInstanceMonitoringSettings)
                    {
                        If ($vmOverRideInstance.$vmOverRideInstanceMonitoringSetting -ne $null) {$vmOverRideInstanceMonitoringRequired = $true}
                    }
                    If ($vmOverRideInstanceMonitoringRequired)
                    {
                        $spec.dasVmConfigSpec[0].info.dasSettings.vmToolsMonitoringSettings = New-Object VMware.Vim.ClusterVmToolsMonitoringSettings
                        Foreach ($vmOverRideInstanceMonitoringSetting in $vmOverRideInstanceMonitoringSettings)
                        {
                            If ($vmOverRideInstance.$vmOverRideInstanceMonitoringSetting -ne $null) { $spec.dasVmConfigSpec[0].info.dasSettings.vmToolsMonitoringSettings.$vmOverRideInstanceMonitoringSetting = $vmOverRideInstance.$vmOverRideInstanceMonitoringSetting }
                        }
                    }
                
                    $vmOverRideInstanceComponentProtectionSettings = @("VmStorageProtectionForAPD","VmTerminateDelayForAPDSec","VmReactionOnAPDCleared","VmStorageProtectionForPDL")
                    $vmOverRideInstanceComponentProtectionRequired = $false
                    Foreach ($vmOverRideInstanceComponentProtectionSetting in $vmOverRideInstanceComponentProtectionSettings)
                    {
                        If ($vmOverRideInstance.$vmOverRideInstanceComponentProtectionSetting -ne $null) {$vmOverRideInstanceComponentProtectionRequired = $true}
                    }
                    If ($vmOverRideInstanceComponentProtectionRequired)
                    {
                        $spec.dasVmConfigSpec[0].info.dasSettings.vmComponentProtectionSettings = New-Object VMware.Vim.ClusterVmComponentProtectionSettings
                        Foreach ($vmOverRideInstanceComponentProtectionSetting in $vmOverRideInstanceComponentProtectionSettings)
                        {
                            If ($vmOverRideInstance.$vmOverRideInstanceComponentProtectionSetting -ne $null) { $spec.dasVmConfigSpec[0].info.dasSettings.vmComponentProtectionSettings.$vmOverRideInstanceComponentProtectionSetting = $vmOverRideInstance.$vmOverRideInstanceComponentProtectionSetting }
                        }
                    }
                
                    #Set DRS Level [Done]
                    If (($vmOverRideInstance.DrsAutomationLevel -ne "AsSpecifiedByCluster") -AND ($vmOverRideInstance.DrsAutomationLevel -ne $null))
                    {
                        $spec.drsVmConfigSpec[0].info.Behavior = $vmOverRideInstance.DrsAutomationLevel #$vmOverRideInstance.DrsAutomationLevel AsSpecifiedByCluster
                        $spec.drsVmConfigSpec[0].info.enabled = $true    
                    }

                    #Set vSphere HA Settings [Done]
                    If ($vmOverRideInstanceOrchestrationSpecRequired)
                    {
                        $spec.vmOrchestrationSpec[0].info.vmReadiness = New-Object VMware.Vim.ClusterVmReadiness
                        Foreach ($vmOverRideInstanceOrchestrationSpecSetting in $vmOverRideInstanceOrchestrationSpecSettings)
                        {
                            If ($vmOverRideInstance.$vmOverRideInstanceOrchestrationSpecSetting -ne $null) { $spec.vmOrchestrationSpec[0].info.vmReadiness.$vmOverRideInstanceOrchestrationSpecSetting = $vmOverRideInstance.$vmOverRideInstanceOrchestrationSpecSetting }
                        }
                
                    }
                    $haDasVmConfigSpecSettings = @("RestartPriority","RestartPriorityTimeout","IsolationResponse")
                    Foreach ($haDasVmConfigSpecSetting in $haDasVmConfigSpecSettings)
                    {
                        If ($vmOverRideInstance.$haDasVmConfigSpecSetting -ne $null) { $spec.dasVmConfigSpec[0].info.dasSettings.$haDasVmConfigSpecSetting = $vmOverRideInstance.$haDasVmConfigSpecSetting }
                    }
                
                    #Configure Cluster
                    $cluster.ExtensionData.ReconfigureComputeResource($spec,$True)
                }
            }
        }
        else {
            Write-Error "$jsonfile not found"
        }
    }
    catch {
        catchWriter -object $_
    }
}

Function Restore-ClusterVMLocations {
    <#
    .SYNOPSIS
        Restores folder and resource pool settings for VMs on a cluster

    .DESCRIPTION
        Restores the folder and resource pool settings for VMs on the the passed cluster from a JSON file

    .EXAMPLE
        Restore-ClusterVMLocations -clusterName 'sfo-m01-cl01' -jsonfile .\sfo-m01-cl01-vmLocations.json
    #>
    Param(
        [Parameter(Mandatory = $true)][String]$clusterName,
        [Parameter(Mandatory = $true)][String]$jsonFile
    )
    try {
        If (Test-Path -path $jsonFile) {
            $vmLocations = Get-Content -path $jsonFile | ConvertFrom-Json
            Foreach ($vmLocation in $vmLocations) {
                If ($vmLocation.name -notlike "vCLS*") {
                    $vm = Get-VM -name $vmLocation.name -errorAction SilentlyContinue
                    If ($vm) {
                        If ($vm.folder -ne $vmLocation.folder) {
                            Write-Output "Setting VM Folder Location for $($vmLocation.name) to $($vmLocation.folder)"
                            Move-VM -VM $vm -InventoryLocation $vmLocation.folder -confirm:$false
                        }
                        If ($vm.resourcePool -ne $vmLocation.resourcePool) {
                            Write-Output "Setting ResourcePool for $($vmLocation.name) to $($vmLocation.resourcePool)"
                            Move-VM -VM $vm -Destination $vmLocation.resourcePool -confirm:$false
                        }
                    } 
                    else {
                        Write-Error "VM $(Get-VM -name $vmLocation.name) not found. Check that it has been restored"
                    }
                }
            }
        }
        else {
            Write-Error "$jsonfile not found"
        }
    }
    catch {
        catchWriter -object $_
    }
}

Function Restore-ClusterDRSGroupsAndRules {
    <#
    .SYNOPSIS
        Restores DRS Groups and Rules for a cluster

    .DESCRIPTION
        Restores the DRS Groups and Rules for a passed cluster from a JSON file

    .EXAMPLE
        Restore-ClusterDRSGroupsAndRules -clusterName 'sfo-m01-cl01' -jsonfile .\sfo-m01-cl01-drsConfiguration.json
    #>
    Param(
        [Parameter(Mandatory = $true)][String]$clusterName,
        [Parameter(Mandatory = $true)][String]$jsonFile
    )
    try {
        If (Test-Path -path $jsonFile) {
            $drsRulesAndGroups = Get-Content -path $jsonFile | ConvertFrom-Json
            Foreach ($vmDrsGroup in $drsRulesAndGroups.vmDrsGroups) {
                $group = Get-DrsClusterGroup -name $vmDrsGroup.name -errorAction SilentlyContinue
                If ($group) {
                    If ($vmDrsGroup.type -eq "VMHostGroup") {
                        Foreach ($member in $vmDrsGroup.members) {
                            Write-Output "Adding $member to VMHostGroup $($vmDrsGroup.name)"
                            Set-DrsClusterGroup -DrsClusterGroup $vmDrsGroup.name -Add -VMHost $member -confirm:$false | Out-Null    
                        }
                    }
                    elseif ($vmDrsGroup.type -eq "VMGroup") {
                        Foreach ($member in $vmDrsGroup.members) {
                            Write-Output "Adding $member to VMGroup $($vmDrsGroup.name)"
                            Set-DrsClusterGroup -DrsClusterGroup $vmDrsGroup.name -Add -VM $member -confirm:$false | Out-Null    
                        }
                    }
                }
                else {
                    If ($vmDrsGroup.type -eq "VMHostGroup") {
                        Write-Output "Creating VMHostGroup $($vmDrsGroup.name) with Members $($vmDrsGroup.members)"
                        New-DrsClusterGroup -Name $vmDrsGroup.name -VMHost $vmDrsGroup.members -Cluster $clusterName | Out-Null
                    }
                    elseif ($vmDrsGroup.type -eq "VMGroup") {
                        Write-Output "Creating VMGroup $($vmDrsGroup.name) with Members $($vmDrsGroup.members)"
                        New-DrsClusterGroup -Name $vmDrsGroup.name -VM $vmDrsGroup.members -Cluster $clusterName | Out-Null
                    }
                }
            }
            Foreach ($vmAffinityRule in $drsRulesAndGroups.vmAffinityRules) {
                $vmRule = Get-DrsRule -name $vmAffinityRule.name -cluster $clusterName -errorAction SilentlyContinue
                If ($vmRule) {
                    Write-Output "Setting VM Rule $($vmAffinityRule.name) with Members $($vmAffinityRule.members)"
                    Set-DrsRule -rule $vmRule -VM $vmAffinityRule.members -Enabled $true -confirm:$false | Out-Null
                }
                else {
                    Write-Output "Creating VM Rule $($vmAffinityRule.name) with Members $($vmAffinityRule.members)"
                    New-DrsRule -cluster $clusterName -name $vmAffinityRule.name -VM $vmAffinityRule.members -keepTogether $vmAffinityRule.keepTogether -Enabled $true | Out-Null
                }
            }
            Foreach ($vmHostAffinityRule in $drsRulesAndGroups.vmHostAffinityRules) {
                $hostRule = Get-DrsVMHostRule -Cluster $clusterName -name $vmHostAffinityRule.name -errorAction SilentlyContinue
                If ($hostRule) {
                    Write-Output "Setting VMHost Rule $($vmHostAffinityRule.name) with VM Group $($vmHostAffinityRule.vmGroupName) and Host Group $($vmHostAffinityRule.hostGroupName)"
                    Set-DrsVMHostRule -rule $hostRule -VMGroup $vmHostAffinityRule.vmGroupName -VMHostGroup $vmHostAffinityRule.hostGroupName -Type $vmHostAffinityRule.variant -confirm:$false | Out-Null
                }
                else {
                    Write-Output "Creating VMHost Rule $($vmHostAffinityRule.name) with VM Group $($vmHostAffinityRule.vmGroupName) and Host Group $($vmHostAffinityRule.hostGroupName)"
                    New-DrsVMHostRule -Name $vmHostAffinityRule.name -Cluster $clusterName -VMGroup $vmHostAffinityRule.vmGroupName -VMHostGroup $vmHostAffinityRule.hostGroupName -Type $vmHostAffinityRule.variant | Out-Null
                }
            }
            Foreach ($vmToVmDependencyRule in $drsRulesAndGroups.vmToVmDependencyRules) {
                $dependencyRule = (Get-Cluster -Name $clusterName).ExtensionData.Configuration.Rule | Where-Object { $_.DependsOnVmGroup -and $_.name -eq $vmToVmDependencyRule.name -and $_.vmGroup -eq $vmToVmDependencyRule.vmGroup -and $_.DependsOnVmGroup -eq $vmToVmDependencyRule.DependsOnVmGroup }
                If (!$dependencyRule) {
                    Write-Output "Creating VM to VM Dependency Rule where $($vmToVmDependencyRule.vmGroup) depends on $($vmToVmDependencyRule.DependsOnVmGroup) "
                    $cluster = Get-Cluster -Name $clusterName
                    $spec = New-Object VMware.Vim.ClusterConfigSpecEx
                    $newRule = New-Object VMware.Vim.ClusterDependencyRuleInfo
                    $newRule.VmGroup = $vmToVmDependencyRule.vmGroup
                    $newRule.DependsOnVmGroup = $vmToVmDependencyRule.DependsOnVmGroup
                    $newRule.Enabled = $true
                    $newRule.Name = $vmToVmDependencyRule.name
                    $newRule.Mandatory = $vmToVmDependencyRule.Mandatory
                    $newRule.UserCreated = $true
                    $ruleSpec = New-Object VMware.Vim.ClusterRuleSpec
                    $ruleSpec.Info = $newRule
                    $spec.RulesSpec += $ruleSpec
                    $cluster.ExtensionData.ReconfigureComputeResource($spec, $True)
                }
            }
        }
        else {
            Write-Error "$jsonfile not found"
        }
    }
    catch {
        catchWriter -object $_
    }
}

#EndRegion vCenter Functions

#Region NSXT Functions
Function createHeader {
    Param(
        [Parameter (Mandatory = $true)]
        [String] $username,
        [Parameter (Mandatory = $true)]
        [String] $password
    )
    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $username, $password))) # Create Basic Authentication Encoded Credentials
    $headers = @{"Accept" = "application/json" }
    $headers.Add("Authorization", "Basic $base64AuthInfo")
    
    Return $headers
}

Function ResponseException {
    #Get response from the exception
    $response = $_.exception.response
    if ($response) {
        $responseStream = $_.exception.response.GetResponseStream()
        $reader = New-Object system.io.streamreader($responseStream)
        $responseBody = $reader.readtoend()
        $errorString = "Exception occured calling invoke-restmethod. $($response.StatusCode.value__) : $($response.StatusDescription) : Response Body: $($responseBody)"
    }
    else {
        Throw $_
    }
    Return $errorString
}


Function Resolve-PhysicalHostTransportNodes {
    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $nsxManagerFqdn,
        [Parameter (Mandatory = $true)][String] $nsxManagerAdmin,
        [Parameter (Mandatory = $true)][String] $nsxManagerAdminPassword
    )
    $vCenterConnection = Connect-VIServer -server $vCenterFQDN -username $vCenterAdmin -password $vCenterAdminPassword
    Write-Output "Getting Hosts for Cluster $clusterName"
    $clusterHosts = (Get-Cluster -name $clusterName | Get-VMHost).name
    
    $headers = createHeader -username $nsxManagerAdmin -password $nsxManagerAdminPassword
    
    #Get TransportNodes
    $uri = "https://$nsxManagerFqdn/api/v1/transport-nodes/"
    Write-Output "Getting Transport Nodes from $nsxManagerFqdn"
    $transportNodeContents = (Invoke-WebRequest -Method GET -URI $uri -ContentType application/json -headers $headers).content | ConvertFrom-Json
    $allHostTransportNodes = ($transportNodeContents.results | Where-Object { ($_.resource_type -eq "TransportNode") -and ($_.node_deployment_info.os_type -eq "ESXI") })
    Write-Output "Filtering Transport Nodes to members of cluster $clusterName"
    $hostIDs = ($allHostTransportNodes | Where-Object { $_.display_name -in $clusterHosts }).id

    #Resolve Hosts
    Foreach ($hostID in $hostIDs) {
        $body = "{`"id`":5726703,`"method`":`"resolveError`",`"params`":[{`"errors`":[{`"user_metadata`":{`"user_input_list`":[]},`"error_id`":26080,`"entity_id`":`"$hostID`"}]}]}"
        $uri = "https://$nsxManagerFqdn/nsxapi/rpc/call/ErrorResolverFacade"
        Write-Output "Resolving NSX Installation on $(($allHostTransportNodes | Where-Object {$_.id -eq $hostID}).display_name) "
        $response = Invoke-WebRequest -Method POST -URI $uri -ContentType application/json -headers $headers -body $body
    }    
}
#EndRegion NSXT Functions

#Region Supporting Functions

Function catchWriter {
    <#
    .SYNOPSIS
        Prints a controlled error message after a failure

    .DESCRIPTION
        Accepts the invocation object from a failure in a Try/Catch block and prints back more precise information regarding
        the cause of the failure

    .EXAMPLE
        catchWriter -object $_
        This example when placed in a catch block will return error message, line number and line text (command) issued

    #>
    Param(
        [Parameter(mandatory = $true)]
        [PSObject]$object
    )
    $lineNumber = $object.InvocationInfo.ScriptLineNumber
    $lineText = $object.InvocationInfo.Line.trim()
    $errorMessage = $object.Exception.Message
    Write-Error "Error at Script Line $lineNumber"
    Write-Error "Relevant Command: $lineText"
    Write-Error "Error Message: $errorMessage"
}
#EndRegion Supporting Functions