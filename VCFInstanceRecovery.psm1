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

Function Get-InstalledSoftware
{
    $software = @()
    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $env:COMPUTERNAME)
    $apps = $reg.OpenSubKey("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall").GetSubKeyNames()
    foreach ($app in $apps) {
        $program = $reg.OpenSubKey("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$app")
        $name = $program.GetValue('DisplayName')
        $software += $name
    }
    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $env:COMPUTERNAME)
    $apps = $reg.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall").GetSubKeyNames()
    foreach ($app in $apps) {
        $program = $reg.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$app")
        $name = $program.GetValue('DisplayName')
        $software += $name
    }
    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('CurrentUser', $env:COMPUTERNAME)
    $apps = $reg.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall").GetSubKeyNames()
    foreach ($app in $apps) {
        $program = $reg.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$app")
        $name = $program.GetValue('DisplayName')
        $software += $name
    }
    Return $software
}
#EndRegion Supporting Functions

Function Confirm-VCFInstanceRecoveryPreReqs
{
    <#
    .SYNOPSIS
    Checks for the presence of supporting software and modules leveraged by VCFInstanceRecovery

    .DESCRIPTION
    The Confirm-VCFInstanceRecoveryPreReqs cmdlet checks for the presence of supporting software and modules leveraged by VCFInstanceRecovery

    .EXAMPLE
    Confirm-VCFInstanceRecoveryPreReqs
    #>

    #Check Dependencies
    $is7Zip4PowerShellInstalled = Get-InstalledModule -name "7Zip4PowerShell" -MinimumVersion "2.4.0" -ErrorAction SilentlyContinue
    If (!$is7Zip4PowerShellInstalled)
    {
        Write-Output "7Zip4PowerShell Module Missing. Please install"
    }
    else 
    {
        Write-Output "7Zip4PowerShell Module found"
    }

    $isPoshSSHInstalled = Get-InstalledModule -name "Posh-SSH" -MinimumVersion "3.0.8" -ErrorAction SilentlyContinue
    If (!$isPoshSSHInstalled)
    {
        Write-Output "Posh-SSH Module Missing. Please install"
    } 
    else 
    {
        Write-Output "Posh-SSH Module found"
    }
    
    $isPowerCLIInstalled = Get-InstalledModule -name "VMware.PowerCLI" -ErrorAction SilentlyContinue
    If (!$isPowerCLIInstalled)
    {
        Write-Output "PowerCLI Module Missing. Please install"
    }
    else
    {
        Write-Output "PowerCLI Module found"
    }

    $isPowerVCFInstalled = Get-InstalledModule -name "PowerVCF" -MinimumVersion "2.4.0" -ErrorAction SilentlyContinue
    If (!$isPowerVCFInstalled)
    {
        Write-Output "PowerVCF Module Missing. Please install"
    } 
    else
    {
        Write-Output "PowerVCF Module found"
    }

    $installedSoftware = Get-InstalledSoftware
    If (!($installedSoftware -match "OpenSSL"))
    {
        $openSslUrlPath = "https://slproweb.com/products/Win32OpenSSL.html"
        Try {$openSslLinks = Invoke-WebRequest $openSslUrlPath -UseBasicParsing -ErrorAction silentlycontinue}Catch{}
        $openSslLink = (($openSslLinks.Links | Where-Object { $_.href -like "/download/Win64OpenSSL_Light*.exe" }).href)[0]
        $Global:openSSLUrl = "https://slproweb.com"+$openSslLink
        If ($openSSLUrl)
        {
            Write-Output "OpenSSL missing. Please install. Latest version detected is here: $openSSLUrl"
        }
        else 
        {
            Write-Output "OpenSSL missing. Please install. Unable to detect latest version on web"
        }
    }
    else
    {
        Write-Output "OpenSSL Module found"
    }
}
Export-ModuleMember -Function Confirm-VCFInstanceRecoveryPreReqs
#Region Data Gathering

Function New-ExtractDataFromSDDCBackup
{
    <#
    .SYNOPSIS
    Decrypts and extracts the contents of the provided VMware Cloud Foundation SDDC manager backup, parses it for information required for instance recovery and stores the data in a file called extracted-sddc-data.json

    .DESCRIPTION
    The New-ExtractDataFromSDDCBackup cmdlet decrypts and extracts the contents of the provided VMware Cloud Foundation SDDC manager backup, parses it for information required for instance recovery and stores the data in a file called extracted-sddc-data.json

    .EXAMPLE
    New-ExtractDataFromSDDCBackup -backupFilePath "F:\backup\vcf-backup-sfo-vcf01-sfo-rainpole-io-2023-09-19-10-53-02.tar.gz" -encryptionPassword "VMw@re1!VMw@re1!"

    .PARAMETER backupFilePath
    Relative or absolute to the VMware Cloud Foundation SDDC manager backup file somewhere on the local filesystem

    .PARAMETER encryptionPassword
    The password that should be used to decrypt the VMware Cloud Foundation SDDC manager backup file ie the password that was used to encrypt it originally.
    #>
    
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
    
    $psqlContent = Get-Content "$extractedBackupFolder\database\sddc-postgres.bkp"
    Write-Output "Retrieving NSX Manager Details"
    
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
                    'vmName' = $hostname.split(".")[0]
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
    
    Write-Output "Retrieving vCenter Details"
    #Get Host and Domain Details
    $hostsAndDomainsLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.host_and_domain " | Select Line,LineNumber).LineNumber
    $hostsAndDomainsLineIndex = $hostsAndDomainsLineNumber
    $hostsAndDomains = @()
    Do 
    {
        $lineContent = $psqlContent | Select-Object -Index $hostsAndDomainsLineIndex
        If ($lineContent -ne '\.')
        {
            $hostId = $lineContent.split("`t")[0]
            $domainID = $lineContent.split("`t")[1]
            $hostsAndDomains += [pscustomobject]@{
                'hostId' = $hostId
                'domainID' = $domainID
            }
        }
        $hostsAndDomainsLineIndex++
    }
    Until ($lineContent -eq '\.')

    #Get Host and vCenter Details
    $hostsandVcentersLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.host_and_vcenter " | Select Line,LineNumber).LineNumber
    $hostsandVcentersLineIndex = $hostsandVcentersLineNumber
    $hostsandVcenters = @()
    Do 
    {
        $lineContent = $psqlContent | Select-Object -Index $hostsandVcentersLineIndex
        If ($lineContent -ne '\.')
        {
            $hostId = $lineContent.split("`t")[0]
            $vCenterID = $lineContent.split("`t")[1]
            $hostsandVcenters += [pscustomobject]@{
                'hostId' = $hostId
                'vCenterID' = $vCenterID
            }
        }
        $hostsandVcentersLineIndex++
    }
    Until ($lineContent -eq '\.')

    #Get Host and vCenter Details
    $vCentersStartingLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.vcenter " | Select Line,LineNumber).LineNumber
    $vCenterLineIndex = $vCentersStartingLineNumber
    $vCenters = @()
    Do 
    {
        $lineContent = $psqlContent | Select-Object -Index $vCentersStartingLineNumber
        If ($lineContent -ne '\.')
        {
            $vCenterID = $lineContent.split("`t")[0]
            $vCenterDatastore= $lineContent.split("`t")[4]
            $vCenterVersion= $lineContent.split("`t")[9]
            $vCenterFqdn= $lineContent.split("`t")[10]
            $vCenterIp= $lineContent.split("`t")[11]
            $vCenterVMname= $lineContent.split("`t")[12]
            $vCenterDomainID = ($hostsAndDomains | Where-Object {$_.hostId -eq (($hostsandVcenters | Where-Object {$_.vCenterID -eq $vCenterID})[0].hostID)}).domainID
            $vCenters += [pscustomobject]@{
                'vCenterID' = $vCenterID
                'vCenterDatastore' = $vCenterDatastore
                'vCenterVersion' = $vCenterVersion
                'vCenterFqdn' = $vCenterFqdn
                'vCenterIp' = $vCenterIp
                'vCenterVMname' = $vCenterVMname
                'vCenterDomainID' = $vCenterDomainID
            }
        }
        $vCentersStartingLineNumber++
    }
    Until ($lineContent -eq '\.')
 
    Write-Output "Assembling Workload Domain Data"
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
            $vCenter = $vCenters | Where-Object {$_.vCenterDomainID -eq $domainId}
            $vCenterDetails = [pscustomobject]@{
                'id' = $vCenter.vCenterID
                'datastore' = $vCenter.vCenterDatastore
                'version' = $vCenter.vCenterVersion
                'fqdn' = $vCenter.vCenterFqdn
                'ip' = $vCenter.vCenterIp
                'vmname' = $vCenter.vCenterVMname
            }
            $workloadDomains += [pscustomobject]@{
                'domainName' = $domainName
                'domainID' = $domainID
                'domainType' = $domainType
                'vCenterDetails' = $vCenterDetails
                'nsxNodeDetails' = ($nsxtManagerClusters | Where-Object {$_.domainIDs -contains $domainId}).nsxNodes
            }
        }
        $domainLineIndex++
    } Until ($lineContent -eq '\.')

    #Get Management Domain Deployment Objects
    $metadataJSON = Get-Content "$parentFolder\$extractedBackupFolder\metadata.json" | ConvertFrom-JSON
    $dnsJSON = Get-Content "$parentFolder\$extractedBackupFolder\appliancemanager_dns_configuration.json" | ConvertFrom-JSON
    $ntpJSON = Get-Content "$parentFolder\$extractedBackupFolder\appliancemanager_ntp_configuration.json" | ConvertFrom-JSON

    $mgmtDomainInfrastructure = [pscustomobject]@{
        'port_group' = $metadataJSON.port_group
        'vsan_datastore' =  $metadataJSON.vsan_datastore
        'cluster' = $metaDataJSON.cluster
        'datacenter' = $metaDataJSON.datacenter
        'netmask' = $metaDataJSON.netmask
        'gateway' = $metaDataJSON.gateway
        'domain' = $metaDataJSON.domain
        'search_path' = $metaDataJSON.search_path
        'primaryDnsServer' = $dnsJSON.primaryDnsServer
        'secondaryDnsServer' = $dnsJSON.secondaryDnsServer
        'ntpServers' = @($ntpJSON.ntpServers)
    }

    Write-Output "Retrieving SDDC Manager Detail"
    $sddcManagerObject = @()
    $sddcManagerObject += [pscustomobject]@{
        'fqdn' = ($passwordVaultObject | Where-Object {$_.entityType -eq "BACKUP"}).entityName
        'vmname' = ((($passwordVaultObject | Where-Object {$_.entityType -eq "BACKUP"}).entityName).split("."))[0]
        'ip' = $metadataJSON.ip
        'fips_enabled' = $metadataJSON.fips_enabled 
    }
    
    Write-Output "Creating extracted-sddc-data.json"
    $sddcDataObject = New-Object -TypeName psobject
    $sddcDataObject | Add-Member -notepropertyname 'sddcManager' -notepropertyvalue $sddcManagerObject
    $sddcDataObject | Add-Member -notepropertyname 'mgmtDomainInfrastructure' -notepropertyvalue $mgmtDomainInfrastructure
    $sddcDataObject | Add-Member -notepropertyname 'workloadDomains' -notepropertyvalue $workloadDomains
    $sddcDataObject | Add-Member -notepropertyname 'passwords' -notepropertyvalue $passwordVaultObject
    $sddcDataObject | ConvertTo-Json -Depth 10 | Out-File "$parentFolder\extracted-sddc-data.json"

    #Cleanup
    Write-Output "Cleaning up extracted files"
    Remove-Item -Path "$parentFolder\decrypted-sddc-manager-backup.tar.gz" -force -confirm:$false
    Remove-Item -Path "$parentFolder\decrypted-sddc-manager-backup.tar" -force -confirm:$false
    Remove-Item -path "$parentFolder\$extractedBackupFolder" -Recurse 
}
Export-ModuleMember -Function New-ExtractDataFromSDDCBackup

Function New-NSXManagerOvaDeployment
{
    <#
    .SYNOPSIS
    Presents a list of NSX Mangers associated with the provided VCF Workload Domain, and deploys an NSX Manager from OVA using data previously extracted from the VCF SDDC Manager Backup

    .DESCRIPTION
    The New-NSXManagerOvaDeployment resents a list of NSX Mangers associated with the provided VCF Workload Domain, and deploys an NSX Manager from OVA using data previously extracted from the VCF SDDC Manager Backup

    .EXAMPLE
    New-NSXManagerOvaDeployment -tempvCenterFQDN "sfo-m01-vc02.sfo.rainpole.io" -tempvCenterAdmin "administrator@vsphere.local" -tempvCenterAdminPassword "VMw@re1!" -extractedSDDCDataFile ".\extracted-sddc-data.json" -workloadDomain "sfo-m01" -nsxManagerOvaFile "F:\OVA\nsx-unified-appliance-3.2.2.1.0.21487565.ova"

    .PARAMETER tempvCenterFQDN
    FQDN of the target vCenter to deploy the NSX Manager OVA to

    .PARAMETER tempvCenterAdmin
    Admin user of the target vCenter to deploy the NSX Manager OVA to
    
    .PARAMETER tempvCenterAdminPassword
    Admin password for the target vCenter to deploy the NSX Manager OVA to
    
    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem
    
    .PARAMETER workloadDomain
    Name of the VCF workload domain that the NSX Manager to deployed to is associated with
    
    .PARAMETER nsxManagerOvaFile
    Relative or absolute to the NSX Manager OVA somewhere on the local filesystem
    #>
    
    Param(
        [Parameter (Mandatory = $true)][String] $tempvCenterFQDN,
        [Parameter (Mandatory = $true)][String] $tempvCenterAdmin,
        [Parameter (Mandatory = $true)][String] $tempvCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $true)][String] $workloadDomain,
        [Parameter (Mandatory = $true)][String] $nsxManagerOvaFile
    )
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $workloadDomainDetails = ($extractedSDDCData.workloadDomains | Where-Object {$_.domainName -eq $workloadDomain})
    $nsxNodes = $workloadDomainDetails.nsxNodeDetails

    $nsxManagersDisplayObject=@()
        $nsxManagersIndex = 1
        $nsxManagersDisplayObject += [pscustomobject]@{
                'ID'    = "ID"
                'Manager' = "NSX Manager"
            }
        $nsxManagersDisplayObject += [pscustomobject]@{
                'ID'    = "--"
                'Manager' = "------------------"
            }
        Foreach ($nsxNode in $nsxNodes)
        {
            $nsxManagersDisplayObject += [pscustomobject]@{
                'ID'    = $nsxManagersIndex
                'Manager' = $nsxNode.vmName
            }
            $nsxManagersIndex++
        }
    $nsxManagersDisplayObject | format-table -Property @{Expression=" "},id,Manager -autosize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r","`n") }
    Do
    {
        Write-Host ""; Write-Host " Enter the ID of the Manager you wish to redeploy, or C to Cancel: " -ForegroundColor Yellow -nonewline
        $nsxManagerSelection = Read-Host
    } Until (($nsxManagerSelection -in $nsxManagersDisplayObject.ID) -OR ($nsxManagerSelection -eq "c"))
    If ($nsxManagerSelection -eq "c") {Break}
    $selectedNsxManager = $nsxNodes | Where-Object {$_.vmName -eq ($nsxManagersDisplayObject | Where-Object {$_.id -eq $nsxManagerSelection}).manager }
    
    $vmNetwork = $extractedSDDCData.mgmtDomainInfrastructure.port_group
    $vmDatastore = $extractedSDDCData.mgmtDomainInfrastructure.vsan_datastore
    $datacenterName = $extractedSDDCData.mgmtDomainInfrastructure.datacenter
    $clusterName = $extractedSDDCData.mgmtDomainInfrastructure.cluster

    # NSX Manager Appliance Configuration 
    $nsxManagerVMName = $selectedNsxManager.vmName
    $nsxManagerIp = $selectedNsxManager.ip
    $nsxManagerHostName = $selectedNsxManager.hostname
    $nsxManagerNetworkMask = $extractedSddcData.mgmtDomainInfrastructure.netmask
    $nsxManagerGateway = $extractedSddcData.mgmtDomainInfrastructure.gateway
    $nsxManagerDns = "$($extractedSddcData.mgmtDomainInfrastructure.primaryDnsServer),$($extractedSddcData.mgmtDomainInfrastructure.secondaryDnsServer)" 
    $nsxManagerDnsDomain = $extractedSddcData.mgmtDomainInfrastructure.domain
    $nsxManagerNtpServer = $extractedSddcData.mgmtDomainInfrastructure.ntpServers -join(",")
    $nsxManagerAdminUsername = ($extractedSddcData.passwords | Where-Object {($_.entityType -eq "NSXT_MANAGER") -and ($_.domainName -eq $workloadDomain) -and ($_.credentialType -eq "API")}).username
    $nsxManagerAdminPassword = ($extractedSddcData.passwords | Where-Object {($_.entityType -eq "NSXT_MANAGER") -and ($_.domainName -eq $workloadDomain) -and ($_.credentialType -eq "API")}).password
    $nsxManagerCliPassword  = ($extractedSddcData.passwords | Where-Object {($_.entityType -eq "NSXT_MANAGER") -and ($_.domainName -eq $workloadDomain) -and ($_.credentialType -eq "API")}).password
    $nsxManagerCliAuditUsername = ($extractedSddcData.passwords | Where-Object {($_.entityType -eq "NSXT_MANAGER") -and ($_.domainName -eq $workloadDomain) -and ($_.credentialType -eq "AUDIT")}).username
    $nsxManagerCliAuditPassword = ($extractedSddcData.passwords | Where-Object {($_.entityType -eq "NSXT_MANAGER") -and ($_.domainName -eq $workloadDomain) -and ($_.credentialType -eq "AUDIT")}).password

    If ($nsxManagerCliAuditUsername)
    {
        $command = '"C:\Program Files\VMware\VMware OVF Tool\ovftool.exe" --noSSLVerify --acceptAllEulas --allowExtraConfig --diskMode=thin --X:injectOvfEnv --X:logFile=ovftool.log --powerOn --name="' + $nsxManagerVMName + '" --datastore="' + $vmDatastore + '" --network="' + $vmNetwork + '" --prop:nsx_role="NSX Manager" --prop:nsx_ip_0="' + $nsxManagerIp + '" --prop:nsx_netmask_0="' + $nsxManagerNetworkMask + '" --prop:nsx_gateway_0="' + $nsxManagerGateway + '" --prop:nsx_dns1_0="' + $nsxManagerDns + '" --prop:nsx_domain_0="' + $nsxManagerDnsDomain + '" --prop:nsx_ntp_0="' + $nsxManagerNtpServer + '" --prop:nsx_isSSHEnabled=True --prop:nsx_allowSSHRootLogin=False --prop:nsx_passwd_0="' + $nsxManagerAdminPassword + '" --prop:nsx_cli_username="' + $nsxManagerAdminUsername+ '" --prop:nsx_cli_passwd_0="' + $nsxManagerCliPassword + '" --prop:nsx_cli_audit_passwd_0="' + $nsxManagerCliAuditPassword + '" --prop:nsx_cli_audit_username="' + $nsxManagerCliAuditUsername + '" --prop:nsx_hostname="' + $nsxManagerHostName + '" "' + $nsxManagerOvaFile + '" ' + '"vi://' + $tempVcenterAdmin + ':' + $tempVcenterAdminPassword + '@' + $tempVcenterFqdn + '/' + $datacenterName + '/host/' + $clusterName + '/"'
    }
    else 
    {
        $command = '"C:\Program Files\VMware\VMware OVF Tool\ovftool.exe" --noSSLVerify --acceptAllEulas --allowExtraConfig --diskMode=thin --X:injectOvfEnv --X:logFile=ovftool.log --powerOn --name="' + $nsxManagerVMName + '" --datastore="' + $vmDatastore + '" --network="' + $vmNetwork + '" --prop:nsx_role="NSX Manager" --prop:nsx_ip_0="' + $nsxManagerIp + '" --prop:nsx_netmask_0="' + $nsxManagerNetworkMask + '" --prop:nsx_gateway_0="' + $nsxManagerGateway + '" --prop:nsx_dns1_0="' + $nsxManagerDns + '" --prop:nsx_domain_0="' + $nsxManagerDnsDomain + '" --prop:nsx_ntp_0="' + $nsxManagerNtpServer + '" --prop:nsx_isSSHEnabled=True --prop:nsx_allowSSHRootLogin=False --prop:nsx_passwd_0="' + $nsxManagerAdminPassword + '" --prop:nsx_cli_username="' + $nsxManagerAdminUsername+ '" --prop:nsx_cli_passwd_0="' + $nsxManagerCliPassword + '" --prop:nsx_hostname="' + $nsxManagerHostName + '" "' + $nsxManagerOvaFile + '" ' + '"vi://' + $tempVcenterAdmin + ':' + $tempVcenterAdminPassword + '@' + $tempVcenterFqdn + '/' + $datacenterName + '/host/' + $clusterName + '/"'    <# Action when all if and elseif conditions are false #>
    }
    Invoke-Expression "& $command"
}
Export-ModuleMember -Function New-NSXManagerOvaDeployment

Function New-vCenterOvaDeployment
{
    <#
    .SYNOPSIS
    Deploys a vCenter appliance from OVA using data previously extracted from the VCF SDDC Manager Backup

    .DESCRIPTION
    The New-vCenterOvaDeployment deploys a vCenter appliance from OVA using data previously extracted from the VCF SDDC Manager Backup

    .EXAMPLE
    New-vCenterOvaDeployment -tempvCenterFQDN "sfo-m01-vc02.sfo.rainpole.io" -tempvCenterAdmin "administrator@vsphere.local" -tempvCenterAdminPassword "VMw@re1!" -extractedSDDCDataFile ".\extracted-sddc-data.json" -workloadDomain "sfo-m01" -restoredvCenterDeploymentSize "small" -vCenterOvaFile "F:\OVA\VMware-vCenter-Server-Appliance-7.0.3.01400-21477706_OVF10.ova"

    .PARAMETER tempvCenterFQDN
    FQDN of the target vCenter to deploy the vCenter OVA to

    .PARAMETER tempvCenterAdmin
    Admin user of the target vCenter to deploy the vCenter OVA to
    
    .PARAMETER tempvCenterAdminPassword
    Admin password for the target vCenter to deploy the vCenter OVA to
    
    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem
    
    .PARAMETER workloadDomain
    Name of the VCF workload domain that the vCenter to deployed to is associated with
    
    .PARAMETER restoredvCenterDeploymentSize
    Size of the vCenter Appliance to deploy
    
    .PARAMETER vCenterOvaFile
    Relative or absolute to the vCenter OVA somewhere on the local filesystem
    #>
    
    Param(
        [Parameter (Mandatory = $true)][String] $tempvCenterFQDN,
        [Parameter (Mandatory = $true)][String] $tempvCenterAdmin,
        [Parameter (Mandatory = $true)][String] $tempvCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $true)][String] $workloadDomain,
        [Parameter (Mandatory = $true)][String] $restoredvCenterDeploymentSize,
        [Parameter (Mandatory = $true)][String] $vCenterOvaFile
    )
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $workloadDomainDetails = ($extractedSDDCData.workloadDomains | Where-Object {$_.domainName -eq $workloadDomain})
    $vmNetwork = $extractedSDDCData.mgmtDomainInfrastructure.port_group
    $vmDatastore = $extractedSDDCData.mgmtDomainInfrastructure.vsan_datastore
    $datacenterName = $extractedSDDCData.mgmtDomainInfrastructure.datacenter
    $clusterName = $extractedSDDCData.mgmtDomainInfrastructure.cluster
    $restoredvCenterVMName = $workloadDomainDetails.vCenterDetails.vmname
    $restoredvCenterIpAddress = $workloadDomainDetails.vCenterDetails.ip
    $restoredvCenterFqdn = $workloadDomainDetails.vCenterDetails.fqdn
    $restoredvCenterNetworkPrefix = 0
    [IPAddress] $ip = $extractedSddcData.mgmtDomainInfrastructure.netmask
    $octets = $ip.IPAddressToString.Split('.')
    Foreach($octet in $octets) { while(0 -ne $octet) { $octet = ($octet -shl 1) -band [byte]::MaxValue; $restoredvCenterNetworkPrefix++; }}
    $restoredvCenterDnsServers = "$($extractedSddcData.mgmtDomainInfrastructure.primaryDnsServer),$($extractedSddcData.mgmtDomainInfrastructure.secondaryDnsServer)" 
    $restoredvCenterGateway = $extractedSddcData.mgmtDomainInfrastructure.gateway
    $restoredvCenterRootPassword = ($extractedSddcData.passwords | Where-Object {($_.entityType -eq "VCENTER") -and ($_.domainName -eq $workloadDomain) -and ($_.credentialType -eq "SSH")}).password

    $command = '"C:\Program Files\VMware\VMware OVF Tool\ovftool.exe" --noSSLVerify --acceptAllEulas --allowExtraConfig --X:enableHiddenProperties --diskMode=thin --X:injectOvfEnv --X:waitForIp --X:logFile=ovftool.log --name="' + $restoredvCenterVMName + '" --net:"Network 1"="' +$vmNetwork + '" --datastore="' + $vmDatastore + '" --deploymentOption="' + $restoredvCenterDeploymentSize + '" --prop:guestinfo.cis.appliance.net.addr.family="ipv4" --prop:guestinfo.cis.appliance.net.addr="' + $restoredvCenterIpAddress + '" --prop:guestinfo.cis.appliance.net.pnid="' + $restoredvCenterFqdn + '" --prop:guestinfo.cis.appliance.net.prefix="' + $restoredvCenterNetworkPrefix + '" --prop:guestinfo.cis.appliance.net.mode="static" --prop:guestinfo.cis.appliance.net.dns.servers="' + $restoredvCenterDnsServers + '" --prop:guestinfo.cis.appliance.net.gateway="' + $restoredvCenterGateway + '" --prop:guestinfo.cis.appliance.root.passwd="' + $restoredvCenterRootPassword + '" --prop:guestinfo.cis.appliance.ssh.enabled="True" "' + $vCenterOvaFile + '" ' + '"vi://' + $tempvCenterAdmin + ':' + $tempvCenterAdminPassword + '@' + $tempvCenterFQDN + '/' + $datacenterName + '/host/' + $clusterName + '/"'
    Invoke-Expression "& $command"

}
Export-ModuleMember -Function New-vCenterOvaDeployment

Function New-SDDCManagerOvaDeployment
{
    <#
    .SYNOPSIS
    Deploys an SDDC Manager appliance from OVA using data previously extracted from the VCF SDDC Manager Backup

    .DESCRIPTION
    The New-SDDCManagerOvaDeployment deploys an SDDC Manager appliance from OVA using data previously extracted from the VCF SDDC Manager Backup

    .EXAMPLE
    New-SDDCManagerOvaDeployment -tempvCenterFQDN "sfo-m01-vc02.sfo.rainpole.io" -tempvCenterAdmin "administrator@vsphere.local" -tempvCenterAdminPassword "VMw@re1!" -extractedSDDCDataFile ".\extracted-sddc-data.json" -sddcManagerOvaFile "F:\OVA\VCF-SDDC-Manager-Appliance-4.5.1.0-21682411.ova" -rootPassword "VMw@re1!" -vcfPassword "VMw@re1!" -localUserPassword "VMw@re1!" -basicAuthPassword "VMw@re1!"

    .PARAMETER tempvCenterFQDN
    FQDN of the target vCenter to deploy the SDDC Manager OVA to

    .PARAMETER tempvCenterAdmin
    Admin user of the target vCenter to deploy the SDDC Manager OVA to
    
    .PARAMETER tempvCenterAdminPassword
    Admin password for the target vCenter to deploy the SDDC Manager OVA to
    
    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem
       
    .PARAMETER sddcManagerOvaFile
    Relative or absolute to the SDDC Manager OVA somewhere on the local filesystem

    .PARAMETER rootPassword
    Password for the root user on the newly deployed appliance
    
    .PARAMETER vcfPassword
    Password for the vcf user on the newly deployed appliance

    .PARAMETER localUserPassword
    Password for the local admin user on the newly deployed appliance

    .PARAMETER basicAuthPassword
    Password for the basic auth user on the newly deployed appliance
    #>
    
    Param(
        [Parameter (Mandatory = $true)][String] $tempvCenterFQDN,
        [Parameter (Mandatory = $true)][String] $tempvCenterAdmin,
        [Parameter (Mandatory = $true)][String] $tempvCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $true)][String] $sddcManagerOvaFile,
        [Parameter (Mandatory = $true)][String] $rootPassword,
        [Parameter (Mandatory = $true)][String] $vcfPassword,
        [Parameter (Mandatory = $true)][String] $localUserPassword,
        [Parameter (Mandatory = $true)][String] $basicAuthPassword
    )
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    # SDDC Manager Configuration
    $sddcManagerVMName = $extractedSDDCData.sddcManager.vmname  
    $sddcManagerBackupPassword = ($extractedSddcData.passwords | Where-Object {$_.entityType -eq "BACKUP"}).password
    $sddcManagerNetworkMask = $extractedSddcData.mgmtDomainInfrastructure.netmask
    $sddcManagerHostName = $extractedSDDCData.sddcManager.fqdn
    $sddcManagerIp = $extractedSDDCData.sddcManager.ip
    $sddcManagerGateway = $extractedSddcData.mgmtDomainInfrastructure.gateway
    $sddcManagerDns = "$($extractedSddcData.mgmtDomainInfrastructure.primaryDnsServer),$($extractedSddcData.mgmtDomainInfrastructure.secondaryDnsServer)"
    $sddcManagerDomainSearch =  $extractedSddcData.mgmtDomainInfrastructure.search_path
    $sddcManagerDnsDomain = $extractedSddcData.mgmtDomainInfrastructure.domain
    $sddcManagerFipsSetting = $extractedSDDCData.sddcManager.fips_enabled
    $ntpServers = $extractedSddcData.mgmtDomainInfrastructure.ntpServers -join(",")

    $command = '"C:\Program Files\VMware\VMware OVF Tool\ovftool.exe" --noSSLVerify --acceptAllEulas --allowAllExtraConfig --diskMode=thin --X:enableHiddenProperties --X:waitForIp --powerOn --name="' + $sddcManagerVMName + '" --network="' + $vmNetwork + '" --datastore="' + $vmDatastore + '" --prop:vami.hostname="' + $sddcManagerHostName + '" --prop:vami.ip0.SDDC-Manager="' + $sddcManagerIp + '" --prop:vami.netmask0.SDDC-Manager="' + $sddcManagerNetworkMask + '" --prop:vami.DNS.SDDC-Manager="' + $sddcManagerDns + '" --prop:vami.gateway.SDDC-Manager="' + $sddcManagerGateway + '" --prop:ROOT_PASSWORD="' + $rootPassword + '" --prop:VCF_PASSWORD="' + $vcfPassword + '" --prop:BASIC_AUTH_PASSWORD="' + $basicAuthPassword + '" --prop:LOCAL_USER_PASSWORD="' + $localUserPassword + '" --prop:vami.searchpath.SDDC-Manager="' + $sddcManagerDomainSearch + '" --prop:vami.domain.SDDC-Manager="' + $sddcManagerDnsDomain + '" --prop:FIPS_ENABLE="' + $sddcManagerFipsSetting + '" --prop:guestinfo.ntp="' + $ntpServers + '" "' + $sddcManagerOvaFile + '" "vi://' + $tempvCenterAdmin + ':' + $tempvCenterAdminPassword + '@' + $tempvCenterFQDN + '/' + $datacenterName + '/host/' + $clusterName + '/"'
    Invoke-Expression "& $command"

}
Export-ModuleMember -Function New-SDDCManagerOvaDeployment


Function New-UploadAndModifySDDCManagerBackup
{
    <#
    .SYNOPSIS
    Uploads the provided VCF SDDC Manager Backup file to SDDC manager, decrypts and extracts it, replaces the SSH keys for the manangement domain vCenter with the current keys, then compresses and reencrypts the files ready for subsequent restore

    .DESCRIPTION
    The New-UploadAndModifySDDCManagerBackup cmdlet uploads the provided VCF SDDC Manager Backup file to SDDC manager, decrypts and extracts it, replaces the SSH keys for the manangement domain vCenter with the current keys, then compresses and reencrypts the files ready for subsequent restore

    .EXAMPLE
    New-UploadAndModifySDDCManagerBackup -rootUserPassword "VMw@re1!" -vcfUserPassword "VMw@re1!" -backupFilePath "F:\backup\vcf-backup-sfo-vcf01-sfo-rainpole-io-2023-09-19-10-53-02.tar.gz" -encryptionPassword "VMw@re1!VMw@re1!" -extractedSDDCDataFile ".\extracted-sddc-data.json" -tempvCenterFQDN "sfo-m01-vc02.sfo.rainpole.io" -tempvCenterAdmin "Administrator@vsphere.local" -tempvCenterAdminPassword VMw@re1!"

    .PARAMETER rootUserPassword
    Password for the root user of the SDDC Manager Appliance

    .PARAMETER vcfUserPassword
    Password for the vcf user of the SDDC Manager Appliance
    
    .PARAMETER backupFilePath
    Relative or absolute to the VMware Cloud Foundation SDDC manager backup file somewhere on the local filesystem

    .PARAMETER encryptionPassword
    The password that should be used to decrypt the VMware Cloud Foundation SDDC manager backup file ie the password that was used to encrypt it originally.

    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem

    .PARAMETER encryptionPassword
    The password that should be used to decrypt the VMware Cloud Foundation SDDC manager backup file ie the password that was used to encrypt it originally.

    .PARAMETER tempvCenterFQDN
    FQDN of the target vCenter that hosts the SDDC Manager VM

    .PARAMETER tempvCenterAdmin
    Admin user of the target vCenter that hosts the SDDC Manager VM
    
    .PARAMETER tempvCenterAdminPassword
    Admin password for the target vCenter that hosts the SDDC Manager VM

    #>
    
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

    $mgmtWorkloadDomain = $extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}
    $mgmtVcenterFqdn =  $mgmtWorkloadDomain.vCenterDetails.fqdn
    $sddcManagerFQDN = $extractedSddcData.sddcManager.fqdn
    $sddcManagerVmName = $extractedSddcData.sddcManager.vmName
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
Export-ModuleMember -Function New-UploadAndModifySDDCManagerBackup
#EndRegion Data Gathering

#Region vCenter Functions
<# Function Add-ClusterHostsToVds {
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
} #>

Function Move-ClusterHostsToRestoredVcenter
{
    <#
    .SYNOPSIS
    Moves ESXi Hosts from a temporary vCenter / cluster to the restored vCenter / cluster. Used for VCF Management Domain cluster recovery.

    .DESCRIPTION
    The Move-ClusterHostsToRestoredVcenter cmdlet moves ESXi Hosts from a temporary vCenter / cluster to the restored vCenter / cluster. Used for VCF Management Domain cluster recovery.

    .EXAMPLE
    Move-ClusterHostsToRestoredVcenter -tempvCenterFQDN "sfo-m01-vc02.sfo.rainpole.io" -tempvCenterAdmin "administrator@vsphere.local" -tempvCenterAdminPassword "VMw@re1!" -tempClusterName "sfo-m01-cl01" -restoredvCenterFQDN "sfo-m01-vc01.sfo.rainpole.io" -restoredvCenterAdmin "administrator@vsphere.local" -restoredvCenterAdminPassword "VMw@re1!" -restoredClusterName "sfo-m01-cl01" -extractedSDDCDataFile ".\extracted-sddc-data.json"

    .PARAMETER tempvCenterFQDN
    FQDN of the temporary vCenter instance

    .PARAMETER tempvCenterAdmin
    Admin user of the temporary vCenter instance
    
    .PARAMETER tempvCenterAdminPassword
    Admin password for the temporary vCenter instance

    .PARAMETER tempclusterName
    Name of the temporary vSphere cluster instance in the temporary vCenter

    .PARAMETER restoredvCenterFQDN
    FQDN of the restored vCenter instance

    .PARAMETER restoredvCenterAdmin
    Admin user of the restored vCenter instance
    
    .PARAMETER restoredvCenterAdminPassword
    Admin password for the restored vCenter instance

    .PARAMETER restoredclusterName
    Name of the restored vSphere cluster instance in the temporary vCenter

    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem
    #>
    
    Param(
        [Parameter (Mandatory = $true)][String] $tempvCenterFQDN,
        [Parameter (Mandatory = $true)][String] $tempvCenterAdmin,
        [Parameter (Mandatory = $true)][String] $tempvCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $tempclusterName,
        [Parameter (Mandatory = $true)][String] $restoredvCenterFQDN,
        [Parameter (Mandatory = $true)][String] $restoredvCenterAdmin,
        [Parameter (Mandatory = $true)][String] $restoredvCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $restoredclusterName,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile
    )
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON
    
    $tempvCenterConnection = connect-viserver $tempvCenterFQDN -user $tempvCenterAdmin -password $tempvCenterAdminPassword
    $esxiHosts = get-cluster -name $tempclusterName | get-vmhost
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
    $restoredvCenterConnection = connect-viserver $restoredvCenterFQDN -user $restoredvCenterAdmin -password $restoredvCenterAdminPassword
    Foreach ($esxiHost in $esxiHosts) {
        $esxiRootPassword = ($extractedSddcData.passwords | Where-Object {($_.entityType -eq "ESXI") -and ($_.entityName -eq $esxiHost.Name) -and ($_.username -eq "root")}).password
        Add-VMHost -Name $esxiHost.Name -Location $restoredclusterName -User root -Password $esxiRootPassword -Force -Confirm:$false | Out-Null
    }
}
Export-ModuleMember -Function Move-ClusterHostsToRestoredVcenter

Function Remove-ClusterHostsFromVds
{
     <#
    .SYNOPSIS
    Removes all hosts in the provided vSphere cluster from the provided vSphere Distributed Switch

    .DESCRIPTION
    The Remove-ClusterHostsFromVds cmdlet removes all hosts in the provided vSphere cluster from the provided vSphere Distributed Switch

    .EXAMPLE
    Remove-ClusterHostsFromVds -vCenterFQDN "sfo-m01-vc02.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01" -vdsName "sfo-m01-cl01-vds01"

    .PARAMETER vCenterFQDN
    FQDN of the vCenter instance hosting the cluster / vds from which hosts should be removed

    .PARAMETER vCenterAdmin
    Admin user of the vCenter instance hosting the cluster / vds from which hosts should be removed
    
    .PARAMETER vCenterAdminPassword
    Admin password for the vCenter instance hosting the cluster / vds from which hosts should be removed

    .PARAMETER clusterName
    Name of the vSphere cluster instance from which hosts should be removed

    .PARAMETER vdsName
    Name of the vSphere Distributed Switch to remove cluster hosts from

    #>
    
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
Export-ModuleMember -Function Remove-ClusterHostsFromVds

Function Move-MgmtVmsToTempPg 
{
    <#
    .SYNOPSIS
    Moves all management VMs in the provided vSphere cluster to a temporary management portgroup

    .DESCRIPTION
    The Move-MgmtVmsToTempPg cmdlet moves all management VMs in the provided vSphere cluster to a temporary management portgroup

    .EXAMPLE
    Move-MgmtVmsToTempPg -vCenterFQDN "sfo-m01-vc02.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01"

    .PARAMETER vCenterFQDN
    FQDN of the vCenter instance hosting the cluster / VMs which should be removed

    .PARAMETER vCenterAdmin
    Admin user of the vCenter instance hosting the cluster / VMs which should be removed
    
    .PARAMETER vCenterAdminPassword
    Admin password for the vCenter instance hosting the cluster / VMs which should be removed

    .PARAMETER clusterName
    Name of the vSphere cluster instance hosting the VMS to be moved
    #>
    
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
Export-ModuleMember -Function Move-MgmtVmsToTempPg

Function Move-ClusterHostNetworkingTovSS 
{
    <#
    .SYNOPSIS
    Describe the purpose

    .DESCRIPTION
    The xxx cmdlet Describe the purpose

    .EXAMPLE
    Show sample usage

    .PARAMETER xxxx
    Description of the parameter

    .PARAMETER yyyy
    Description of the parameter
    #>
    
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
Export-ModuleMember -Function Move-ClusterHostNetworkingTovSS

Function Move-ClusterVmnicTovSwitch
{
    <#
    .SYNOPSIS
    Describe the purpose

    .DESCRIPTION
    The xxx cmdlet Describe the purpose

    .EXAMPLE
    Show sample usage

    .PARAMETER xxxx
    Description of the parameter

    .PARAMETER yyyy
    Description of the parameter
    #>
    
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
Export-ModuleMember -Function Move-ClusterVmnicTovSwitch

Function Set-ClusterHostsvSanIgnoreClusterMemberList
{
    <#
    .SYNOPSIS
    Describe the purpose

    .DESCRIPTION
    The xxx cmdlet Describe the purpose

    .EXAMPLE
    Show sample usage

    .PARAMETER xxxx
    Description of the parameter

    .PARAMETER yyyy
    Description of the parameter
    #>
    
    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $true)][ValidateSet("enable", "disable")][String] $setting
    )

    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

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
    foreach ($esxiHost in $esxiHosts) {
        $esxiRootPassword = ($extractedSddcData.passwords | Where-Object {($_.entityType -eq "ESXI") -and ($_.entityName -eq $esxiHost.Name) -and ($_.username -eq "root")}).password
        $password = ConvertTo-SecureString $esxiRootPassword -AsPlainText -Force
        $mycreds = New-Object System.Management.Automation.PSCredential ("root", $password)    
        Get-SSHTrustedHost -HostName $esxiHost | Remove-SSHTrustedHost | Out-Null
        Write-Host "Setting vSAN Ignore Cluster Member to `'$setting`' for $esxiHost"
        $sshSession = New-SSHSession -computername $esxiHost -credential $mycreds -AcceptKey
        Invoke-SSHCommand -timeout 30 -sessionid $sshSession.SessionId -command $esxCommand | Out-Null
    }
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
}
Export-ModuleMember -Function Set-ClusterHostsvSanIgnoreClusterMemberList

Function Move-ClusterVMsToFirstHost
{
    <#
    .SYNOPSIS
    Describe the purpose

    .DESCRIPTION
    The xxx cmdlet Describe the purpose

    .EXAMPLE
    Show sample usage

    .PARAMETER xxxx
    Description of the parameter

    .PARAMETER yyyy
    Description of the parameter
    #>
    
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
Export-ModuleMember -Function Move-ClusterVMsToFirstHost

Function Resolve-PhysicalHostServiceAccounts 
{
    <#
    .SYNOPSIS
    Describe the purpose

    .DESCRIPTION
    The xxx cmdlet Describe the purpose

    .EXAMPLE
    Show sample usage

    .PARAMETER xxxx
    Description of the parameter

    .PARAMETER yyyy
    Description of the parameter
    #>
    
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
Export-ModuleMember -Function Resolve-PhysicalHostServiceAccounts

Function Set-ClusterDRSLevel 
{
    <#
    .SYNOPSIS
    Describe the purpose

    .DESCRIPTION
    The xxx cmdlet Describe the purpose

    .EXAMPLE
    Show sample usage

    .PARAMETER xxxx
    Description of the parameter

    .PARAMETER yyyy
    Description of the parameter
    #>
    
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
Export-ModuleMember -Function Set-ClusterDRSLevel

Function Remove-NonResponsiveHosts 
{
    <#
    .SYNOPSIS
    Describe the purpose

    .DESCRIPTION
    The xxx cmdlet Describe the purpose

    .EXAMPLE
    Show sample usage

    .PARAMETER xxxx
    Description of the parameter

    .PARAMETER yyyy
    Description of the parameter
    #>
    
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
Export-ModuleMember -Function Remove-NonResponsiveHosts

Function Add-HostsToCluster 
{
    <#
    .SYNOPSIS
    Describe the purpose

    .DESCRIPTION
    The xxx cmdlet Describe the purpose

    .EXAMPLE
    Show sample usage

    .PARAMETER xxxx
    Description of the parameter

    .PARAMETER yyyy
    Description of the parameter
    #>
    
    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $true)][String] $sddcManagerFQDN,
        [Parameter (Mandatory = $true)][String] $sddcManagerUser,
        [Parameter (Mandatory = $true)][String] $sddcManagerPassword
    )

    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $tokenRequest = Request-VCFToken -fqdn $sddcManagerFQDN -username $sddcManagerUser -password $sddcManagerPassword
    $newHosts = (get-vcfhost | where-object { $_.id -in ((get-vcfcluster -name $clusterName).hosts.id) }).fqdn
    $vCenterConnection = connect-viserver $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    foreach ($newHost in $newHosts) {
        $vmHosts = (Get-cluster -name $clusterName | Get-VMHost).Name
        if ($newHost -notin $vmHosts) {
            $esxiRootPassword = ($extractedSddcData.passwords | Where-Object {($_.entityType -eq "ESXI") -and ($_.entityName -eq $newHost) -and ($_.username -eq "root")}).password
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
Export-ModuleMember -Function Add-HostsToCluster


Function Remove-StandardSwitch 
{
    <#
    .SYNOPSIS
    Describe the purpose

    .DESCRIPTION
    The xxx cmdlet Describe the purpose

    .EXAMPLE
    Show sample usage

    .PARAMETER xxxx
    Description of the parameter

    .PARAMETER yyyy
    Description of the parameter
    #>
    
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
Export-ModuleMember -Function Remove-StandardSwitch

Function Add-VMKernelsToHost 
{
    <#
    .SYNOPSIS
    Describe the purpose

    .DESCRIPTION
    The xxx cmdlet Describe the purpose

    .EXAMPLE
    Show sample usage

    .PARAMETER xxxx
    Description of the parameter

    .PARAMETER yyyy
    Description of the parameter
    #>
    
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
Export-ModuleMember -Function Add-VMKernelsToHost

Function Backup-ClusterVMOverrides
{
    <#
    .SYNOPSIS
    Describe the purpose

    .DESCRIPTION
    The xxx cmdlet Describe the purpose

    .EXAMPLE
    Show sample usage

    .PARAMETER xxxx
    Description of the parameter

    .PARAMETER yyyy
    Description of the parameter
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
Export-ModuleMember -Function Backup-ClusterVMOverrides

Function Backup-ClusterVMLocations
{
    <#
    .SYNOPSIS
    Describe the purpose

    .DESCRIPTION
    The xxx cmdlet Describe the purpose

    .EXAMPLE
    Show sample usage

    .PARAMETER xxxx
    Description of the parameter

    .PARAMETER yyyy
    Description of the parameter
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
Export-ModuleMember -Function Backup-ClusterVMLocations

Function Backup-ClusterDRSGroupsAndRules
{
    <#
    .SYNOPSIS
    Describe the purpose

    .DESCRIPTION
    The xxx cmdlet Describe the purpose

    .EXAMPLE
    Show sample usage

    .PARAMETER xxxx
    Description of the parameter

    .PARAMETER yyyy
    Description of the parameter
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
Export-ModuleMember -Function Backup-ClusterDRSGroupsAndRules

Function Restore-ClusterVMOverrides
{
    <#
    .SYNOPSIS
    Describe the purpose

    .DESCRIPTION
    The xxx cmdlet Describe the purpose

    .EXAMPLE
    Show sample usage

    .PARAMETER xxxx
    Description of the parameter

    .PARAMETER yyyy
    Description of the parameter
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
Export-ModuleMember -Function Restore-ClusterVMOverrides

Function Restore-ClusterVMLocations
{
    <#
    .SYNOPSIS
    Describe the purpose

    .DESCRIPTION
    The xxx cmdlet Describe the purpose

    .EXAMPLE
    Show sample usage

    .PARAMETER xxxx
    Description of the parameter

    .PARAMETER yyyy
    Description of the parameter
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
Export-ModuleMember -Function Restore-ClusterVMLocations

Function Restore-ClusterDRSGroupsAndRules
{
    <#
    .SYNOPSIS
    Describe the purpose

    .DESCRIPTION
    The xxx cmdlet Describe the purpose

    .EXAMPLE
    Show sample usage

    .PARAMETER xxxx
    Description of the parameter

    .PARAMETER yyyy
    Description of the parameter
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
Export-ModuleMember -Function Restore-ClusterDRSGroupsAndRules

#EndRegion vCenter Functions

#Region NSXT Functions
Function VCFIRCreateHeader
{
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

Function Resolve-PhysicalHostTransportNodes
{
    <#
    .SYNOPSIS
    Describe the purpose

    .DESCRIPTION
    The xxx cmdlet Describe the purpose

    .EXAMPLE
    Show sample usage

    .PARAMETER xxxx
    Description of the parameter

    .PARAMETER yyyy
    Description of the parameter
    #>
 
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
    
    $headers = VCFIRCreateHeader -username $nsxManagerAdmin -password $nsxManagerAdminPassword
    
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
Export-ModuleMember -Function Resolve-PhysicalHostTransportNodes

Function Invoke-NSXEdgeClusterRecovery
{
    <#
    .SYNOPSIS
    Describe the purpose

    .DESCRIPTION
    The xxx cmdlet Describe the purpose

    .EXAMPLE
    Show sample usage

    .PARAMETER xxxx
    Description of the parameter

    .PARAMETER yyyy
    Description of the parameter
    #>
 
    Param(
        [Parameter (Mandatory = $true)][String] $nsxManagerFqdn,
        [Parameter (Mandatory = $true)][String] $nsxManagerAdmin,
        [Parameter (Mandatory = $true)][String] $nsxManagerAdminPassword,
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName
    )
    $vcenterConnection = Connect-VIServer -server $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    $cluster = Get-Cluster -name $clusterName
    $clusterMoRef = $cluster.ExtensionData.MoRef.Value

    #Get TransportNodes
    $headers = VCFIRCreateHeader -username $nsxManagerAdmin -password $nsxManagerAdminPassword
    $uri = "https://$nsxManagerFqdn/api/v1/transport-nodes/"
    $transportNodeContents = (Invoke-WebRequest -Method GET -URI $uri -ContentType application/json -headers $headers).content | ConvertFrom-Json
    $allEdgeTransportNodes = ($transportNodeContents.results | Where-Object { ($_.node_deployment_info.resource_type -eq "EdgeNode") -and ($_.node_deployment_info.deployment_config.vm_deployment_config.compute_id) -eq $clusterMoRef})

    #Redeploy Failed Edges
    Foreach ($edge in $allEdgeTransportNodes)
    {
        $uri = "https://$nsxManagerFqdn/api/v1/transport-nodes/$($edge.node_id)/state"
        $edgeState = (Invoke-WebRequest -Method GET -URI $uri -ContentType application/json -headers $headers).content | ConvertFrom-Json
        If ($edgeState.node_deployment_state.state -ne "success")
        {
            Write-Host "[$($edge.display_name)] is in state $($edgeState.node_deployment_state.state)"
            If ($edgeState.node_deployment_state.state -eq "MPA_DISCONNECTED")
            {
                Write-Host "[$($edge.display_name)] Redeploying"
                $uri = "https://$nsxManagerFqdn/api/v1/transport-nodes/$($edge.node_id)"
                $edgeResponse = (Invoke-WebRequest -Method GET -URI $uri -ContentType application/json -headers $headers).content
                $uri = "https://$nsxManagerFqdn/api/v1/transport-nodes/$($edge.node_id)?action=redeploy"
                $edgeRedeploy = Invoke-WebRequest -Method POST -URI $uri -ContentType application/json -body $edgeResponse -headers $headers
            }
            else 
            {   
                Write-Host "[$($edge.display_name)] Not in a suitable state for redeployment. Please review and retry"
            }
        }
    }
}
Export-ModuleMember -Function Invoke-NSXEdgeClusterRecovery
#EndRegion NSXT Functions