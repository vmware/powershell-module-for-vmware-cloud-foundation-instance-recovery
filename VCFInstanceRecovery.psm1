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

#Region Pre-Requisites
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
    $jumpboxName = hostname
    $is7Zip4PowerShellInstalled = Get-InstalledModule -name "7Zip4PowerShell" -MinimumVersion "2.4.0" -ErrorAction SilentlyContinue
    If (!$is7Zip4PowerShellInstalled)
    {
        Write-Host "[$jumpboxName] 7Zip4PowerShell Module Missing. Please install"
    }
    else 
    {
        Write-Host "[$jumpboxName] 7Zip4PowerShell Module found"
    }

    $isPoshSSHInstalled = Get-InstalledModule -name "Posh-SSH" -MinimumVersion "3.0.8" -ErrorAction SilentlyContinue
    If (!$isPoshSSHInstalled)
    {
        Write-Host "[$jumpboxName] Posh-SSH Module Missing. Please install"
    } 
    else 
    {
        Write-Host "[$jumpboxName] Posh-SSH Module found"
    }
    
    $isPowerCLIInstalled = Get-InstalledModule -name "VMware.PowerCLI" -ErrorAction SilentlyContinue
    If (!$isPowerCLIInstalled)
    {
        Write-Host "[$jumpboxName] PowerCLI Module Missing. Please install"
    }
    else
    {
        Write-Host "[$jumpboxName] PowerCLI Module found"
    }

    $isPowerVCFInstalled = Get-InstalledModule -name "PowerVCF" -MinimumVersion "2.4.0" -ErrorAction SilentlyContinue
    If (!$isPowerVCFInstalled)
    {
        Write-Host "[$jumpboxName] PowerVCF Module Missing. Please install"
    } 
    else
    {
        Write-Host "[$jumpboxName] PowerVCF Module found"
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
            Write-Host "[$jumpboxName] OpenSSL missing. Please install. Latest version detected is here: $openSSLUrl"
        }
        else 
        {
            Write-Host "[$jumpboxName] OpenSSL missing. Please install. Unable to detect latest version on web"
        }
    }
    else
    {
        Write-Host "[$jumpboxName] OpenSSL Utility found"
    }
    $pathEntries = $env:path -split (";")
    $OpenSSLPath = $pathEntries | Where-Object {$_ -like "*OpenSSL*"}
    If ($OpenSSLPath)
    {
        $testOpenSSExe = Test-Path "$OpenSSLPath\openssl.exe"
        IF ($testOpenSSExe)
        {
            Write-Host "[$jumpboxName] openssl.exe found in $OpenSSLPath"
        }
        else 
        {
            Write-Host "[$jumpboxName] $OpenSSLPath was found in environment path, but no openssl.exe was found in that path"
        }

    }
    else 
    {
        Write-Host "[$jumpboxName] No folder path that looks like OpenSSL was discovered in the environment path variable. Please double check that the location of OpenSSL is included in the path variable"
    }
}
Export-ModuleMember -Function Confirm-VCFInstanceRecoveryPreReqs
#EndRegion Pre-Requisites

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
    $backupFileFullPath = (Resolve-Path -Path $backupFilePath).path
    $backupFileName = (Get-ChildItem -path $backupFileFullPath).name
    $parentFolder = Split-Path -Path $backupFileFullPath
    $extractedBackupFolder = ($backupFileName -Split(".tar.gz"))[0]
    $jumpboxName = hostname

    #Decrypt Backup
    Write-Host "[$jumpboxName] Decrypting Backup"
    $command = "openssl enc -d -aes-256-cbc -md sha256 -in $backupFileFullPath -pass pass:`"$encryptionPassword`" -out `"$parentFolder\decrypted-sddc-manager-backup.tar.gz`""
    Invoke-Expression "& $command" *>$null

    #Extract Backup
    Write-Host "[$jumpboxName] Extracting Backup"
    Expand-7Zip -ArchiveFileName "$parentFolder\decrypted-sddc-manager-backup.tar.gz" -TargetPath $parentFolder
    Expand-7Zip -ArchiveFileName "$parentFolder\decrypted-sddc-manager-backup.tar" -TargetPath $parentFolder

    #Get Content of Password Vault
    Write-Host "[$jumpboxName] Reading Password Vault"
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
    
    $psqlContent = Get-Content "$extractedBackupFolder\database\sddc-postgres.bkp"
    Write-Host "[$jumpboxName] Retrieving NSX Manager Details"
    
    #Get All NSX Manager Clusters
    $nsxManagerstartingLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.nsxt (id" | Select-Object Line,LineNumber).LineNumber
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
                'clusterVip' = $lineContent.split("`t")[5]
                'clusterFqdn' = $lineContent.split("`t")[6]
                'domainIDs' = $nodeContent.domainIds
                'nsxNodes' = $nsxNodes
            }
        }
        $nsxManagerlineIndex++
    }
    Until ($lineContent -eq '\.')
    
    #Get Host and Domain Details
    Write-Host "[$jumpboxName] Retrieving Host and Domain Mappings"
    $hostsAndDomainsLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.host_and_domain " | Select-Object Line,LineNumber).LineNumber
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
    Write-Host "[$jumpboxName] Retrieving Host and vCenter Mappings"
    $hostsandVcentersLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.host_and_vcenter " | Select-Object Line,LineNumber).LineNumber
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
    Write-Host "[$jumpboxName] Retrieving vCenter Details"
    $vCentersStartingLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.vcenter " | Select-Object Line,LineNumber).LineNumber
    $vCenterLineIndex = $vCentersStartingLineNumber
    $vCenters = @()
    Do 
    {
        $lineContent = $psqlContent | Select-Object -Index $vCentersStartingLineNumber
        If ($lineContent -ne '\.')
        {
            $vCenterID = $lineContent.split("`t")[0]
            $vCenterVersion= $lineContent.split("`t")[9]
            $vCenterFqdn= $lineContent.split("`t")[10]
            $vCenterIp= $lineContent.split("`t")[11]
            $vCenterVMname= $lineContent.split("`t")[12]
            $vCenterDomainID = ($hostsAndDomains | Where-Object {$_.hostId -eq (($hostsandVcenters | Where-Object {$_.vCenterID -eq $vCenterID})[0].hostID)}).domainID
            $vCenters += [pscustomobject]@{
                'vCenterID' = $vCenterID
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

    #Get Hosts and Pools
    Write-Host "[$jumpboxName] Retrieving Host and Network Pool Mappings"
    $hostsAndPoolsLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.host_and_network_pool" | Select-Object Line,LineNumber).LineNumber
    $hostsAndPoolsLineIndex = $hostsAndPoolsLineNumber
    $hostsandPools = @()
    Do 
    {
        $lineContent = $psqlContent | Select-Object -Index $hostsAndPoolsLineIndex
        If ($lineContent -ne '\.')
        {
            $hostId = $lineContent.split("`t")[1]
            $poolID = $lineContent.split("`t")[2]
            $hostsandPools += [pscustomobject]@{
                'hostId' = $hostId
                'poolId' = $poolID
            }
        }
        $hostsAndPoolsLineIndex++
    }
    Until ($lineContent -eq '\.')

    #Get Network Pools
    Write-Host "[$jumpboxName] Retrieving Network Pool Details"
    $networkPoolsLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.network_pool " | Select-Object Line,LineNumber).LineNumber
    $networkPoolsLineIndex = $networkPoolsLineNumber
    $networkPools = @()
    Do 
    {
        $lineContent = $psqlContent | Select-Object -Index $networkPoolsLineIndex
        If ($lineContent -ne '\.')
        {
            $poolID = $lineContent.split("`t")[0]
            $poolName = $lineContent.split("`t")[3]
            $networkPools += [pscustomobject]@{
                'poolID' = $poolID
                'poolName' = $poolName
            }
        }
        $networkPoolsLineIndex++
    }
    Until ($lineContent -eq '\.')

    #Get VDSs
    Write-Host "[$jumpboxName] Retrieving vDS Details"
    $vdsLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.vds" | Select-Object Line,LineNumber).LineNumber
    $vdsLineIndex = $vdsLineNumber
    $virtualDistributedSwitches = @()
    Do 
    {
        $lineContent = $psqlContent | Select-Object -Index $vdsLineIndex
        If ($lineContent -ne '\.')
        {
            $vdsId = $lineContent.split("`t")[0]
            $vdsMtu = $lineContent.split("`t")[3]
            $vdsName = $lineContent.split("`t")[4]
            $niocs = $lineContent.split("`t")[5] | ConvertFrom-Json
            $vdsPortgroups = $lineContent.split("`t")[6] | ConvertFrom-Json
            $version = $lineContent.split("`t")[8]
            $virtualDistributedSwitches += [pscustomobject]@{
                'Id' = $vdsId
                'niocs' = $niocs
                'Mtu' = $vdsMtu
                'Name' = $vdsName
                'PortGroups' = $vdsPortgroups
                'version' = $version
            }
        }
        $vdsLineIndex++
    }
    Until ($lineContent -eq '\.')

    #Get Cluster and VDS
    Write-Host "[$jumpboxName] Retrieving Cluster and vDS Mappings"
    $clusterAndVdsLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.cluster_and_vds" | Select-Object Line,LineNumber).LineNumber
    $clusterAndVdsLineIndex = $clusterAndVdsLineNumber
    $clusterAndVds = @()
    Do 
    {
        $lineContent = $psqlContent | Select-Object -Index $clusterAndVdsLineIndex
        If ($lineContent -ne '\.')
        {
            $clusterID = $lineContent.split("`t")[1]
            $vdsID = $lineContent.split("`t")[2]
            $clusterAndVds += [pscustomobject]@{
                'clusterID' = $clusterID
                'vdsID' = $vdsID
            }
        }
        $clusterAndVdsLineIndex++
    }
    Until ($lineContent -eq '\.')

    #Get Clusters
    Write-Host "[$jumpboxName] Retrieving Cluster Details"
    $clustersLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.cluster " | Select-Object Line,LineNumber).LineNumber
    $clustersLineIndex = $clustersLineNumber
    $clusters = @()
    Do 
    {
        $lineContent = $psqlContent | Select-Object -Index $clustersLineIndex
        If ($lineContent -ne '\.')
        {
            $id = $lineContent.split("`t")[0]
            $datacenter = $lineContent.split("`t")[3]
            $ftt = $lineContent.split("`t")[4]
            $isDefault = $lineContent.split("`t")[5]
            $isStretched = $lineContent.split("`t")[6]
            $name = $lineContent.split("`t")[7]
            $vCenterID = $lineContent.split("`t")[9]
            $primaryDatastoreName = $lineContent.split("`t")[12]
            $primaryDatastoreType = $lineContent.split("`t")[13]
            $sourceID = $lineContent.split("`t")[14]
            $vdsDetails = @()
            Foreach ($vds in ($clusterAndVds | Where-Object {$_.clusterID -eq $id}))
            {
                $virtualDistributedSwitchDetails = $virtualDistributedSwitches | Where-Object {$_.id -eq $vds.vdsId}
                $niocSpecsObject = @()
                Foreach ($niocSpec in $virtualDistributedSwitchDetails.niocs)
                {
                    $niocSpecsObject += [PSCustomObject]@{
                        'trafficType' = $niocSpec.network
                        'value' = ($niocSpec.level).toUpper()
                    }
                }
                $vdsObject = New-Object -type PSObject
                $vdsObject | Add-Member -NotePropertyName 'mtu' -NotePropertyValue $virtualDistributedSwitchDetails.mtu
                $vdsObject | Add-Member -NotePropertyName 'niocSpecs' -NotePropertyValue $niocSpecsObject
                $vdsObject | Add-Member -NotePropertyName 'portgroups' -NotePropertyValue $virtualDistributedSwitchDetails.portgroups
                $vdsObject | Add-Member -NotePropertyName 'dvsName' -NotePropertyValue $virtualDistributedSwitchDetails.name
                $vdsObject | Add-Member -NotePropertyName 'vmnics' -NotePropertyValue $null
                $vdsObject | Add-Member -NotePropertyName 'networks' -NotePropertyValue ("MANAGEMENT","VSAN","VMOTION" | Where-Object {$_ -in $niocSpecsObject.trafficType})
                
                $vdsDetails += $vdsObject
            }
            $clusters += [pscustomobject]@{
                'id' = $id
                'datacenter' = $datacenter
                'ftt' = $ftt
                'isDefault' = $isDefault
                'isStretched' = $isStretched
                'name' = $name
                'vCenterID' = $vCenterID
                'primaryDatastoreName' = $primaryDatastoreName
                'primaryDatastoreType' = $primaryDatastoreType
                'sourceID' = $sourceID
                'vdsDetails' = $vdsDetails
            }
        }
        $clustersLineIndex++
    }
    Until ($lineContent -eq '\.')

    #Get Cluster and vCenter
    Write-Host "[$jumpboxName] Retrieving Cluster and vCenter Mappings"
    $clusterAndVcenterLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.cluster_and_vcenter" | Select-Object Line,LineNumber).LineNumber
    $clusterAndVcenterLineIndex = $clusterAndVcenterLineNumber
    $clusterAndVcenter = @()
    Do 
    {
        $lineContent = $psqlContent | Select-Object -Index $clusterAndVcenterLineIndex
        If ($lineContent -ne '\.')
        {
            $clusterID = $lineContent.split("`t")[0]
            $vcenterID = $lineContent.split("`t")[1]
            $clusterAndVcenter += [pscustomobject]@{
                'clusterID' = $clusterID
                'vcenterID' = $vcenterID
            }
        }
        $clusterAndVcenterLineIndex++
    }
    Until ($lineContent -eq '\.')

    #Get Cluster and Domain
    Write-Host "[$jumpboxName] Retrieving Cluster and Domain Mappings"
    $clusterAndDomainLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.cluster_and_domain" | Select-Object Line,LineNumber).LineNumber
    $clusterAndDomainLineIndex = $clusterAndDomainLineNumber
    $clusterAndDomain = @()
    Do 
    {
        $lineContent = $psqlContent | Select-Object -Index $clusterAndDomainLineIndex
        If ($lineContent -ne '\.')
        {
            $clusterID = $lineContent.split("`t")[0]
            $domainID = $lineContent.split("`t")[1]
            $clusterAndDomain += [pscustomobject]@{
                'clusterID' = $clusterID
                'domainID' = $domainID
            }
        }
        $clusterAndDomainLineIndex++
    }
    Until ($lineContent -eq '\.')


    #Get Pools and Networks
    Write-Host "[$jumpboxName] Retrieving Network Pools and Network Mappings"
    $poolsAndNetworksLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.vcf_network_and_network_pool" | Select-Object Line,LineNumber).LineNumber
    $poolsAndNetworksLineIndex = $poolsAndNetworksLineNumber
    $poolsAndNetworks = @()
    Do 
    {
        $lineContent = $psqlContent | Select-Object -Index $poolsAndNetworksLineIndex
        If ($lineContent -ne '\.')
        {
            $networkID = $lineContent.split("`t")[0]
            $poolID = $lineContent.split("`t")[1]
            $poolsAndNetworks += [pscustomobject]@{
                'networkID' = $networkID
                'poolID' = $poolID
            }
        }
        $poolsAndNetworksLineIndex++
    }
    Until ($lineContent -eq '\.')

    #Get Networks
    Write-Host "[$jumpboxName] Retrieving Network Details"
    $networksLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.vcf_network " | Select-Object Line,LineNumber).LineNumber
    $networksLineIndex = $networksLineNumber
    $networks = @()
    Do 
    {
        $lineContent = $psqlContent | Select-Object -Index $networksLineIndex
        If ($lineContent -ne '\.')
        {
            $id = $lineContent.split("`t")[0]
            $gateway = $lineContent.split("`t")[4]
            $ipInclusionRanges = $lineContent.split("`t")[5] | ConvertFrom-Json
            $startIPAddress = $ipInclusionRanges.start
            $endIPAddress = $ipInclusionRanges.end
            $mtu = $lineContent.split("`t")[6]
            $subnet = $lineContent.split("`t")[7]
            $subnetMask = $lineContent.split("`t")[8]
            $type = $lineContent.split("`t")[9]
            $vlanId = $lineContent.split("`t")[11]
            $networks += [pscustomobject]@{
                'id' = $id
                'gateway' = $gateway
                'startIPAddress' = $startIPAddress
                'endIPAddress' = $endIPAddress
                'mtu' = $mtu
                'subnet' = $subnet
                'subnetMask' = $subnetMask
                'type' = $type
                'vlanId' = $vlanId
            }
        }
        $networksLineIndex++
    }
    Until ($lineContent -eq '\.')

    #Get License Models
    Write-Host "[$jumpboxName] Retrieving Licensing Models"
    $licenseModelLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY licensemanager.licensing_info" | Select-Object Line,LineNumber).LineNumber
    $licenseModelLineIndex = $licenseModelLineNumber
    $licenseModels = @()
    Do 
    {
        $lineContent = $psqlContent | Select-Object -Index $licenseModelLineIndex
        If ($lineContent -ne '\.')
        {
            $resourceType = $lineContent.split("`t")[1]
            $resourceId = $lineContent.split("`t")[2]
            $licensingMode = $lineContent.split("`t")[3]
            $licenseModels += [pscustomobject]@{
                'resourceType' = $resourceType
                'resourceId' = $resourceId
                'licensingMode' = $licensingMode
            }
        }
        $licenseModelLineIndex++
    }
    Until ($lineContent -eq '\.')

    
    #Get License Keys
    Write-Host "[$jumpboxName] Retrieving License Keys"
    $licenseLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY licensemanager.licensekey" | Select-Object Line,LineNumber).LineNumber
    $licenseLineIndex = $licenseLineNumber
    $licenseKeys = @()
    Do 
    {
        $lineContent = $psqlContent | Select-Object -Index $licenseLineIndex
        If ($lineContent -ne '\.')
        {
            $id = $lineContent.split("`t")[0]
            $key = $lineContent.split("`t")[1]
            $description = $lineContent.split("`t")[2]
            $productType = $lineContent.split("`t")[3]
            $licenseKeys += [pscustomobject]@{
                'id' = $id
                'key' = $key
                'description' = $description
                'productType' = $productType
            }
        }
        $licenseLineIndex++
    }
    Until ($lineContent -eq '\.')

    Write-Host "[$jumpboxName] Assembling Workload Domain Data"
    #GetDomainDetails
    $domainsStartingLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.domain (id" | Select-Object Line,LineNumber).LineNumber
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
            $ssoDomain = $lineContent.split("`t")[11]
            $vCenter = $vCenters | Where-Object {$_.vCenterDomainID -eq $domainId}
            $vCenterDetails = [pscustomobject]@{
                'id' = $vCenter.vCenterID
                'version' = $vCenter.vCenterVersion
                'fqdn' = $vCenter.vCenterFqdn
                'ip' = $vCenter.vCenterIp
                'vmname' = $vCenter.vCenterVMname
            }
            #HostID from hostsAndDomains of first host in domain based on DomainID
            $hostID = (($hostsAndDomains | Where-Object {$_.domainID -eq $domainID})[0]).hostId

            #PoolID from HostandPools based on HostID
            $poolID = ($hostsAndPools | Where-Object {$_.hostId -eq $hostID}).PoolID

            #poolName from Networkpools based on PoolID
            $poolName = ($networkPools | Where-Object {$_.poolID -eq $poolID}).PoolName

            #networks from poolID
            $domainNetworks = ($poolsAndNetworks| Where-Object {$_.poolID -eq $poolID}).networkID
            $vmotionNetwork = $networks | Where-Object {($_.type -eq "VMOTION") -and ($_.id -in $domainNetworks)}
            $vsanNetwork = $networks | Where-Object {($_.type -eq "VSAN") -and ($_.id -in $domainNetworks)}
            $sddcManagerIP = $metadataJSON.ip
            $managementSubnetMask = $metaDataJSON.netmask
            $ip = [ipaddress]$sddcManagerIP
            $subnet = [ipaddress]$managementSubnetMask
            $netid = [ipaddress]($ip.address -band $subnet.address)           
            $managementSubnet = $($netid.ipaddresstostring)

            $networkSpecs = @()
            $networkSpecs += [pscustomobject]@{  #Review
                'type' = "MANAGEMENT"
                'subnet_mask' = $metaDataJSON.netmask
                'subnet' =  $managementSubnet
                'mtu' =  "1500" # Review
                'vlanID' = ($virtualDistributedSwitches.portgroups | Where-Object {$_.name -eq $metadataJSON.port_group}).vlanId
                'gateway' = $metaDataJSON.gateway
                'portgroupKey' = $metadataJSON.port_group
            }
            $networkSpecs += [pscustomobject]@{
                'type' = "VMOTION"
                'subnet_mask' = $vmotionNetwork.subnetMask
                'subnet' =  $vmotionNetwork.subnet
                'mtu' =  $vmotionNetwork.mtu
                'startIpAddress' = $vmotionNetwork.startIpAddress
                'endIpAddress' = $vmotionNetwork.endIpAddress
                'vlanID' = $vmotionNetwork.vlanID
                'gateway' = $vmotionNetwork.gateway
                'portgroupKey' = ($virtualDistributedSwitches.portgroups | Where-Object {$_.vlanId -eq $vmotionNetwork.vlanID}).name
            }
            $networkSpecs += [pscustomobject]@{
                'type' = "VSAN"
                'subnet_mask' = $vsanNetwork.subnetMask
                'subnet' =  $vsanNetwork.subnet
                'mtu' =  $vsanNetwork.mtu
                'startIpAddress' = $vsanNetwork.startIpAddress
                'endIpAddress' = $vsanNetwork.endIpAddress
                'vlanID' = $vsanNetwork.vlanID
                'gateway' = $vsanNetwork.gateway
                'portgroupKey' = ($virtualDistributedSwitches.portgroups | Where-Object {$_.vlanId -eq $vsanNetwork.vlanID}).name
            }
            $nsxClusterDetailsObject = New-Object -type psobject
            $nsxClusterDetailsObject | Add-Member -NotePropertyName 'clusterVip' -NotePropertyValue ($nsxtManagerClusters | Where-Object {$_.domainIDs -contains $domainId}).clusterVip
            $nsxClusterDetailsObject | Add-Member -NotePropertyName 'clusterFqdn' -NotePropertyValue ($nsxtManagerClusters | Where-Object {$_.domainIDs -contains $domainId}).clusterFqdn
            $nsxClusterDetailsObject | Add-Member -NotePropertyName 'rootNsxtManagerPassword' -NotePropertyValue ($passwordVaultObject | Where-Object {($_.entityName -eq ($nsxtManagerClusters | Where-Object {$_.domainIDs -contains $domainId}).clusterFqdn) -and ($_.credentialType -eq 'SSH')}).password
            $nsxClusterDetailsObject | Add-Member -NotePropertyName 'nsxtAdminPassword' -NotePropertyValue ($passwordVaultObject | Where-Object {($_.entityName -eq ($nsxtManagerClusters | Where-Object {$_.domainIDs -contains $domainId}).clusterFqdn) -and ($_.credentialType -eq 'API')}).password
            $nsxClusterDetailsObject | Add-Member -NotePropertyName 'nsxtAuditPassword' -NotePropertyValue ($passwordVaultObject  | Where-Object {($_.entityName -eq ($nsxtManagerClusters | Where-Object {$_.domainIDs -contains $domainId}).clusterFqdn) -and ($_.credentialType -eq 'AUDIT')}).password

            $workloadDomains += [pscustomobject]@{
                'domainName' = $domainName
                'domainID' = $domainID
                'domainType' = $domainType
                'licenseModel' = ($licenseModels | Where-Object {$_.resourceId -eq $domainID}).licensingMode
                'ssoDomain' = $ssoDomain
                'networkPool' = $poolName
                'vCenterDetails' = $vCenterDetails
                'networkDetails' = $networkSpecs
                'nsxClusterDetails' = $nsxClusterDetailsObject
                'nsxNodeDetails' = ($nsxtManagerClusters | Where-Object {$_.domainIDs -contains $domainId}).nsxNodes
                'vsphereClusterDetails' = ($clusters | Where-Object {$_.vCenterID -eq $vcenterDetails.id})
            }
        }
        $domainLineIndex++
    } Until ($lineContent -eq '\.')

    Write-Host "[$jumpboxName] Retrieving SDDC Manager Detail"
    #GetDomainDetails
    $ceipStartingLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.sddc_manager_controller" | Select-Object Line,LineNumber).LineNumber
    $lineContent = $psqlContent | Select-Object -Index $ceipStartingLineNumber
    $sddcManagerIp = $lineContent.split("`t")[3]
    $sddcManagerVersion = $lineContent.split("`t")[5]
    $sddcManagerFqdn = $lineContent.split("`t")[6]
    $sddcManagerVmName = $lineContent.split("`t")[8]
    If ($lineContent.split("`t")[9] -eq 'ENABLED') { $ceipStatus = $true} else {$ceipStatus = $false}

    $sddcManagerObject = @()
    $sddcManagerObject += [pscustomobject]@{
        'fqdn' = $sddcManagerFqdn
        'vmname' = $sddcManagerVmName
        'ip' = $sddcManagerIp
        'fips_enabled' = $metadataJSON.fips_enabled 
        'ceip_enabled' = $ceipStatus
        'version' = $sddcManagerVersion
    }
    
    Write-Host "[$jumpboxName] Creating extracted-sddc-data.json"
    $sddcDataObject = New-Object -TypeName psobject
    $sddcDataObject | Add-Member -notepropertyname 'sddcManager' -notepropertyvalue $sddcManagerObject
    $sddcDataObject | Add-Member -notepropertyname 'mgmtDomainInfrastructure' -notepropertyvalue $mgmtDomainInfrastructure
    $sddcDataObject | Add-Member -notepropertyname 'licenseKeys' -notepropertyvalue $licenseKeys
    $sddcDataObject | Add-Member -notepropertyname 'workloadDomains' -notepropertyvalue $workloadDomains
    $sddcDataObject | Add-Member -notepropertyname 'passwords' -notepropertyvalue $passwordVaultObject
    $sddcDataObject | ConvertTo-Json -Depth 10 | Out-File "$parentFolder\extracted-sddc-data.json"

    #Cleanup
    Write-Host "[$jumpboxName] Cleaning up extracted files"
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
    New-NSXManagerOvaDeployment -tempvCenterFqdn "sfo-m01-vc02.sfo.rainpole.io" -tempvCenterAdmin "administrator@vsphere.local" -tempvCenterAdminPassword "VMw@re1!" -extractedSDDCDataFile ".\extracted-sddc-data.json" -workloadDomain "sfo-m01" -restoredNsxManagerDeploymentSize medium -nsxManagerOvaFile "F:\OVA\nsx-unified-appliance-3.2.2.1.0.21487565.ova"

    .PARAMETER tempvCenterFqdn
    FQDN of the target vCenter to deploy the NSX Manager OVA to

    .PARAMETER tempvCenterAdmin
    Admin user of the target vCenter to deploy the NSX Manager OVA to
    
    .PARAMETER tempvCenterAdminPassword
    Admin password for the target vCenter to deploy the NSX Manager OVA to
    
    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem
    
    .PARAMETER workloadDomain
    Name of the VCF workload domain that the NSX Manager to deployed to is associated with
    
    .PARAMETER restoredNsxManagerDeploymentSize
    Size of the NSX Manager Appliance to deploy

    .PARAMETER nsxManagerOvaFile
    Relative or absolute to the NSX Manager OVA somewhere on the local filesystem
    #>
    
    Param(
        [Parameter (Mandatory = $true)][String] $tempvCenterFqdn,
        [Parameter (Mandatory = $true)][String] $tempvCenterAdmin,
        [Parameter (Mandatory = $true)][String] $tempvCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $true)][String] $workloadDomain,
        [Parameter (Mandatory = $true)][String] $restoredNsxManagerDeploymentSize,
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
        $command = '"C:\Program Files\VMware\VMware OVF Tool\ovftool.exe" --noSSLVerify --acceptAllEulas --allowExtraConfig --diskMode=thin --X:injectOvfEnv --X:logFile=ovftool.log --powerOn --name="' + $nsxManagerVMName + '" --datastore="' + $vmDatastore + '" --deploymentOption="' + $restoredNsxManagerDeploymentSize + '" --network="' + $vmNetwork + '" --prop:nsx_role="NSX Manager" --prop:nsx_ip_0="' + $nsxManagerIp + '" --prop:nsx_netmask_0="' + $nsxManagerNetworkMask + '" --prop:nsx_gateway_0="' + $nsxManagerGateway + '" --prop:nsx_dns1_0="' + $nsxManagerDns + '" --prop:nsx_domain_0="' + $nsxManagerDnsDomain + '" --prop:nsx_ntp_0="' + $nsxManagerNtpServer + '" --prop:nsx_isSSHEnabled=True --prop:nsx_allowSSHRootLogin=True --prop:nsx_passwd_0="' + $nsxManagerAdminPassword + '" --prop:nsx_cli_username="' + $nsxManagerAdminUsername+ '" --prop:nsx_cli_passwd_0="' + $nsxManagerCliPassword + '" --prop:nsx_cli_audit_passwd_0="' + $nsxManagerCliAuditPassword + '" --prop:nsx_cli_audit_username="' + $nsxManagerCliAuditUsername + '" --prop:nsx_hostname="' + $nsxManagerHostName + '" "' + $nsxManagerOvaFile + '" ' + '"vi://' + $tempVcenterAdmin + ':' + $tempVcenterAdminPassword + '@' + $tempVcenterFqdn + '/' + $datacenterName + '/host/' + $clusterName + '/"'
    }
    else 
    {
        $command = '"C:\Program Files\VMware\VMware OVF Tool\ovftool.exe" --noSSLVerify --acceptAllEulas --allowExtraConfig --diskMode=thin --X:injectOvfEnv --X:logFile=ovftool.log --powerOn --name="' + $nsxManagerVMName + '" --datastore="' + $vmDatastore + '" --deploymentOption="' + $restoredNsxManagerDeploymentSize + '" --network="' + $vmNetwork + '" --prop:nsx_role="NSX Manager" --prop:nsx_ip_0="' + $nsxManagerIp + '" --prop:nsx_netmask_0="' + $nsxManagerNetworkMask + '" --prop:nsx_gateway_0="' + $nsxManagerGateway + '" --prop:nsx_dns1_0="' + $nsxManagerDns + '" --prop:nsx_domain_0="' + $nsxManagerDnsDomain + '" --prop:nsx_ntp_0="' + $nsxManagerNtpServer + '" --prop:nsx_isSSHEnabled=True --prop:nsx_allowSSHRootLogin=True --prop:nsx_passwd_0="' + $nsxManagerAdminPassword + '" --prop:nsx_cli_username="' + $nsxManagerAdminUsername+ '" --prop:nsx_cli_passwd_0="' + $nsxManagerCliPassword + '" --prop:nsx_hostname="' + $nsxManagerHostName + '" "' + $nsxManagerOvaFile + '" ' + '"vi://' + $tempVcenterAdmin + ':' + $tempVcenterAdminPassword + '@' + $tempVcenterFqdn + '/' + $datacenterName + '/host/' + $clusterName + '/"'    <# Action when all if and elseif conditions are false #>
    }
    Write-Host "[$nsxManagerVMName] Deploying NSX Manager OVA"
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
    New-vCenterOvaDeployment -tempvCenterFqdn "sfo-m01-vc02.sfo.rainpole.io" -tempvCenterAdmin "administrator@vsphere.local" -tempvCenterAdminPassword "VMw@re1!" -extractedSDDCDataFile ".\extracted-sddc-data.json" -workloadDomain "sfo-m01" -restoredvCenterDeploymentSize "small" -vCenterOvaFile "F:\OVA\VMware-vCenter-Server-Appliance-7.0.3.01400-21477706_OVF10.ova"

    .PARAMETER tempvCenterFqdn
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
        [Parameter (Mandatory = $true)][String] $tempvCenterFqdn,
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
    Write-Host "[$restoredvCenterVMName] Deploying vCenter OVA"
    $command = '"C:\Program Files\VMware\VMware OVF Tool\ovftool.exe" --noSSLVerify --acceptAllEulas --allowExtraConfig --X:enableHiddenProperties --diskMode=thin --X:injectOvfEnv --X:waitForIp --X:logFile=ovftool.log --name="' + $restoredvCenterVMName + '" --net:"Network 1"="' +$vmNetwork + '" --datastore="' + $vmDatastore + '" --deploymentOption="' + $restoredvCenterDeploymentSize + '" --prop:guestinfo.cis.appliance.net.addr.family="ipv4" --prop:guestinfo.cis.appliance.net.addr="' + $restoredvCenterIpAddress + '" --prop:guestinfo.cis.appliance.net.pnid="' + $restoredvCenterFqdn + '" --prop:guestinfo.cis.appliance.net.prefix="' + $restoredvCenterNetworkPrefix + '" --prop:guestinfo.cis.appliance.net.mode="static" --prop:guestinfo.cis.appliance.net.dns.servers="' + $restoredvCenterDnsServers + '" --prop:guestinfo.cis.appliance.net.gateway="' + $restoredvCenterGateway + '" --prop:guestinfo.cis.appliance.root.passwd="' + $restoredvCenterRootPassword + '" --prop:guestinfo.cis.appliance.ssh.enabled="True" "' + $vCenterOvaFile + '" ' + '"vi://' + $tempvCenterAdmin + ':' + $tempvCenterAdminPassword + '@' + $tempvCenterFqdn + '/' + $datacenterName + '/host/' + $clusterName + '/"'
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
    New-SDDCManagerOvaDeployment -tempvCenterFqdn "sfo-m01-vc02.sfo.rainpole.io" -tempvCenterAdmin "administrator@vsphere.local" -tempvCenterAdminPassword "VMw@re1!" -extractedSDDCDataFile ".\extracted-sddc-data.json" -sddcManagerOvaFile "F:\OVA\VCF-SDDC-Manager-Appliance-4.5.1.0-21682411.ova" -rootUserPassword "VMw@re1!" -vcfUserPassword "VMw@re1!" -localUserPassword "VMw@re1!" -basicAuthUserPassword "VMw@re1!"

    .PARAMETER tempvCenterFqdn
    FQDN of the target vCenter to deploy the SDDC Manager OVA to

    .PARAMETER tempvCenterAdmin
    Admin user of the target vCenter to deploy the SDDC Manager OVA to
    
    .PARAMETER tempvCenterAdminPassword
    Admin password for the target vCenter to deploy the SDDC Manager OVA to
    
    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem
       
    .PARAMETER sddcManagerOvaFile
    Relative or absolute to the SDDC Manager OVA somewhere on the local filesystem

    .PARAMETER rootUserPassword
    Password for the root user on the newly deployed appliance
    
    .PARAMETER vcfUserPassword
    Password for the vcf user on the newly deployed appliance

    .PARAMETER localUserPassword
    Password for the local admin user on the newly deployed appliance

    .PARAMETER basicAuthUserPassword
    Password for the basic auth user on the newly deployed appliance
    #>
    
    Param(
        [Parameter (Mandatory = $true)][String] $tempvCenterFqdn,
        [Parameter (Mandatory = $true)][String] $tempvCenterAdmin,
        [Parameter (Mandatory = $true)][String] $tempvCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $true)][String] $sddcManagerOvaFile,
        [Parameter (Mandatory = $true)][String] $rootUserPassword,
        [Parameter (Mandatory = $true)][String] $vcfUserPassword,
        [Parameter (Mandatory = $true)][String] $localUserPassword,
        [Parameter (Mandatory = $true)][String] $basicAuthUserPassword
    )
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    # SDDC Manager Configuration
    $vmNetwork = $extractedSDDCData.mgmtDomainInfrastructure.port_group
    $vmDatastore = $extractedSDDCData.mgmtDomainInfrastructure.vsan_datastore
    $datacenterName = $extractedSDDCData.mgmtDomainInfrastructure.datacenter
    $clusterName = $extractedSDDCData.mgmtDomainInfrastructure.cluster
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
    
    Write-Host "[$sddcManagerVMName] Deploying SDDC Manager OVA"
    $command = '"C:\Program Files\VMware\VMware OVF Tool\ovftool.exe" --noSSLVerify --acceptAllEulas --allowAllExtraConfig --diskMode=thin --X:enableHiddenProperties --X:waitForIp --powerOn --name="' + $sddcManagerVMName + '" --network="' + $vmNetwork + '" --datastore="' + $vmDatastore + '" --prop:vami.hostname="' + $sddcManagerHostName + '" --prop:vami.ip0.SDDC-Manager="' + $sddcManagerIp + '" --prop:vami.netmask0.SDDC-Manager="' + $sddcManagerNetworkMask + '" --prop:vami.DNS.SDDC-Manager="' + $sddcManagerDns + '" --prop:vami.gateway.SDDC-Manager="' + $sddcManagerGateway + '" --prop:BACKUP_PASSWORD="' + $sddcManagerBackupPassword + '" --prop:ROOT_PASSWORD="' + $rootUserPassword + '" --prop:VCF_PASSWORD="' + $vcfUserPassword + '" --prop:BASIC_AUTH_PASSWORD="' + $basicAuthUserPassword + '" --prop:LOCAL_USER_PASSWORD="' + $localUserPassword + '" --prop:vami.searchpath.SDDC-Manager="' + $sddcManagerDomainSearch + '" --prop:vami.domain.SDDC-Manager="' + $sddcManagerDnsDomain + '" --prop:FIPS_ENABLE="' + $sddcManagerFipsSetting + '" --prop:guestinfo.ntp="' + $ntpServers + '" "' + $sddcManagerOvaFile + '" "vi://' + $tempvCenterAdmin + ':' + $tempvCenterAdminPassword + '@' + $tempvCenterFqdn + '/' + $datacenterName + '/host/' + $clusterName + '/"'
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
    New-UploadAndModifySDDCManagerBackup -rootUserPassword "VMw@re1!" -vcfUserPassword "VMw@re1!" -backupFilePath "F:\backup\vcf-backup-sfo-vcf01-sfo-rainpole-io-2023-09-19-10-53-02.tar.gz" -encryptionPassword "VMw@re1!VMw@re1!" -extractedSDDCDataFile ".\extracted-sddc-data.json" -tempvCenterFqdn "sfo-m01-vc02.sfo.rainpole.io" -tempvCenterAdmin "Administrator@vsphere.local" -tempvCenterAdminPassword VMw@re1!"

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

    .PARAMETER tempvCenterFqdn
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
        [Parameter (Mandatory = $true)][String] $tempvCenterFqdn,
        [Parameter (Mandatory = $true)][String] $tempvCenterAdmin,
        [Parameter (Mandatory = $true)][String] $tempvCenterAdminPassword
    )
    $jumpboxName = hostname
    Write-Host "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $mgmtWorkloadDomain = $extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}
    $mgmtVcenterFqdn =  $mgmtWorkloadDomain.vCenterDetails.fqdn
    $sddcManagerFQDN = $extractedSddcData.sddcManager.fqdn
    $sddcManagerVmName = $extractedSddcData.sddcManager.vmName
    $backupFileFullPath = (Resolve-Path -Path $backupFilePath).path
    $backupFileName = (Get-ChildItem -path $backupFileFullPath).name
    $extractedBackupFolder = ($backupFileName -Split(".tar.gz"))[0]
    
    #Establish SSH Connection to SDDC Manager
    Write-Host "[$jumpboxName] Establishing Connection to SDDC Manager Appliance"
    $SecurePassword = ConvertTo-SecureString -String $vcfUserPassword -AsPlainText -Force
    $mycreds = New-Object System.Management.Automation.PSCredential ("vcf", $SecurePassword)
    Get-SSHTrustedHost | Remove-SSHTrustedHost | Out-Null
    $inmem = New-SSHMemoryKnownHost
    New-SSHTrustedHost -KnownHostStore $inmem -HostName $sddcManagerFQDN -FingerPrint ((Get-SSHHostKey -ComputerName $sddcManagerFQDN).fingerprint) | Out-Null
    Do
    {
        $sshSession = New-SSHSession -computername $sddcManagerFQDN -Credential $mycreds -KnownHost $inmem
    } Until ($sshSession)

    #Perform KeyScan
    Write-Host "[$sddcManagerFQDN] Performing Keyscan on SDDC Manager Appliance"
    $result = (Invoke-SSHCommand -timeout 30 -sessionid $sshSession.SessionId -command "ssh-keyscan $mgmtVcenterFqdn").output

    #Close SSH Session
    Remove-SSHSession -SSHSession $sshSession | Out-Null
    
    #Determine new SSH Keys
    $newNistKey = '"' + (($result | Where-Object {$_ -like "*ecdsa-sha2-nistp256*"}).split("ecdsa-sha2-nistp256 "))[1] + '"'
    If ($newNistKey) { Write-Host "[$sddcManagerFQDN] New ecdsa-sha2-nistp256 key for $mgmtVcenterFqdn retrieved" }
    $newRSAKey = '"' + (($result | Where-Object {$_ -like "*ssh-rsa*"}).split("ssh-rsa "))[1] + '"'
    If ($newRSAKey) { Write-Host "[$sddcManagerFQDN] New ssh-rsa key for $mgmtVcenterFqdn retrieved" }

    #Upload Backup
    $vCenterConnection = Connect-VIServer -server $tempvCenterFqdn -user $tempvCenterAdmin -password $tempvCenterAdminPassword
    Write-Host "[$jumpboxName] Uploading Backup File to SDDC Manager Appliance"
    $copyFile = Copy-VMGuestFile -Source $backupFileFullPath -Destination "/tmp/$backupFileName" -LocalToGuest -VM $sddcManagerVmName -GuestUser "root" -GuestPassword $rootUserPassword -Force -WarningAction SilentlyContinue -WarningVariable WarnMsg

    #Decrypt/Extract Backup
    Write-Host "[$sddcManagerFQDN] Decrypting Backup on SDDC Manager Appliance"
    #$command = "cd /tmp; OPENSSL_FIPS=1 openssl enc -d -aes-256-cbc -md sha256 -in /tmp/$backupFileName -pass pass:`'$encryptionPassword`' | tar -xz"
    $command = "cd /tmp; echo `'$encryptionPassword`' | OPENSSL_FIPS=1 openssl enc -d -aes-256-cbc -md sha256 -in /tmp/$backupFileName -pass stdin | tar -xz"
    $result = ((Invoke-VMScript -ScriptText $command -VM $sddcManagerVmName -GuestUser 'root' -GuestPassword $rootUserPassword).ScriptOutput) -replace "(`n|`r)"

    #Modfiy JSON file  
    #Existing Nist Key
    Write-Host "[$sddcManagerFQDN] Parsing Backup on SDDC Manager Appliance for original ecdsa-sha2-nistp256 key for $mgmtVcenterFqdn"
    $command = "cat /tmp/$extractedBackupFolder/appliancemanager_ssh_knownHosts.json  | jq `'.knownHosts[] | select(.host==`"$mgmtVcenterFqdn`") | select(.keyType==`"ecdsa-sha2-nistp256`")| .key`'"
    $oldNistKey = ((Invoke-VMScript -ScriptText $command -VM $sddcManagerVmName -GuestUser 'root' -GuestPassword $rootUserPassword).ScriptOutput) -replace "(`n|`r)"

    #Existing rsa Key
    Write-Host "[$sddcManagerFQDN] Parsing Backup on SDDC Manager Appliance for original ssh-rsa key for $mgmtVcenterFqdn"
    $command = "cat /tmp/$extractedBackupFolder/appliancemanager_ssh_knownHosts.json  | jq `'.knownHosts[] | select(.host==`"$mgmtVcenterFqdn`") | select(.keyType==`"ssh-rsa`")| .key`'"
    $oldRSAKey = ((Invoke-VMScript -ScriptText $command -VM $sddcManagerVmName -GuestUser 'root' -GuestPassword $rootUserPassword).ScriptOutput) -replace "(`n|`r)"

    #Sed File
    Write-Host "[$sddcManagerFQDN] Replacing ecdsa-sha2-nistp256 and ssh-rsa keys and re-encrypting the SDDC Manager Backup"
    $command = "sed -i `'s@$oldNistKey@$newNistKey@`' /tmp/$extractedBackupFolder/appliancemanager_ssh_knownHosts.json; sed -i `'s@$oldRSAKey@$newRSAKey@`' /tmp/$extractedBackupFolder/appliancemanager_ssh_knownHosts.json; mv /tmp/$backupFileName /tmp/$backupFileName.original; export encryptionPassword='$encryptionPassword'; cd /tmp; tar -cz $extractedBackupFolder | OPENSSL_FIPS=1 openssl enc -aes-256-cbc -md sha256 -out /tmp/$backupFileName -pass env:encryptionPassword"
    $result = ((Invoke-VMScript -ScriptText $command -VM $sddcManagerVmName -GuestUser 'root' -GuestPassword $rootUserPassword).ScriptOutput) -replace "(`n|`r)"

    #Disconnect from vCenter
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
}
Export-ModuleMember -Function New-UploadAndModifySDDCManagerBackup

Function New-ReconstructedPartialBringupJsonSpec
{
    <#
    .SYNOPSIS
    Reconstructs a managment domain bringup JSON spec based on information scraped from the backup being restored from

    .DESCRIPTION
    The New-ReconstructedPartialBringupJsonSpec cmdlet Reconstructs a managment domain bringup JSON spec based on information scraped from the backup being restored from

    .EXAMPLE
    New-ReconstructedPartialBringupJsonSpec -extractedSDDCDataFile ".\extracted-sddc-data.json" -tempVcenterIp "172.16.11.170" -tempVcenterHostname "sfo-m01-vc02" -vcfLocalUserPassword "VMw@re1!VMw@re1!" -vcfRootUserPassword "VMw@re1!" -vcfRestApiPassword "VMw@re1!" -vcfSecondUserPassword "VMw@re1!" -transportVlanId 1614 -dedupEnabled $false -vds0nics "vmnic0","vmnic1" -vcenterServerSize "small"

    .PARAMETER tempVcenterIp
    As a temporary vCenter will be used, a temporary IP Address must be provdied for use

    .PARAMETER tempVcenterHostname
    As a temporary vCenter will be used, a temporary Hostname must be provdied for use
    
    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem

    .PARAMETER vcfLocalUserPassword
    Password to be assigned to the local user account

    .PARAMETER vcfRootUserPassword
    Password to be assigned to the root user account

    .PARAMETER vcfRestApiPassword
    Password to be assigned to the api user account

    .PARAMETER vcfSecondUserPassword
    Password to be assigned to the vcf user account

    .PARAMETER transportVlanId
    VLAN ID to be used for the transport VLAN. Should be the same as that used in the original build

    .PARAMETER dedupEnabled
    Boolean value to specify with depude should be enabled or not

    .PARAMETER vds0nics
    Comma seperated list of vmnics to assign to the first vds in the format "vmnic0","vmnic1"
    
    .PARAMETER vcenterServerSize
    Size of the vCenter appliance to be deployed for the temporary vCenter

    #>
    
    Param(
        [Parameter (Mandatory = $true)][String] $tempVcenterIp,
        [Parameter (Mandatory = $true)][String] $tempVcenterHostname,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $true)][String] $vcfLocalUserPassword,
        [Parameter (Mandatory = $true)][String] $vcfRootUserPassword,
        [Parameter (Mandatory = $true)][String] $vcfRestApiPassword,
        [Parameter (Mandatory = $true)][String] $vcfSecondUserPassword,
        [Parameter (Mandatory = $true)][String] $transportVlanId,
        [Parameter (Mandatory = $true)][boolean] $dedupEnabled,
        [Parameter (Mandatory = $true)][Array] $vds0nics,
        [Parameter (Mandatory = $true)][String] $vcenterServerSize
    )
    $jumpboxName = hostname
    Write-Host "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $domainName = ($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).domainName

    $mgmtDomainObject = New-Object -type psobject
    $mgmtDomainObject | Add-Member -notepropertyname 'taskName' -notepropertyvalue "workflowconfig/workflowspec-ems.json"
    $mgmtDomainObject | Add-Member -notepropertyname 'sddcId' -notepropertyvalue ($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).domainName
    $mgmtDomainObject | Add-Member -notepropertyname 'ceipEnabled' -notepropertyvalue "$($extractedSddcData.sddcManager.ceip_enabled)"
    $mgmtDomainObject | Add-Member -notepropertyname 'fipsEnabled' -notepropertyvalue "$($extractedSddcData.sddcManager.fips_enabled)"
    $mgmtDomainObject | Add-Member -notepropertyname 'managementPoolName' -notepropertyvalue ($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).networkPool
    $mgmtDomainObject | Add-Member -notepropertyname 'skipEsxThumbprintValidation' -notepropertyvalue $true # Review
    $mgmtDomainObject | Add-Member -notepropertyname 'esxLicense' -notepropertyvalue ($extractedSddcData.licenseKeys | Where-Object {$_.productType -eq "ESXI"}).key
    $mgmtDomainObject | Add-Member -notepropertyname 'excludedComponents' -notepropertyvalue @("NSX-V")
    $mgmtDomainObject | Add-Member -notepropertyname 'ntpServers' -notepropertyvalue $extractedSddcData.mgmtDomainInfrastructure.ntpServers

    #dnsSpec
    $dnsSpecObject = New-Object -type psobject
    $dnsSpecObject | Add-Member -notepropertyname 'domain' -notepropertyvalue $extractedSddcData.mgmtDomainInfrastructure.domain
    $dnsSpecObject | Add-Member -notepropertyname 'subdomain' -notepropertyvalue $extractedSddcData.mgmtDomainInfrastructure.domain
    $dnsSpecObject | Add-Member -notepropertyname 'nameserver' -notepropertyvalue $extractedSddcData.mgmtDomainInfrastructure.primaryDnsServer
    $dnsSpecObject | Add-Member -notepropertyname 'secondaryNameserver' -notepropertyvalue $extractedSddcData.mgmtDomainInfrastructure.secondaryDnsServer
    $mgmtDomainObject | Add-Member -notepropertyname 'dnsSpec' -notepropertyvalue $dnsSpecObject

    #sddcManagerSpec
    $rootUserCredentialsObject = New-Object -type psobject
    $rootUserCredentialsObject | Add-Member -notepropertyname 'username' -notepropertyvalue "root"
    $rootUserCredentialsObject | Add-Member -notepropertyname 'password' -notepropertyvalue $vcfRootUserPassword
    $restApiCredentialsObject = New-Object -type psobject
    $restApiCredentialsObject | Add-Member -notepropertyname 'username' -notepropertyvalue "admin"
    $restApiCredentialsObject | Add-Member -notepropertyname 'password' -notepropertyvalue $vcfRestApiPassword
    $secondUserCredentialsObject = New-Object -type psobject
    $secondUserCredentialsObject | Add-Member -notepropertyname 'username' -notepropertyvalue "vcf"
    $secondUserCredentialsObject | Add-Member -notepropertyname 'password' -notepropertyvalue $vcfSecondUserPassword
    $sddcManagerSpecObject = New-Object -type psobject
    $sddcManagerSpecObject | Add-Member -notepropertyname 'hostname' -notepropertyvalue $extractedSddcData.sddcManager.vmname
    $sddcManagerSpecObject | Add-Member -notepropertyname 'ipAddress' -notepropertyvalue $extractedSddcData.sddcManager.ip
    $sddcManagerSpecObject | Add-Member -notepropertyname 'netmask' -notepropertyvalue $extractedSddcData.mgmtDomainInfrastructure.netmask
    $sddcManagerSpecObject | Add-Member -notepropertyname 'localUserPassword' -notepropertyvalue $vcfLocalUserPassword
    $sddcManagerSpecObject | Add-Member -notepropertyname 'rootUserCredentials' $rootUserCredentialsObject
    $sddcManagerSpecObject | Add-Member -notepropertyname 'restApiCredentials' $restApiCredentialsObject
    $sddcManagerSpecObject | Add-Member -notepropertyname 'secondUserCredentials' $secondUserCredentialsObject
    $mgmtDomainObject | Add-Member -notepropertyname 'sddcManagerSpec' -notepropertyvalue $sddcManagerSpecObject

    #networkSpecs
    $vmotionIpObject = @()
    $vmotionIpObject += [pscustomobject]@{
        'startIpAddress' = (($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).networkDetails | Where-Object {$_.type -eq 'VMOTION'}).startIPAddress
        'endIpAddress'   = (($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).networkDetails | Where-Object {$_.type -eq 'VMOTION'}).endIPAddress
    }
    $vsanIpObject = @()
    $vsanIpObject += [pscustomobject]@{
        'startIpAddress' = (($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).networkDetails | Where-Object {$_.type -eq 'VSAN'}).startIPAddress
        'endIpAddress'   = (($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).networkDetails | Where-Object {$_.type -eq 'VSAN'}).endIPAddress
    }
    $networkSpecsObject = @()
    [IPAddress] $ip = (($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).networkDetails | Where-Object {$_.type -eq 'MANAGEMENT'}).subnet_mask
    $octets = $ip.IPAddressToString.Split('.')
    Foreach($octet in $octets) { while(0 -ne $octet) { $octet = ($octet -shl 1) -band [byte]::MaxValue; $managementNetworkCidr++; }}
    $managmentNetworkSubnet = ((($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).networkDetails | Where-Object {$_.type -eq 'MANAGEMENT'}).subnet + "/" + $managementNetworkCidr)
    $networkSpecsObject += [pscustomobject]@{
        'networkType'  = "MANAGEMENT"
        'subnet'       = $managmentNetworkSubnet
        'vlanId'       = (($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).networkDetails | Where-Object {$_.type -eq 'MANAGEMENT'}).vlanId -as [string]
        'mtu'          = (($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).networkDetails | Where-Object {$_.type -eq 'MANAGEMENT'}).mtu -as [string]
        'gateway'      = (($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).networkDetails | Where-Object {$_.type -eq 'MANAGEMENT'}).gateway
        'portGroupKey' = (($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).networkDetails | Where-Object {$_.type -eq 'MANAGEMENT'}).portGroupKey
    }
    [IPAddress] $ip = (($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).networkDetails | Where-Object {$_.type -eq 'VMOTION'}).subnet_mask
    $octets = $ip.IPAddressToString.Split('.')
    Foreach($octet in $octets) { while(0 -ne $octet) { $octet = ($octet -shl 1) -band [byte]::MaxValue; $vmotionNetworkCidr++; }}
    $vmotionNetworkSubnet = ((($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).networkDetails | Where-Object {$_.type -eq 'VMOTION'}).subnet + "/" + $vmotionNetworkCidr)
    $networkSpecsObject += [pscustomobject]@{
        'networkType'          = "VMOTION"
        'subnet'               = $vmotionNetworkSubnet
        'includeIpAddressRanges' = $vmotionIpObject
        'vlanId'               = (($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).networkDetails | Where-Object {$_.type -eq 'VMOTION'}).vlanId -as [string]
        'mtu'                  = (($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).networkDetails | Where-Object {$_.type -eq 'VMOTION'}).mtu -as [string]
        'gateway'              = (($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).networkDetails | Where-Object {$_.type -eq 'VMOTION'}).gateway
        'portGroupKey'         = (($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).networkDetails | Where-Object {$_.type -eq 'VMOTION'}).portGroupKey
    }
    [IPAddress] $ip = (($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).networkDetails | Where-Object {$_.type -eq 'VSAN'}).subnet_mask
    $octets = $ip.IPAddressToString.Split('.')
    Foreach($octet in $octets) { while(0 -ne $octet) { $octet = ($octet -shl 1) -band [byte]::MaxValue; $vsanNetworkCidr++; }}
    $vsanNetworkSubnet = ((($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).networkDetails | Where-Object {$_.type -eq 'VSAN'}).subnet + "/" + $vsanNetworkCidr)
    $networkSpecsObject += [pscustomobject]@{
        'networkType'          = "VSAN"
        'subnet'               = $vsanNetworkSubnet
        'includeIpAddressRanges' = $vsanIpObject
        'vlanId'               = (($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).networkDetails | Where-Object {$_.type -eq 'VSAN'}).vlanId -as [string]
        'mtu'                  = (($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).networkDetails | Where-Object {$_.type -eq 'VSAN'}).mtu -as [string]
        'gateway'              = (($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).networkDetails | Where-Object {$_.type -eq 'VSAN'}).gateway
        'portGroupKey'         = (($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).networkDetails | Where-Object {$_.type -eq 'VSAN'}).portGroupKey
    }
    $mgmtDomainObject | Add-Member -notepropertyname 'networkSpecs' -notepropertyvalue $networkSpecsObject

    #nsxtSpec
    $nsxtManagersObject = @()
    Foreach ($nsxManager in (($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).nsxNodeDetails))
    {
        $nsxtManagersObject += [pscustomobject]@{
            'hostname' = $nsxManager.vmName
            'ip' = $nsxManager.ip
        }
    }
    $overLayTransportZoneObject = New-Object -type psobject
    $overLayTransportZoneObject | Add-Member -notepropertyname 'zoneName' -notepropertyvalue "$(($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).domainName)-tz-overlay01" #Review
    $overLayTransportZoneObject | Add-Member -notepropertyname 'networkName' -notepropertyvalue "netName-overlay"
    $vlanTransportZoneObject = New-Object -type psobject
    $vlanTransportZoneObject | Add-Member -notepropertyname 'zoneName' -notepropertyvalue "$(($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).domainName)-tz-vlan01" #Review
    $vlanTransportZoneObject | Add-Member -notepropertyname 'networkName' -notepropertyvalue "netName-vlan"
    $nsxtSpecObject = New-Object -type psobject
    $nsxtSpecObject | Add-Member -notepropertyname 'nsxtManagerSize' -notepropertyvalue "medium" #Review
    $nsxtSpecObject | Add-Member -notepropertyname 'nsxtManagers' -notepropertyvalue $nsxtManagersObject
    $nsxtSpecObject | Add-Member -notepropertyname 'rootNsxtManagerPassword' -notepropertyvalue ($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).nsxClusterDetails.rootNsxtManagerPassword
    $nsxtSpecObject | Add-Member -notepropertyname 'nsxtAdminPassword' -notepropertyvalue ($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).nsxClusterDetails.nsxtAdminPassword
    $nsxtSpecObject | Add-Member -notepropertyname 'nsxtAuditPassword' -notepropertyvalue ($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).nsxClusterDetails.nsxtAuditPassword
    $nsxtSpecObject | Add-Member -notepropertyname 'rootLoginEnabledForNsxtManager' -notepropertyvalue "true" #Review
    $nsxtSpecObject | Add-Member -notepropertyname 'sshEnabledForNsxtManager' -notepropertyvalue "true" #Review
    $nsxtSpecObject | Add-Member -notepropertyname 'overLayTransportZone' -notepropertyvalue $overLayTransportZoneObject
    $nsxtSpecObject | Add-Member -notepropertyname 'vlanTransportZone' -notepropertyvalue $vlanTransportZoneObject
    $nsxtSpecObject | Add-Member -notepropertyname 'vip' -notepropertyvalue ($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).nsxClusterDetails.clusterVip
    $nsxtSpecObject | Add-Member -notepropertyname 'vipFqdn' -notepropertyvalue ($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).nsxClusterDetails.clusterFqdn
    $nsxtSpecObject | Add-Member -notepropertyname 'nsxtLicense' -notepropertyvalue ($extractedSddcData.licenseKeys | Where-Object {$_.productType -eq "NSXT"}).key
    $nsxtSpecObject | Add-Member -notepropertyname 'transportVlanId' -notepropertyvalue $transportVlanId
    $mgmtDomainObject | Add-Member -notepropertyname 'nsxtSpec' -notepropertyvalue $nsxtSpecObject

    #Derive Primary Cluster
    $primaryCluster = ($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).vsphereClusterDetails | Where-Object {$_.isDefault -eq 't'}
        
    #vsanSpec
    
    $vsanSpecObject = New-Object -type psobject
    $vsanSpecObject | Add-Member -notepropertyname 'vsanName' -notepropertyvalue "vsan-1"
    $vsanSpecObject | Add-Member -notepropertyname 'licenseFile' -notepropertyvalue ($extractedSddcData.licenseKeys | Where-Object {$_.productType -eq "VSAN"}).key
    $vsanSpecObject | Add-Member -notepropertyname 'vsanDedup' -notepropertyvalue $dedupEnabled
    $vsanSpecObject | Add-Member -notepropertyname 'datastoreName' -notepropertyvalue $primaryCluster.primaryDatastoreName
    $mgmtDomainObject | Add-Member -notepropertyname 'vsanSpec' -notepropertyvalue $vsanSpecObject

    #dvsSpecs
    $clusterVDSs = @()
    Foreach ($vds in ($primaryCluster.vdsDetails))
    {
        $clustervdsObject = New-Object -type psobject
        $clustervdsObject | Add-Member -notepropertyname 'mtu' -notepropertyvalue $vds.mtu
        $clustervdsObject | Add-Member -notepropertyname 'niocSpecs' -notepropertyvalue $vds.niocSpecs
        $clustervdsObject | Add-Member -notepropertyname 'dvsName' -notepropertyvalue $vds.dvsName
        $clustervdsObject | Add-Member -notepropertyname 'vmnics' -notepropertyvalue $vds0nics
        $clustervdsObject | Add-Member -notepropertyname 'networks' -notepropertyvalue $vds.networks
        $clusterVDSs += $clustervdsObject
    }
    $mgmtDomainObject | Add-Member -notepropertyname 'dvsSpecs' -notepropertyvalue $clusterVDSs

    #clusterSpec
    $vmFoldersObject = New-Object -type psobject
    $vmFoldersObject | Add-Member -notepropertyname 'MANAGEMENT' -notepropertyvalue (($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).domainName + "-fd-mgmt")
    $vmFoldersObject | Add-Member -notepropertyname 'NETWORKING' -notepropertyvalue (($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).domainName + "-fd-nsx")
    $vmFoldersObject | Add-Member -notepropertyname 'EDGENODES' -notepropertyvalue (($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).domainName + "-fd-edge")
    $clusterSpecObject = New-Object -type psobject
    $clusterSpecObject | Add-Member -notepropertyname 'vmFolders' -notepropertyvalue $vmFoldersObject
    $clusterSpecObject | Add-Member -notepropertyname 'clusterName' -notepropertyvalue $primaryCluster.name
    $clusterSpecObject | Add-Member -notepropertyname 'clusterEvcMode' -notepropertyvalue ""
    $mgmtDomainObject | Add-Member -notepropertyname 'clusterSpec' -notepropertyvalue $clusterSpecObject

    #pscSpecs
    $pscSpecs = @()
    $ssoDomain = ($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).ssoDomain
    $psoSsoSpecObject =  New-Object -type psobject
    $psoSsoSpecObject | Add-Member -notepropertyname 'ssoDomain' -notepropertyvalue $ssoDomain
    $pscSpecs += [PSCustomObject]@{
        'pscSsoSpec' = $psoSsoSpecObject
        'adminUserSsoPassword' = ($extractedSddcData.passwords | Where-Object {($_.credentialType -eq "SSO") -and ($_.username -like "*$ssoDomain") -and ($_.entityType -eq "PSC")}).password
    }
    $mgmtDomainObject | Add-Member -notepropertyname 'pscSpecs' -notepropertyvalue $pscSpecs

    #vcenterSpec
    $vcenterSpecObject = New-Object -type psobject
    $vcenterSpecObject | Add-Member -notepropertyname 'vcenterIp' -notepropertyvalue $tempVcenterIp
    $vcenterSpecObject | Add-Member -notepropertyname 'vcenterHostname' -notepropertyvalue $tempVcenterHostname
    $vcenterSpecObject | Add-Member -notepropertyname 'licenseFile' -notepropertyvalue ($extractedSddcData.licenseKeys | Where-Object {$_.productType -eq "VCENTER"}).key
    $vcenterSpecObject | Add-Member -notepropertyname 'rootVcenterPassword' -notepropertyvalue ($extractedSddcData.passwords | Where-Object {($_.domainName -eq $domainName) -and ($_.entityType -eq "VCENTER") -and ($_.username -eq "root")}).password
    $vcenterSpecObject | Add-Member -notepropertyname 'vmSize' -notepropertyvalue $vcenterServerSize
    $mgmtDomainObject | Add-Member -notepropertyname 'vcenterSpec' -notepropertyvalue $vcenterSpecObject

    #hostSpecs
    $mgmtHosts = $extractedSddcData.passwords | where-object {($_.domainName -eq $domainName) -and ($_.entityType -eq "ESXI") -and ($_.username -eq "root")}
    $hostSpecs =@()
    Foreach ($mgmtHost in $mgmtHosts)
    {
        $credentialObject = New-Object -type psobject
        $credentialObject | Add-Member -notepropertyname 'username' -notepropertyvalue $mgmtHost.username
        $credentialObject | Add-Member -notepropertyname 'password' -notepropertyvalue $mgmtHost.password
        $ipAddressPrivateObject = New-Object -type psobject
        $ipAddressPrivateObject | Add-Member -notepropertyname 'subnet' -notepropertyvalue (($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).networkDetails | Where-Object {$_.type -eq "MANAGEMENT"}).subnet_mask
        $ipAddressPrivateObject | Add-Member -notepropertyname 'ipAddress' -notepropertyvalue $mgmtHost.entityIpAddress
        $ipAddressPrivateObject | Add-Member -notepropertyname 'gateway' -notepropertyvalue (($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).networkDetails | Where-Object {$_.type -eq "MANAGEMENT"}).gateway
        $hostSpecs += [PSCustomObject]@{
            'hostname' = $mgmtHost.entityName.split(".")[0]
            'vSwitch' = "vSwitch0"
            'association' = $extractedSddcData.mgmtDomainInfrastructure.datacenter
            'credentials' = $credentialObject
            'ipAddressPrivate' = $ipAddressPrivateObject
        }
    }
    $mgmtDomainObject | Add-Member -notepropertyname 'hostSpecs' -notepropertyvalue $hostSpecs

    $licenseMode = ($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).licenseModel
    If ($licenseMode -eq "PERPETUAL") {$subscriptionLicensing = "False" } else {$subscriptionLicensing = "True"}
    $mgmtDomainObject | Add-Member -notepropertyname 'subscriptionLicensing' -notepropertyvalue $subscriptionLicensing
    
    Write-Host "[$jumpboxName] Saving partial bringup JSON spec: $(($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).domainName + "-partial-bringup-spec.json")"
    $mgmtDomainObject | ConvertTo-Json -depth 10 | Out-File (($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).domainName + "-partial-bringup-spec.json")
}
Export-ModuleMember -Function New-ReconstructedPartialBringupJsonSpec

#EndRegion Data Gathering

#Region SDDC Manager Functions
Function Invoke-SDDCManagerRestore
{
    Param(
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $true)][String] $backupFilePath,
        [Parameter (Mandatory = $true)][String] $vcfUserPassword,
        [Parameter (Mandatory = $true)][String] $localUserPassword,
        [Parameter (Mandatory = $true)][String] $rootUserPassword
    )
    $jumpboxName = hostname
    Write-Host "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $backupFileFullPath = (Resolve-Path -Path $backupFilePath).path
    $backupFileName = (Get-ChildItem -path $backupFileFullPath).name

    #Establish Session to SDDC Manager and Start SSH Stream
    $extractedSddcManagerFqdn = $extractedSddcData.sddcManager.fqdn
    
    Write-Host "[$jumpboxName] Establishing Connection to $extractedSddcManagerFqdn"
    $SecurePassword = ConvertTo-SecureString -String $vcfUserPassword -AsPlainText -Force
    $mycreds = New-Object System.Management.Automation.PSCredential ('vcf', $SecurePassword)
    $inmem = New-SSHMemoryKnownHost
    New-SSHTrustedHost -KnownHostStore $inmem -HostName $extractedSddcManagerFqdn -FingerPrint ((Get-SSHHostKey -ComputerName $extractedSddcManagerFqdn).fingerprint) | Out-Null
    Do
    {
        $sshSession = New-SSHSession -computername $extractedSddcManagerFqdn -Credential $mycreds -KnownHost $inmem
    } Until ($sshSession)

    #Upload Modified Restore Status Json
    Write-Host "[$extractedSddcManagerFqdn] Configuring Restore Process"
    $modulePath = (Get-InstalledModule -Name VCFInstanceRecovery).InstalledLocation
    If ($extractedSddcData.sddcManager.version.replace(".","").substring(0,3) -gt "451")
    {
        $sourceFile = "$modulePath\reference-files\new_restore_status.json"
    }
    else 
    {
        $sourceFile = "$modulePath\reference-files\old_restore_status.json"
    }

    $stream = New-SSHShellStream -SSHSession $sshSession
    $stream.writeline("su -")
    Start-Sleep 2
    $stream.writeline("$rootUserPassword")
    Start-Sleep 2
    $stream.writeline("cp /opt/vmware/sddc-support/backup/restore_status.json /opt/vmware/sddc-support/backup/restore_status.json.bak")
    Start-Sleep 2
    $uploadFile = Set-SCPItem -ComputerName $extractedSddcManagerFqdn -Credential $mycreds -path $sourceFile -destination "/tmp" -KnownHost $inmem
    $stream.writeline("cp /tmp/new_restore_status.json /opt/vmware/sddc-support/backup/restore_status.json")
    Start-Sleep 2
    $stream.writeline("chmod 640 /opt/vmware/sddc-support/backup/restore_status.json")
    Start-Sleep 2
   
    #Execute Restore
    Write-Host "[$extractedSddcManagerFqdn] Performing Restore"
    $scriptText = "curl https://$extractedSddcManagerFqdn/v1/tokens -k -X POST -H `"Content-Type: application/json`" -d `'{`"username`": `"admin@local`",`"password`": `"$localUserPassword`"}`' | awk -F `"\`"`" `'{ print `$4}`'"
    $token = (Invoke-SSHCommand -timeout 30 -sessionid $sshSession.SessionId -command $scriptText).output
    If ($token)
    {
        #Check Status of Services
        $scriptText = "curl https://$extractedSddcManagerFqdn/v1/vcf-services  -k -X GET -H `"Content-Type: application/json`" -H `"Authorization: Bearer $token`" | json_pp"
        Write-Host "[$extractedSddcManagerFqdn] Waiting for Operations Manager Service to be Up"
        $Counter = 0
        Do
        {
            $SddcManagerServiceStatus = (Invoke-SSHCommand -timeout 30 -sessionid $sshSession.SessionId -command $scriptText).output
            $operationsManagerServiceStatus = (($SddcManagerServiceStatus | ConvertFrom-Json).elements | Where-Object {$_.name -eq "OPERATIONS_MANAGER"}).status
            If ($operationsManagerServiceStatus -ne "UP") {$counter ++; Write-Host "operationsManagerServiceStatus status is $operationsManagerServiceStatus. Wait $counter"; Sleep 10;}
        } Until ($operationsManagerServiceStatus -eq "UP")
        $scriptText = "curl https://$extractedSddcManagerFqdn/v1/restores/tasks -k -X POST -H `"Content-Type: application/json`" -H `"Authorization: Bearer $token`" -d `'{`"elements`" : [ {`"resourceType`" : `"SDDC_MANAGER`"} ],`"backupFile`" : `"/tmp/$backupFileName`",`"encryption`" : {`"passphrase`" : `"$localUserPassword`"}}`' | json_pp | jq `'.id`' | cut -d `'`"`' -f 2"
        Do
        {
            Sleep 10
            $restoreID = (Invoke-SSHCommand -timeout 30 -sessionid $sshSession.SessionId -command $scriptText).output
        } Until ($restoreId)
        If ($restoreID)
        {
            $scriptText = "curl https://$extractedSddcManagerFqdn/v1/restores/tasks/$restoreID -k -X GET -H `"Content-Type: application/json`" -H `"Authorization: Bearer $token`" | json_pp"
            Write-Host "[$extractedSddcManagerFqdn] Monitoring Restore Task $restoreID progress (polling every 60 seconds)"
            Do
            {
                Sleep 60
                $restoreProgress = ((Invoke-SSHCommand -timeout 30 -sessionid $sshSession.SessionId -command $scriptText).output | ConvertFrom-JSON).status
                Write-Host "[$extractedSddcManagerFqdn] Restore Status: $restoreProgress"
            } While ($restoreProgress -in "IN PROGRESS")    
        }
        else 
        {
            Write-Host "[$extractedSddcManagerFqdn] Restore Task ID not returned"
        }
    }
    else 
    {
        Write-Host "[$extractedSddcManagerFqdn] Failed to get SDDC Manager Token"
    }

    #Close SSH Session
    Remove-SSHSession -SSHSession $sshSession | Out-Null
}
Export-ModuleMember -Function Invoke-SDDCManagerRestore
#EndRegion SDDC Manager Functions

#Region vCenter Functions

Function Move-ClusterHostsToRestoredVcenter
{
    <#
    .SYNOPSIS
    Moves ESXi Hosts from a temporary vCenter / cluster to the restored vCenter / cluster. Used for VCF Management Domain cluster recovery.

    .DESCRIPTION
    The Move-ClusterHostsToRestoredVcenter cmdlet moves ESXi Hosts from a temporary vCenter / cluster to the restored vCenter / cluster. Used for VCF Management Domain cluster recovery.

    .EXAMPLE
    Move-ClusterHostsToRestoredVcenter -tempvCenterFqdn "sfo-m01-vc02.sfo.rainpole.io" -tempvCenterAdmin "administrator@vsphere.local" -tempvCenterAdminPassword "VMw@re1!" -restoredvCenterFQDN "sfo-m01-vc01.sfo.rainpole.io" -restoredvCenterAdmin "administrator@vsphere.local" -restoredvCenterAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01" -extractedSDDCDataFile ".\extracted-sddc-data.json"

    .PARAMETER tempvCenterFqdn
    FQDN of the temporary vCenter instance

    .PARAMETER tempvCenterAdmin
    Admin user of the temporary vCenter instance
    
    .PARAMETER tempvCenterAdminPassword
    Admin password for the temporary vCenter instance

    .PARAMETER restoredvCenterFQDN
    FQDN of the restored vCenter instance

    .PARAMETER restoredvCenterAdmin
    Admin user of the restored vCenter instance
    
    .PARAMETER restoredvCenterAdminPassword
    Admin password for the restored vCenter instance

    .PARAMETER clusterName
    Name of the restored vSphere cluster instance in the temporary vCenter

    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem
    #>
    
    Param(
        [Parameter (Mandatory = $true)][String] $tempvCenterFqdn,
        [Parameter (Mandatory = $true)][String] $tempvCenterAdmin,
        [Parameter (Mandatory = $true)][String] $tempvCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $restoredvCenterFQDN,
        [Parameter (Mandatory = $true)][String] $restoredvCenterAdmin,
        [Parameter (Mandatory = $true)][String] $restoredvCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile
    )
    $jumpboxName = hostname
    Write-Host "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON
    
    $tempvCenterConnection = connect-viserver $tempvCenterFqdn -user $tempvCenterAdmin -password $tempvCenterAdminPassword
    $esxiHosts = get-cluster -name $clusterName | get-vmhost
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
    $restoredvCenterConnection = connect-viserver $restoredvCenterFQDN -user $restoredvCenterAdmin -password $restoredvCenterAdminPassword
    Foreach ($esxiHost in $esxiHosts) {
        Write-Host "[$($esxiHost.name)] Moving to $restoredvCenterFQDN"
        $esxiRootPassword = ($extractedSddcData.passwords | Where-Object {($_.entityType -eq "ESXI") -and ($_.entityName -eq $esxiHost.Name) -and ($_.username -eq "root")}).password
        Add-VMHost -Name $esxiHost.Name -Location $clusterName -User root -Password $esxiRootPassword -Force -Confirm:$false | Out-Null
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
        Write-Host "[$($esxiHost.name)] Removing from $vdsName"
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
        Write-Host "[$($vmToMove.name)] Moving to mgmt_temp"
        Get-VM -Name $vmToMove | Get-NetworkAdapter | Set-NetworkAdapter -NetworkName "mgmt_temp" -confirm:$false | Out-Null
    }
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
}
Export-ModuleMember -Function Move-MgmtVmsToTempPg

Function Move-ClusterHostNetworkingTovSS 
{
    <#
    .SYNOPSIS
    Moves all hosts in a cluster from a vsphere Distributed switch to a vSphere Standard switch

    .DESCRIPTION
    The Move-ClusterHostNetworkingTovSS cmdlet moves all hosts in a cluster from a vsphere Distributed switch to a vSphere Standard switch

    .EXAMPLE
    Move-ClusterHostNetworkingTovSS -vCenterFQDN "sfo-m01-vc02.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01" -vdsName "sfo-m01-cl01-vds01" -mtu 9000 -vmnic "vmnic1" -mgmtVlanId 1611 -vMotionVlanId 1612 -vSanVlanId 1613

    .PARAMETER vCenterFQDN
    FQDN of the vCenter instance hosting the cluster which should be moved

    .PARAMETER vCenterAdmin
    Admin user of the vCenter instance hosting the cluster which should be moved
    
    .PARAMETER vCenterAdminPassword
    Admin password for the vCenter instance hosting the cluster which should be moved

    .PARAMETER clusterName
    Name of the vSphere cluster instance hosting the VMS to be moved

    .PARAMETER vdsName
    Name of the vDS from which the hosts should be moved

    .PARAMETER mtu
    MTU to be assigned to the temporary standard switch
    
    .PARAMETER vmnic
    vmnic to be moved from the vDS to the vSS

    .PARAMETER mgmtVlanId
    Management network vLan ID

    .PARAMETER vMotionVlanId
    vMotion network vLan ID

    .PARAMETER vSanVlanId
    vSAN network vLan ID
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
    Moves VMs to the temporary vSS

    .DESCRIPTION
    The Move-ClusterVmnicTovSwitch cmdlet moves VMs to the temporary vSS

    .EXAMPLE
    Move-ClusterVmnicTovSwitch -vCenterFQDN "sfo-m01-vc02.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01" -mtu 9000 -VLanId 1611 -vmnic "vmnic1" 

    .PARAMETER vCenterFQDN
    FQDN of the vCenter instance hosting the VMs to be moved

    .PARAMETER vCenterAdmin
    Admin user of the vCenter instance hosting the VMs to be moved
    
    .PARAMETER vCenterAdminPassword
    Admin password for the vCenter instance hosting the VMs to be moved

    .PARAMETER clusterName
    Name of the vSphere cluster instance hosting the VMS to be moved

    .PARAMETER mtu
    MTU to be assigned to the temporary standard switch

    .PARAMETER VLanId
    Management network vLan ID
        
    .PARAMETER vmnic
    vmnic to be used for the vSS

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
    Toggles the vSAN Ignore Cluster Member List Updates setting on a vSAN cluster ESXi host

    .DESCRIPTION
    The Set-ClusterHostsvSanIgnoreClusterMemberList cmdlet toggles the vSAN Ignore Cluster Member List Updates setting on a vSAN cluster ESXi host

    .EXAMPLE
    Set-ClusterHostsvSanIgnoreClusterMemberList -vCenterFQDN "sfo-m01-vc02.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01"  -extractedSDDCDataFile ".\extracted-sddc-data.json" -setting "enable"

    .PARAMETER vCenterFQDN
    FQDN of the vCenter instance hosting the ESXi hosts to be updated

    .PARAMETER vCenterAdmin
    Admin user of the vCenter instance hosting the ESXi hosts to be updated
    
    .PARAMETER vCenterAdminPassword
    Admin password for the vCenter instance hosting the ESXi hosts to be updated

    .PARAMETER clusterName
    Name of the vSphere cluster instance hosting the ESXi hosts to be updated

    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem

    .PARAMETER setting
    The setting to apply to the hosts - either enable or disable
    #>
    
    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $true)][ValidateSet("enable", "disable")][String] $setting
    )
    $jumpboxName = hostname
    Write-Host "[$jumpboxName] Reading Extracted Data"
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
        Write-Host "[$esxiHost] Setting vSAN Ignore Cluster Member to `'$setting`'"
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
    Moves all VMs in a cluster to a single ESXi host

    .DESCRIPTION
    The Move-ClusterVMsToFirstHost cmdlet moves all VMs in a cluster to a single ESXi host

    .EXAMPLE
    Move-ClusterVMsToFirstHost -vCenterFQDN "sfo-m01-vc02.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01"

    .PARAMETER vCenterFQDN
    FQDN of the vCenter instance hosting the VMs to be moved

    .PARAMETER vCenterAdmin
    Admin user of the vCenter instance hosting the VMs to be moved
    
    .PARAMETER vCenterAdminPassword
    Admin password for the vCenter instance hosting the VMs to be moved

    .PARAMETER clusterName
    Name of the vSphere cluster instance hosting the VMs to be moved
    #>
    
    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName
        
    )
    $vCenterConnection = connect-viserver $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    $vms = Get-Cluster -Name $clusterName | Get-VM | Where-Object { $_.Name -notlike "vCLS*" } | Select-Object Name, VMhost
    $firstHost = ((Get-cluster -name $clusterName | Get-VMHost | Sort-Object -property Name)[0]).Name
    Foreach ($vm in $vms) {
        if ($vm.vmHost.Name -ne $firstHost) {
            Get-VM -Name $vm.name | Move-VM -Location $firstHost -Runasync | Out-Null
            Write-Host "[$($vm.name)] Moving to $firstHost"
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
    Creates a new VCF Service Account on each ESXi host and remediates the SDDC Manager inventory

    .DESCRIPTION
    The Resolve-PhysicalHostServiceAccounts cmdlet creates a new VCF Service Account on each ESXi host and remediates the SDDC Manager inventory

    .EXAMPLE
    Resolve-PhysicalHostServiceAccounts -vCenterFQDN "sfo-w01-vc01.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -clusterName "sfo-w01-cl01" -svcAccountPassword "VMw@re123!" -sddcManagerFQDN "sfo-vcf01.sfo.rainpole.io" -sddcManagerAdmin "administrator@vsphere.local" -sddcManagerAdminPassword "VMw@re1!"

    .PARAMETER vCenterFQDN
    FQDN of the vCenter instance hosting the ESXi hosts to be updated

    .PARAMETER vCenterAdmin
    Admin user of the vCenter instance hosting the ESXi hosts to be updated
    
    .PARAMETER vCenterAdminPassword
    Admin password for the vCenter instance hosting the ESXi hosts to be updated

    .PARAMETER clusterName
    Name of the vSphere cluster instance hosting the ESXi hosts to be updated

    .PARAMETER svcAccountPassword
    Service account password to be used

    .PARAMETER sddcManagerFQDN
    FQDN of SDDC Manager

    .PARAMETER sddcManagerAdmin
    SDDC Manager API username with ADMIN role

    .PARAMETER sddcManagerAdminPassword
    SDDC Manager API username password
    #>
    
    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $svcAccountPassword,
        [Parameter (Mandatory = $true)][String] $sddcManagerFQDN,
        [Parameter (Mandatory = $true)][String] $sddcManagerAdmin,
        [Parameter (Mandatory = $true)][String] $sddcManagerAdminPassword
    )
    $vCenterConnection = Connect-VIServer -server $vCenterFQDN -username $vCenterAdmin -password $vCenterAdminPassword
    $clusterHosts = Get-Cluster -name $clusterName | Get-VMHost
    Disconnect-VIServer * -confirm:$false
    $tokenRequest = Request-VCFToken -fqdn $sddcManagerFQDN -username $sddcManagerAdmin -password $sddcManagerAdminPassword
    #verify SDDC Manager credential API state
    $credentialAPILastTask = ((Get-VCFCredentialTask -errorAction silentlyContinue| Sort-Object -Property creationTimeStamp)[-1]).status
    if ($credentialAPILastTask -eq "FAILED")
    {
        Write-Host "[$sddcManagerFQDN] Failed credential operation detected. Please resolve in SDDC Manager and try again" ; break
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
        Write-Host "$taskStatus"
    }
}
Export-ModuleMember -Function Resolve-PhysicalHostServiceAccounts

Function Set-ClusterDRSLevel 
{
    <#
    .SYNOPSIS
    Modifies the DRS level of a vSphere cluster

    .DESCRIPTION
    The Set-ClusterDRSLevel cmdlet modifies the DRS level of a vSphere cluster

    .EXAMPLE
    Set-ClusterDRSLevel -vCenterFQDN "sfo-m01-vc01.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01" -DrsAutomationLevel "Manual"

    .PARAMETER vCenterFQDN
    FQDN of the vCenter instance hosting the cluster to be updated

    .PARAMETER vCenterAdmin
    Admin user of the vCenter instance hosting the cluster to be updated
    
    .PARAMETER vCenterAdminPassword
    Admin password for the vCenter instance hosting the cluster to be updated

    .PARAMETER clusterName
    Name of the vSphere cluster instance to be updated

    .PARAMETER DrsAutomationLevel
    DrsAutomationLevel to be set. One of: FullyAutomated or Manual
    #>
    
    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][ValidateSet("FullyAutomated", "Manual")][String] $DrsAutomationLevel
        
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
    Removes non-responsive hosts from a cluster

    .DESCRIPTION
    The Remove-NonResponsiveHosts cmdlet removes non-responsive hosts from a cluster

    .EXAMPLE
    Remove-NonResponsiveHosts -vCenterFQDN "sfo-m01-vc01.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01"

    .PARAMETER vCenterFQDN
    FQDN of the vCenter instance hosting the cluster from which to remove non-responsive hosts

    .PARAMETER vCenterAdmin
    Admin user of the vCenter instance hosting the cluster from which to remove non-responsive hosts
    
    .PARAMETER vCenterAdminPassword
    Admin password for the vCenter instance hosting the cluster from which to remove non-responsive hosts

    .PARAMETER clusterName
    Name of the vSphere cluster instance from which to remove non-responsive hosts
    #>
    
    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName
        
    )
    $vCenterConnection = connect-viserver $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    $nonResponsiveHosts = get-cluster -name $clusterName | get-vmhost | Where-Object { $_.ConnectionState -in "NotResponding","Disconnected" }
    foreach ($nonResponsiveHost in $nonResponsiveHosts) {
        Write-Host "[$($nonResponsiveHost.name)] Removing from $clusterName"
        Get-VMHost | Where-Object { $_.Name -eq $nonResponsiveHost.Name } | Remove-VMHost -Confirm:$false
    }
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
}
Export-ModuleMember -Function Remove-NonResponsiveHosts

Function Add-HostsToCluster 
{
    <#
    .SYNOPSIS
    Adds hosts to a vSphere cluster using data from the SDDC Manager backup

    .DESCRIPTION
    The Add-HostsToCluster cmdlet Adds hosts to a vSphere cluster using data from the SDDC Manager backup

    .EXAMPLE
    Add-HostsToCluster -vCenterFQDN "sfo-m01-vc02.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01"  -extractedSDDCDataFile ".\extracted-sddc-data.json" -sddcManagerFQDN "sfo-vcf01.sfo.rainpole.io" -sddcManagerAdmin "administrator@vsphere.local" -sddcManagerAdminPassword "VMw@re1!"

    .PARAMETER vCenterFQDN
    FQDN of the vCenter instance hosting the cluster to which the hosts will be added

    .PARAMETER vCenterAdmin
    Admin user of the vCenter instance hosting the cluster to which the hosts will be added
    
    .PARAMETER vCenterAdminPassword
    Admin password for the vCenter instance hosting the cluster to which the hosts will be added

    .PARAMETER clusterName
    Name of the vSphere cluster instance to which the hosts will be added

    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem

    .PARAMETER sddcManagerFQDN
    FQDN of SDDC Manager

    .PARAMETER sddcManagerAdmin
    SDDC Manager API username with ADMIN role

    .PARAMETER sddcManagerAdminPassword
    SDDC Manager API username password
    #>
    
    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $true)][String] $sddcManagerFQDN,
        [Parameter (Mandatory = $true)][String] $sddcManagerAdmin,
        [Parameter (Mandatory = $true)][String] $sddcManagerAdminPassword
    )
    $jumpboxName = hostname
    Write-Host "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $tokenRequest = Request-VCFToken -fqdn $sddcManagerFQDN -username $sddcManagerAdmin -password $sddcManagerAdminPassword
    $newHosts = (get-vcfhost | where-object { $_.id -in ((get-vcfcluster -name $clusterName).hosts.id) }).fqdn
    $vCenterConnection = connect-viserver $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    foreach ($newHost in $newHosts) {
        $vmHosts = (Get-cluster -name $clusterName | Get-VMHost).Name
        if ($newHost -notin $vmHosts) {
            $esxiRootPassword = ($extractedSddcData.passwords | Where-Object {($_.entityType -eq "ESXI") -and ($_.entityName -eq $newHost) -and ($_.username -eq "root")}).password
            $esxiConnection = connect-viserver $newHost -user root -password $esxiRootPassword
            if ($esxiConnection) {
                Write-Host "[$newHost] Adding to cluster $clusterName"
                Add-VMHost $newHost -username root -password $esxiRootPassword -Location $clusterName -Force -Confirm:$false | Out-Null
            }
            else {
                Write-Error "[$newHost] Unable to connect. Host will not be added to the cluster"
            }
        }
        else {
            Write-Host "[$newHost] Already part of $clusterName. Skipping"
        }
    }
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
}
Export-ModuleMember -Function Add-HostsToCluster

Function Remove-StandardSwitch 
{
    <#
    .SYNOPSIS
    Removes a temporary standard switch from all hosts in a cluster

    .DESCRIPTION
    The Remove-StandardSwitch cmdlet removes a temporary standard switch from all hosts in a cluster

    .EXAMPLE
    Remove-StandardSwitch -vCenterFQDN "sfo-m01-vc01.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01"

    .PARAMETER vCenterFQDN
    FQDN of the vCenter instance hosting the ESXi hosts from which the standard switch will be removed

    .PARAMETER vCenterAdmin
    Admin user of the vCenter instance hosting the ESXi hosts from which the standard switch will be removed
    
    .PARAMETER vCenterAdminPassword
    Admin password for the vCenter instance hosting the ESXi hosts from which the standard switch will be removed

    .PARAMETER clusterName
    Name of the vSphere cluster instance hosting the ESXi hosts from which the standard switch will be removed
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
        Write-Host "[$vmhost] Removing standard vSwitch" 
        Get-VMHost -Name $vmhost | Get-VirtualSwitch -Name "vSwitch0" | Remove-VirtualSwitch -Confirm:$false | Out-Null
    }
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
}
Export-ModuleMember -Function Remove-StandardSwitch

Function Add-VMKernelsToHost 
{
    <#
    .SYNOPSIS
    Adds VMkernels to ESXi hosts using data from the SDDC Manager inventory to map the correct IP addresses

    .DESCRIPTION
    The Add-VMKernelsToHost cmdlet adds VMkernels to ESXi hosts using data from the SDDC Manager inventory to map the correct IP addresses

    .EXAMPLE
    Add-VMKernelsToHost -vCenterFQDN "sfo-m01-vc01.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01" -sddcManagerFQDN "sfo-vcf01.sfo.rainpole.io" -sddcManagerAdmin "administrator@vsphere.local" -sddcManagerAdminPassword "VMw@re1!"

    .PARAMETER vCenterFQDN
    FQDN of the vCenter instance hosting the ESXi hosts to which VMkernels will be added

    .PARAMETER vCenterAdmin
    Admin user of the vCenter instance hosting the ESXi hosts to which VMkernels will be added
    
    .PARAMETER vCenterAdminPassword
    Admin password for the vCenter instance hosting the ESXi hosts to which VMkernels will be added

    .PARAMETER clusterName
    Name of the vSphere cluster instance hosting the ESXi hosts to which VMkernels will be added

    .PARAMETER sddcManagerFQDN
    FQDN of SDDC Manager

    .PARAMETER sddcManagerAdmin
    SDDC Manager API username with ADMIN role

    .PARAMETER sddcManagerAdminPassword
    SDDC Manager API username password
    #>
    
    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $sddcManagerFQDN,
        [Parameter (Mandatory = $true)][String] $sddcManagerAdmin,
        [Parameter (Mandatory = $true)][String] $sddcManagerAdminPassword
    )
    $tokenRequest = Request-VCFToken -fqdn $sddcManagerFQDN -username $sddcManagerAdmin -password $sddcManagerAdminPassword
    
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

        Write-Host "[$vmhost] Creating vMotion vMK"
        $dvportgroup = Get-VDPortgroup -name $vmotionPG -VDSwitch $vmotionVDSName
        $vmk = New-VMHostNetworkAdapter -VMHost $vmhost -VirtualSwitch $vmotionVDSName -mtu $vmotionMTU -PortGroup $dvportgroup -ip $vmotionIP -SubnetMask $vmotionMask -NetworkStack (Get-VMHostNetworkStack -vmhost $vmhost | Where-Object { $_.id -eq "vmotion" })
        Write-Host "[$vmhost] Setting vMotion Gateway"
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

        Write-Host "[$vmhost] Creating vSAN vMK"
        $dvportgroup = Get-VDPortgroup -name $vsanPG -VDSwitch $vsanVDSName
        $vmk = New-VMHostNetworkAdapter -VMHost $vmhost -VirtualSwitch $vsanVDSName -mtu $vsanMTU -PortGroup $dvportgroup -ip $vsanIP -SubnetMask $vsanMask -VsanTrafficEnabled:$true

        Write-Host "[$vmhost] Setting vSAN Gateway"
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
    Backs up the VM Overrides for the specified cluster

    .DESCRIPTION
    The Backup-ClusterVMOverrides cmdlet backs up the VM Overrides for the specified cluster

    .EXAMPLE
    Backup-ClusterVMOverrides -clusterName "sfo-m01-cl01"

    .PARAMETER clusterName
    Cluster whose VM Overrides you wish to backup
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
    Backs up the VM Locations for the specified cluster

    .DESCRIPTION
    The Backup-ClusterVMLocations cmdlet backs up the VM Locations for the specified cluster

    .EXAMPLE
    Backup-ClusterVMLocations -clusterName "sfo-m01-cl01"

    .PARAMETER clusterName
    Cluster whose VM Locations you wish to backup
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
    Backs up the DRS Groups and Rules for the specified cluster

    .DESCRIPTION
    The Backup-ClusterDRSGroupsAndRules cmdlet backs up the DRS Groups and Rules for the specified cluster

    .EXAMPLE
    Backup-ClusterDRSGroupsAndRules -clusterName "sfo-m01-cl01"

    .PARAMETER clusterName
    Cluster whose DRS Groups and Rules you wish to backup
    #>
 
    Param(
        [Parameter(Mandatory = $true)]
        [String]$clusterName
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
    Restores the VM Overrides for the specified cluster

    .DESCRIPTION
    The Restore-ClusterVMOverrides cmdlet restores the VM Overrides for the specified cluster

    .EXAMPLE
    Restore-ClusterVMOverrides -clusterName "sfo-m01-cl01" -jsonFile ".\sfo-m01-cl01-vmOverrides.json"

    .PARAMETER clusterName
    Cluster whose VM Overrides you wish to restore

    .PARAMETER jsonFile
    Path to the JSON File that contains the backup for the VM Overrides for the Cluster
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
                    Write-Host "[$($vmOverRideInstance.name)] Restoring VM Overide Settings"
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
    Restores the VM Locations for the specified cluster

    .DESCRIPTION
    The Restore-ClusterVMLocations cmdlet restores the VM Locations for the specified cluster

    .EXAMPLE
    Restore-ClusterVMLocations -clusterName "sfo-m01-cl01" -jsonFile ".\sfo-m01-cl01-vmLocations.json"

    .PARAMETER clusterName
    Cluster whose VM Locations you wish to restore

    .PARAMETER jsonFile
    Path to the JSON File that contains the backup for the VM Locations for the Cluster
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
                            Write-Host "[$($vmLocation.name)] Setting VM Folder Location to $($vmLocation.folder)"
                            Move-VM -VM $vm -InventoryLocation $vmLocation.folder -confirm:$false
                        }
                        If ($vm.resourcePool -ne $vmLocation.resourcePool) {
                            Write-Host "[$($vmLocation.name)] Setting ResourcePool to $($vmLocation.resourcePool)"
                            Move-VM -VM $vm -Destination $vmLocation.resourcePool -confirm:$false
                        }
                    } 
                    else {
                        Write-Error "[$(Get-VM -name $vmLocation.name)] Not found. Check that it has been restored"
                    }
                }
            }
        }
        else {
            $jumpboxName = hostname
            Write-Error "[$jumpboxName] $jsonfile not found"
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
    Restores the DRS Groups and Rules for the specified cluster

    .DESCRIPTION
    The Restore-ClusterDRSGroupsAndRules cmdlet restores the DRS Groups and Rules for the specified cluster

    .EXAMPLE
    Restore-ClusterDRSGroupsAndRules -clusterName "sfo-m01-cl01" -jsonFile ".\sfo-m01-cl01-drsConfiguration.json"

    .PARAMETER clusterName
    Cluster whose DRS Groups and Rules you wish to restore

    .PARAMETER jsonFile
    Path to the JSON File that contains the backup for the DRS Groups and Rules for the Cluster
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
                            Write-Host "[$member] Adding to VMHostGroup $($vmDrsGroup.name)"
                            Set-DrsClusterGroup -DrsClusterGroup $vmDrsGroup.name -Add -VMHost $member -confirm:$false | Out-Null    
                        }
                    }
                    elseif ($vmDrsGroup.type -eq "VMGroup") {
                        Foreach ($member in $vmDrsGroup.members) {
                            Write-Host "[$member] Adding to VMGroup $($vmDrsGroup.name)"
                            Set-DrsClusterGroup -DrsClusterGroup $vmDrsGroup.name -Add -VM $member -confirm:$false | Out-Null    
                        }
                    }
                }
                else {
                    If ($vmDrsGroup.type -eq "VMHostGroup") {
                        Write-Host "[$($vmDrsGroup.name)] Creating VMHostGroup with Members $($vmDrsGroup.members)"
                        New-DrsClusterGroup -Name $vmDrsGroup.name -VMHost $vmDrsGroup.members -Cluster $clusterName | Out-Null
                    }
                    elseif ($vmDrsGroup.type -eq "VMGroup") {
                        Write-Host "[$($vmDrsGroup.name)] Creating VMGroup with Members $($vmDrsGroup.members)"
                        New-DrsClusterGroup -Name $vmDrsGroup.name -VM $vmDrsGroup.members -Cluster $clusterName | Out-Null
                    }
                }
            }
            Foreach ($vmAffinityRule in $drsRulesAndGroups.vmAffinityRules) {
                If ($vmAffinityRule.members.count -gt 1)
                {
                    $vmRule = Get-DrsRule -name $vmAffinityRule.name -cluster $clusterName -errorAction SilentlyContinue
                    If ($vmRule) {
                        Write-Host "[$($vmAffinityRule.name)] Setting VM Rule with Members $($vmAffinityRule.members)"
                        Set-DrsRule -rule $vmRule -VM $vmAffinityRule.members -Enabled $true -confirm:$false | Out-Null
                    }
                    else {
                        Write-Host "[$($vmAffinityRule.name)] Creating VM Rule with Members $($vmAffinityRule.members)"
                        New-DrsRule -cluster $clusterName -name $vmAffinityRule.name -VM $vmAffinityRule.members -keepTogether $vmAffinityRule.keepTogether -Enabled $true | Out-Null
                    }    
                }
            }
            Foreach ($vmHostAffinityRule in $drsRulesAndGroups.vmHostAffinityRules) {
                $hostRule = Get-DrsVMHostRule -Cluster $clusterName -name $vmHostAffinityRule.name -errorAction SilentlyContinue
                If ($hostRule) {
                    Write-Host "[$($vmHostAffinityRule.name)] Setting VMHost Rule with VM Group $($vmHostAffinityRule.vmGroupName) and Host Group $($vmHostAffinityRule.hostGroupName)"
                    Set-DrsVMHostRule -rule $hostRule -VMGroup $vmHostAffinityRule.vmGroupName -VMHostGroup $vmHostAffinityRule.hostGroupName -Type $vmHostAffinityRule.variant -confirm:$false | Out-Null
                }
                else {
                    Write-Host "[$($vmHostAffinityRule.name)] Creating VMHost Rule with VM Group $($vmHostAffinityRule.vmGroupName) and Host Group $($vmHostAffinityRule.hostGroupName)"
                    New-DrsVMHostRule -Name $vmHostAffinityRule.name -Cluster $clusterName -VMGroup $vmHostAffinityRule.vmGroupName -VMHostGroup $vmHostAffinityRule.hostGroupName -Type $vmHostAffinityRule.variant | Out-Null
                }
            }
            Foreach ($vmToVmDependencyRule in $drsRulesAndGroups.vmToVmDependencyRules) {
                $dependencyRule = (Get-Cluster -Name $clusterName).ExtensionData.Configuration.Rule | Where-Object { $_.DependsOnVmGroup -and $_.name -eq $vmToVmDependencyRule.name -and $_.vmGroup -eq $vmToVmDependencyRule.vmGroup -and $_.DependsOnVmGroup -eq $vmToVmDependencyRule.DependsOnVmGroup }
                If (!$dependencyRule) {
                    Write-Host "[$($vmToVmDependencyRule.vmGroup)] Creating VM to VM Dependency Rule to depend on $($vmToVmDependencyRule.DependsOnVmGroup) "
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
            $jumpboxName = hostname
            Write-Error "[$jumpboxName] $jsonfile not found"
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
    Resolves the state of ESXi Transport Nodes in a restored NSX Manager when the ESXi hosts have been rebuilt

    .DESCRIPTION
    The Resolve-PhysicalHostTransportNodes cmdlet resolves the state of ESXi Transport Nodes in a restored NSX Manager when the ESXi hosts have been rebuilt

    .EXAMPLE
    Resolve-PhysicalHostTransportNodes -vCenterFQDN "sfo-m01-vc01.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01" -NsxManagerFQDN "sfo-m01-nsx01a.sfo.rainpole.io" -NsxManagerAdmin "admin" -NsxManagerAdminPassword "VMw@re1!VMw@re1!"

    .PARAMETER vCenterFQDN
    FQDN of the vCenter instance that hosts the cluster whose hosts need to be resolved

    .PARAMETER vCenterAdmin
    Admin user of the vCenter instance that hosts the cluster whose hosts need to be resolved
    
    .PARAMETER vCenterAdminPassword
    Admin password for the vCenter instance that hosts the cluster  whose hosts need to be resolved

    .PARAMETER clusterName
    Name of the vSphere cluster instance whose hosts need to be resolved

    .PARAMETER nsxManagerFqdn
    FQDN of the NSX Manager where hosts need to be resolved

    .PARAMETER nsxManagerAdmin
    Admin user of the NSX Manager where hosts need to be resolved
    
    .PARAMETER nsxManagerAdminPassword
    Admin Password of the NSX Manager where hosts need to be resolved
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
    Write-Host "[$clusterName] Getting Hosts"
    $clusterHosts = (Get-Cluster -name $clusterName | Get-VMHost).name
    
    $headers = VCFIRCreateHeader -username $nsxManagerAdmin -password $nsxManagerAdminPassword
    
    #Get TransportNodes
    $uri = "https://$nsxManagerFqdn/api/v1/transport-nodes/"
    Write-Host "[$nsxManagerFqdn] Getting Transport Nodes"
    $transportNodeContents = (Invoke-WebRequest -Method GET -URI $uri -ContentType application/json -headers $headers).content | ConvertFrom-Json
    $allHostTransportNodes = ($transportNodeContents.results | Where-Object { ($_.resource_type -eq "TransportNode") -and ($_.node_deployment_info.os_type -eq "ESXI") })
    Write-Host "[$nsxManagerFqdn] Filtering Transport Nodes to members of cluster $clusterName"
    $hostIDs = ($allHostTransportNodes | Where-Object { $_.display_name -in $clusterHosts }).id

    #Resolve Hosts
    Foreach ($hostID in $hostIDs) {
        $body = "{`"id`":5726703,`"method`":`"resolveError`",`"params`":[{`"errors`":[{`"user_metadata`":{`"user_input_list`":[]},`"error_id`":26080,`"entity_id`":`"$hostID`"}]}]}"
        $uri = "https://$nsxManagerFqdn/nsxapi/rpc/call/ErrorResolverFacade"
        Write-Host "[$nsxManagerFqdn] Resolving NSX Installation on $(($allHostTransportNodes | Where-Object {$_.id -eq $hostID}).display_name) "
        $response = Invoke-WebRequest -Method POST -URI $uri -ContentType application/json -headers $headers -body $body
    }    
}
Export-ModuleMember -Function Resolve-PhysicalHostTransportNodes

Function Invoke-NSXEdgeClusterRecovery
{
    <#
    .SYNOPSIS
    Redeploys the NSX Egdes from the provided vSphere Cluster

    .DESCRIPTION
    The Invoke-NSXEdgeClusterRecovery cmdlet redeploys the NSX Egdes from the provided vSphere Cluster

    .EXAMPLE
    Invoke-NSXEdgeClusterRecovery -nsxManagerFqdn "sfo-m01-nsx01.sfo.rainpole.io" -nsxManagerAdmin "admin" -nsxManagerAdminPassword "VMw@re1!VMw@re1!" -vCenterFQDN "sfo-m01-vc01.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01"

    .EXAMPLE
    Invoke-NSXEdgeClusterRecovery -nsxManagerFqdn "sfo-m01-nsx01.sfo.rainpole.io" -nsxManagerAdmin "admin" -nsxManagerAdminPassword "VMw@re1!VMw@re1!" -vCenterFQDN "sfo-m01-vc01.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -resourcePoolName "VCF-edge_sfo-m01-ec01_ResourcePool_7d6d6cb0abdfae659f6d36046ac7ddbc"

    .PARAMETER nsxManagerFqdn
    FQDN of the NSX Manager whose Edges need to be redeployed

    .PARAMETER nsxManagerAdmin
    Admin user of the NSX Manager whose Edges need to be redeployed
    
    .PARAMETER nsxManagerAdminPassword
    Admin Password of the NSX Manager whose Edges need to be redeployed

    .PARAMETER vCenterFQDN
    FQDN of the vCenter instance that hosts the cluster whose Egdes need to be redeployed

    .PARAMETER vCenterAdmin
    Admin user of the vCenter instance that hosts the cluster whose Egdes need to be redeployed
    
    .PARAMETER vCenterAdminPassword
    Admin password for the vCenter instance that hosts the cluster whose Egdes need to be redeployed

    .PARAMETER clusterName
    Name of the vSphere cluster instance whose Egdes need to be redeployed

    .PARAMETER resourcePoolName
    Name of the Resource Pool whose Egdes need to be redeployed

    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem
    #>

    Param(
        [Parameter (Mandatory = $true)][String] $nsxManagerFqdn,
        [Parameter (Mandatory = $true)][String] $nsxManagerAdmin,
        [Parameter (Mandatory = $true)][String] $nsxManagerAdminPassword,
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile
    )

    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $vcenterConnection = Connect-VIServer -server $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword

    #Get all Resource Pool moRefs and add cluster moReg
    $resourcePools = @(Get-Cluster -name $clusterName | Get-ResourcePool | Where-Object {$_.name -ne "Resources"})
    $cluster = (Get-Cluster -name $clusterName)
    
    $edgeLocations = @()
    Foreach ($resourcePool in $resourcePools)
    {
        $edgeLocations += [PSCustomObject]@{
            'Type' = 'ResourcePool'
            'Name' = $resourcePool.Name
            'moRef' = $resourcePool.extensionData.moref.value
        }
    }
    $edgeLocations += [PSCustomObject]@{
        'Type' = 'Cluster'
        'Name' = $cluster.Name
        'moRef' = $cluster.extensionData.moref.value
    }

    Foreach ($edgeLocation in $edgeLocations)
    {
        #Get TransportNodes
        Write-Host "[$nsxManagerFqdn] Looking for Edges to recover in $($edgeLocation.type): $($edgeLocation.name)"
        $headers = VCFIRCreateHeader -username $nsxManagerAdmin -password $nsxManagerAdminPassword
        $uri = "https://$nsxManagerFqdn/api/v1/transport-nodes/"
        $transportNodeContents = (Invoke-WebRequest -Method GET -URI $uri -ContentType application/json -headers $headers).content | ConvertFrom-Json
        $allEdgeTransportNodes = ($transportNodeContents.results | Where-Object { ($_.node_deployment_info.resource_type -eq "EdgeNode") -and ($_.node_deployment_info.deployment_config.vm_deployment_config.compute_id -eq $edgeLocation.MoRef)}) | Sort-Object -Property display_name
        
        If ($allEdgeTransportNodes)
        {
            Write-Host "[$nsxManagerFqdn] Found Edges to recover: $($allEdgeTransportNodes.display_name -join(","))"
        }
        else 
        {
            Write-Host "[$nsxManagerFqdn] No Edges found needing recovery"
        }
        #Redeploy Failed Edges
        Foreach ($edge in $allEdgeTransportNodes)
        {
            $edgeVmPresent = get-vm -name $edge.display_name -ErrorAction SilentlyContinue
            If (!$edgeVmPresent)
            {
                #Getting Existing Placement Details
                Write-Host "[$($edge.display_name)] Getting Placement References"
                $uri = "https://$nsxManagerFqdn/api/v1/transport-nodes/$($edge.node_id)"
                $edgeConfig = (Invoke-WebRequest -Method GET -URI $uri -ContentType application/json -headers $headers).content | ConvertFrom-Json
                $vmDeploymentConfig = $edgeConfig.node_deployment_info.deployment_config.vm_deployment_config
                $NumCpu = $vmDeploymentConfig.resource_allocation.cpu_count
                $memoryGB = $vmDeploymentConfig.resource_allocation.memory_allocation_in_mb / 1024
                $cpuShareLevel = (($vmDeploymentConfig.reservation_info.cpu_reservation.reservation_in_shares -split("_"))[0]).tolower()
                $attachedNetworks = $vmDeploymentConfig.data_network_ids

                #Create Dummy VM
                Write-Host "[$($edge.display_name)] Preparing to Update Placement References"
                $clusterVdsName = ($extractedSddcData.workloadDomains.vsphereClusterDetails | Where-Object {$_.name -eq $clusterName}).vdsdetails.dvsName
                $portgroup = (($extractedSddcData.workloadDomains.vsphereClusterDetails | Where-Object {$_.name -eq $clusterName}).vdsdetails.portgroups | Where-Object {$_.transportType -eq 'MANAGEMENT'}).NAME 
                $nestedNetworkPG = Get-VDPortGroup -name $portgroup -ErrorAction silentlyContinue | Where-Object {$_.VDSwitch -match $clusterVdsName}
                $datastore = ($extractedSddcData.workloadDomains.vsphereClusterDetails | Where-Object {$_.name -eq $clusterName}).primaryDatastoreName
                
                If ($edgeLocation.type -eq "ResourcePool")
                {
                    New-VM -VMhost (get-cluster -name $clusterName | Get-VMHost | Get-Random ) -Name $edge.display_name -Datastore $datastore -resourcePool $edgeLocation.name -DiskGB 200 -DiskStorageFormat Thin -MemoryGB $MemoryGB -NumCpu $NumCpu -portgroup $portgroup -GuestID "ubuntu64Guest" -Confirm:$false | Out-Null
                }
                else 
                {
                    New-VM -VMhost (get-cluster -name $clusterName | Get-VMHost | Get-Random ) -Name $edge.display_name -Datastore $datastore -DiskGB 200 -DiskStorageFormat Thin -MemoryGB $MemoryGB -NumCpu $NumCpu -portgroup $portgroup -GuestID "ubuntu64Guest" -Confirm:$false | Out-Null
                }
                
                Get-VM -Name $edge.display_name | Get-VMResourceConfiguration | Set-VMResourceConfiguration -MemReservationGB $memoryGB | Out-Null
                Get-VM -Name $edge.display_name | Get-VMResourceConfiguration | Set-VMResourceConfiguration -CpuSharesLevel $cpuShareLevel | Out-Null
                Foreach ($attachedNetwork in $attachedNetworks)
                {
                    $attachedNetworkPg = Get-VDPortGroup -id ("DistributedVirtualPortgroup-" + $attachedNetwork)
                    Get-VM -Name $edge.display_name | New-NetworkAdapter -portGroup $attachedNetworkPg -StartConnected -Type Vmxnet3 -Confirm:$false | Out-Null
                }
                $vmID = (get-vm -name $edge.display_name).extensionData.moref.value
                
                #Build Edge DeploymentSpec
                Write-Host "[$($edge.display_name)] Updating Placement References"
                $datastoreMoRef = (Get-Datastore -name $datastore).ExtensionData.moref.value
                $vmDeploymentConfig.storage_id = $datastoreMoRef
                $nodeUserSettingsObject = New-Object -type psobject
                $nodeUserSettingsObject | Add-Member -NotePropertyName 'cli_username' -NotePropertyValue 'admin'
                $nodeUserSettingsObject | Add-Member -NotePropertyName 'audit_username' -NotePropertyValue 'audit'
                $edgeRefreshObject = New-Object -type psobject
                $edgeRefreshObject | Add-Member -NotePropertyName 'vm_id' -NotePropertyValue $vmID
                $edgeRefreshObject | Add-Member -NotePropertyName 'vm_deployment_config' -NotePropertyValue $vmDeploymentConfig
                $edgeRefreshObject | Add-Member -NotePropertyName 'node_user_settings' -NotePropertyValue $nodeUserSettingsObject
                $vmDeploymentConfigJson = $edgeRefreshObject | Convertto-Json -depth 10
                $uri = "https://$nsxManagerFqdn/api/v1/transport-nodes/$($edge.node_id)?action=addOrUpdatePlacementReferences"
                $edgeReConfig = (Invoke-WebRequest -Method POST -URI $uri -ContentType application/json -body $vmDeploymentConfigJson -headers $headers).content | ConvertFrom-Json

                #Redeploy Edge
                Write-Host "[$($edge.display_name)] Getting Edge State"
                $uri = "https://$nsxManagerFqdn/api/v1/transport-nodes/$($edge.node_id)/state"
                $edgeState = (Invoke-WebRequest -Method GET -URI $uri -ContentType application/json -headers $headers).content | ConvertFrom-Json
                If ($edgeState.node_deployment_state.state -ne "success")
                {
                    Write-Host "[$($edge.display_name)] State is $($edgeState.node_deployment_state.state)"
                    If ($edgeState.node_deployment_state.state -in "MPA_DISCONNECTED","VM_PLACEMENT_REFRESH_FAILED","NODE_READY")
                    {
                        Write-Host "[$($edge.display_name)] Redeploying Edge"
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
    }
}
Export-ModuleMember -Function Invoke-NSXEdgeClusterRecovery
#EndRegion NSXT Functions