# Copyright 2025 Broadcom. All Rights Reserved.
# SPDX-License-Identifier: BSD-2

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

If ($PSEdition -eq 'Core') {
    $Script:PSDefaultParameterValues = @{
        "invoke-restmethod:SkipCertificateCheck" = $true
        "invoke-webrequest:SkipCertificateCheck" = $true
    }
} else {
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

Function Filter-X509() {
    begin {
        $doOutput = $false
    }
    process {
        if ( $_.Contains("-----BEGIN CERTIFICATE-----") ) {
            $doOutput = $true
        }
        if ($doOutput) {
            Write-Output $_
        }
        if ( $_.Contains("-----END CERTIFICATE-----") ) {
            $doOutput = $false
        }
    }
    end {
        if ($doOutput) {
            throw "still printing certificate"
        }
    }
}

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

Function Get-InstalledSoftware {
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
    #$logContent = '[' + $timeStamp + '] [' +$threadTag + '] ' + $type + ' ' + $message
    #Add-Content -path $logFile $logContent
}

Function Test-MemberOfSubnet {
    [cmdletbinding()]
    [outputtype([System.Boolean])]
    param(
        [parameter(Mandatory = $true)]
        [string] $IPAddress,
        [parameter(Mandatory = $true)]
        [string] $Subnet
    )

    # Split Subnet into the address and the CIDR notation
    [String]$CIDRAddress = $Subnet.Split('/')[0]
    [int]$CIDRBits = $Subnet.Split('/')[1]

    # Address from Subnet and the search address are converted to Int32 and the full mask is calculated from the CIDR notation.
    [int]$BaseAddress = [System.BitConverter]::ToInt32((([System.Net.IPAddress]::Parse($CIDRAddress)).GetAddressBytes()), 0)
    [int]$Address = [System.BitConverter]::ToInt32(([System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes()), 0)
    [int]$Mask = [System.Net.IPAddress]::HostToNetworkOrder(-1 -shl ( 32 - $CIDRBits))

    # Determine whether the address is in the Subnet.
    If (($BaseAddress -band $Mask) -eq ($Address -band $Mask)) { $true } else { $false }
}

Function VCFIRCreateHeader {
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

Function Move-VMKernel {
    Param (
        [object]$VMHost,
        [string]$Interface,
        [string]$NetworkName
    )

    #Get Network ID
    $networkid = $VMHost.ExtensionData.Configmanager.NetworkSystem

    # ------- UpdateVirtualNic ------- Migrate adapter to Vswitch
    $nic = New-Object VMware.Vim.HostVirtualNicSpec
    $nic.portgroup = $NetworkName

    $_this = Get-View -Id $networkid
    $_this.UpdateVirtualNic($Interface, $nic)
}

Function cidrToMask {
    Param (
        [Parameter (Mandatory = $true)] [String]$cidr
    )

    $subnetMasks = @(
        ($32 = @{ cidr = "32"; mask = "255.255.255.255" }),
        ($31 = @{ cidr = "31"; mask = "255.255.255.254" }),
        ($30 = @{ cidr = "30"; mask = "255.255.255.252" }),
        ($29 = @{ cidr = "29"; mask = "255.255.255.248" }),
        ($28 = @{ cidr = "28"; mask = "255.255.255.240" }),
        ($27 = @{ cidr = "27"; mask = "255.255.255.224" }),
        ($26 = @{ cidr = "26"; mask = "255.255.255.192" }),
        ($25 = @{ cidr = "25"; mask = "255.255.255.128" }),
        ($24 = @{ cidr = "24"; mask = "255.255.255.0" }),
        ($23 = @{ cidr = "23"; mask = "255.255.254.0" }),
        ($22 = @{ cidr = "22"; mask = "255.255.252.0" }),
        ($21 = @{ cidr = "21"; mask = "255.255.248.0" }),
        ($20 = @{ cidr = "20"; mask = "255.255.240.0" }),
        ($19 = @{ cidr = "19"; mask = "255.255.224.0" }),
        ($18 = @{ cidr = "18"; mask = "255.255.192.0" }),
        ($17 = @{ cidr = "17"; mask = "255.255.128.0" }),
        ($16 = @{ cidr = "16"; mask = "255.255.0.0" }),
        ($15 = @{ cidr = "15"; mask = "255.254.0.0" }),
        ($14 = @{ cidr = "14"; mask = "255.252.0.0" }),
        ($13 = @{ cidr = "13"; mask = "255.248.0.0" }),
        ($12 = @{ cidr = "12"; mask = "255.240.0.0" }),
        ($11 = @{ cidr = "11"; mask = "255.224.0.0" }),
        ($10 = @{ cidr = "10"; mask = "255.192.0.0" }),
        ($9 = @{ cidr = "9"; mask = "255.128.0.0" }),
        ($8 = @{ cidr = "8"; mask = "255.0.0.0" }),
        ($7 = @{ cidr = "7"; mask = "254.0.0.0" }),
        ($6 = @{ cidr = "6"; mask = "252.0.0.0" }),
        ($5 = @{ cidr = "5"; mask = "248.0.0.0" }),
        ($4 = @{ cidr = "4"; mask = "240.0.0.0" }),
        ($3 = @{ cidr = "3"; mask = "224.0.0.0" }),
        ($2 = @{ cidr = "2"; mask = "192.0.0.0" }),
        ($1 = @{ cidr = "1"; mask = "128.0.0.0" }),
        ($0 = @{ cidr = "0"; mask = "0.0.0.0" })
    )
    $foundMask = $subnetMasks | Where-Object { $_.'cidr' -eq $cidr }
    Return $foundMask.mask
}
#EndRegion Supporting Functions

#Region Pre-Requisites
Function Confirm-VCFInstanceRecoveryPreReqs {
    <#
    .SYNOPSIS
    Checks for the presence of supporting software and modules leveraged by VMware.CloudFoundation.InstanceRecovery

    .DESCRIPTION
    The Confirm-VCFInstanceRecoveryPreReqs cmdlet checks for the presence of supporting software and modules leveraged by VMware.CloudFoundation.InstanceRecovery

    .EXAMPLE
    Confirm-VCFInstanceRecoveryPreReqs
    #>

    #Check Dependencies
    $jumpboxName = hostname

    #Check for windows tar.exe
    $isTarInstalled = Test-Path "C:\Windows\System32\tar.exe"
    If (!$isTarInstalled) {
        LogMessage -type WARNING -message "[$jumpboxName] tar.exe Missing. Please install"
    } else {
        LogMessage -type INFO -message "[$jumpboxName] tar.exe found"
    }

    $isPoshSSHInstalled = Get-InstalledModule -name "Posh-SSH" -RequiredVersion "3.0.8" -ErrorAction SilentlyContinue
    If (!$isPoshSSHInstalled) {
        LogMessage -type WARNING -message "[$jumpboxName] Posh-SSH Module Missing. Please install"
    } else {
        LogMessage -type INFO -message "[$jumpboxName] Posh-SSH Module found"
    }

    $isPowerCLIInstalled = Get-InstalledModule -name "VCF.PowerCLI" -ErrorAction SilentlyContinue
    If (!$isPowerCLIInstalled) {
        LogMessage -type WARNING -message "[$jumpboxName] VCF PowerCLI Module Missing. Please install"
    } else {
        LogMessage -type INFO -message "[$jumpboxName] PowerCLI Module found"
    }

    $installedSoftware = Get-InstalledSoftware
    If (!($installedSoftware -match "OpenSSL")) {
        $openSslUrlPath = "https://slproweb.com/products/Win32OpenSSL.html"
        Try { $openSslLinks = Invoke-WebRequest $openSslUrlPath -UseBasicParsing -ErrorAction silentlycontinue }Catch {}
        $openSslLink = (($openSslLinks.Links | Where-Object { $_.href -like "/download/Win64OpenSSL_Light*.exe" }).href)[0]
        $Global:openSSLUrl = "https://slproweb.com" + $openSslLink
        If ($openSSLUrl) {
            LogMessage -type WARNING -message "[$jumpboxName] OpenSSL missing. Please install. Latest version detected is here: $openSSLUrl"
        } else {
            LogMessage -type WARNING -message "[$jumpboxName] OpenSSL missing. Please install. Unable to detect latest version on web"
        }
    } else {
        LogMessage -type INFO -message "[$jumpboxName] OpenSSL Utility found"
    }
    $pathEntries = $env:path -split (";")
    $OpenSSLPath = $pathEntries | Where-Object { $_ -like "*OpenSSL*" }
    If ($OpenSSLPath) {
        $testOpenSSExe = Test-Path "$OpenSSLPath\openssl.exe"
        IF ($testOpenSSExe) {
            LogMessage -type INFO -message "[$jumpboxName] openssl.exe found in $OpenSSLPath"
        } else {
            LogMessage -type WARNING -message "[$jumpboxName] $OpenSSLPath was found in environment path, but no openssl.exe was found in that path"
        }

    } else {
        LogMessage -type WARNING -message "[$jumpboxName] No folder path that looks like OpenSSL was discovered in the environment path variable. Please double check that the location of OpenSSL is included in the path variable"
    }

    $viServerModeConfig = (Get-PowerCLIConfiguration | Where-Object { $_.scope -eq "AllUsers" }).DefaultVIServerMode
    If ($viServerModeConfig -eq 'Multiple') {
        LogMessage -type INFO -message "[$jumpboxName] DefaultVIServerMode is correctly set to 'Multiple'"
    } else {
        LogMessage -type WARNING -message "[$jumpboxName] DefaultVIServerMode is not correctly set. Please run 'Set-PowerCLIConfiguration -DefaultVIServerMode Multiple' to correct"
    }
}
Export-ModuleMember -Function Confirm-VCFInstanceRecoveryPreReqs
#EndRegion Pre-Requisites

#Region Data Gathering

Function New-ExtractDataFromSDDCBackup {
    <#
    .SYNOPSIS
    Decrypts and extracts the contents of the provided VMware Cloud Foundation SDDC manager backup, parses it for information required for instance recovery and stores the data in a file called extracted-sddc-data.json

    .DESCRIPTION
    The New-ExtractDataFromSDDCBackup cmdlet decrypts and extracts the contents of the provided VMware Cloud Foundation SDDC manager backup, parses it for information required for instance recovery and stores the data in a file called extracted-sddc-data.json

    .EXAMPLE
    New-ExtractDataFromSDDCBackup -backupFilePath "F:\backup\vcf-backup-sfo-vcf01-sfo-rainpole-io-2023-09-19-10-53-02.tar.gz" -encryptionPassword "VMw@re1!VMw@re1!"

    .PARAMETER vcfBackupFilePath
    Relative or absolute to the VMware Cloud Foundation SDDC manager backup file somewhere on the local filesystem

    .PARAMETER encryptionPassword
    The password that should be used to decrypt the VMware Cloud Foundation SDDC manager backup file ie the password that was used to encrypt it originally.
    #>

    Param(
        [Parameter (Mandatory = $true)][String] $vcfBackupFilePath,
        [Parameter (Mandatory = $true)][String] $encryptionPassword
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $backupFileFullPath = (Resolve-Path -Path $vcfBackupFilePath).path
    $backupFileName = (Get-ChildItem -path $backupFileFullPath).name
    $parentFolder = Split-Path -Path $backupFileFullPath
    $extractedBackupFolder = ($backupFileName -Split (".tar.gz"))[0]

    #Decrypt Backup
    LogMessage -type INFO -message "[$jumpboxName] Decrypting Backup"
    $command = "openssl enc -d -aes-256-cbc -md sha256 -in $backupFileFullPath -pass pass:`"$encryptionPassword`" -out `"$parentFolder\decrypted-sddc-manager-backup.tar.gz`""
    Invoke-Expression "& $command" *>$null

    #Extract Required Files From Backup Leveraging Windows tar.exe
    LogMessage -type INFO -message "[$jumpboxName] Extracting Backup"
    Push-Location
    Set-Location "$parentFolder"
    tar -xzf "$parentFolder\decrypted-sddc-manager-backup.tar.gz" "$extractedBackupFolder/metadata.json" "$extractedBackupFolder/appliancemanager_dns_configuration.json" "$extractedBackupFolder/appliancemanager_ntp_configuration.json" "$extractedBackupFolder/security_password_vault.json" "$extractedBackupFolder/database/sddc-postgres.bkp"


    #Get Content of Password Vault
    LogMessage -type INFO -message "[$jumpboxName] Reading Password Vault"
    $passwordVaultJson = Get-Content "$parentFolder\$extractedBackupFolder\security_password_vault.json" | ConvertFrom-JSON
    $passwordVaultObject = @()
    Foreach ($object in $passwordVaultJson) {
        $passwordVaultObject += [pscustomobject]@{
            'entityId'        = $object.entityId
            'entityName'      = $object.entityName
            'entityType'      = $object.entityType
            'credentialType'  = $object.credentialType
            'entityIpAddress' = $object.entityIpAddress
            'username'        = $object.username
            'domainName'      = $object.domainName
            'password'        = $object.password
        }
    }

    #Get Management Domain Deployment Objects
    $metadataJSON = Get-Content "$parentFolder\$extractedBackupFolder\metadata.json" | ConvertFrom-JSON
    $dnsJSON = Get-Content "$parentFolder\$extractedBackupFolder\appliancemanager_dns_configuration.json" | ConvertFrom-JSON
    $ntpJSON = Get-Content "$parentFolder\$extractedBackupFolder\appliancemanager_ntp_configuration.json" | ConvertFrom-JSON
    #$mgmtVcenterMetadata = Get-Content -Path ($vCenterbackupFolderFullPath + "/backup-metadata.json") | ConvertFrom-JSON
    #$managementSubnetMask = cidrToMask $mgmtVcenterMetadata.PrimaryNetworkInfo.ipv4.prefix

    $sddcManagerIP = $metadataJSON.ip
    #$managementSubnetMask = $metaDataJSON.netmask
    $ip = [ipaddress]$sddcManagerIP
    $subnet = [ipaddress]$metaDataJSON.netmask
    $netid = [ipaddress]($ip.address -band $subnet.address)
    $managementSubnet = $($netid.ipaddresstostring)

    $mgmtDomainInfrastructure = [pscustomobject]@{
        'port_group'         = $metadataJSON.port_group
        'vsan_datastore'     = $metadataJSON.vsan_datastore
        'cluster'            = $metaDataJSON.cluster
        'datacenter'         = $metaDataJSON.datacenter
        'netmask'            = $metaDataJSON.netmask
        'subnet'             = $managementSubnet
        'gateway'            = $metaDataJSON.gateway
        'domain'             = $metaDataJSON.domain
        'search_path'        = $metaDataJSON.search_path
        'primaryDnsServer'   = $dnsJSON.primaryDnsServer
        'secondaryDnsServer' = $dnsJSON.secondaryDnsServer
        'ntpServers'         = @($ntpJSON.ntpServers)
    }

    $psqlContent = Get-Content "$parentFolder\$extractedBackupFolder\database\sddc-postgres.bkp"

    LogMessage -type INFO -message "[$jumpboxName] Retrieving SDDC Manager Detail"
    #Find the column number for each required element. Future proofed if column number changes
    $headerLine = ($psqlContent | Select-String -SimpleMatch "COPY public.sddc_manager_controller" | Select-Object Line).Line
    $columnHeaders = [regex]::Match($headerLine, '\((.*?)\)').Groups[1].Value
    $columns = $columnHeaders -split '\s*,\s*'
    $sddcManagerIpColumn = $columns.IndexOf('vm_management_ip_address')
    $sddcManagerFqdnColumn = $columns.IndexOf('vm_hostname')
    $sddcManagerVersionColumn = $columns.IndexOf('version')
    $sddcManagerVmNameColumn = $columns.IndexOf('vm_name')
    $ceipStatusColumn = $columns.IndexOf('ceip_status')

    #GetDomainDetails
    $ceipStartingLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.sddc_manager_controller" | Select-Object Line, LineNumber).LineNumber
    $lineContent = $psqlContent | Select-Object -Index $ceipStartingLineNumber
    $sddcManagerIp = $lineContent.split("`t")[$sddcManagerIpColumn]
    $sddcManagerVersion = $lineContent.split("`t")[$sddcManagerVersionColumn]
    $sddcManagerFqdn = $lineContent.split("`t")[$sddcManagerFqdnColumn]
    $sddcManagerVmName = $lineContent.split("`t")[$sddcManagerVmNameColumn]
    If ($lineContent.split("`t")[$ceipStatusColumn] -eq 'ENABLED') { $ceipStatus = $true } else { $ceipStatus = $false }

    $sddcManagerObject = @()
    $sddcManagerObject += [pscustomobject]@{
        'fqdn'         = $sddcManagerFqdn
        'vmname'       = $sddcManagerVmName
        'ip'           = (Resolve-DnsName $sddcManagerFqdn).IPAddress
        'fips_enabled' = $metadataJSON.fips_enabled
        'ceip_enabled' = $ceipStatus
        'version'      = $sddcManagerVersion
    }

    LogMessage -type INFO -message "[$jumpboxName] Retrieving NSX Manager Details"
    #Get All NSX Manager Clusters
    #Find the column number for each required element. Future proofed if column number changes
    $headerLine = ($psqlContent | Select-String -SimpleMatch "COPY public.nsxt (id" | Select-Object Line).Line
    $columnHeaders = [regex]::Match($headerLine, '\((.*?)\)').Groups[1].Value
    $columns = $columnHeaders -split '\s*,\s*'
    $nsxConfigurationColumn = $columns.IndexOf('configuration')

    $nsxManagerstartingLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.nsxt (id" | Select-Object Line, LineNumber).LineNumber
    $nsxManagerlineIndex = $nsxManagerstartingLineNumber
    $nsxtManagerClusters = @()
    Do {
        $lineContent = $psqlContent | Select-Object -Index $nsxManagerlineIndex
        If ($lineContent -ne '\.') {
            $nodeContent = (($lineContent.split("`t")[$nsxConfigurationColumn]).replace("\n", "")) | ConvertFrom-Json
            $nodeIPs = ($nodeContent.managerIpsFqdnMap | Get-Member -type NoteProperty).name
            $nsxNodes = @()
            Foreach ($nodeIP in $nodeIPs) {
                $hostname = $nodeContent.managerIpsFqdnMap.$($nodeIP)
                $nsxNodes += [pscustomobject]@{
                    'vmName'   = $hostname.split(".")[0]
                    'hostname' = $hostname
                    'ip'       = $nodeIP
                }
            }
            $nsxtManagerClusters += [pscustomobject]@{
                'clusterVip'  = (Resolve-DnsName $lineContent.split("`t")[5]).IPAddress
                'clusterFqdn' = $lineContent.split("`t")[5]
                'domainIDs'   = $nodeContent.domainIds
                'nsxNodes'    = $nsxNodes
            }
        }
        $nsxManagerlineIndex++
    }
    Until ($lineContent -eq '\.')

    #Get Hosts
    LogMessage -type INFO -message "[$jumpboxName] Retrieving Host Details"
    #Find the column number for each required element. Future proofed if column number changes
    $headerLine = ($psqlContent | Select-String -SimpleMatch "COPY public.host " | Select-Object Line).Line
    $columnHeaders = [regex]::Match($headerLine, '\((.*?)\)').Groups[1].Value
    $columns = $columnHeaders -split '\s*,\s*'
    $hostIdColumn = $columns.IndexOf('id')
    $hostNameColumn = $columns.IndexOf('hostname')
    $hostVersionColumn = $columns.IndexOf('version')
    $hostVmotionIpColumn = $columns.IndexOf('vmotion_ip_address')
    $hostVsanIpColumn = $columns.IndexOf('vsan_ip_address')

    $hostsLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.host " | Select-Object Line, LineNumber).LineNumber
    $hostsLineIndex = $hostsLineNumber
    $hosts = @()
    Do {
        $lineContent = $psqlContent | Select-Object -Index $hostsLineIndex
        If ($lineContent -ne '\.') {
            $hostId = $lineContent.split("`t")[$hostIdColumn]
            #$gateway = $lineContent.split("`t")[7]
            $hostName = $lineContent.split("`t")[$hostNameColumn]
            $hostMgmtIp = (Resolve-DnsName $lineContent.split("`t")[$hostnameColumn]).IPAddress
            #$hostMask = $lineContent.split("`t")[17]
            $hostVersion = $lineContent.split("`t")[$hostVersionColumn]
            $hostVmotionIp = $lineContent.split("`t")[$hostVmotionIpColumn]
            $hostVsanIP = $lineContent.split("`t")[$hostVsanIpColumn]

            #Calculate Managment Subnet (Management Domain Hosts Only)
            <#  If (($gateway -ne "\N") -AND ($hostMask -ne "\N")) {

                $ip = [ipaddress]$hostMgmtIp
                $subnet = [ipaddress]$hostMask
                $netid = [ipaddress]($ip.address -band $subnet.address)
                $hostManagementSubnet = $($netid.ipaddresstostring)
            } #>

            $hosts += [pscustomobject]@{
                'id'        = $hostId
                #'gateway'   = $gateway
                'hostName'  = $hostName
                'mgmtIp'    = $hostMgmtIp
                #'mask'      = $hostMask
                #'subnet'    = $hostManagementSubnet
                'version'   = $hostVersion
                'vmotionIP' = $hostVmotionIp
                'vsanIP'    = $hostVsanIP
            }
        }
        $hostsLineIndex++
    }
    Until ($lineContent -eq '\.')

    #Get Host and Domain Details
    LogMessage -type INFO -message "[$jumpboxName] Retrieving Host and Domain Mappings"
    #Find the column number for each required element. Future proofed if column number changes
    $headerLine = ($psqlContent | Select-String -SimpleMatch "COPY public.host_and_domain " | Select-Object Line).Line
    $columnHeaders = [regex]::Match($headerLine, '\((.*?)\)').Groups[1].Value
    $columns = $columnHeaders -split '\s*,\s*'
    $hostIdColumn = $columns.IndexOf('host_id')
    $domainIdColumn = $columns.IndexOf('domain_id')

    $hostsAndDomainsLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.host_and_domain " | Select-Object Line, LineNumber).LineNumber
    $hostsAndDomainsLineIndex = $hostsAndDomainsLineNumber
    $hostsAndDomains = @()
    Do {
        $lineContent = $psqlContent | Select-Object -Index $hostsAndDomainsLineIndex
        If ($lineContent -ne '\.') {
            $hostId = $lineContent.split("`t")[$hostIdColumn]
            $domainID = $lineContent.split("`t")[$domainIdColumn]
            $hostsAndDomains += [pscustomobject]@{
                'hostId'   = $hostId
                'domainID' = $domainID
            }
        }
        $hostsAndDomainsLineIndex++
    }
    Until ($lineContent -eq '\.')

    #Get Host and vCenter Details
    LogMessage -type INFO -message "[$jumpboxName] Retrieving Host and vCenter Mappings"
    #Find the column number for each required element. Future proofed if column number changes
    $headerLine = ($psqlContent | Select-String -SimpleMatch "COPY public.host_and_vcenter " | Select-Object Line).Line
    $columnHeaders = [regex]::Match($headerLine, '\((.*?)\)').Groups[1].Value
    $columns = $columnHeaders -split '\s*,\s*'
    $hostIdColumn = $columns.IndexOf('host_id')
    $vcenterIdColumn = $columns.IndexOf('vcenter_id')

    $hostsandVcentersLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.host_and_vcenter " | Select-Object Line, LineNumber).LineNumber
    $hostsandVcentersLineIndex = $hostsandVcentersLineNumber
    $hostsandVcenters = @()
    Do {
        $lineContent = $psqlContent | Select-Object -Index $hostsandVcentersLineIndex
        If ($lineContent -ne '\.') {
            $hostId = $lineContent.split("`t")[$hostIdColumn]
            $vCenterID = $lineContent.split("`t")[$vcenterIdColumn]
            $hostsandVcenters += [pscustomobject]@{
                'hostId'    = $hostId
                'vCenterID' = $vCenterID
            }
        }
        $hostsandVcentersLineIndex++
    }
    Until ($lineContent -eq '\.')

    #Get Host and vCenter Details
    LogMessage -type INFO -message "[$jumpboxName] Retrieving vCenter Details"
    #Find the column number for each required element. Future proofed if column number changes
    $headerLine = ($psqlContent | Select-String -SimpleMatch "COPY public.vcenter " | Select-Object Line).Line
    $columnHeaders = [regex]::Match($headerLine, '\((.*?)\)').Groups[1].Value
    $columns = $columnHeaders -split '\s*,\s*'
    $vCenterIDColumn = $columns.IndexOf('id')
    $vCenterVersionColumn = $columns.IndexOf('version')
    $vCenterFqdnColumn = $columns.IndexOf('vm_hostname')
    $vCenterVMnameColumn = $columns.IndexOf('vm_name')

    $vCentersStartingLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.vcenter " | Select-Object Line, LineNumber).LineNumber
    $vCenterLineIndex = $vCentersStartingLineNumber
    $vCenters = @()
    Do {
        $lineContent = $psqlContent | Select-Object -Index $vCentersStartingLineNumber
        If ($lineContent -ne '\.') {
            $vCenterID = $lineContent.split("`t")[$vCenterIDColumn]
            $vCenterVersion = $lineContent.split("`t")[$vCenterVersionColumn]
            $vCenterFqdn = $lineContent.split("`t")[$vCenterFqdnColumn]
            $vCenterIp = (Resolve-DnsName $vCenterFqdn).IPAddress
            $vCenterVMname = $lineContent.split("`t")[$vCenterVMnameColumn]
            $vCenterDomainID = ($hostsAndDomains | Where-Object { $_.hostId -eq (($hostsandVcenters | Where-Object { $_.vCenterID -eq $vCenterID })[0].hostID) }).domainID
            $vCenters += [pscustomobject]@{
                'vCenterID'       = $vCenterID
                'vCenterVersion'  = $vCenterVersion
                'vCenterFqdn'     = $vCenterFqdn
                'vCenterIp'       = $vCenterIp
                'vCenterVMname'   = $vCenterVMname
                'vCenterDomainID' = $vCenterDomainID
            }
        }
        $vCentersStartingLineNumber++
    }
    Until ($lineContent -eq '\.')

    #Get Hosts and Pools
    LogMessage -type INFO -message "[$jumpboxName] Retrieving Host and Network Pool Mappings"
    #Find the column number for each required element. Future proofed if column number changes
    $headerLine = ($psqlContent | Select-String -SimpleMatch "COPY public.host_and_network_pool" | Select-Object Line).Line
    $columnHeaders = [regex]::Match($headerLine, '\((.*?)\)').Groups[1].Value
    $columns = $columnHeaders -split '\s*,\s*'
    $hostIdColumn = $columns.IndexOf('host_id')
    $poolIdColumn = $columns.IndexOf('network_pool_id')

    $hostsAndPoolsLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.host_and_network_pool" | Select-Object Line, LineNumber).LineNumber
    $hostsAndPoolsLineIndex = $hostsAndPoolsLineNumber
    $hostsandPools = @()
    Do {
        $lineContent = $psqlContent | Select-Object -Index $hostsAndPoolsLineIndex
        If ($lineContent -ne '\.') {
            $hostId = $lineContent.split("`t")[$hostIdColumn]
            $poolID = $lineContent.split("`t")[$poolIdColumn]
            $hostsandPools += [pscustomobject]@{
                'hostId' = $hostId
                'poolId' = $poolID
            }
        }
        $hostsAndPoolsLineIndex++
    }
    Until ($lineContent -eq '\.')

    #Get Network Pools
    LogMessage -type INFO -message "[$jumpboxName] Retrieving Network Pool Details"
    #Find the column number for each required element. Future proofed if column number changes
    $headerLine = ($psqlContent | Select-String -SimpleMatch "COPY public.network_pool " | Select-Object Line).Line
    $columnHeaders = [regex]::Match($headerLine, '\((.*?)\)').Groups[1].Value
    $columns = $columnHeaders -split '\s*,\s*'
    $poolIdColumn = $columns.IndexOf('id')
    $poolNameColumn = $columns.IndexOf('name')

    $networkPoolsLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.network_pool " | Select-Object Line, LineNumber).LineNumber
    $networkPoolsLineIndex = $networkPoolsLineNumber
    $networkPools = @()
    Do {
        $lineContent = $psqlContent | Select-Object -Index $networkPoolsLineIndex
        If ($lineContent -ne '\.') {
            $poolID = $lineContent.split("`t")[$poolIdColumn]
            $poolName = $lineContent.split("`t")[$poolNameColumn]
            $networkPools += [pscustomobject]@{
                'poolID'   = $poolID
                'poolName' = $poolName
            }
        }
        $networkPoolsLineIndex++
    }
    Until ($lineContent -eq '\.')

    #Get VDSs
    LogMessage -type INFO -message "[$jumpboxName] Retrieving vDS Details"
    #Find the column number for each required element. Future proofed if column number changes
    $headerLine = ($psqlContent | Select-String -SimpleMatch "COPY public.vds" | Select-Object Line).Line
    $columnHeaders = [regex]::Match($headerLine, '\((.*?)\)').Groups[1].Value
    $columns = $columnHeaders -split '\s*,\s*'
    $idColumn = $columns.IndexOf('id')
    $mtuColumn = $columns.IndexOf('mtu')
    $nameColumn = $columns.IndexOf('name')
    $niocsColumn = $columns.IndexOf('niocs')
    $portGroupsColumn = $columns.IndexOf('port_groups')
    $sourceIdColumn = $columns.IndexOf('source_id')
    $versionColumn = $columns.IndexOf('version')
    $switchConfigColumn = $columns.IndexOf('nsxt_switch_config')

    $vdsLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.vds" | Select-Object Line, LineNumber).LineNumber
    $vdsLineIndex = $vdsLineNumber
    $virtualDistributedSwitches = @()
    Do {
        $lineContent = $psqlContent | Select-Object -Index $vdsLineIndex
        If ($lineContent -ne '\.') {
            $vdsId = $lineContent.split("`t")[$idColumn]
            $vdsMtu = $lineContent.split("`t")[$mtuColumn]
            $vdsName = $lineContent.split("`t")[$nameColumn]
            $niocs = $lineContent.split("`t")[$niocsColumn] | ConvertFrom-Json
            If ($lineContent.split("`t")[$portGroupsColumn] -ne '\N') {
                $vdsPortgroups = $lineContent.split("`t")[$portGroupsColumn] | ConvertFrom-Json
            } else {
                $vdsPortgroups = $null
            }
            $sourceID = $lineContent.split("`t")[$sourceIdColumn]

            $version = $lineContent.split("`t")[$versionColumn]
            $virtualDistributedSwitch = [pscustomobject]@{
                'Id'         = $vdsId
                'niocs'      = $niocs
                'Mtu'        = $vdsMtu
                'Name'       = $vdsName
                'PortGroups' = $vdsPortgroups
                'version'    = $version
                'sourceID'   = $sourceID
            }

            If ($lineContent.split("`t")[$switchConfigColumn] -ne '\N') {
                $overlayContent = $lineContent.split("`t")[$switchConfigColumn] | ConvertFrom-Json
                $transportZoneContent = $overlayContent.transportZones
                If ($overlayContent.hostSwitchOperationalMode -ne $null) {
                    $hostSwitchOperationalModeContent = $overlayContent.hostSwitchOperationalMode
                } else {
                    $hostSwitchOperationalModeContent = 'STANDARD'
                }

                $virtualDistributedSwitch | Add-Member -NotePropertyName 'transportZones' -NotePropertyValue $transportZoneContent
                $virtualDistributedSwitch | Add-Member -NotePropertyName 'hostSwitchOperationalMode' -NotePropertyValue $hostSwitchOperationalModeContent
            }
            $virtualDistributedSwitches += $virtualDistributedSwitch
        }
        $vdsLineIndex++
    }
    Until ($lineContent -eq '\.')

    #Get Networks
    LogMessage -type INFO -message "[$jumpboxName] Retrieving Network Details"
    #Find the column number for each required element. Future proofed if column number changes
    $headerLine = ($psqlContent | Select-String -SimpleMatch "COPY public.vcf_network " | Select-Object Line).Line
    $columnHeaders = [regex]::Match($headerLine, '\((.*?)\)').Groups[1].Value
    $columns = $columnHeaders -split '\s*,\s*'
    $idColumn = $columns.IndexOf('id')
    $mtuColumn = $columns.IndexOf('mtu')
    $gatewayColumn = $columns.IndexOf('gateway')
    $ipInclusionRangesColumn = $columns.IndexOf('ip_inclusion_ranges')
    $subnetColumn = $columns.IndexOf('subnet')
    $subnetMaskColumn = $columns.IndexOf('subnet_mask')
    $typeColumn = $columns.IndexOf('type')
    $vlanIdColumn = $columns.IndexOf('vlan_id')

    $networksLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.vcf_network " | Select-Object Line, LineNumber).LineNumber
    $networksLineIndex = $networksLineNumber
    $networks = @()
    Do {
        $lineContent = $psqlContent | Select-Object -Index $networksLineIndex
        If ($lineContent -ne '\.') {
            $id = $lineContent.split("`t")[$idColumn]
            $gateway = $lineContent.split("`t")[$gatewayColumn]
            $ipInclusionRanges = $lineContent.split("`t")[$ipInclusionRangesColumn] | ConvertFrom-Json
            $ipInclusionRangeArray = $ipInclusionRanges | Select-Object -Property @{
                Name       = 'startIPAddress'
                Expression = { $_.Start }
            }, @{
                Name       = 'endIPAddress'
                Expression = { $_.end }
            }
            $mtu = $lineContent.split("`t")[$mtuColumn]
            $subnet = $lineContent.split("`t")[$subnetColumn]
            $subnetMask = $lineContent.split("`t")[$subnetMaskColumn]
            $type = $lineContent.split("`t")[$typeColumn]
            $vlanId = $lineContent.split("`t")[$vlanIdColumn]
            $networks += [pscustomobject]@{
                'id'                     = $id
                'gateway'                = $gateway
                'includeIpAddressRanges' = $ipInclusionRangeArray
                'mtu'                    = $mtu
                'subnet'                 = $subnet
                'subnetMask'             = $subnetMask
                'type'                   = $type
                'vlanId'                 = $vlanId
            }
        }
        $networksLineIndex++
    }
    Until ($lineContent -eq '\.')

    #Get Pools and Networks
    LogMessage -type INFO -message "[$jumpboxName] Retrieving Network Pools and Network Mappings"
    #Find the column number for each required element. Future proofed if column number changes
    $headerLine = ($psqlContent | Select-String -SimpleMatch "COPY public.vcf_network_and_network_pool" | Select-Object Line).Line
    $columnHeaders = [regex]::Match($headerLine, '\((.*?)\)').Groups[1].Value
    $columns = $columnHeaders -split '\s*,\s*'
    $networkIDColumn = $columns.IndexOf('vcf_network_id')
    $poolIDColumn = $columns.IndexOf('network_pool_id')

    $poolsAndNetworksLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.vcf_network_and_network_pool" | Select-Object Line, LineNumber).LineNumber
    $poolsAndNetworksLineIndex = $poolsAndNetworksLineNumber
    $poolsAndNetworks = @()
    Do {
        $lineContent = $psqlContent | Select-Object -Index $poolsAndNetworksLineIndex
        If ($lineContent -ne '\.') {
            $networkID = $lineContent.split("`t")[$networkIDColumn]
            $poolID = $lineContent.split("`t")[$poolIDColumn]
            $poolsAndNetworks += [pscustomobject]@{
                'networkID' = $networkID
                'poolID'    = $poolID
            }
        }
        $poolsAndNetworksLineIndex++
    }
    Until ($lineContent -eq '\.')

    #Get Cluster and VDS
    LogMessage -type INFO -message "[$jumpboxName] Retrieving Cluster and vDS Mappings"
    #Find the column number for each required element. Future proofed if column number changes
    $headerLine = ($psqlContent | Select-String -SimpleMatch "COPY public.cluster_and_vds" | Select-Object Line).Line
    $columnHeaders = [regex]::Match($headerLine, '\((.*?)\)').Groups[1].Value
    $columns = $columnHeaders -split '\s*,\s*'
    $clusterIDColumn = $columns.IndexOf('cluster_id')
    $vdsIDColumn = $columns.IndexOf('vds_id')

    $clusterAndVdsLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.cluster_and_vds" | Select-Object Line, LineNumber).LineNumber
    $clusterAndVdsLineIndex = $clusterAndVdsLineNumber
    $clusterAndVds = @()
    Do {
        $lineContent = $psqlContent | Select-Object -Index $clusterAndVdsLineIndex
        If ($lineContent -ne '\.') {
            $clusterID = $lineContent.split("`t")[$clusterIDColumn]
            $vdsID = $lineContent.split("`t")[$vdsIDColumn]
            $clusterAndVds += [pscustomobject]@{
                'clusterID' = $clusterID
                'vdsID'     = $vdsID
            }
        }
        $clusterAndVdsLineIndex++
    }
    Until ($lineContent -eq '\.')

    LogMessage -type INFO -message "[$jumpboxName] Retrieving Host to Cluster Mappings"
    #Find the column number for each required element. Future proofed if column number changes
    $headerLine = ($psqlContent | Select-String -SimpleMatch "COPY public.host_and_cluster " | Select-Object Line).Line
    $columnHeaders = [regex]::Match($headerLine, '\((.*?)\)').Groups[1].Value
    $columns = $columnHeaders -split '\s*,\s*'
    $hostIDColumn = $columns.IndexOf('host_id')
    $clusterIDColumn = $columns.IndexOf('cluster_id')

    $hostAndClusterLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.host_and_cluster " | Select-Object Line, LineNumber).LineNumber
    $hostAndClusterLineIndex = $hostAndClusterLineNumber
    $hostAndCluster = @()
    Do {
        $lineContent = $psqlContent | Select-Object -Index $hostAndClusterLineIndex
        If ($lineContent -ne '\.') {
            $hostID = $lineContent.split("`t")[$hostIDColumn]
            $clusterID = $lineContent.split("`t")[$clusterIDColumn]
            $hostAndCluster += [pscustomobject]@{
                'hostID'    = $hostID
                'clusterID' = $clusterID
            }
        }
        $hostAndClusterLineIndex++
    }
    Until ($lineContent -eq '\.')

    #Get Clusters
    LogMessage -type INFO -message "[$jumpboxName] Retrieving Cluster Details"
    #Find the column number for each required element. Future proofed if column number changes
    $headerLine = ($psqlContent | Select-String -SimpleMatch "COPY public.cluster " | Select-Object Line).Line
    $columnHeaders = [regex]::Match($headerLine, '\((.*?)\)').Groups[1].Value
    $columns = $columnHeaders -split '\s*,\s*'
    $idColumn = $columns.IndexOf('id')
    $fttColumn = $columns.IndexOf('ftt')
    $isDefaultColumn = $columns.IndexOf('is_default')
    $isStretchedColumn = $columns.IndexOf('is_stretched')
    $vCenterIDColumn = $columns.IndexOf('vcenter_id')
    $primaryDatastoreNameColumn = $columns.IndexOf('primary_datastore_name')
    $primaryDatastoreTypeColumn = $columns.IndexOf('primary_datastore_type')
    $sourceIDColumn = $columns.IndexOf('source_id')
    $isImagedBasedColumn = $columns.IndexOf('is_image_based')

    $clustersLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.cluster " | Select-Object Line, LineNumber).LineNumber
    $clustersLineIndex = $clustersLineNumber
    $clusters = @()
    Do {
        $lineContent = $psqlContent | Select-Object -Index $clustersLineIndex
        If ($lineContent -ne '\.') {
            $id = $lineContent.split("`t")[$idColumn]
            #$datacenter = $lineContent.split("`t")[3]
            $ftt = $lineContent.split("`t")[$fttColumn]
            $isDefault = $lineContent.split("`t")[$isDefaultColumn]
            $isStretched = $lineContent.split("`t")[$isStretchedColumn]
            #$name = $lineContent.split("`t")[7]
            $vCenterID = $lineContent.split("`t")[$vCenterIDColumn]
            $primaryDatastoreName = $lineContent.split("`t")[$primaryDatastoreNameColumn]
            $primaryDatastoreType = $lineContent.split("`t")[$primaryDatastoreTypeColumn]
            $sourceID = $lineContent.split("`t")[$sourceIDColumn]
            $isImagedBased = $lineContent.split("`t")[$isImagedBasedColumn]
            $vdsDetails = @()

            #Experimental
            $clusterHosts = $hostAndCluster | Where-Object { $_.clusterID -eq $id }
            $hostsArray = @()
            Foreach ($clusterHost in $clusterHosts) {
                $hostname = ($hosts | Where-Object { $_.id -eq $clusterHost.hostId }).hostname
                $gateway = ($hosts | Where-Object { $_.id -eq $clusterHost.hostId }).gateway
                $mask = ($hosts | Where-Object { $_.id -eq $clusterHost.hostId }).mask
                $subnet = ($hosts | Where-Object { $_.id -eq $clusterHost.hostId }).subnet
                $vmotionIp = ($hosts | Where-Object { $_.id -eq $clusterHost.hostId }).vmotionIp
                $vsanIp = ($hosts | Where-Object { $_.id -eq $clusterHost.hostId }).vsanIp

                $networkPoolID = ($hostsAndPools | Where-Object { $_.hostId -eq $clusterHost.hostId }).poolId
                $hostNetworkIds = ($poolsAndNetworks | Where-Object { $_.poolID -eq $networkPoolID }).networkId
                $hostNetworks = @()
                $hostNetworks += [pscustomobject]@{
                    'type'    = "MANAGEMENT"
                    'gateway' = $gateway
                    'mtu'     = "1500"
                    'mask'    = $mask
                    'subnet'  = $subnet
                }
                $hostNetworks += $networks | Where-Object { $_.id -in $hostNetworkIds }
                $hostsArray += [pscustomobject]@{
                    'hostname'       = $hostname
                    'networkPoolID'  = $networkPoolID
                    'hostNetworkIds' = $hostNetworkIds
                    'networks'       = $hostNetworks
                    'vmotionIp'      = $vmotionIp
                    'vsanIp'         = $vsanIp
                }
            }
            #End Experimental

            Foreach ($vds in ($clusterAndVds | Where-Object { $_.clusterID -eq $id })) {
                $virtualDistributedSwitchDetails = $virtualDistributedSwitches | Where-Object { $_.id -eq $vds.vdsId }
                $niocSpecsObject = @()
                Foreach ($niocSpec in $virtualDistributedSwitchDetails.niocs) {
                    $niocSpecsObject += [PSCustomObject]@{
                        'trafficType' = $niocSpec.network
                        'value'       = ($niocSpec.level).toUpper()
                    }
                }
                $vdsObject = New-Object -type PSObject
                $vdsObject | Add-Member -NotePropertyName 'mtu' -NotePropertyValue $virtualDistributedSwitchDetails.mtu
                $vdsObject | Add-Member -NotePropertyName 'niocSpecs' -NotePropertyValue $niocSpecsObject
                $vdsObject | Add-Member -NotePropertyName 'portgroups' -NotePropertyValue $virtualDistributedSwitchDetails.portgroups
                $vdsObject | Add-Member -NotePropertyName 'dvsName' -NotePropertyValue $virtualDistributedSwitchDetails.name
                $vdsObject | Add-Member -NotePropertyName 'id' -NotePropertyValue $vds.vdsId
                $vdsObject | Add-Member -NotePropertyName 'sourceID' -NotePropertyValue $virtualDistributedSwitchDetails.sourceID
                $vdsObject | Add-Member -NotePropertyName 'vmnics' -NotePropertyValue $null
                $vdsObject | Add-Member -NotePropertyName 'networks' -NotePropertyValue ("VM_MANAGEMENT", "MANAGEMENT", "VSAN", "VMOTION" | Where-Object { $_ -in $virtualDistributedSwitchDetails.portgroups.transportType })
                If ($virtualDistributedSwitchDetails.transportZones) {
                    $vdsObject | Add-Member -NotePropertyName 'transportZones' -NotePropertyValue $virtualDistributedSwitchDetails.transportZones
                    $vdsObject | Add-Member -NotePropertyName 'hostSwitchOperationalMode' -NotePropertyValue $virtualDistributedSwitchDetails.hostSwitchOperationalMode
                }

                $vdsDetails += $vdsObject
            }
            $clusters += [pscustomobject]@{
                'id'                   = $id
                #'datacenter'           = $datacenter
                'ftt'                  = $ftt
                'isDefault'            = $isDefault
                'isStretched'          = $isStretched
                'name'                 = $name
                'vCenterID'            = $vCenterID
                'primaryDatastoreName' = $primaryDatastoreName
                'primaryDatastoreType' = $primaryDatastoreType
                'primaryDatastorePolicy' = $null
                'isImageBased'           = $isImagedBased
                'sourceID'               = $sourceID
                'vdsDetails'             = $vdsDetails
                'hosts'                  = @($hostsArray | Sort-Object -Property hostname)
            }
        }
        $clustersLineIndex++
    }
    Until ($lineContent -eq '\.')

    #Get Cluster and vCenter
    LogMessage -type INFO -message "[$jumpboxName] Retrieving Cluster and vCenter Mappings"
    #Find the column number for each required element. Future proofed if column number changes
    $headerLine = ($psqlContent | Select-String -SimpleMatch "COPY public.cluster_and_vcenter" | Select-Object Line).Line
    $columnHeaders = [regex]::Match($headerLine, '\((.*?)\)').Groups[1].Value
    $columns = $columnHeaders -split '\s*,\s*'
    $clusterIDColumn = $columns.IndexOf('cluster_id')
    $vcenterIDColumn = $columns.IndexOf('vcenter_id')

    $clusterAndVcenterLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.cluster_and_vcenter" | Select-Object Line, LineNumber).LineNumber
    $clusterAndVcenterLineIndex = $clusterAndVcenterLineNumber
    $clusterAndVcenter = @()
    Do {
        $lineContent = $psqlContent | Select-Object -Index $clusterAndVcenterLineIndex
        If ($lineContent -ne '\.') {
            $clusterID = $lineContent.split("`t")[$clusterIDColumn]
            $vcenterID = $lineContent.split("`t")[$vcenterIDColumn]
            $clusterAndVcenter += [pscustomobject]@{
                'clusterID' = $clusterID
                'vcenterID' = $vcenterID
            }
        }
        $clusterAndVcenterLineIndex++
    }
    Until ($lineContent -eq '\.')

    #Get Cluster and Domain
    LogMessage -type INFO -message "[$jumpboxName] Retrieving Cluster and Domain Mappings"
    #Find the column number for each required element. Future proofed if column number changes
    $headerLine = ($psqlContent | Select-String -SimpleMatch "COPY public.cluster_and_domain" | Select-Object Line).Line
    $columnHeaders = [regex]::Match($headerLine, '\((.*?)\)').Groups[1].Value
    $columns = $columnHeaders -split '\s*,\s*'
    $clusterIDColumn = $columns.IndexOf('cluster_id')
    $domainIDColumn = $columns.IndexOf('domain_id')

    $clusterAndDomainLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.cluster_and_domain" | Select-Object Line, LineNumber).LineNumber
    $clusterAndDomainLineIndex = $clusterAndDomainLineNumber
    $clusterAndDomain = @()
    Do {
        $lineContent = $psqlContent | Select-Object -Index $clusterAndDomainLineIndex
        If ($lineContent -ne '\.') {
            $clusterID = $lineContent.split("`t")[$clusterIDColumn]
            $domainID = $lineContent.split("`t")[$domainIDColumn]
            $clusterAndDomain += [pscustomobject]@{
                'clusterID' = $clusterID
                'domainID'  = $domainID
            }
        }
        $clusterAndDomainLineIndex++
    }
    Until ($lineContent -eq '\.')

    #Get License Models
    LogMessage -type INFO -message "[$jumpboxName] Retrieving Licensing Models"
    #Find the column number for each required element. Future proofed if column number changes
    $headerLine = ($psqlContent | Select-String -SimpleMatch "COPY licensemanager.licensing_info" | Select-Object Line).Line
    $columnHeaders = [regex]::Match($headerLine, '\((.*?)\)').Groups[1].Value
    $columns = $columnHeaders -split '\s*,\s*'
    $resourceTypeColumn = $columns.IndexOf('resource_type')
    $resourceIdColumn = $columns.IndexOf('resource_id')
    $licensingModeColumn = $columns.IndexOf('licensing_mode')

    $licenseModelLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY licensemanager.licensing_info" | Select-Object Line, LineNumber).LineNumber
    If ($licenseModelLineNumber) {
        $licenseModelLineIndex = $licenseModelLineNumber
        $licenseModels = @()
        Do {
            $lineContent = $psqlContent | Select-Object -Index $licenseModelLineIndex
            If ($lineContent -ne '\.') {
                $resourceType = $lineContent.split("`t")[$resourceTypeColumn]
                $resourceId = $lineContent.split("`t")[$resourceIdColumn]
                $licensingMode = $lineContent.split("`t")[$licensingModeColumn]
                $licenseModels += [pscustomobject]@{
                    'resourceType'  = $resourceType
                    'resourceId'    = $resourceId
                    'licensingMode' = $licensingMode
                }
            }
            $licenseModelLineIndex++
        }
        Until ($lineContent -eq '\.')
    }

    #Get License Keys
    LogMessage -type INFO -message "[$jumpboxName] Retrieving License Keys"
    #Find the column number for each required element. Future proofed if column number changes
    $headerLine = ($psqlContent | Select-String -SimpleMatch "COPY licensemanager.licensekey" | Select-Object Line).Line
    $columnHeaders = [regex]::Match($headerLine, '\((.*?)\)').Groups[1].Value
    $columns = $columnHeaders -split '\s*,\s*'
    $idColumn = $columns.IndexOf('id')
    $keyColumn = $columns.IndexOf('key')
    $descriptionColumn = $columns.IndexOf('description')
    $productTypeColumn = $columns.IndexOf('product_type')

    $licenseLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY licensemanager.licensekey" | Select-Object Line, LineNumber).LineNumber
    $licenseLineIndex = $licenseLineNumber
    $licenseKeys = @()
    Do {
        $lineContent = $psqlContent | Select-Object -Index $licenseLineIndex
        If ($lineContent -ne '\.') {
            $id = $lineContent.split("`t")[$idColumn]
            $key = $lineContent.split("`t")[$keyColumn]
            $description = $lineContent.split("`t")[$descriptionColumn]
            $productType = $lineContent.split("`t")[3]
            $licenseKeys += [pscustomobject]@{
                'id'          = $id
                'key'         = $key
                'description' = $description
                'productType' = $productType
            }
        }
        $licenseLineIndex++
    }
    Until ($lineContent -eq '\.')

    LogMessage -type INFO -message "[$jumpboxName] Retrieving PSC Data"
    #Find the column number for each required element. Future proofed if column number changes
    $headerLine = ($psqlContent | Select-String -SimpleMatch "COPY public.psc (id" | Select-Object Line).Line
    $columnHeaders = [regex]::Match($headerLine, '\((.*?)\)').Groups[1].Value
    $columns = $columnHeaders -split '\s*,\s*'
    $pscIdColumn = $columns.IndexOf('id')
    $ssoDomainColumn = $columns.IndexOf('sso_domain')

    $pscsStartingLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.psc (id" | Select-Object Line, LineNumber).LineNumber
    $pscsLineIndex = $pscsStartingLineNumber
    $pscs = @()
    Do {
        $lineContent = $psqlContent | Select-Object -Index $pscsLineIndex
        If ($lineContent -ne '\.') {
            $pscId = $lineContent.split("`t")[$pscIdColumn]
            $ssoDomain = $lineContent.split("`t")[$ssoDomainColumn]
            $pscs += [pscustomobject]@{
                'id'        = $pscId
                'ssoDomain' = $ssoDomain
            }
        }
        $pscsLineIndex ++
    }
    Until ($lineContent -eq '\.')

    #Find the column number for each required element. Future proofed if column number changes
    $headerLine = ($psqlContent | Select-String -SimpleMatch "COPY public.vcenter_and_psc" | Select-Object Line).Line
    $columnHeaders = [regex]::Match($headerLine, '\((.*?)\)').Groups[1].Value
    $columns = $columnHeaders -split '\s*,\s*'
    $vCenterIdColumn = $columns.IndexOf('vcenter_id')
    $pscIdColumn = $columns.IndexOf('psc_id')
    $vCentersAndPscsStartingLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.vcenter_and_psc" | Select-Object Line, LineNumber).LineNumber
    $vCentersAndPscsLineIndex = $vCentersAndPscsStartingLineNumber
    $vCentersAndPscs = @()
    Do {
        $lineContent = $psqlContent | Select-Object -Index $vCentersAndPscsLineIndex
        If ($lineContent -ne '\.') {
            $vCenterId = $lineContent.split("`t")[$vCenterIdColumn]
            $pscId = $lineContent.split("`t")[$pscIdColumn]
            $vCentersAndPscs += [pscustomobject]@{
                'vcenterId' = $vCenterId
                'pscId'     = $pscId
            }
        }
        $vCentersAndPscsLineIndex ++
    }
    Until ($lineContent -eq '\.')

    LogMessage -type INFO -message "[$jumpboxName] Assembling Workload Domain Data"
    #GetDomainDetails
    #Find the column number for each required element. Future proofed if column number changes
    $headerLine = ($psqlContent | Select-String -SimpleMatch "COPY public.domain (id" | Select-Object Line).Line
    $columnHeaders = [regex]::Match($headerLine, '\((.*?)\)').Groups[1].Value
    $columns = $columnHeaders -split '\s*,\s*'
    $domainIdColumn = $columns.IndexOf('id')
    $domainNameColumn = $columns.IndexOf('name')
    $domainTypeColumn = $columns.IndexOf('type')

    $domainsStartingLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.domain (id" | Select-Object Line, LineNumber).LineNumber
    $domainLineIndex = $domainsStartingLineNumber
    $workloadDomains = @()
    Do {
        $lineContent = $psqlContent | Select-Object -Index $domainLineIndex
        If ($lineContent -ne '\.') {
            $domainId = $lineContent.split("`t")[$domainIdColumn]
            $domainName = $lineContent.split("`t")[$domainNameColumn]
            $domainType = $lineContent.split("`t")[$domainTypeColumn]
            $vCenter = $vCenters | Where-Object { $_.vCenterDomainID -eq $domainId }
            $pscId = ($vCentersAndPscs | where-object { $_.vCenterId -eq $vCenters.vCenterID }).pscId
            $ssoDomain = ($pscs | where-object { $pscs.id -eq $pscId }).ssoDomain
            $vCenterDetails = [pscustomobject]@{
                'id'      = $vCenter.vCenterID
                'version' = $vCenter.vCenterVersion
                'fqdn'    = $vCenter.vCenterFqdn
                'ip'      = $vCenter.vCenterIp
                'vmname'  = $vCenter.vCenterVMname
            }
            #HostID from hostsAndDomains of first host in domain based on DomainID
            $hostID = (($hostsAndDomains | Where-Object { $_.domainID -eq $domainID })[0]).hostId

            #PoolID from HostandPools based on HostID
            $poolID = ($hostsAndPools | Where-Object { $_.hostId -eq $hostID }).PoolID

            #poolName from Networkpools based on PoolID
            $poolName = ($networkPools | Where-Object { $_.poolID -eq $poolID }).PoolName

            #networks from poolID
            $domainNetworks = ($poolsAndNetworks | Where-Object { $_.poolID -eq $poolID }).networkID
            $vmotionNetwork = $networks | Where-Object { ($_.type -eq "VMOTION") -and ($_.id -in $domainNetworks) }
            $vsanNetwork = $networks | Where-Object { ($_.type -eq "VSAN") -and ($_.id -in $domainNetworks) }


            $nsxClusterDetailsObject = New-Object -type psobject
            $nsxClusterDetailsObject | Add-Member -NotePropertyName 'clusterVip' -NotePropertyValue ($nsxtManagerClusters | Where-Object { $_.domainIDs -contains $domainId }).clusterVip
            $nsxClusterDetailsObject | Add-Member -NotePropertyName 'clusterFqdn' -NotePropertyValue ($nsxtManagerClusters | Where-Object { $_.domainIDs -contains $domainId }).clusterFqdn
            $nsxClusterDetailsObject | Add-Member -NotePropertyName 'rootNsxtManagerPassword' -NotePropertyValue ($passwordVaultObject | Where-Object { ($_.entityName -eq ($nsxtManagerClusters | Where-Object { $_.domainIDs -contains $domainId }).clusterFqdn) -and ($_.credentialType -eq 'SSH') }).password
            $nsxClusterDetailsObject | Add-Member -NotePropertyName 'nsxtAdminPassword' -NotePropertyValue ($passwordVaultObject | Where-Object { ($_.entityName -eq ($nsxtManagerClusters | Where-Object { $_.domainIDs -contains $domainId }).clusterFqdn) -and ($_.credentialType -eq 'API') -and ($_.username -eq 'admin') }).password
            $nsxClusterDetailsObject | Add-Member -NotePropertyName 'nsxtAuditPassword' -NotePropertyValue ($passwordVaultObject | Where-Object { ($_.entityName -eq ($nsxtManagerClusters | Where-Object { $_.domainIDs -contains $domainId }).clusterFqdn) -and ($_.credentialType -eq 'AUDIT') }).password

            If (($licenseModels | Where-Object { $_.resourceId -eq $domainID }).licensingMode) {
                $licenseModel = ($licenseModels | Where-Object { $_.resourceId -eq $domainID }).licensingMode
            } else {
                $licenseModel = 'PERPETUAL'
            }
            $workloadDomains += [pscustomobject]@{
                'domainName'            = $domainName
                'domainID'              = $domainID
                'domainType'            = $domainType
                'licenseModel'          = $licenseModel
                'ssoDomain'             = $ssoDomain
                'networkPool'           = $poolName
                'vCenterDetails'        = $vCenterDetails
                'nsxClusterDetails'     = $nsxClusterDetailsObject
                'nsxNodeDetails'        = ($nsxtManagerClusters | Where-Object { $_.domainIDs -contains $domainId }).nsxNodes
                'vsphereClusterDetails' = @($clusters | Where-Object { $_.vCenterID -eq $vcenterDetails.id })
            }
        }
        $domainLineIndex++
    } Until ($lineContent -eq '\.')

    LogMessage -type INFO -message "[$jumpboxName] Creating extracted-sddc-data.json"
    $sddcDataObject = New-Object -TypeName psobject
    $sddcDataObject | Add-Member -notepropertyname 'sddcManager' -notepropertyvalue $sddcManagerObject
    $sddcDataObject | Add-Member -notepropertyname 'mgmtDomainInfrastructure' -notepropertyvalue $mgmtDomainInfrastructure
    $sddcDataObject | Add-Member -notepropertyname 'licenseKeys' -notepropertyvalue $licenseKeys
    $sddcDataObject | Add-Member -notepropertyname 'workloadDomains' -notepropertyvalue $workloadDomains
    $sddcDataObject | Add-Member -notepropertyname 'passwords' -notepropertyvalue $passwordVaultObject
    $sddcDataObject | ConvertTo-Json -Depth 10 | Out-File "$parentFolder\extracted-sddc-data.json"

    #Cleanup
    <# LogMessage -type INFO -message "[$jumpboxName] Cleaning up extracted files"
    Remove-Item -Path "$parentFolder\decrypted-sddc-manager-backup.tar.gz" -force -confirm:$false
    Remove-Item -Path "$parentFolder\decrypted-sddc-manager-backup.tar" -force -confirm:$false
    Remove-Item -path "$parentFolder\$extractedBackupFolder" -Recurse #>
    Pop-Location
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function New-ExtractDataFromSDDCBackup

Function Update-ExtractedSDDCData {
    <#
    .SYNOPSIS
    Updates extracted SDDC Data JSON file with detail not caprured in the SDDC manager backup VCF Instance Recovery.

    .DESCRIPTION
    The Update-ExtractedSDDCData cmdlet Updates extracted SDDC Data JSON file with detail not caprured in the SDDC manager backup VCF Instance Recovery.

    .EXAMPLE
    Update-ExtractedSDDCData -extractedSDDCDataFile "".\extracted-sddc-data.json" -sddcManagerFQDN "sfo-vcf01.sfo.rainpole.io" -sddcManagerAdmin "administrator@vsphere.local" -sddcManagerAdminPassword "VMw@re1!VMw@re1!"

    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem

    .PARAMETER sddcManagerFQDN
    FQDN of the SDDC Manager that should be queried

    .PARAMETER sddcManagerAdminUser
    Admin username for SDDC Manager

    .PARAMETER sddcManagerAdminUserPassword
    Password for the admin user on SDDC Manager

    .PARAMETER vCenterFqdn
    FQDN of the target vCenter to update details from
    #>

    Param(
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $true)][String] $sddcManagerFQDN,
        [Parameter (Mandatory = $true)][String] $sddcManagerAdmin,
        [Parameter (Mandatory = $true)][String] $sddcManagerAdminPassword,
        [Parameter (Mandatory = $true)][String] $vCenterFQDN
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON
    $sddcManagerConnection = Connect-VcfSddcManagerServer -server $sddcManagerFQDN -User $sddcManagerAdmin -Password $sddcManagerAdminPassword

    Foreach ($workloadDomain in $extractedSddcData.workloadDomains | Where-Object { $_.vcenterDetails.fqdn -eq $vCenterFQDN }) {
        $vCenterAdmin = ($extractedSddcData.passwords | Where-Object { ($_.credentialType -eq "SSO") -and ($_.entityName -eq $vCenterFQDN) -and ($_.entityType -eq "PSC") }).username
        $vCenterAdminPassword = ($extractedSddcData.passwords | Where-Object { ($_.credentialType -eq "SSO") -and ($_.entityName -eq $vCenterFQDN) -and ($_.entityType -eq "PSC") }).password
        $vCenterConnection = Connect-VIServer -server $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword

        Foreach ($cluster in $workloadDomain.vsphereClusterDetails) {
            $clusterInfo = Invoke-VcfGetCluster -Id $cluster.id
            $clusterName = $clusterInfo.Name
            LogMessage -type INFO -message "Injecting cluster name $clusterName into $($workloadDomain.domainName)"
            $cluster.name = $clusterName
            $primaryDatastoreName = $clusterInfo.PrimaryDatastoreName
            $primaryDatastorePolicy = ((Get-Datastore -name $primaryDatastoreName | Get-SpbmEntityConfiguration)).storagePolicy.name
            LogMessage -type INFO -message "Injecting primary datastore name $primaryDatastoreName into $($workloadDomain.domainName)"
            $cluster.primaryDatastoreName = $primaryDatastoreName
            LogMessage -type INFO -message "Injecting primary datastore storage policy $primaryDatastorePolicy into $($workloadDomain.domainName)"
            $cluster.primaryDatastorePolicy = $primaryDatastorePolicy
            Foreach ($vds in $cluster.vdsDetails) {
                $vdsName = (Invoke-VcfGetVdses -ClusterId $cluster.id | Where-Object { $_.id -eq $vds.id }).Name
                $vds.dvsName = $vdsName

                Foreach ($portGroup in $vds.PortGroups) {
                    if ($portGroup.TransportType -eq "VM_MANAGEMENT") {
                        $vmManagementPGName = ((Invoke-VcfGetVdses -ClusterId $cluster.id).PortGroups | Where-Object { $_.TransportType -eq "VM_MANAGEMENT" }).Name
                        LogMessage -type INFO -message "Injecting portgroup name $vmManagementPGName on $($vds.dvsName)"
                        $portGroup | Add-Member -NotePropertyName "Name" -NotePropertyValue $vmManagementPGName -Force
                    }
                    if ($portGroup.TransportType -eq "MANAGEMENT") {
                        $managementPGName = ((Invoke-VcfGetVdses -ClusterId $cluster.id).PortGroups | Where-Object { $_.TransportType -eq "MANAGEMENT" }).Name
                        LogMessage -type INFO -message "Injecting portgroup name $managementPGName on $($vds.dvsName)"
                        $portGroup | Add-Member -NotePropertyName "Name" -NotePropertyValue $managementPGName -Force
                    }
                    if ($portGroup.TransportType -eq "VMOTION") {
                        $vMotionPGName = ((Invoke-VcfGetVdses -ClusterId $cluster.id).PortGroups | Where-Object { $_.TransportType -eq "VMOTION" }).Name
                        LogMessage -type INFO -message "Injecting portgroup name $vMotionPGName on $($vds.dvsName)"
                        $portGroup | Add-Member -NotePropertyName "Name" -NotePropertyValue $vMotionPGName -Force
                    }
                    if ($portGroup.TransportType -eq "VSAN") {
                        $vSanPGName = ((Invoke-VcfGetVdses -ClusterId $cluster.id).PortGroups | Where-Object { $_.TransportType -eq "VSAN" }).Name
                        LogMessage -type INFO -message "Injecting portgroup name $vSanPGName on $($vds.dvsName)"
                        $portGroup | Add-Member -NotePropertyName "Name" -NotePropertyValue $vSanPGName -Force
                    }
                }
            }
        }
        Disconnect-VIServer * -confirm:$false
    }
    LogMessage -type INFO -message "[$jumpboxName] Updating Extracted Data"
    $extractedSddcData | ConvertTo-Json -Depth 20 | Out-File $extractedSDDCDataFile
}
Export-ModuleMember -Function Update-ExtractedSDDCData



Function New-VVFBasedPartialBringupJsonSpec {

    Param(
        [Parameter (Mandatory = $true)][String] $tempVcenterIp,
        [Parameter (Mandatory = $true)][String] $tempVcenterFqdn,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $true)][String] $transportVlanId,
        [Parameter (Mandatory = $true)][boolean] $dedupEnabled,
        [Parameter (Mandatory = $true)][String] $vcenterServerSize,
        [Parameter (Mandatory = $true)][String] $esxManagementNetworkSubnet,
        [Parameter (Mandatory = $true)][String]$esxManagementNetworkGateway
    )

    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"

    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $managementDomain = $extractedSddcData.workloadDomains | Where-Object { $_.domaintype -eq "MANAGEMENT" }
    $domainName = $managementDomain.domainName
    $defaultManagementcluster = $managementDomain.vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' }
    $defaultManagementclusterDistributedSwitches = $defaultManagementcluster.vdsDetails
    $managementNetworkSubnet = $esxManagementNetworkSubnet

    LogMessage -Type INFO -Message "[$jumpboxName] Generating VVF Bringup JSON Specification"

    #dnsSpec
    If ($extractedSddcData.mgmtDomainInfrastructure.secondaryDnsServer -eq "n/a") {
        [Array]$nameServers = $extractedSddcData.mgmtDomainInfrastructure.primaryDnsServer
    } else {
        [Array]$nameServers = $extractedSddcData.mgmtDomainInfrastructure.primaryDnsServer, $extractedSddcData.mgmtDomainInfrastructure.secondaryDnsServer
    }
    $dnsObject = @()
    $dnsObject += [pscustomobject]@{
        'nameservers' = $nameServers
        'subdomain'   = $tempVcenterFqdn.split(".", 2)[1]
    }

    #ntpServers
    If ($extractedSddcData.mgmtDomainInfrastructure.ntpServers[1] -eq "n/a") {
        [Array]$ntpServers = $extractedSddcData.mgmtDomainInfrastructure.ntpServers[0]
    } else {
        [Array]$ntpServers = $extractedSddcData.mgmtDomainInfrastructure.ntpServers[0], $extractedSddcData.mgmtDomainInfrastructure.ntpServers[1]
    }

    #vcenterSpec
    $vcenterObject = @()
    $vcenterObject += [pscustomobject]@{
        'vcenterHostname'       = $tempVcenterFqdn
        'rootVcenterPassword'   = ($extractedSddcData.passwords | Where-Object { ($_.domainName -eq $managementDomain.domainName) -and ($_.entityType -eq "VCENTER") -and ($_.username -eq "root") }).password
        'adminUserSsoPassword'  = ($extractedSddcData.passwords | Where-Object { ($_.domainName -eq $managementDomain.domainName) -and ($_.entityType -eq "PSC") }).password
        'vmSize'                = $vcenterServerSize
        'storageSize'           = 'lstorage'
        'ssoDomain'             = ($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).ssoDomain
        'useExistingDeployment' = $false
    }

    #clusterSpec
    $clusterObject = @()
    $clusterObject += [pscustomobject]@{
        'clusterName'    = $extractedSddcData.mgmtDomainInfrastructure.vsan_datastore
        'datacenterName' = $extractedSddcData.mgmtDomainInfrastructure.datacenter
    }

    #vsanSpec
    If ($defaultManagementcluster.primaryDatastoreType -eq "VSAN_ESA") {
        $ESAenabledtrueobject = @()
        $ESAenabledtrueobject += [pscustomobject]@{
            'enabled' = $true
        }
    } elseIf ($defaultManagementcluster.primaryDatastoreType -eq "VSAN_OSA") {
        $ESAenabledtrueobject = @()
        $ESAenabledtrueobject += [pscustomobject]@{
            'enabled' = $false
        }
    }
    $vsanObject = @()
    $vsanObject += [pscustomobject]@{
        'datastoreName' = $extractedSddcData.mgmtDomainInfrastructure.vsan_datastore
        'esaConfig'     = ($ESAenabledtrueobject | Select-Object -Skip 0)
    }
    If ($defaultManagementcluster.primaryDatastoreType -eq "VSAN-OSA") {
        $vsanObject | Add-Member -NotePropertyName 'vsanDedup' -NotePropertyValue $dedupEnabled
    }
    $datastoreSpecObject = @()
    $datastoreSpecObject += [pscustomobject]@{
        'vsanSpec' = ($vsanObject | Select-Object -Skip 0)
    }

    #hostSpecsObject
    $mgmtHosts = ($extractedSddcData.passwords | where-object { ($_.domainName -eq $domainName) -and ($_.entityType -eq "ESXI") -and ($_.username -eq "root") -and ($_.entityName -in $defaultManagementcluster.hosts.hostname) }) | Sort-Object -Property entityName
    $hostSpecsObject = @()
    Foreach ($mgmtHost in $mgmtHosts) {
        $hostCredentialsObject = @()
        $hostCredentialsObject += [pscustomobject]@{
            'username' = $mgmtHost.Username
            'password' = $mgmtHost.Password
        }

        If ([System.Environment]::OSVersion.Platform -eq 'Win32NT') {
            $sslThumbPrint = (echo "Q" | openssl.exe s_client -connect "$($mgmtHost.entityName):443" -showcerts 2>$null | Filter-X509 | openssl.exe x509 -noout -fingerprint -sha256).split("sha256 Fingerprint=")[1]
        } else {
            $sslThumbPrint = (echo "Q" | openssl s_client -connect "$($mgmtHost.entityName):443" -showcerts 2>$null | Filter-X509 | openssl x509 -noout -fingerprint -sha256).split("sha256 Fingerprint=")[1]
        }
        $hostSpecsObject += [pscustomobject]@{
            'hostname'      = $mgmtHost.entityName
            'credentials'   = ($hostCredentialsObject | Select-Object -Skip 0)
            'sslThumbprint' = $sslThumbPrint
        }
    }

    #networkSpecs
    <# $vmotionIpObject = @()
    $vmotionIpObject += [pscustomobject]@{
        'startIpAddress' = ($defaultManagementCluster.hosts[0].networks | Where-Object { $_.type -eq 'VMOTION' }).startIPAddress
        'endIpAddress'   = ($defaultManagementCluster.hosts[0].networks | Where-Object { $_.type -eq 'VMOTION' }).endIpAddress
    }
    $vsanIpObject = @()
    $vsanIpObject += [pscustomobject]@{
        'startIpAddress' = ($defaultManagementCluster.hosts[0].networks | Where-Object { $_.type -eq 'VSAN' }).startIPAddress
        'endIpAddress'   = ($defaultManagementCluster.hosts[0].networks | Where-Object { $_.type -eq 'VSAN' }).endIpAddress
    } #>

    $activeUplinksArray = @()
    $activeUplinksArray += "uplink1"
    $activeUplinksArray += "uplink2"

    $networkSpecsObject = @()

    #VM_MANAGEMENT network
    [IPAddress] $ip = $extractedSddcData.mgmtDomainInfrastructure.netmask
    $octets = $ip.IPAddressToString.Split('.')
    Foreach ($octet in $octets) { $binary = [System.Convert]::ToString([int]$octet, 2).PadLeft(8, '0'); $managementVmNetworkCidr += ($binary.ToCharArray() | Where-Object { $_ -eq '1' }).Count }
    $managementVmNetworkSubnet = ($extractedSddcData.mgmtDomainInfrastructure.subnet + "/" + $managementVmNetworkCidr)
    $networkSpecsObject += [pscustomobject]@{
        'networkType'   = "VM_MANAGEMENT"
        'subnet'        = $managementVmNetworkSubnet
        'gateway'       = $extractedSddcData.mgmtDomainInfrastructure.gateway
        'vlanId'        = ($defaultManagementCluster.vdsDetails.portgroups | Where-Object { $_.transportType -eq 'VM_MANAGEMENT' }).vlanId -as [string]
        'mtu'           = "1500"
        'teamingPolicy' = 'loadbalance_loadbased'
        'activeUplinks' = $activeUplinksArray
        'portGroupKey'  = $extractedSddcData.mgmtDomainInfrastructure.port_group
    }

    #MANAGEMENT network
    Foreach ($octet in $octets) { $binary = [System.Convert]::ToString([int]$octet, 2).PadLeft(8, '0'); $managementNetworkCidr += ($binary.ToCharArray() | Where-Object { $_ -eq '1' }).Count }
    $managementNetworkSubnet = ((($defaultManagementCluster | Where-Object { $_.isDefault -eq 't' }).hosts[0].networks | Where-Object { $_.type -eq 'MANAGEMENT' }).subnet + "/" + $managementNetworkCidr)
    $networkSpecsObject += [pscustomobject]@{
        'networkType'   = "MANAGEMENT"
        'subnet'        = $managementNetworkSubnet
        'gateway'       = $esxManagementNetworkGateway
        'vlanId'        = ($defaultManagementCluster.vdsDetails.portgroups | Where-Object { $_.transportType -eq 'MANAGEMENT' }).vlanId -as [string]
        'mtu'           = ($defaultManagementCluster.hosts[0].networks | Where-Object { $_.type -eq 'MANAGEMENT' }).mtu -as [string]
        'teamingPolicy' = 'loadbalance_loadbased'
        'activeUplinks' = $activeUplinksArray
        'portGroupKey'  = "vcfir-cl01-vds01-pg-esx-mgmt"
    }

    #VMOTION network
    [IPAddress] $ip = ($defaultManagementCluster.hosts[0].networks | Where-Object { $_.type -eq 'VMOTION' }).subnetMask
    $octets = $ip.IPAddressToString.Split('.')
    Foreach ($octet in $octets) { $binary = [System.Convert]::ToString([int]$octet, 2).PadLeft(8, '0'); $vmotionNetworkCidr += ($binary.ToCharArray() | Where-Object { $_ -eq '1' }).Count }
    $vmotionNetworkSubnet = (($defaultManagementCluster.hosts[0].networks | Where-Object { $_.type -eq 'VMOTION' }).subnet + "/" + $vmotionNetworkCidr)
    $networkSpecsObject += [pscustomobject]@{
        'networkType'            = "VMOTION"
        'subnet'                 = $vmotionNetworkSubnet
        'gateway'                = ($defaultManagementCluster.hosts[0].networks | Where-Object { $_.type -eq 'VMOTION' }).gateway
        'includeIpAddressRanges' = ($defaultManagementCluster.hosts[0].networks | Where-Object { $_.type -eq 'VMOTION' }).includeIpAddressRanges
        'vlanId'                 = ($defaultManagementCluster.hosts[0].networks | Where-Object { $_.type -eq 'VMOTION' }).vlanId -as [string]
        'mtu'                    = ($defaultManagementCluster.hosts[0].networks | Where-Object { $_.type -eq 'VMOTION' }).mtu -as [string]
        'teamingPolicy'          = 'loadbalance_loadbased'
        'activeUplinks'          = $activeUplinksArray
        #'standbyUplinks'         = $null
        'portGroupKey'           = "vcfir-cl01-vds01-pg-vmotion"
    }

    #VSAN network
    [IPAddress] $ip = ($defaultManagementCluster.hosts[0].networks | Where-Object { $_.type -eq 'VSAN' }).subnetMask
    $octets = $ip.IPAddressToString.Split('.')
    Foreach ($octet in $octets) { $binary = [System.Convert]::ToString([int]$octet, 2).PadLeft(8, '0'); $vsanNetworkCidr += ($binary.ToCharArray() | Where-Object { $_ -eq '1' }).Count }
    $vsanNetworkSubnet = (($defaultManagementCluster.hosts[0].networks | Where-Object { $_.type -eq 'VSAN' }).subnet + "/" + $vmotionNetworkCidr)
    $networkSpecsObject += [pscustomobject]@{
        'networkType'            = "VSAN"
        'subnet'                 = $vsanNetworkSubnet
        'gateway'                = ($defaultManagementCluster.hosts[0].networks | Where-Object { $_.type -eq 'VSAN' }).gateway
        #'subnetMask'             = $null
        #'includeIpAddress'       = $null
        'includeIpAddressRanges' = ($defaultManagementCluster.hosts[0].networks | Where-Object { $_.type -eq 'VSAN' }).includeIpAddressRanges
        'vlanId'                 = ($defaultManagementCluster.hosts[0].networks | Where-Object { $_.type -eq 'VSAN' }).vlanId -as [string]
        'mtu'                    = ($defaultManagementCluster.hosts[0].networks | Where-Object { $_.type -eq 'VSAN' }).mtu -as [string]
        'teamingPolicy'          = 'loadbalance_loadbased'
        'activeUplinks'          = $activeUplinksArray
        #'standbyUplinks'         = $null
        'portGroupKey'           = "vcfir-cl01-vds01-pg-vsan"
    }

    #dvsSpecsObject
    $hostConnection = Connect-ViServer $($mgmtHosts[0].entityName) -user $hostSpecsObject[0].credentials.username -password $hostSpecsObject[0].credentials.password
    $nics = (Get-EsxCli -VMHost $($mgmtHosts[0].entityName)).network.nic.list() | Select-Object Name, Driver, LinkStatus, Description

    $nicsDisplayObject = @()
    $nicsIndex = 1
    $nicsDisplayObject += [pscustomobject]@{
        'ID'          = "ID"
        'deviceName'  = "Device Name"
        'driver'      = "Driver"
        'linkStatus'  = "Link Status"
        'description' = "Description"
    }
    $nicsDisplayObject += [pscustomobject]@{
        'ID'          = "--"
        'deviceName'  = "-----------"
        'driver'      = "----------"
        'linkStatus'  = "-----------"
        'description' = "-----------------------------------------------"
    }
    Foreach ($nic in $nics) {
        $nicsDisplayObject += [pscustomobject]@{
            'ID'          = $nicsIndex
            'deviceName'  = $nic.name
            'driver'      = $nic.driver
            'linkStatus'  = $nic.linkStatus
            'description' = $nic.description
        }
        $nicsIndex++
    }
    Write-Host ""; Write-Host " Recreating Virtual Distributed Switches as per previous deployment" -ForegroundColor Yellow
    $vdsConfiguration = @()
    $remainingNicsDisplayObject = $nicsDisplayObject

    #Loop Through VDS Creation
    For ($i = 1; $i -le $defaultManagementclusterDistributedSwitches.count; $i++) {
        $vdsConfigurationIndex = ($i - 1)
        If ($defaultManagementclusterDistributedSwitches[$vdsConfigurationIndex].networks -ne $null) {
            Do {
                $nicNamesArray = @()
                Write-Host ""; $remainingNicsDisplayObject | format-table -Property @{Expression = " " }, id, deviceName, driver, linkStatus, description -autosize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r", "`n") }
                If ($defaultManagementclusterDistributedSwitches[$vdsConfigurationIndex].transportZones) {
                    $networksDisplay = ($defaultManagementclusterDistributedSwitches[$vdsConfigurationIndex].networks += "OVERLAY") -join (",")
                    $dvsName = "vcfir-cl01-vds0$($i)-nsx"
                } else {
                    $networksDisplay = $defaultManagementclusterDistributedSwitches[$vdsConfigurationIndex].networks -join (",")
                    $dvsName = "vcfir-cl01-vds0$($i)"
                }
                Write-Host ""; Write-Host " Creating " -ForegroundColor Yellow -nonewline; Write-Host $dvsName -ForegroundColor cyan -nonewline; Write-Host " which will contain the networks: " -ForegroundColor Yellow -nonewline; Write-Host "$networksDisplay" -ForegroundColor Cyan
                Write-Host " Enter a comma seperated list of IDs to use as vmnics for this VDS, or C to Cancel: " -ForegroundColor Yellow -nonewline
                $nicSelection = Read-Host
                If ($nicSelection -ne "C") {
                    $nicSelectionInvalid = $false
                    $nicArray = $nicSelection -split (",")
                    Foreach ($nic in $nicArray) {
                        $nicNamesArray += ($nicsDisplayObject | Where-Object { $_.id -eq $nic }).deviceName
                        If ($nic -notin $nicsDisplayObject.id) {
                            $nicSelectionInvalid = $true
                        }
                    }
                }
            } Until (($nicSelectionInvalid -eq $false) -OR ($nicSelection -eq "c"))
            If ($nicSelection -eq "c") { Break }
            $individualVds = [PSCustomObject]@{
                'vdsName'     = $dvsName
                'nicnames'    = $nicNamesArray
                'vdsNetworks' = $defaultManagementclusterDistributedSwitches[$vdsConfigurationIndex].networks
                'portgroups'  = $defaultManagementclusterDistributedSwitches[$vdsConfigurationIndex].portgroups
            }
            $vdsConfiguration += $individualVds
            $tempremainingNicsDisplayObject = @()
            Foreach ( $displaynic in $remainingNicsDisplayObject) {
                If ($displaynic.id -notin $nicArray) {
                    $tempremainingNicsDisplayObject += $displaynic
                }
            }
            $remainingNicsDisplayObject = $tempremainingNicsDisplayObject
        }
    }
    If (($nicSelection -eq "c") -or ($nicSelection -eq "c")) { Break }

    $proposedConfigDisplayObject = @()
    $configIndex = 1
    $proposedConfigDisplayObject += [pscustomobject]@{
        'vdsName'     = "VDS Name"
        'nicnames'    = "NIC Names"
        'vdsNetworks' = "VDS Networks"
    }
    $proposedConfigDisplayObject += [pscustomobject]@{
        'vdsName'     = "----------------------------------------"
        'nicnames'    = "---------------"
        'vdsNetworks' = "------------------------------"
    }
    Foreach ($config in $vdsConfiguration) {
        $proposedConfigDisplayObject += [pscustomobject]@{
            'vdsName'     = $config.vdsName
            'nicnames'    = $config.nicnames -join (", ")
            'vdsNetworks' = $config.vdsNetworks -join (", ")
        }
        $configIndex++
    }
    Write-Host ""; Write-Host " Proposed VDS Configuration " -ForegroundColor Yellow
    Write-Host ""; $proposedConfigDisplayObject | format-table -Property @{Expression = " " }, vdsName, nicnames, vdsNetworks, -autosize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r", "`n") }
    Write-Host ""; Write-Host " Do you wish to proceed with the proposed configuration? (Y/N): " -ForegroundColor Yellow -nonewline
    $proposedConfigAccepted = Read-Host
    $proposedConfigAccepted = $proposedConfigAccepted -replace "`t|`n|`r", ""

    If ($proposedConfigAccepted -ieq "Y") {
        #Update Objects in Memory with chosen nics
        Foreach ($vds in $defaultManagementclusterDistributedSwitches) {
            If ($vds.networks -ne $null) {
                $nicsToUse = ($proposedConfigDisplayObject | Where-Object { (($_.vdsNetworks.split(", ")) -join (",")) -eq ($vds.networks -join (",")) }).nicnames
            } else {
                $nicsToUse = ($proposedConfigDisplayObject | Where-Object { $_.vdsNetworks -eq "OVERLAY" }).nicnames
            }
            $vds.vmnics = @($nicsToUse -split (", "))
        }
    }

    $dvsSpecObject = @()
    Foreach ($distributedSwitch in $defaultManagementclusterDistributedSwitches) {
        If ($distributedSwitch.networks -ne $null) {
            $vmnicObject = @()
            $vmnicObject += [pscustomobject]@{
                'id'     = $distributedSwitch.vmnics[0]
                'uplink' = "uplink1"
            }
            $vmnicObject += [pscustomobject]@{
                'id'     = $distributedSwitch.vmnics[1]
                'uplink' = "uplink2"
            }

            If ($distributedSwitch.networks -like "*OVERLAY*") {
                $dvsName = ("vcfir-cl01-vds0" + $($defaultManagementclusterDistributedSwitches.indexof($distributedSwitch) + 1)) + "-nsx"
            } else {
                $dvsName = $("vcfir-cl01-vds0" + $($defaultManagementclusterDistributedSwitches.indexof($distributedSwitch) + 1))
            }
            $dvsObject = [pscustomobject]@{
                'dvsName'          = $dvsName
                'mtu'              = $distributedSwitch.mtu
                'nsxtSwitchConfig' = $null
                'vmnicsToUplinks'  = $vmnicObject
                'nsxTeamings'      = $teamingsArray
                'networks'         = @($distributedSwitch.networks)
            }
            $dvsSpecObject += $dvsObject
        }
    }

    #vcfOperationsSpec
    $vcfOpsNodesObject += [pscustomobject]@{
        'hostname'         = $managementDomain.vCenterDetails.fqdn
        'rootUserPassword' = 'VMw@re1!VMw@re1!'
        'type'             = 'master'
    }
    $vcfOperationsSpecObject += [pscustomobject]@{
        'nodes'                 = @($vcfOpsNodesObject)
        'adminUserPassword'     = 'VMw@re1!VMw@re1!'
        'applianceSize'         = 'medium'
        'useExistingDeployment' = $false
    }

    $excludedComponentsArray = @("VCF_MANAGEMENT_COMPONENTS_NATIVE_DEPLOYMENT")
    $managementDomainObject = New-Object -TypeName psobject
    $managementDomainObject | Add-Member -notepropertyname 'excludedComponents' -notepropertyvalue $excludedComponentsArray
    $managementDomainObject | Add-Member -notepropertyname 'sddcId' -notepropertyvalue $domainName
    $managementDomainObject | Add-Member -notepropertyname 'workflowType' -notepropertyvalue "VVF"
    $managementDomainObject | Add-Member -notepropertyname 'version' -notepropertyvalue $extractedSddcData.sddcManager.version.Substring(0, $extractedSddcData.sddcManager.version.LastIndexOf("."))
    $managementDomainObject | Add-Member -notepropertyname 'ceipEnabled' -notepropertyvalue $true
    $managementDomainObject | Add-Member -notepropertyname 'dnsSpec' -notepropertyvalue ($dnsObject | Select-Object -Skip 0)
    $managementDomainObject | Add-Member -notepropertyname 'ntpServers' -notepropertyvalue $ntpServers
    $managementDomainObject | Add-Member -notepropertyname 'vcenterSpec' -notepropertyvalue ($vcenterObject | Select-Object -Skip 0)
    $managementDomainObject | Add-Member -notepropertyname 'clusterSpec' -notepropertyvalue ($clusterObject | Select-Object -Skip 0)
    $managementDomainObject | Add-Member -notepropertyname 'datastoreSpec' -notepropertyvalue ($datastoreSpecObject | Select-Object -Skip 0)
    $managementDomainObject | Add-Member -notepropertyname 'hostSpecs' -notepropertyvalue $hostSpecsObject
    $managementDomainObject | Add-Member -notepropertyname 'networkSpecs' -notepropertyvalue $networkSpecsObject
    $managementDomainObject | Add-Member -notepropertyname 'dvsSpecs' -notepropertyvalue $dvsSpecObject
    $managementDomainObject | Add-Member -notepropertyname 'vcfOperationsSpec' -notepropertyvalue ($vcfOperationsSpecObject | Select-Object -Skip 0)

    LogMessage -type INFO -message "[$jumpboxName] Saving partial bringup JSON spec: $(($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).domainName + "-partial-bringup-spec.json")"
    ConvertTo-Json $managementDomainObject -depth 10 | Out-File (($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).domainName + "-partial-bringup-spec.json")
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function New-VVFBasedPartialBringupJsonSpec

Function New-PartialManagementDomainDeployment {
    Param(
        [Parameter (Mandatory = $true)][String] $partialBringupSpecFile,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $true)][String] $cloudBuilderFQDN,
        [Parameter (Mandatory = $true)][String] $cloudBuilderAdminUserPassword
    )

    Try {
        $jumpboxName = hostname
        LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
        LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
        $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
        $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON
        $partialBringupSpecFilePath = (Resolve-Path -Path $partialBringupSpecFile).path

        $url = "https://" + $cloudBuilderFQDN
        LogMessage -Type INFO -Message "[$jumpboxName] Connecting to Cloud Builder Appliance $cloudBuilderFQDN"
        $connectCloudbuilder = Connect-CloudBuilder -fqdn $cloudBuilderFQDN -username 'admin' -password $cloudBuilderAdminUserPassword

        LogMessage -Type WAIT -Message "[$cloudBuilderFQDN] Starting validation of Management Domain specification"
        $sddcValidation = Start-CloudBuilderSDDCValidation -json $partialBringupSpecFilePath
        Start-Sleep 5
        $pollLoopCounter = 0
        Do {
            If (($pollLoopCounter % 5 -eq 0) -AND ($pollLoopCounter -gt 4)) {
                LogMessage -Type INFO -Message "[$cloudBuilderFQDN] Checking status of the Management Domain specification validation"
            }
            $status = Get-CloudBuilderSDDCValidation -id $sddcValidation.id
            If (($pollLoopCounter % 5 -eq 0) -AND ($pollLoopCounter -gt 4)) {
                LogMessage -type INFO -Message "[$cloudBuilderFQDN] Management Domain specification validation: $($status.executionStatus)"
            }
            If ($status.executionStatus -eq "IN_PROGRESS") {
                Start-Sleep 40
                $pollLoopCounter ++
            }
        }
        While ($status.executionStatus -eq "IN_PROGRESS")
        $completedState = Get-CloudBuilderSDDCValidation -id $sddcValidation.id
        $failed = $completedState.validationChecks | Where-Object { $_.resultStatus -eq "FAILED" }
        If ($failed) {
            $realErrorFound = "False"
            $knownErrorFound = "False"
            LogMessage -type NOTE -Message "The following validation errors were reported:"
            Foreach ($failure in $failed) {
                $failureMessages = $($failure.errorResponse.nestedErrors.message -split (";") | Get-Unique)
                Foreach ($failureMessage in $failureMessages) {
                    If ($failureMessage) {
                        If (($failureMessage -like "*is not currently synchronising time with NTP Server*") -OR ($failureMessage -like "*reject or unable to use NTP server*")) {
                            $knownErrorFound = "True"
                            LogMessage -Type WARNING -Message "$($failure.description): $failureMessage"
                        } else {
                            $realErrorFound = "True"
                            LogMessage -Type ERROR -Message "$($failure.description): $failureMessage"
                        }
                    } else {
                        If ($failure -like "*Time Synchronization Validation*") {
                            $knownErrorFound = "True"
                            LogMessage -Type WARNING -Message "$($failure.description)"
                        } else {
                            $realErrorFound = "True"
                            LogMessage -Type ERROR -Message "$($failure.description)"
                        }
                    }
                }
            }
            If ($realErrorFound -eq "True") {
                Break
            }
        }
        LogMessage -Type WAIT -Message "[$cloudBuilderFQDN] Starting Management Domain Deployment"
        $sddcDeployment = Start-CloudBuilderSDDC -json $partialBringupSpecFilePath
        $pollLoopCounter = 0
        $status = Get-CloudBuilderSDDC $sddcDeployment.id
        If ($status.Status -ne "IN_PROGRESS") {
            Do {
                Start-Sleep 5
                $status = Get-CloudBuilderSDDC $sddcDeployment.id
                $pollLoopCounter = $pollLoopCounter + 5
            } Until (($status.Status -eq "IN_PROGRESS") -OR ($pollLoopCounter -eq 180))
            If ($status.Status -ne "IN_PROGRESS") {
                LogMessage -Type ERROR -Message "Management Domain Deployment failed to start after $pollLoopCounter seconds. Please check CloudBuilder UI / Logs for Errors"
                anyKey
                Break
            }
        }
        $pollLoopCounter = 0
        Do {
            If (($pollLoopCounter % 10 -eq 0) -AND ($pollLoopCounter -gt 9)) {
                LogMessage -Type INFO -Message "[$cloudBuilderFQDN] Checking the status of the Management Domain deployment"
            }
            $status = Get-CloudBuilderSDDC $sddcDeployment.id
            If (($pollLoopCounter % 10 -eq 0) -AND ($pollLoopCounter -gt 9)) {
                LogMessage -Type INFO -Message "[$cloudBuilderFQDN] Management Domain deployment: $($status.status)"
            }
            If ($status.Status -eq "IN_PROGRESS") {
                Start-Sleep 60
                $pollLoopCounter ++
            }
        }
        While ($status.Status -eq "IN_PROGRESS")
        If ($status.status -eq "COMPLETED_WITH_FAILURE") {
            LogMessage -Type ERROR -Message "[$cloudBuilderFQDN] Deployment of Management Domain completed with errors. Please consult the UI and troubleshoot"
        } else {
            LogMessage -Type INFO -Message "[$cloudBuilderFQDN] Deployment of Management Domain completed successfully"
        }
    } Catch {
        $ErrorMessage = $_.Exception.Message
        LogMessage -Type EXCEPTION -Message "Error was: $ErrorMessage"
    }
}
Export-ModuleMember -Function New-PartialManagementDomainDeployment

Function New-NSXManagerOvaDeployment {
    <#
    .SYNOPSIS
    Presents a list of NSX Mangers associated with the provided VCF Workload Domain, and deploys an NSX Manager from OVA using data previously extracted from the VCF SDDC Manager Backup

    .DESCRIPTION
    The New-NSXManagerOvaDeployment resents a list of NSX Mangers associated with the provided VCF Workload Domain, and deploys an NSX Manager from OVA using data previously extracted from the VCF SDDC Manager Backup

    .EXAMPLE
    New-NSXManagerOvaDeployment -targetFqdn "sfo-m01-vc02.sfo.rainpole.io" -targetAdmin "administrator@vsphere.local" -targetAdminPassword "VMw@re1!" -extractedSDDCDataFile ".\extracted-sddc-data.json" -workloadDomain "sfo-m01" -restoredNsxManagerDeploymentSize medium -nsxManagerOvaFile "F:\OVA\nsx-unified-appliance-3.2.2.1.0.21487565.ova" -targetType "vcenter"

    .EXAMPLE
    New-NSXManagerOvaDeployment -targetFqdn "sfo01-m01-esx01.sfo.rainpole.io" -targetAdmin "root" -targetAdminPassword "VMw@re1!" -extractedSDDCDataFile ".\extracted-sddc-data.json" -workloadDomain "sfo-m01" -restoredNsxManagerDeploymentSize medium -nsxManagerOvaFile "F:\OVA\nsx-unified-appliance-3.2.2.1.0.21487565.ova" -targetType "esx"

    .PARAMETER targetFqdn
    FQDN of the target vCenter or ESXi host to deploy the NSX Manager OVA to

    .PARAMETER targetAdmin
    Admin user of the target vCenter or ESXi host to deploy the NSX Manager OVA to

    .PARAMETER targetAdminPassword
    Admin password for the target vCenter or ESXi host to deploy the NSX Manager OVA to

    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem

    .PARAMETER workloadDomain
    Name of the VCF workload domain that the NSX Manager to deployed to is associated with

    .PARAMETER restoredNsxManagerDeploymentSize
    Size of the NSX Manager Appliance to deploy

    .PARAMETER nsxManagerOvaFile
    Relative or absolute to the NSX Manager OVA somewhere on the local filesystem

    .PARAMETER targetType
    Specifies the deployment target type. Valid values are 'vcenter' or 'esx'. Default is 'vcenter'.
    #>

    Param(
        [Parameter (Mandatory = $true)][String] $targetFqdn,
        [Parameter (Mandatory = $true)][String] $targetAdmin,
        [Parameter (Mandatory = $true)][String] $targetAdminPassword,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $true)][String] $workloadDomain,
        [Parameter (Mandatory = $true)][String] $restoredNsxManagerDeploymentSize,
        [Parameter (Mandatory = $true)][String] $nsxManagerOvaFile,
        [Parameter (Mandatory = $false)][ValidateSet("vcenter", "esx")][String] $targetType = "vcenter"
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $workloadDomainDetails = ($extractedSDDCData.workloadDomains | Where-Object { $_.domainName -eq $workloadDomain })
    $nsxNodes = $workloadDomainDetails.nsxNodeDetails

    $nsxManagersDisplayObject = @()
    $nsxManagersIndex = 1
    $nsxManagersDisplayObject += [pscustomobject]@{
        'ID'      = "ID"
        'Manager' = "NSX Manager"
    }
    $nsxManagersDisplayObject += [pscustomobject]@{
        'ID'      = "--"
        'Manager' = "------------------"
    }
    Foreach ($nsxNode in $nsxNodes) {
        $nsxManagersDisplayObject += [pscustomobject]@{
            'ID'      = $nsxManagersIndex
            'Manager' = $nsxNode.vmName
        }
        $nsxManagersIndex++
    }
    Write-Host ""; $nsxManagersDisplayObject | format-table -Property @{Expression = " " }, id, Manager -autosize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r", "`n") }
    Do {
        Write-Host ""; Write-Host " Enter the ID of the Manager you wish to redeploy, or C to Cancel: " -ForegroundColor Yellow -nonewline
        $nsxManagerSelection = Read-Host
    } Until (($nsxManagerSelection -in $nsxManagersDisplayObject.ID) -OR ($nsxManagerSelection -eq "c"))
    If ($nsxManagerSelection -eq "c") { Break }
    $selectedNsxManager = $nsxNodes | Where-Object { $_.vmName -eq ($nsxManagersDisplayObject | Where-Object { $_.id -eq $nsxManagerSelection }).manager }

    $vmDatastore = $extractedSDDCData.mgmtDomainInfrastructure.vsan_datastore
    If ($workloadDomainDetails.domainType -eq "MANAGEMENT") {
        $vmNetwork = "vm_mgmt"
    } else {
        $vmNetwork = $extractedSDDCData.mgmtDomainInfrastructure.port_group
    }
    $datacenterName = $extractedSDDCData.mgmtDomainInfrastructure.datacenter
    $clusterName = $extractedSDDCData.mgmtDomainInfrastructure.cluster
    <# #Following parameters converted to known entities for 9.0. Consider refactoring in 9.1 if data is saved in manifest.json

        $vmNetwork = "vcfir-cl01-vds01-pg-vm-mgmt"
        $datacenterName = "vcfir-dc01"
        $clusterName = "vcfir-cl01" #>

    # NSX Manager Appliance Configuration
    $nsxManagerVMName = $selectedNsxManager.vmName
    $nsxManagerIp = $selectedNsxManager.ip
    $nsxManagerHostName = $selectedNsxManager.hostname
    $nsxManagerNetworkMask = $extractedSddcData.mgmtDomainInfrastructure.netmask
    $nsxManagerGateway = $extractedSddcData.mgmtDomainInfrastructure.gateway
    $nsxManagerDns = "$($extractedSddcData.mgmtDomainInfrastructure.primaryDnsServer),$($extractedSddcData.mgmtDomainInfrastructure.secondaryDnsServer)"
    $nsxManagerDnsDomain = $extractedSddcData.mgmtDomainInfrastructure.domain
    $nsxManagerNtpServer = $extractedSddcData.mgmtDomainInfrastructure.ntpServers -join (",")
    $nsxManagerAdminUsername = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "NSXT_MANAGER") -and ($_.domainName -eq $workloadDomain) -and ($_.username -eq "admin") }).username
    $nsxManagerAdminPassword = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "NSXT_MANAGER") -and ($_.domainName -eq $workloadDomain) -and ($_.username -eq "admin") }).password
    $nsxManagerCliPassword = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "NSXT_MANAGER") -and ($_.domainName -eq $workloadDomain) -and ($_.username -eq "admin") }).password
    $nsxManagerCliAuditUsername = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "NSXT_MANAGER") -and ($_.domainName -eq $workloadDomain) -and ($_.credentialType -eq "AUDIT") }).username
    $nsxManagerCliAuditPassword = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "NSXT_MANAGER") -and ($_.domainName -eq $workloadDomain) -and ($_.credentialType -eq "AUDIT") }).password

    LogMessage -type INFO -message "[$jumpboxName] Deploying NSX Manager OVA to $targetType target"

    If ($targetType -eq "vcenter") {
        $targetUrl = '"vi://' + $targetAdmin + ':' + $targetAdminPassword + '@' + $targetFqdn + '/' + $datacenterName + '/host/' + $clusterName + '/"'
    } else {
        $targetUrl = '"vi://' + $targetAdmin + ':' + $targetAdminPassword + '@' + $targetFqdn + '/"'
    }

    If ($nsxManagerCliAuditUsername) {
        $command = '"C:\Program Files\VMware\VMware OVF Tool\ovftool.exe" --noSSLVerify --acceptAllEulas --allowExtraConfig --diskMode=thin --X:injectOvfEnv --X:logFile=ovftool.log --powerOn --X:waitForIp --name="' + $nsxManagerVMName + '" --datastore="' + $vmDatastore + '" --deploymentOption="' + $restoredNsxManagerDeploymentSize + '" --network="' + $vmNetwork + '" --prop:nsx_role="NSX Manager" --prop:nsx_ip_0="' + $nsxManagerIp + '" --prop:nsx_netmask_0="' + $nsxManagerNetworkMask + '" --prop:nsx_gateway_0="' + $nsxManagerGateway + '" --prop:nsx_dns1_0="' + $nsxManagerDns + '" --prop:nsx_domain_0="' + $nsxManagerDnsDomain + '" --prop:nsx_ntp_0="' + $nsxManagerNtpServer + '" --prop:nsx_isSSHEnabled=True --prop:nsx_allowSSHRootLogin=True --prop:nsx_passwd_0="' + $nsxManagerAdminPassword + '" --prop:nsx_cli_username="' + $nsxManagerAdminUsername + '" --prop:nsx_cli_passwd_0="' + $nsxManagerCliPassword + '" --prop:nsx_cli_audit_passwd_0="' + $nsxManagerCliAuditPassword + '" --prop:nsx_cli_audit_username="' + $nsxManagerCliAuditUsername + '" --prop:nsx_hostname="' + $nsxManagerHostName + '" "' + $nsxManagerOvaFile + '" ' + $targetUrl
    } else {
        $command = '"C:\Program Files\VMware\VMware OVF Tool\ovftool.exe" --noSSLVerify --acceptAllEulas --allowExtraConfig --diskMode=thin --X:injectOvfEnv --X:logFile=ovftool.log --powerOn --X:waitForIp --name="' + $nsxManagerVMName + '" --datastore="' + $vmDatastore + '" --deploymentOption="' + $restoredNsxManagerDeploymentSize + '" --network="' + $vmNetwork + '" --prop:nsx_role="NSX Manager" --prop:nsx_ip_0="' + $nsxManagerIp + '" --prop:nsx_netmask_0="' + $nsxManagerNetworkMask + '" --prop:nsx_gateway_0="' + $nsxManagerGateway + '" --prop:nsx_dns1_0="' + $nsxManagerDns + '" --prop:nsx_domain_0="' + $nsxManagerDnsDomain + '" --prop:nsx_ntp_0="' + $nsxManagerNtpServer + '" --prop:nsx_isSSHEnabled=True --prop:nsx_allowSSHRootLogin=True --prop:nsx_passwd_0="' + $nsxManagerAdminPassword + '" --prop:nsx_cli_username="' + $nsxManagerAdminUsername + '" --prop:nsx_cli_passwd_0="' + $nsxManagerCliPassword + '" --prop:nsx_hostname="' + $nsxManagerHostName + '" "' + $nsxManagerOvaFile + '" ' + $targetUrl
    }
    $scriptBlock = { Invoke-Expression "& $using:command" }
    $deploymentJob = Start-Job -scriptblock $scriptBlock -ArgumentList $command
    Do { Sleep 1; $jobStatus = (Get-Job -id $deploymentJob.id).state } Until ($jobStatus -eq "Running" )
    Sleep 10
    $progress = @(Get-Job -id $deploymentJob.id | Receive-Job)
    Foreach ($line in $progress) {
        LogMessage -type INFO -message "[$jumpboxName] $line"
    }
    LogMessage -type INFO -message "[$jumpboxName] Polling at 60 second intervals"
    Do {
        $progress = @(Get-Job -id $deploymentJob.id | Receive-Job)
        If ($progress) {
            If ($progress[-1] -notlike "Disk progress*") {
                Foreach ($line in $progress) {
                    If (($line -ne "") -and ($line -notlike "Task progress*")) {
                        LogMessage -type INFO -message "[$jumpboxName] $line"
                    }
                }
            } else {
                LogMessage -type INFO -message "[$jumpboxName] $($progress[-1])"
            }
        }
        $jobStatus = (Get-Job -id $deploymentJob.id).state
        If ($jobStatus -eq "Running") { Sleep 60 }
    } While ($jobStatus -eq "Running")
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function New-NSXManagerOvaDeployment

Function New-vCenterOvaDeployment {
    <#
    .SYNOPSIS
    Deploys a vCenter appliance from OVA using data previously extracted from the VCF SDDC Manager Backup

    .DESCRIPTION
    The New-vCenterOvaDeployment deploys a vCenter appliance from OVA using data previously extracted from the VCF SDDC Manager Backup

    .EXAMPLE
    New-vCenterOvaDeployment -targetFqdn "sfo-m01-vc02.sfo.rainpole.io" -targetAdmin "administrator@vsphere.local" -targetAdminPassword "VMw@re1!" -extractedSDDCDataFile ".\extracted-sddc-data.json" -workloadDomain "sfo-m01" -restoredvCenterDeploymentSize "small" -vCenterOvaFile "F:\OVA\VMware-vCenter-Server-Appliance-7.0.3.01400-21477706_OVF10.ova" -targetType "vcenter"

    .EXAMPLE
    New-vCenterOvaDeployment -targetFqdn "sfo01-m01-esx01.sfo.rainpole.io" -targetAdmin "root" -targetAdminPassword "VMw@re1!" -extractedSDDCDataFile ".\extracted-sddc-data.json" -workloadDomain "sfo-m01" -restoredvCenterDeploymentSize "small" -vCenterOvaFile "F:\OVA\VMware-vCenter-Server-Appliance-7.0.3.01400-21477706_OVF10.ova" -targetType "esx"

    .PARAMETER targetFqdn
    FQDN of the target vCenter or ESXi host to deploy the vCenter OVA to

    .PARAMETER targetAdmin
    Admin user of the target vCenter or ESXi host to deploy the vCenter OVA to

    .PARAMETER targetAdminPassword
    Admin password for the target vCenter or ESXi host to deploy the vCenter OVA to

    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem

    .PARAMETER workloadDomain
    Name of the VCF workload domain that the vCenter to deployed to is associated with

    .PARAMETER restoredvCenterDeploymentSize
    Size of the vCenter Appliance to deploy

    .PARAMETER vCenterOvaFile
    Relative or absolute to the vCenter OVA somewhere on the local filesystem

    .PARAMETER targetType
    Specifies the deployment target type. Valid values are 'vcenter' or 'esx'. Default is 'vcenter'.
    #>

    Param(
        [Parameter (Mandatory = $true)][String] $targetFqdn,
        [Parameter (Mandatory = $true)][String] $targetAdmin,
        [Parameter (Mandatory = $true)][String] $targetAdminPassword,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $true)][String] $workloadDomain,
        [Parameter (Mandatory = $true)][String] $restoredvCenterDeploymentSize,
        [Parameter (Mandatory = $true)][String] $vCenterOvaFile,
        [Parameter (Mandatory = $false)][ValidateSet("vcenter", "esx")][String] $targetType = "vcenter"
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $workloadDomainDetails = ($extractedSDDCData.workloadDomains | Where-Object { $_.domainName -eq $workloadDomain })
    $vmDatastore = $extractedSDDCData.mgmtDomainInfrastructure.vsan_datastore
    If ($workloadDomainDetails.domainType -eq "MANAGEMENT") {
        $vmNetwork = "vm_mgmt"
    } else {
        $vmNetwork = $extractedSDDCData.mgmtDomainInfrastructure.port_group
    }
    $datacenterName = $extractedSDDCData.mgmtDomainInfrastructure.datacenter
    $clusterName = $extractedSDDCData.mgmtDomainInfrastructure.cluster
    <# #Following parameters converted to known entities for 9.0. Consider refactoring in 9.1 if data is saved in manifest.json

        $vmNetwork = "vcfir-cl01-vds01-pg-vm-mgmt"
        $datacenterName = "vcfir-dc01"
        $clusterName = "vcfir-cl01" #>

    $restoredvCenterVMName = $workloadDomainDetails.vCenterDetails.vmname
    $restoredvCenterIpAddress = $workloadDomainDetails.vCenterDetails.ip
    $restoredvCenterFqdn = $workloadDomainDetails.vCenterDetails.fqdn
    $restoredvCenterNetworkPrefix = 0
    [IPAddress] $ip = $extractedSddcData.mgmtDomainInfrastructure.netmask
    $octets = $ip.IPAddressToString.Split('.')
    Foreach ($octet in $octets) { while (0 -ne $octet) { $octet = ($octet -shl 1) -band [byte]::MaxValue; $restoredvCenterNetworkPrefix++; } }
    $restoredvCenterDnsServers = "$($extractedSddcData.mgmtDomainInfrastructure.primaryDnsServer),$($extractedSddcData.mgmtDomainInfrastructure.secondaryDnsServer)"
    $restoredvCenterGateway = $extractedSddcData.mgmtDomainInfrastructure.gateway
    $restoredvCenterRootPassword = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "VCENTER") -and ($_.domainName -eq $workloadDomain) -and ($_.credentialType -eq "SSH") }).password
    LogMessage -type INFO -message "[$jumpboxName] Deploying vCenter OVA to $targetType target"

    If ($targetType -eq "vcenter") {
        $targetUrl = '"vi://' + $targetAdmin + ':' + $targetAdminPassword + '@' + $targetFqdn + '/' + $datacenterName + '/host/' + $clusterName + '/"'
    } else {
        $targetUrl = '"vi://' + $targetAdmin + ':' + $targetAdminPassword + '@' + $targetFqdn + '/"'
    }

    $command = '"C:\Program Files\VMware\VMware OVF Tool\ovftool.exe" --noSSLVerify --acceptAllEulas --allowExtraConfig --X:enableHiddenProperties --diskMode=thin --X:injectOvfEnv --powerOn --X:waitForIp --X:logFile=ovftool.log --name="' + $restoredvCenterVMName + '" --net:"Network 1"="' + $vmNetwork + '" --datastore="' + $vmDatastore + '" --deploymentOption="' + $restoredvCenterDeploymentSize + '" --prop:guestinfo.cis.appliance.net.addr.family="ipv4" --prop:guestinfo.cis.appliance.net.addr="' + $restoredvCenterIpAddress + '" --prop:guestinfo.cis.appliance.net.pnid="' + $restoredvCenterFqdn + '" --prop:guestinfo.cis.appliance.net.prefix="' + $restoredvCenterNetworkPrefix + '" --prop:guestinfo.cis.appliance.net.mode="static" --prop:guestinfo.cis.appliance.net.dns.servers="' + $restoredvCenterDnsServers + '" --prop:guestinfo.cis.appliance.net.gateway="' + $restoredvCenterGateway + '" --prop:guestinfo.cis.appliance.root.passwd="' + $restoredvCenterRootPassword + '" --prop:guestinfo.cis.appliance.ssh.enabled="True" "' + $vCenterOvaFile + '" ' + $targetUrl
    $scriptBlock = { Invoke-Expression "& $using:command" }
    $deploymentJob = Start-Job -scriptblock $scriptBlock -ArgumentList $command
    Do { Sleep 1; $jobStatus = (Get-Job -id $deploymentJob.id).state } Until ($jobStatus -eq "Running" )
    Sleep 10
    $progress = @(Get-Job -id $deploymentJob.id | Receive-Job)
    Foreach ($line in $progress) {
        LogMessage -type INFO -message "[$jumpboxName] $line"
    }
    LogMessage -type INFO -message "[$jumpboxName] Polling at 60 second intervals"
    Do {
        $progress = @(Get-Job -id $deploymentJob.id | Receive-Job)
        If ($progress) {
            If ($progress[-1] -notlike "Disk progress*") {
                Foreach ($line in $progress) {
                    If (($line -ne "") -and ($line -notlike "Task progress*")) {
                        LogMessage -type INFO -message "[$jumpboxName] $line"
                    }
                }
            } else {
                LogMessage -type INFO -message "[$jumpboxName] $($progress[-1])"
            }
        }
        $jobStatus = (Get-Job -id $deploymentJob.id).state
        If ($jobStatus -eq "Running") { Sleep 60 }
    } While ($jobStatus -eq "Running")
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function New-vCenterOvaDeployment

Function New-SDDCManagerOvaDeployment {
    <#
    .SYNOPSIS
    Deploys an SDDC Manager appliance from OVA using data previously extracted from the VCF SDDC Manager Backup

    .DESCRIPTION
    The New-SDDCManagerOvaDeployment deploys an SDDC Manager appliance from OVA using data previously extracted from the VCF SDDC Manager Backup

    .EXAMPLE
    New-SDDCManagerOvaDeployment -targetFqdn "sfo-m01-vc02.sfo.rainpole.io" -targetAdmin "administrator@vsphere.local" -targetAdminPassword "VMw@re1!" -extractedSDDCDataFile ".\extracted-sddc-data.json" -sddcManagerOvaFile "F:\OVA\VCF-SDDC-Manager-Appliance-4.5.1.0-21682411.ova" -rootUserPassword "VMw@re1!" -vcfUserPassword "VMw@re1!" -localUserPassword "VMw@re1!VMw@re1!" -basicAuthUserPassword "VMw@re1!" -targetType "vcenter"

    .EXAMPLE
    New-SDDCManagerOvaDeployment -targetFqdn "sfo01-m01-esx01.sfo.rainpole.io" -targetAdmin "root" -targetAdminPassword "VMw@re1!" -extractedSDDCDataFile ".\extracted-sddc-data.json" -sddcManagerOvaFile "F:\OVA\VCF-SDDC-Manager-Appliance-4.5.1.0-21682411.ova" -rootUserPassword "VMw@re1!" -vcfUserPassword "VMw@re1!" -localUserPassword "VMw@re1!VMw@re1!" -basicAuthUserPassword "VMw@re1!" -targetType "esx"

    .PARAMETER targetFqdn
    FQDN of the target vCenter or ESXi host to deploy the SDDC Manager OVA to

    .PARAMETER targetAdmin
    Admin user of the target vCenter or ESXi host to deploy the SDDC Manager OVA to

    .PARAMETER targetAdminPassword
    Admin password for the target vCenter or ESXi host to deploy the SDDC Manager OVA to

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

    .PARAMETER targetType
    Specifies the deployment target type. Valid values are 'vcenter' or 'esx'. Default is 'vcenter'.
    #>

    Param(
        [Parameter (Mandatory = $true)][String] $targetFqdn,
        [Parameter (Mandatory = $true)][String] $targetAdmin,
        [Parameter (Mandatory = $true)][String] $targetAdminPassword,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $true)][String] $sddcManagerOvaFile,
        [Parameter (Mandatory = $true)][String] $rootUserPassword,
        [Parameter (Mandatory = $true)][String] $vcfUserPassword,
        [Parameter (Mandatory = $true)][String] $localUserPassword,
        [Parameter (Mandatory = $true)][String] $basicAuthUserPassword,
        [Parameter (Mandatory = $false)][ValidateSet("vcenter", "esx")][String] $targetType = "vcenter"
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    # SDDC Manager Configuration
    $vmDatastore = $extractedSDDCData.mgmtDomainInfrastructure.vsan_datastore
    $vmNetwork = "vm_mgmt"
    $datacenterName = $extractedSDDCData.mgmtDomainInfrastructure.datacenter
    $clusterName = $extractedSDDCData.mgmtDomainInfrastructure.cluster
    <# #Following parameters converted to known entities for 9.0. Consider refactoring in 9.1 if data is saved in manifest.json

        $vmNetwork = "vcfir-cl01-vds01-pg-vm-mgmt"
        $datacenterName = "vcfir-dc01"
        $clusterName = "vcfir-cl01" #>
    $sddcManagerVMName = $extractedSDDCData.sddcManager.vmname
    $sddcManagerBackupPassword = ($extractedSddcData.passwords | Where-Object { $_.entityType -eq "BACKUP" }).password
    $sddcManagerNetworkMask = $extractedSddcData.mgmtDomainInfrastructure.netmask
    $sddcManagerHostName = $extractedSDDCData.sddcManager.fqdn
    $sddcManagerIp = $extractedSDDCData.sddcManager.ip
    $sddcManagerGateway = $extractedSddcData.mgmtDomainInfrastructure.gateway
    $sddcManagerDns = "$($extractedSddcData.mgmtDomainInfrastructure.primaryDnsServer),$($extractedSddcData.mgmtDomainInfrastructure.secondaryDnsServer)"
    $sddcManagerDomainSearch = $extractedSddcData.mgmtDomainInfrastructure.search_path
    $sddcManagerDnsDomain = $extractedSddcData.mgmtDomainInfrastructure.domain
    $ntpServers = $extractedSddcData.mgmtDomainInfrastructure.ntpServers -join (",")

    LogMessage -type INFO -message "[$jumpboxName] Deploying SDDC Manager OVA to $targetType target"

    If ($targetType -eq "vcenter") {
        $targetUrl = '"vi://' + $targetAdmin + ':' + $targetAdminPassword + '@' + $targetFqdn + '/' + $datacenterName + '/host/' + $clusterName + '/"'
    } else {
        $targetUrl = '"vi://' + $targetAdmin + ':' + $targetAdminPassword + '@' + $targetFqdn + '/"'
    }

    $command = '"C:\Program Files\VMware\VMware OVF Tool\ovftool.exe" --noSSLVerify --acceptAllEulas --allowExtraConfig --diskMode=thin --X:enableHiddenProperties --X:injectOvfEnv --X:logFile=ovftool.log --X:waitForIp --powerOn --name="' + $sddcManagerVMName + '" --network="' + $vmNetwork + '" --datastore="' + $vmDatastore + '" --prop:vami.hostname="' + $sddcManagerHostName + '" --prop:vami.ip0.SDDC-Manager="' + $sddcManagerIp + '" --prop:vami.netmask0.SDDC-Manager="' + $sddcManagerNetworkMask + '" --prop:vami.DNS.SDDC-Manager="' + $sddcManagerDns + '" --prop:vami.gateway.SDDC-Manager="' + $sddcManagerGateway + '" --prop:BACKUP_PASSWORD="' + $sddcManagerBackupPassword + '" --prop:ROOT_PASSWORD="' + $rootUserPassword + '" --prop:VCF_PASSWORD="' + $vcfUserPassword + '" --prop:BASIC_AUTH_PASSWORD="' + $basicAuthUserPassword + '" --prop:LOCAL_USER_PASSWORD="' + $localUserPassword + '" --prop:vami.searchpath.SDDC-Manager="' + $sddcManagerDomainSearch + '" --prop:vami.domain.SDDC-Manager="' + $sddcManagerDnsDomain + '" --prop:guestinfo.ntp="' + $ntpServers + '" "' + $sddcManagerOvaFile + '" ' + $targetUrl
    $scriptBlock = { Invoke-Expression "& $using:command" }
    $deploymentJob = Start-Job -scriptblock $scriptBlock -ArgumentList $command
    Do { Sleep 1; $jobStatus = (Get-Job -id $deploymentJob.id).state } Until ($jobStatus -eq "Running" )
    Sleep 10
    $progress = @(Get-Job -id $deploymentJob.id | Receive-Job)
    Foreach ($line in $progress) {
        LogMessage -type INFO -message "[$jumpboxName] $line"
    }
    LogMessage -type INFO -message "[$jumpboxName] Polling at 60 second intervals"
    Do {
        $progress = @(Get-Job -id $deploymentJob.id | Receive-Job)
        If ($progress) {
            If ($progress[-1] -notlike "Disk progress*") {
                Foreach ($line in $progress) {
                    If (($line -ne "") -and ($line -notlike "Task progress*")) {
                        LogMessage -type INFO -message "[$jumpboxName] $line"
                    }
                }
            } else {
                LogMessage -type INFO -message "[$jumpboxName] $($progress[-1])"
            }
        }
        $jobStatus = (Get-Job -id $deploymentJob.id).state
        If ($jobStatus -eq "Running") { Sleep 60 }
    } While ($jobStatus -eq "Running")
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function New-SDDCManagerOvaDeployment

Function New-UploadAndModifySDDCManagerBackup {
    <#
    .SYNOPSIS
    Uploads the provided VCF SDDC Manager Backup file to SDDC manager, decrypts and extracts it, replaces the SSH keys for the manangement domain vCenter with the current keys, then compresses and reencrypts the files ready for subsequent restore

    .DESCRIPTION
    The New-UploadAndModifySDDCManagerBackup cmdlet uploads the provided VCF SDDC Manager Backup file to SDDC manager, decrypts and extracts it, replaces the SSH keys for the manangement domain vCenter with the current keys, then compresses and reencrypts the files ready for subsequent restore

    .EXAMPLE
    New-UploadAndModifySDDCManagerBackup -rootUserPassword "VMw@re1!" -vcfUserPassword "VMw@re1!" -backupFilePath "F:\backup\vcf-backup-sfo-vcf01-sfo-rainpole-io-2023-09-19-10-53-02.tar.gz" -encryptionPassword "VMw@re1!VMw@re1!" -extractedSDDCDataFile ".\extracted-sddc-data.json" -targetFqdn "sfo-m01-vc02.sfo.rainpole.io" -targetAdmin "Administrator@vsphere.local" -targetAdminPassword "VMw@re1!" -targetType "vcenter"

    .EXAMPLE
    New-UploadAndModifySDDCManagerBackup -rootUserPassword "VMw@re1!" -vcfUserPassword "VMw@re1!" -backupFilePath "F:\backup\vcf-backup-sfo-vcf01-sfo-rainpole-io-2023-09-19-10-53-02.tar.gz" -encryptionPassword "VMw@re1!VMw@re1!" -extractedSDDCDataFile ".\extracted-sddc-data.json" -targetFqdn "sfo01-m01-esx01.sfo.rainpole.io" -targetAdmin "root" -targetAdminPassword "VMw@re1!" -targetType "esx"

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

    .PARAMETER targetFqdn
    FQDN of the target vCenter or ESXi host that hosts the SDDC Manager VM

    .PARAMETER targetAdmin
    Admin user of the target vCenter or ESXi host that hosts the SDDC Manager VM

    .PARAMETER targetAdminPassword
    Admin password for the target vCenter or ESXi host that hosts the SDDC Manager VM

    .PARAMETER targetType
    Specifies the target type. Valid values are 'vcenter' or 'esx'. Default is 'vcenter'.

    #>

    Param(
        [Parameter (Mandatory = $true)][String] $rootUserPassword,
        [Parameter (Mandatory = $true)][String] $vcfUserPassword,
        [Parameter (Mandatory = $true)][String] $backupFilePath,
        [Parameter (Mandatory = $true)][String] $encryptionPassword,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $true)][String] $targetFqdn,
        [Parameter (Mandatory = $true)][String] $targetAdmin,
        [Parameter (Mandatory = $true)][String] $targetAdminPassword,
        [Parameter (Mandatory = $false)][ValidateSet("vcenter", "esx")][String] $targetType = "vcenter"
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $mgmtWorkloadDomain = $extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }
    $mgmtVcenterFqdn = $mgmtWorkloadDomain.vCenterDetails.fqdn
    $sddcManagerFQDN = $extractedSddcData.sddcManager.fqdn
    $sddcManagerVmName = $extractedSddcData.sddcManager.vmName
    $backupFileFullPath = (Resolve-Path -Path $backupFilePath).path
    $backupFileName = (Get-ChildItem -path $backupFileFullPath).name
    $extractedBackupFolder = ($backupFileName -Split (".tar.gz"))[0]

    #Establish SSH Connection to SDDC Manager
    LogMessage -type INFO -message "[$jumpboxName] Establishing Connection to $sddcManagerFQDN"
    $SecurePassword = ConvertTo-SecureString -String $vcfUserPassword -AsPlainText -Force
    $mycreds = New-Object System.Management.Automation.PSCredential ("vcf", $SecurePassword)
    Get-SSHTrustedHost | Remove-SSHTrustedHost | Out-Null
    $inmem = New-SSHMemoryKnownHost
    New-SSHTrustedHost -KnownHostStore $inmem -HostName $sddcManagerFQDN -FingerPrint ((Get-SSHHostKey -ComputerName $sddcManagerFQDN).fingerprint) | Out-Null
    Do {
        $sshSession = New-SSHSession -computername $sddcManagerFQDN -Credential $mycreds -KnownHost $inmem
    } Until ($sshSession)

    #Perform KeyScan
    LogMessage -type INFO -message "[$sddcManagerFQDN] Performing Keyscan on SDDC Manager Appliance"
    $result = (Invoke-SSHCommand -timeout 30 -sessionid $sshSession.SessionId -command "ssh-keyscan $mgmtVcenterFqdn").output

    #Close SSH Session
    Remove-SSHSession -SSHSession $sshSession | Out-Null

    #Determine new SSH Keys
    $newNistKey = '"' + (($result | Where-Object { $_ -like "*ecdsa-sha2-nistp256*" }).split("ecdsa-sha2-nistp256 "))[1] + '"'
    If ($newNistKey) { LogMessage -type INFO -message "[$sddcManagerFQDN] New ecdsa-sha2-nistp256 key for $mgmtVcenterFqdn retrieved" }
    $newRSAKey = '"' + (($result | Where-Object { $_ -like "*ssh-rsa*" }).split("ssh-rsa "))[1] + '"'
    If ($newRSAKey) { LogMessage -type INFO -message "[$sddcManagerFQDN] New ssh-rsa key for $mgmtVcenterFqdn retrieved" }

    #Upload Backup
    $viConnection = Connect-VIServer -server $targetFqdn -user $targetAdmin -password $targetAdminPassword
    LogMessage -type INFO -message "[$jumpboxName] Uploading Backup File to SDDC Manager Appliance"
    $copyFile = Copy-VMGuestFile -Source $backupFileFullPath -Destination "/tmp/$backupFileName" -LocalToGuest -VM $sddcManagerVmName -GuestUser "root" -GuestPassword $rootUserPassword -Force -WarningAction SilentlyContinue -WarningVariable WarnMsg

    #Decrypt/Extract Backup
    LogMessage -type INFO -message "[$sddcManagerFQDN] Decrypting Backup on SDDC Manager Appliance"
    #$command = "cd /tmp; OPENSSL_FIPS=1 openssl enc -d -aes-256-cbc -md sha256 -in /tmp/$backupFileName -pass pass:`'$encryptionPassword`' | tar -xz"
    $command = "cd /tmp; echo `'$encryptionPassword`' | OPENSSL_FIPS=1 openssl enc -d -aes-256-cbc -md sha256 -in /tmp/$backupFileName -pass stdin | tar -xz"
    $result = ((Invoke-VMScript -ScriptText $command -VM $sddcManagerVmName -GuestUser 'root' -GuestPassword $rootUserPassword).ScriptOutput) -replace "(`n|`r)"

    #Modfiy JSON file
    #Existing Nist Key
    LogMessage -type INFO -message "[$sddcManagerFQDN] Parsing Backup on SDDC Manager Appliance for original ecdsa-sha2-nistp256 key for $mgmtVcenterFqdn"
    $command = "cat /tmp/$extractedBackupFolder/appliancemanager_ssh_knownHosts.json  | jq `'.knownHosts[] | select(.host==`"$mgmtVcenterFqdn`") | select(.keyType==`"ecdsa-sha2-nistp256`")| .key`'"
    $oldNistKey = ((Invoke-VMScript -ScriptText $command -VM $sddcManagerVmName -GuestUser 'root' -GuestPassword $rootUserPassword).ScriptOutput) -replace "(`n|`r)"

    #Existing rsa Key
    LogMessage -type INFO -message "[$sddcManagerFQDN] Parsing Backup on SDDC Manager Appliance for original ssh-rsa key for $mgmtVcenterFqdn"
    $command = "cat /tmp/$extractedBackupFolder/appliancemanager_ssh_knownHosts.json  | jq `'.knownHosts[] | select(.host==`"$mgmtVcenterFqdn`") | select(.keyType==`"ssh-rsa`")| .key`'"
    $oldRSAKey = ((Invoke-VMScript -ScriptText $command -VM $sddcManagerVmName -GuestUser 'root' -GuestPassword $rootUserPassword).ScriptOutput) -replace "(`n|`r)"

    #Sed File
    LogMessage -type INFO -message "[$sddcManagerFQDN] Replacing ecdsa-sha2-nistp256 and ssh-rsa keys and re-encrypting the SDDC Manager Backup"
    $command = "sed -i `'s@$oldNistKey@$newNistKey@`' /tmp/$extractedBackupFolder/appliancemanager_ssh_knownHosts.json; sed -i `'s@$oldRSAKey@$newRSAKey@`' /tmp/$extractedBackupFolder/appliancemanager_ssh_knownHosts.json; mv /tmp/$backupFileName /tmp/$backupFileName.original; export encryptionPassword='$encryptionPassword'; cd /tmp; tar -cz $extractedBackupFolder | OPENSSL_FIPS=1 openssl enc -aes-256-cbc -md sha256 -out /tmp/$backupFileName -pass env:encryptionPassword"
    $result = ((Invoke-VMScript -ScriptText $command -VM $sddcManagerVmName -GuestUser 'root' -GuestPassword $rootUserPassword).ScriptOutput) -replace "(`n|`r)"

    #Disconnect from vCenter
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function New-UploadAndModifySDDCManagerBackup

#EndRegion Data Gathering

#Region SDDC Manager Functions
Function Invoke-SDDCManagerRestore {
    <#
    .SYNOPSIS
    Restores SDDC Manager from backup

    .DESCRIPTION
    The Invoke-SDDCManagerRestore cmdlet restores SDDC Manager from backup

    .EXAMPLE
    Invoke-SDDCManagerRestore -extractedSDDCDataFile ".\extracted-sddc-data.json" -backupFilePath "F:\backup\vcf-backup-sfo-vcf01-sfo-rainpole-io-2023-09-19-10-53-02.tar.gz" -rootUserPassword "VMw@re1!" -vcfUserPassword "VMw@re1!" -localUserPassword "VMw@re1!VMw@re1!" -basicAuthUserPassword "VMw@re1!"

    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem

    .PARAMETER backupFilePath
    Relative or absolute to the VMware Cloud Foundation SDDC manager backup file somewhere on the local filesystem

    .PARAMETER vcfUserPassword
    Password for the vcf user on the newly deployed appliance

    .PARAMETER localUserPassword
    Password for the local admin user on the newly deployed appliance

    .PARAMETER rootUserPassword
    Password for the root user on the newly deployed appliance

    .PARAMETER encryptionPassword
    Password to decrypt an encrypted SDDC Manager backup

    #>
    Param(
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $true)][String] $backupFilePath,
        [Parameter (Mandatory = $true)][String] $vcfUserPassword,
        [Parameter (Mandatory = $true)][String] $localUserPassword,
        [Parameter (Mandatory = $true)][String] $rootUserPassword,
        [Parameter (Mandatory = $true)][String] $encryptionPassword
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $backupFileFullPath = (Resolve-Path -Path $backupFilePath).path
    $backupFileName = (Get-ChildItem -path $backupFileFullPath).name

    #Establish Session to SDDC Manager and Start SSH Stream
    $extractedSddcManagerFqdn = $extractedSddcData.sddcManager.fqdn

    LogMessage -type INFO -message "[$jumpboxName] Establishing Connection to $extractedSddcManagerFqdn"
    $SecurePassword = ConvertTo-SecureString -String $vcfUserPassword -AsPlainText -Force
    $mycreds = New-Object System.Management.Automation.PSCredential ('vcf', $SecurePassword)
    $inmem = New-SSHMemoryKnownHost
    New-SSHTrustedHost -KnownHostStore $inmem -HostName $extractedSddcManagerFqdn -FingerPrint ((Get-SSHHostKey -ComputerName $extractedSddcManagerFqdn).fingerprint) | Out-Null
    Do {
        $sshSession = New-SSHSession -computername $extractedSddcManagerFqdn -Credential $mycreds -KnownHost $inmem
    } Until ($sshSession)

    #Upload Modified Restore Status Json
    LogMessage -type INFO -message "[$extractedSddcManagerFqdn] Configuring Restore Process"
    $modulePath = (Get-InstalledModule -Name VMware.CloudFoundation.InstanceRecovery).InstalledLocation
    If ($extractedSddcData.sddcManager.version.replace(".", "").substring(0, 3) -gt "451") {
        $sourceFile = "$modulePath\reference-files\new_restore_status.json"
    } else {
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
    LogMessage -type INFO -message "[$extractedSddcManagerFqdn] Performing Restore"
    $scriptText = "curl https://$extractedSddcManagerFqdn/v1/tokens -k -X POST -H `"Content-Type: application/json`" -d `'{`"username`": `"admin@local`",`"password`": `"$localUserPassword`"}`' | awk -F `"\`"`" `'{ print `$4}`'"
    $token = (Invoke-SSHCommand -timeout 30 -sessionid $sshSession.SessionId -command $scriptText).output
    If ($token) {
        #Check Status of Services
        $scriptText = "curl https://$extractedSddcManagerFqdn/v1/vcf-services  -k -X GET -H `"Content-Type: application/json`" -H `"Authorization: Bearer $token`" | json_pp"
        $Counter = 0
        $SddcManagerServiceStatus = (Invoke-SSHCommand -timeout 30 -sessionid $sshSession.SessionId -command $scriptText).output
        $operationsManagerServiceStatus = (($SddcManagerServiceStatus | ConvertFrom-Json).elements | Where-Object { $_.name -eq "OPERATIONS_MANAGER" }).status
        If ($operationsManagerServiceStatus -ne "UP") {
            LogMessage -type WAIT -message "[$extractedSddcManagerFqdn] Waiting for Operations Manager Service to be Up"
            Do {
                Sleep 30
                $scriptText = "curl https://$extractedSddcManagerFqdn/v1/tokens -k -X POST -H `"Content-Type: application/json`" -d `'{`"username`": `"admin@local`",`"password`": `"$localUserPassword`"}`' | awk -F `"\`"`" `'{ print `$4}`'"
                $token = (Invoke-SSHCommand -timeout 30 -sessionid $sshSession.SessionId -command $scriptText).output
                $scriptText = "curl https://$extractedSddcManagerFqdn/v1/vcf-services  -k -X GET -H `"Content-Type: application/json`" -H `"Authorization: Bearer $token`" | json_pp"
                $SddcManagerServiceStatus = (Invoke-SSHCommand -timeout 30 -sessionid $sshSession.SessionId -command $scriptText).output
                $operationsManagerServiceStatus = (($SddcManagerServiceStatus | ConvertFrom-Json).elements | Where-Object { $_.name -eq "OPERATIONS_MANAGER" }).status

            } While ($operationsManagerServiceStatus -ne "UP")
        }
        $scriptText = "curl https://$extractedSddcManagerFqdn/v1/restores/tasks -k -X POST -H `"Content-Type: application/json`" -H `"Authorization: Bearer $token`" -d `'{`"elements`" : [ {`"resourceType`" : `"SDDC_MANAGER`"} ],`"backupFile`" : `"/tmp/$backupFileName`",`"encryption`" : {`"passphrase`" : `"$encryptionPassword`"}}`' | json_pp | jq `'.id`' | cut -d `'`"`' -f 2"
        Do {
            Sleep 10
            $restoreID = (Invoke-SSHCommand -timeout 30 -sessionid $sshSession.SessionId -command $scriptText).output
        } Until ($restoreId)
        If ($restoreID) {
            $scriptText = "curl https://$extractedSddcManagerFqdn/v1/restores/tasks/$restoreID -k -X GET -H `"Content-Type: application/json`" -H `"Authorization: Bearer $token`" | json_pp"
            LogMessage -type INFO -message "[$extractedSddcManagerFqdn] Monitoring Restore Task $restoreID progress (polling every 60 seconds)"
            Do {
                Sleep 60
                $restoreProgress = ((Invoke-SSHCommand -timeout 30 -sessionid $sshSession.SessionId -command $scriptText).output | ConvertFrom-JSON).status
                LogMessage -type INFO -message "[$extractedSddcManagerFqdn] Restore Status: $restoreProgress"
            } While ($restoreProgress -in "IN PROGRESS")
        } else {
            LogMessage -type ERROR -message "[$extractedSddcManagerFqdn] Restore Task ID not returned"
        }
    } else {
        LogMessage -type ERROR -message "[$extractedSddcManagerFqdn] Failed to get SDDC Manager Token"
    }

    #Close SSH Session
    Remove-SSHSession -SSHSession $sshSession | Out-Null

    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function Invoke-SDDCManagerRestore

Function Resolve-PhysicalHostServiceAccounts {
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
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $vCenterConnection = Connect-VIServer -server $vCenterFQDN -username $vCenterAdmin -password $vCenterAdminPassword
    $clusterHosts = Get-Cluster -name $clusterName | Get-VMHost
    Disconnect-VIServer * -confirm:$false
    $sddcManagerConnection = Connect-VcfSddcManagerServer -server $sddcManagerFQDN -User $sddcManagerAdmin -Password $sddcManagerAdminPassword
    #verify SDDC Manager credential API state
    $credentialAPILastTask = ((Invoke-VcfGetCredentialsTasks -errorAction silentlyContinue | Sort-Object -Property creationTimeStamp)[-1]).status
    if ($credentialAPILastTask -eq "FAILED") {
        LogMessage -type INFO -message "[$sddcManagerFQDN] Failed credential operation detected. Please resolve in SDDC Manager and try again" ; break
    }

    Foreach ($hostInstance in $clusterHosts) {
        $esxiRootPassword = [String]((Invoke-VcfGetCredentials).Elements | where-object { $_.Resource.ResourceName -eq $hostInstance.name }).password
        $esxiConnection = Connect-VIServer -Server $hostInstance.name -User root -Password $esxiRootPassword.Trim() | Out-Null
        $esxiHostName = $hostInstance.name.Split(".")[0]
        $svcAccountName = "svc-vcf-$esxiHostName"
        $accountExists = Get-VMHostAccount -Server $esxiConnection -User $svcAccountName -erroraction SilentlyContinue
        If (!$accountExists) {
            LogMessage -type INFO -message "[$($hostInstance.name)] VCF Service Account Not Found: Creating"
            New-VMHostAccount -Id $svcAccountName -Password $svcAccountPassword -Description "ESXi User" | Out-Null
            New-VIPermission -Entity (Get-Folder root) -Principal $svcAccountName -Role Admin | Out-Null
        } else {
            LogMessage -type INFO -message "[$($hostInstance.name)] VCF Service Account Found: Setting Password"
            Set-VMHostAccount -UserAccount $svcAccountName -Password $svcAccountPassword | Out-Null
        }
        Disconnect-VIServer $hostInstance.name -confirm:$false | Out-Null
    }

    Foreach ($hostInstance in $clusterHosts) {
        Remove-Variable credentialsObject -ErrorAction SilentlyContinue
        Remove-Variable elementsObject -ErrorAction SilentlyContinue
        Remove-Variable esxHostObject -ErrorAction SilentlyContinue

        $esxiHostName = $hostInstance.name.Split(".")[0]
        $svcAccountName = "svc-vcf-$esxiHostName"
        LogMessage -type INFO -message "[$($hostInstance.name)] Remediating VCF Service Account Password: " -nonewline
        $BaseCredential = Initialize-VcfBaseCredential -AccountType "SERVICE" -CredentialType "SSH" -Password $svcAccountPassword -Username $svcAccountName
        $ResourceCredentials = Initialize-VcfResourceCredentials -Credentials $BaseCredential -ResourceName $hostInstance.name -ResourceType "ESXI"
        $CredentialsUpdateSpec = Initialize-VcfCredentialsUpdateSpec -Elements $ResourceCredentials -OperationType "REMEDIATE"
        $taskID = (Invoke-VcfUpdateOrRotatePasswords -credentialsUpdateSpec $credentialsUpdateSpec).Id
        Do {
            Sleep 5
            $taskStatus = (Invoke-VcfGetCredentialsTask -id $taskID).Status
        } Until ($taskStatus -ne "IN_PROGRESS")
        Write-Host "$taskStatus" -ForegroundColor Green
    }
    Disconnect-VcfSddcManagerServer *
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"

}
Export-ModuleMember -Function Resolve-PhysicalHostServiceAccounts

Function Set-SDDCManagerOfflineDepot {
    Param (
        [Parameter(Mandatory = $true)] [String] $sddcManagerFqdn,
        [Parameter(Mandatory = $true)] [String] $sddcManagerUser,
        [Parameter(Mandatory = $true)] [String] $sddcManagerPassword,
        [Parameter(Mandatory = $true)] [String] $offlineDepotFqdn,
        [Parameter(Mandatory = $true)] [INT] $offlineDepotPort,
        [Parameter(Mandatory = $true)] [String] $offlineDepotUsername,
        [Parameter(Mandatory = $true)] [String] $offlineDepotPassword
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    # Get SDDC Manager API Token
    LogMessage -type INFO -message "[$sddcManagerFqdn] Getting Authentication Token"
    $tokenUri = "https://$sddcManagerFqdn/v1/tokens"
    $tokenBody = @{
        username = $sddcManagerUser
        password = $sddcManagerPassword
    } | ConvertTo-Json
    $tokenResponse = Invoke-RestMethod -Uri $tokenUri -Method POST -ContentType "application/json" -Body $tokenBody -SkipCertificateCheck
    $accessToken = $tokenResponse.accessToken

    #Create Headers
    $headers = @{
        "Authorization" = "Bearer $accessToken"
        "Content-Type"  = "application/json"
    }

    #Set services config URI
    $servicesConfigUri = "https://$sddcManagerFqdn/v1/services-config"

    #Get Current Depot Services Configuration
    LogMessage -type INFO -message "[$sddcManagerFqdn] Capturing Original Depot Fleet Depot Configuration"
    $currentDepotServicesConfig = Invoke-RestMethod -Uri $servicesConfigUri -Method GET -Headers $headers -SkipCertificateCheck
    $currentDepotServicesConfig | ConvertTo-Json -depth 10 > originalDepotServicesconfig.json

    #Delete Services Configuration
    LogMessage -type INFO -message "[$sddcManagerFqdn] Removing Original Depot Fleet Depot Configuration"
    $deleteServicesConfigURI = "https://$sddcManagerFqdn/v1/services-config/$($currentDepotServicesConfig.services.key)"
    Invoke-RestMethod -Uri $deleteServicesConfigURI -Method DELETE -Headers $headers -SkipCertificateCheck *>$null

    #Trust Depot Cert on SDDC Manager
    LogMessage -type INFO -message "[$sddcManagerFqdn] Trusting Offline Depot Certificate"
    $SecurePassword = ConvertTo-SecureString -String $sddcManagerPassword -AsPlainText -Force
    $mycreds = New-Object System.Management.Automation.PSCredential ('vcf', $SecurePassword)
    $inmem = New-SSHMemoryKnownHost
    New-SSHTrustedHost -KnownHostStore $inmem -HostName $sddcManagerFqdn -FingerPrint ((Get-SSHHostKey -ComputerName $sddcManagerFqdn).fingerprint) | Out-Null
    Do {
        $sshSession = New-SSHSession -ComputerName $sddcManagerFqdn -Credential $mycreds -KnownHost $inmem
    } Until ($sshSession)

    # Create shell stream for interactive session
    $stream = New-SSHShellStream -SSHSession $sshSession

    # Switch to root
    $stream.WriteLine("su -")
    Start-Sleep 2
    $stream.WriteLine($sddcManagerPassword)  # Or use a separate $rootPassword variable if different
    Start-Sleep 2

    # Build the command to trust the depot certificate
    $scriptCommand = [System.Text.StringBuilder]::new()
    [void]$scriptCommand.AppendLine("echo '{ ""certificate"" : '`$(openssl s_client -connect ${offlineDepotFqdn}:${offlineDepotPort} 2>/dev/null </dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | jq -sR)',""certificateUsageType"" : ""TRUSTED_FOR_OUTBOUND""}' > /tmp/trusted-cert-spec.json && \")
    [void]$scriptCommand.AppendLine("token=`$(curl -k --location ""https://localhost/v1/tokens"" --header 'Content-Type: application/json' --header 'Accept: application/json' --data-raw '{""username"" : ""admin@local"",""password"" : ""$sddcManagerPassword""}' | jq -r '.accessToken') && \")
    [void]$scriptCommand.AppendLine("curl -k --location --request POST ""https://localhost/v1/sddc-manager/trusted-certificates"" --header 'Content-Type: application/json' --header ""Authorization: Bearer `$token"" -d@/tmp/trusted-cert-spec.json && \")
    [void]$scriptCommand.Append("rm -f /tmp/trusted-cert-spec.json")

    #Trust the Cert
    $stream.WriteLine($scriptCommand.ToString())
    Start-Sleep 5

    # Exit from root and close session
    $stream.WriteLine("exit")
    Start-Sleep 1
    Remove-SSHSession -SSHSession $sshSession | Out-Null

    #Seting Depot URI
    $depotUri = "https://$sddcManagerFqdn/v1/system/settings/depot"

    LogMessage -type INFO -message "[$sddcManagerFqdn] Configuring Offline Depot"
    #Configure Offline Depot
    $depotBody = @{
        offlineAccount     = @{
            username = $offlineDepotUsername
            password = $offlineDepotPassword
        }
        depotConfiguration = @{
            isOfflineDepot = $true
            hostname       = $offlineDepotFqdn
            port           = $offlineDepotPort
        }
    } | ConvertTo-Json -Depth 3
    $result = Invoke-RestMethod -Uri $depotUri -Method PUT -Headers $headers -Body $depotBody -SkipCertificateCheck

    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function Set-SDDCManagerOfflineDepot

Function Set-SDDCManagerFDSDepot {
    Param (
        [Parameter(Mandatory = $true)] [String] $sddcManagerFqdn,
        [Parameter(Mandatory = $true)] [String] $sddcManagerUser,
        [Parameter(Mandatory = $true)] [String] $sddcManagerPassword,
        [Parameter(Mandatory = $true)] [String] $originalConfigurationFile
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    LogMessage -type INFO -message "[$sddcManagerFqdn] Retrieving Original Configuration from JSON file"
    $servicesConfigBody = Get-Content -path $originalConfigurationFile

    LogMessage -type INFO -message "[$sddcManagerFqdn] Getting Authentication Token"
    # Get SDDC Manager API Token
    $tokenUri = "https://$sddcManagerFqdn/v1/tokens"
    $tokenBody = @{
        username = $sddcManagerUser
        password = $sddcManagerPassword
    } | ConvertTo-Json
    $tokenResponse = Invoke-RestMethod -Uri $tokenUri -Method POST -ContentType "application/json" -Body $tokenBody -SkipCertificateCheck
    $accessToken = $tokenResponse.accessToken

    #Create Headers
    $headers = @{
        "Authorization" = "Bearer $accessToken"
        "Content-Type"  = "application/json"
    }

    #Seting Depot URI
    $depotUri = "https://$sddcManagerFqdn/v1/system/settings/depot"

    LogMessage -type INFO -message "[$sddcManagerFqdn] Deleting Existing Depot Configuration"
    #Delete Depot Settings
    Invoke-RestMethod -Uri $depotUri -Method DELETE -Headers $headers -SkipCertificateCheck

    #Set services config URI
    $servicesConfigUri = "https://$sddcManagerFqdn/v1/services-config"

    LogMessage -type INFO -message "[$sddcManagerFqdn] Reinstating Fleet Depot Configuration"
    #Reinstate service config
    $servicesConfigBody = $currentDepotServicesConfig | ConvertTo-Json -depth 10
    Invoke-RestMethod -Uri $servicesConfigUri -Method PUT -Headers $headers -Body $servicesConfigBody -SkipCertificateCheck

    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function Set-SDDCManagerFDSDepot

Function Invoke-SddcManagerBundleDownload {
    <#
    .SYNOPSIS
        Downloads VCF bundles from the depot on a SDDC manager appliance via SSH

    .PARAMETER sddcManagerFqdn
        FQDN of the SDDC manager appliance

    .PARAMETER vcfUserPassword
        SSH password for the vcf user

    .PARAMETER rootPassword
        Root password for the SDDC manager appliance

    .PARAMETER adminPassword
        Password for admin@local API user

    .PARAMETER VcfVersion
        VCF version to download bundles for (e.g., "9.0.0.0", "9.1.0.0")

    .PARAMETER SkipMode
        Optional: 'skipFleetManagement' or 'skipAutomationOnly' to skip certain bundles

    .PARAMETER WaitForCompletion
        If specified, waits for all bundle downloads to complete
    #>

    Param (
        [Parameter(Mandatory = $true)] [String] $sddcManagerFqdn,
        [Parameter(Mandatory = $true)] [String] $vcfUserPassword,
        [Parameter(Mandatory = $true)] [String] $rootPassword,
        [Parameter(Mandatory = $true)] [String] $adminPassword,
        [Parameter(Mandatory = $true)] [String] $VcfVersion,
        [Parameter(Mandatory = $false)] [Switch] $WaitForCompletion
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    # Use StringBuilder for efficient string concatenation
    $sb = [System.Text.StringBuilder]::new()

    # Script header and authentication
    [void]$sb.AppendLine('#!/bin/bash')
    [void]$sb.AppendLine("# Get authentication token")
    [void]$sb.AppendLine("token=`$(curl -k --location ""https://localhost/v1/tokens"" --header 'Content-Type: application/json' --header 'Accept: application/json' --data-raw '{""username"" : ""admin@local"",""password"" : ""$adminPassword""}' | jq -r '.accessToken')")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("version=""$VcfVersion""")
    [void]$sb.AppendLine("")

    # Define component names and their variable names
    $components = @(
        @{ Name = 'VRA'; Var = 'automationBundleId' }
        @{ Name = 'TELEMETRY_ACCEPTOR'; Var = 'telemetryAcceptor' }
        @{ Name = 'VSP'; Var = 'vsp' }
        @{ Name = 'VCF_FLEET_LCM'; Var = 'fleetLcm' }
        @{ Name = 'DEPOT_SERVICE'; Var = 'depotService' }
        @{ Name = 'VCF_SDDC_LCM'; Var = 'sddcLcm' }
        @{ Name = 'VCF_SALT'; Var = 'vcfSalt' }
        @{ Name = 'VCF_SALT_RAAS'; Var = 'vcfSaltRaas' }
        @{ Name = 'VIDB'; Var = 'vidb' }
        @{ Name = 'VCF_SERVICE_VCD_MIGRATION_BACKEND'; Var = 'migrationServiceEngine' }
    )

    # Build bundle ID retrieval commands
    [void]$sb.AppendLine("# Get bundle IDs for each component")
    foreach ($component in $components) {
        [void]$sb.AppendLine("$($component.Var)=`$(curl -k -H ""Authorization: Bearer `$token"" ""https://localhost/v1/releases/VCF/release-components?releaseVersion=$VcfVersion&imageType=INSTALL&automatedInstall=true"" | jq '.elements[].components' | jq '.[] | select(.name==""$($component.Name)"") | .versions' | jq '.[] | .artifacts.bundles' | jq '.[] | .id' | cut -d '""' -f 2)")
    }
    [void]$sb.AppendLine("")

    # Build bundle selection based on version and skip mode
    $bundleList = '($automationBundleId $telemetryAcceptor $vsp $fleetLcm $depotService $sddcLcm $vcfSalt $vcfSaltRaas $vidb $migrationServiceEngine)'

    [void]$sb.AppendLine("declare -a bundlesToDownload=$bundleList")
    [void]$sb.AppendLine("")

    # Add download trigger logic
    [void]$sb.AppendLine("# Trigger download for all bundles")
    [void]$sb.AppendLine('for bundleId in "${bundlesToDownload[@]}"')
    [void]$sb.AppendLine("do")
    [void]$sb.AppendLine('   echo "Downloading $bundleId"')
    [void]$sb.AppendLine('   curl -k --location --request PATCH "https://localhost/v1/bundles/$bundleId" --header ''Content-Type: application/json'' --header "Authorization: Bearer $token" --data ''{"bundleDownloadSpec": {"downloadNow": true}}''')
    [void]$sb.AppendLine("done")

    # Add wait for completion logic if requested
    if ($WaitForCompletion) {
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("# Wait for all bundles to download")
        [void]$sb.AppendLine('allBundlesDownloaded="false"')
        [void]$sb.AppendLine('foundIncompleteBundle="false"')
        [void]$sb.AppendLine('while [[ "$allBundlesDownloaded" = "false" ]]')
        [void]$sb.AppendLine("do")
        [void]$sb.AppendLine("   sleep 60")
        [void]$sb.AppendLine('   for bundleId in "${bundlesToDownload[@]}"')
        [void]$sb.AppendLine("   do")
        [void]$sb.AppendLine("      downloadStatus=`$(curl -k -H ""Authorization: Bearer `$token"" ""https://localhost/v1/bundles/download-status?releaseVersion=$VcfVersion&imageType=INSTALL"" | jq '.elements' | jq --arg bundleId ""`$bundleId"" '.[] | select(.bundleId==`$bundleId) | .downloadStatus')")
        [void]$sb.AppendLine('      echo "Bundle $bundleId status: $downloadStatus"')
        [void]$sb.AppendLine('      if [ $downloadStatus != ''"SUCCESS"'' ]')
        [void]$sb.AppendLine("      then")
        [void]$sb.AppendLine('         foundIncompleteBundle="true"')
        [void]$sb.AppendLine("      fi")
        [void]$sb.AppendLine("   done")
        [void]$sb.AppendLine('   if [ $foundIncompleteBundle = "true" ]')
        [void]$sb.AppendLine("   then")
        [void]$sb.AppendLine('      allBundlesDownloaded="false"')
        [void]$sb.AppendLine('      foundIncompleteBundle="false"')
        [void]$sb.AppendLine("   else")
        [void]$sb.AppendLine('      allBundlesDownloaded="true"')
        [void]$sb.AppendLine("   fi")
        [void]$sb.AppendLine("done")
        [void]$sb.AppendLine('echo "All bundles downloaded successfully!"')
    }

    # Get the final script content
    $scriptContent = $sb.ToString()

    # Establish SSH Connection using inmem method
    LogMessage -type INFO -message "[$sddcManagerFqdn] Establishing SSH Connection"
    $SecurePassword = ConvertTo-SecureString -String $vcfUserPassword -AsPlainText -Force
    $mycreds = New-Object System.Management.Automation.PSCredential ('vcf', $SecurePassword)
    $inmem = New-SSHMemoryKnownHost
    New-SSHTrustedHost -KnownHostStore $inmem -HostName $sddcManagerFqdn -FingerPrint ((Get-SSHHostKey -ComputerName $sddcManagerFqdn).fingerprint) | Out-Null

    Do {
        $sshSession = New-SSHSession -ComputerName $sddcManagerFqdn -Credential $mycreds -KnownHost $inmem
    } Until ($sshSession)

    # Create shell stream for interactive session
    $stream = New-SSHShellStream -SSHSession $sshSession

    # Switch to root
    $stream.WriteLine("su -")
    Start-Sleep 2
    $stream.WriteLine($rootPassword)
    Start-Sleep 2

    # Write script to remote file
    LogMessage -type INFO -message "[$sddcManagerFqdn] Creating Download Script"
    $scriptPath = "/root/download-bundles.sh"

    $stream.WriteLine("cat > $scriptPath << 'EOFSCRIPT'")
    Start-Sleep 1
    $stream.WriteLine($scriptContent)
    Start-Sleep 1
    $stream.WriteLine("EOFSCRIPT")
    Start-Sleep 2

    # Make executable and run
    $stream.WriteLine("chmod +x $scriptPath")
    Start-Sleep 1

    LogMessage -type INFO -message "[$sddcManagerFqdn] Running Download Script"
    $stream.WriteLine("$scriptPath")

    # Wait for script to start and capture initial output
    Start-Sleep 10
    $output = $stream.Read()
    #Write-Host $output

    if ($WaitForCompletion) {
        LogMessage -type WAIT -message "[$sddcManagerFqdn] Waiting for bundle downloads to complete (this may take a while)..."
        $timeout = 7200  # 2 hour timeout
        $elapsed = 0
        $interval = 30

        while ($elapsed -lt $timeout) {
            Start-Sleep $interval
            $elapsed += $interval
            $newOutput = $stream.Read()
            if ($newOutput) {
                if ($newOutput -match "All bundles downloaded successfully!") {
                    break
                }
            }
        }
    }

    # Cleanup
    LogMessage -type INFO -message "[$sddcManagerFqdn] Cleaning Up"
    $stream.WriteLine("rm -f $scriptPath")
    Start-Sleep 1
    $stream.WriteLine("exit")
    Start-Sleep 1
    # Close SSH Session
    Remove-SSHSession -SSHSession $sshSession | Out-Null

    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function Invoke-SddcManagerBundleDownload
#EndRegion SDDC Manager Functions

#Region vCenter Functions

Function Invoke-vCenterRestore {
    <#
    .SYNOPSIS
    Restores a vCenter appliance using the specified backup

    .DESCRIPTION
    The Invoke-vCenterRestore restores a vCenter appliance using the specified backup

    .EXAMPLE
    Invoke-vCenterRestore -vCenterFqdn "sfo-m01-vc02.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" "-extractedSDDCDataFile .\extracted-sddc-data.json" -workloadDomain "sfo-m01" -vCenterBackupPath "10.50.5.63/F$/Backups/vcenter-backup/sn_sfo-m01-vc01.sfo.rainpole.io/M_9.0.0.0_20250922-105520_" -locationtype "SMB" -locationUser "Administrator" -locationPassword "VMw@re1!"

    .PARAMETER vCenterFqdn
    FQDN of the temporary vCenter hosting the deployed vCenter OVA to which the backup should be restored

    .PARAMETER vCenterAdmin
    Admin user of the temporary vCenter hosting the deployed vCenter OVA to which the backup should be restored

    .PARAMETER vCenterAdminPassword
    Admin password of the temporary vCenter hosting the deployed vCenter OVA to which the backup should be restored

    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem

    .PARAMETER workloadDomain
    Name of the VCF workload domain that the vCenter to restored is associated with

    .PARAMETER vCenterBackupPath
    Path to the vCenter Backup on the backup location

    .PARAMETER locationtype
    Type of backup location. Valid types are FTP, FTPS, HTTP, HTTPS, SFTP, NFS, or SMB

    .PARAMETER locationUser
    User account for connecting to the backup location passed with vCenterBackupPath

    .PARAMETER backupPassword
    Password to decrypt an encrypted vCenter Server backup file
    #>

    Param(
        #[Parameter (Mandatory = $true)][String] $vCenterFqdn,
        #[Parameter (Mandatory = $true)][String] $vCenterAdmin,
        #[Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $true)][String] $workloadDomain,
        [Parameter (Mandatory = $true)][String] $vCenterBackupPath,
        [Parameter (Mandatory = $true)][String] $locationtype,
        [Parameter (Mandatory = $true)][String] $locationUser,
        [Parameter (Mandatory = $true)][String] $locationPassword,
        [Parameter (Mandatory = $false)][String] $backupPassword
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON
    $restoredVcenterFqdn = ($extractedSddcData.workloadDomains | Where-Object { $_.domainName -eq $workloadDomain }).vCenterDetails.fqdn
    #$restoredVcenterVmName = ($extractedSddcData.workloadDomains | Where-Object { $_.domainName -eq $workloadDomain }).vCenterDetails.vmname
    $restoredvCenterRootPassword = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "VCENTER") -and ($_.domainName -eq $workloadDomain) -and ($_.credentialType -eq "SSH") }).password
    $ssoDomain = ($extractedSddcData.workloadDomains | Where-Object { $_.domainName -eq $workloadDomain }).ssoDomain
    $ssoAdminUserName = ($extractedSddcData.passwords | Where-Object { $_.entityType -eq "PSC" -and $_.username -like "*$($ssoDomain)" }).username
    $ssoAdminUserPassword = ($extractedSddcData.passwords | Where-Object { $_.entityType -eq "PSC" -and $_.username -like "*$($ssoDomain)" }).password

    #Power Up vCenter Appliance
    <#
    $vCenterConnection = Connect-VIServer -server $vCenterFqdn -user $vCenterAdmin -password $vCenterAdminPassword
    LogMessage -type INFO -message "[$restoredVcenterVmName] Powering On VM"
    Get-VM -Name $restoredVcenterVmName | Start-VM -confirm:$false | Out-Null
    Disconnect-VIServer * -Force -Confirm:$false -ErrorAction SilentlyContinue
    #>

    #Wait for successful ping test
    LogMessage -type WAIT -message "[$restoredVcenterFqdn] Waiting for successful ping test"
    Do {
        Sleep 10
        $pingTest = Test-Connection -ComputerName $restoredVcenterFqdn -count 1 -ErrorAction SilentlyContinue
    } Until ($pingTest)

    #Form credentials for connecting to vCenter
    $SecurePassword = ConvertTo-SecureString -String $restoredvCenterRootPassword -AsPlainText -Force
    $mycreds = New-Object System.Management.Automation.PSCredential ('root', $SecurePassword)

    #Create SSH Trusted Host
    LogMessage -type WAIT -message "[$jumpboxName] Waiting for SSH Connection to $restoredVcenterFqdn to be possible"
    $inmem = New-SSHMemoryKnownHost
    Do {
        $sshHostKey = Get-SSHHostKey -ComputerName $restoredVcenterFqdn -ErrorAction SilentlyContinue
        If ($sshHostKey) {
            $sshTrustedHost = New-SSHTrustedHost -KnownHostStore $inmem -HostName $restoredVcenterFqdn -FingerPrint $sshHostKey.fingerprint
        }
    } Until ($sshTrustedHost)

    #Wait for RPM initialization to Finish
    LogMessage -type WAIT -message "[$restoredVcenterFqdn] Waiting for Appliance to finish RPM initialization"
    Do {
        #Note: Looped SSH connections is quite deliberate here as the connections appear to be continually dropped as the process progresses
        Sleep 10
        Remove-SSHSession -SSHSession $sshSession | Out-Null
        Do {
            $sshSession = New-SSHSession -computername $restoredVcenterFqdn -Credential $mycreds -KnownHost $inmem -erroraction silentlyContinue
        } Until ($sshSession)
        $rpmStatus = (Invoke-SSHCommand -SessionId $sshSession.sessionid -Command "api com.vmware.appliance.version1.services.status.get --name cap_init" -erroraction silentlyContinue).output
    } Until ($rpmStatus -eq "Status: down")
    LogMessage -type INFO -message "[$restoredVcenterFqdn] RPM initialization Complete"

    #Restore vCenter
    $stream = New-SSHShellStream -SSHSession $sshSession
    LogMessage -type INFO -message "[$restoredVcenterFqdn] Submitting Restore Request"
    $restoreString = "api com.vmware.appliance.recovery.restore.job.create --locationType $locationtype --location $vCenterBackupPath --locationUser $locationUser --locationPassword --ssoAdminUserName $ssoAdminUserName --ssoAdminUserPassword --ignoreWarnings TRUE"
    If ($backupPassword) {
        $restoreString = $restoreString += " --backupPassword"
    }
    $stream.writeline($restoreString)
    Start-Sleep 5
    If ($backupPassword) {
        $stream.writeline($backupPassword)
        Start-Sleep 5
    }
    $stream.writeline($locationPassword)
    Start-Sleep 5
    $stream.writeline($ssoAdminUserPassword)

    Remove-SSHSession -SSHSession $sshSession | Out-Null

    LogMessage -type WAIT -message "[$restoredVcenterFqdn] Waiting for Restore to Start"
    Do {
        #Note: Looped SSH connections is quite deliberate here as the connections appear to be continually dropped as the process progresses
        Start-Sleep 5
        Remove-SSHSession -SSHSession $sshSession | Out-Null
        $sshSession = New-SSHSession -computername $restoredVcenterFqdn -Credential $mycreds -KnownHost $inmem -erroraction silentlycontinue
        If ($sshSession) {
            $stream = New-SSHShellStream -SSHSession $sshSession
            $stream.writeline('appliancesh')
            Start-Sleep 5
            $stream.writeline($restoredvCenterRootPassword)
            Start-Sleep 5
            $response = $stream.Read()
            Start-Sleep 5
            $stream.writeline('api com.vmware.appliance.recovery.restore.job.get')
            Start-Sleep 5
            $Global:restoreStatus = $stream.Read()
            $restoreStatusArray = $restoreStatus -split ("\r\n")
            $state = $restoreStatusArray[2].trim()
        }
    } Until ($state -eq "State: INPROGRESS")
    LogMessage -type INFO -message "[$restoredVcenterFqdn] Restore $state"

    Do {
        #Note: Looped SSH connections is quite deliberate here as the connections appear to be continually dropped as the process progresses
        Start-Sleep 20
        Remove-SSHSession -SSHSession $sshSession | Out-Null
        $sshSession = New-SSHSession -computername $restoredVcenterFqdn -Credential $mycreds -KnownHost $inmem -erroraction silentlycontinue
        If ($sshSession) {
            $stream = New-SSHShellStream -SSHSession $sshSession
            $stream.writeline('appliancesh')
            Start-Sleep 5
            $stream.writeline($restoredvCenterRootPassword)
            Start-Sleep 5
            $response = $stream.Read()
            Start-Sleep 5
            $stream.writeline('api com.vmware.appliance.recovery.restore.job.get')
            Start-Sleep 5
            $restoreStatus = $stream.Read()
            If ($restoreStatus) {
                $restoreStatusArray = $restoreStatus -split ("\r\n")
                If ($restoreStatusArray) {
                    If ($restoreStatusArray[2]) {
                        $state = $restoreStatusArray[2].trim()
                    }
                    If ($restoreStatusArray[6]) {
                        $progress = $restoreStatusArray[6].trim()
                        If (($progress -like "Progress*") -and ($state -eq "State: INPROGRESS")) {
                            LogMessage -type INFO -message "[$restoredVcenterFqdn] Restore $($progress)%"
                        }
                    }
                }
            }
        }
    } Until (($state -eq "State: SUCCEEDED") -or ($state -eq "State: FAILED"))
    If ($state -eq "State: SUCCEEDED") {
        LogMessage -type INFO -message "[$restoredVcenterFqdn] Restore finished with $state"
    } else {
        LogMessage -type ERROR -message "[$restoredVcenterFqdn] Restore finished with $state"
    }

    #Close SSH Session
    Remove-SSHSession -SSHSession $sshSession | Out-Null
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function Invoke-vCenterRestore

Function Move-ClusterHostsToRestoredVcenter {
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

    .PARAMETER restoredClusterName
    Admin password for the restored vCenter instance

    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem
    #>

    Param(
        [Parameter (Mandatory = $true)][String] $tempvCenterFqdn,
        [Parameter (Mandatory = $true)][String] $tempvCenterAdmin,
        [Parameter (Mandatory = $true)][String] $tempvCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $restoredvCenterFQDN,
        [Parameter (Mandatory = $true)][String] $restoredvCenterAdmin,
        [Parameter (Mandatory = $true)][String] $restoredvCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $restoredClusterName,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $tempvCenterConnection = connect-viserver $tempvCenterFqdn -user $tempvCenterAdmin -password $tempvCenterAdminPassword
    $clusterName = (Get-Cluster).name
    $esxiHosts = get-cluster -name $clusterName | get-vmhost | Sort-Object -Property Name
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
    $restoredvCenterConnection = connect-viserver $restoredvCenterFQDN -user $restoredvCenterAdmin -password $restoredvCenterAdminPassword
    Foreach ($esxiHost in $esxiHosts) {
        LogMessage -type INFO -message "[$($esxiHost.name)] Moving to $restoredvCenterFQDN"
        $esxiRootPassword = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "ESXI") -and ($_.entityName -eq $esxiHost.Name) -and ($_.username -eq "root") }).password
        Add-VMHost -Name $esxiHost.Name -Location $restoredClusterName -User root -Password $esxiRootPassword -Force -Confirm:$false | Out-Null
    }
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function Move-ClusterHostsToRestoredVcenter

Function Remove-ClusterHostsFromVds {
    <#
    .SYNOPSIS
    Removes all hosts in the provided vSphere cluster from the provided vSphere Distributed Switch

    .DESCRIPTION
    The Remove-ClusterHostsFromVds cmdlet removes all hosts in the provided vSphere cluster from the provided vSphere Distributed Switch

    .EXAMPLE
    Remove-ClusterHostsFromVds -vCenterFQDN "sfo-m01-vc02.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -vdsName "sfo-m01-cl01-vds01"

    .PARAMETER vCenterFQDN
    FQDN of the vCenter instance hosting the cluster / vds from which hosts should be removed

    .PARAMETER vCenterAdmin
    Admin user of the vCenter instance hosting the cluster / vds from which hosts should be removed

    .PARAMETER vCenterAdminPassword
    Admin password for the vCenter instance hosting the cluster / vds from which hosts should be removed

    #>

    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $vCenterConnection = connect-viserver $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    $clusterName = (Get-Cluster).name
    $esxiHosts = Get-Cluster -name $clusterName | get-vmhost | Sort-Object -Property Name
    Foreach ($esxiHost in $esxiHosts) {
        $connectedVdswitches = Get-VDSwitch -VMHost $esxiHost
        Foreach ($vds in $connectedVdswitches) {
            $vss_name = "$($vds.name)-vss"
            LogMessage -type INFO -message "[$($esxiHost.name)] Removing from $($vds.name)"
            $vmnicsInUse = Get-VDSwitch -Name $vds.name | Get-VMHostNetworkAdapter -VMHost $esxiHost -Physical
            Get-VDSwitch -Name $vds.name | Get-VMHostNetworkAdapter -VMHost $esxiHost -Physical | Remove-VDSwitchPhysicalNetworkAdapter -Confirm:$false | Out-Null
            Get-VDSwitch -Name $vds.name | Remove-VDSwitchVMHost -VMHost $esxiHost -Confirm:$false | Out-Null
            $vss = Get-VMHost -Name $esxiHost | Get-VirtualSwitch -Name $vss_name
            Add-VirtualSwitchPhysicalNetworkAdapter -VirtualSwitch $vss -VMHostPhysicalNic $vmnicsInUse -Confirm:$false
        }
    }
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function Remove-ClusterHostsFromVds

Function Move-MgmtVmsToTempPg {
    <#
    .SYNOPSIS
    Moves all management VMs in the provided vSphere cluster to a temporary management portgroup

    .DESCRIPTION
    The Move-MgmtVmsToTempPg cmdlet moves all management VMs in the provided vSphere cluster to a temporary management portgroup

    .EXAMPLE
    Move-MgmtVmsToTempPg -vCenterFQDN "sfo-m01-vc02.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!"

    .PARAMETER vCenterFQDN
    FQDN of the vCenter instance hosting the cluster / VMs which should be removed

    .PARAMETER vCenterAdmin
    Admin user of the vCenter instance hosting the cluster / VMs which should be removed

    .PARAMETER vCenterAdminPassword
    Admin password for the vCenter instance hosting the cluster / VMs which should be removed

    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem
    #>

    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON
    $workloadDomain = ($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" })
    $domainName = $workloadDomain.domainName


    $vCenterConnection = connect-viserver $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    $clusterName = (Get-Cluster).name
    $vmhosts = (Get-Cluster -name $clusterName | Get-VMHost).name
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false

    Foreach ($vmhost in $vmhosts) {
        $vmHostUser = ($extractedSddcData.passwords | where-object { ($_.domainName -eq $domainName) -and ($_.entityType -eq "ESXI") -and ($_.username -eq "root") -and ($_.entityName -eq $vmhost) }).username
        $vmHostPassword = ($extractedSddcData.passwords | where-object { ($_.domainName -eq $domainName) -and ($_.entityType -eq "ESXI") -and ($_.username -eq "root") -and ($_.entityName -eq $vmhost) }).password
        $vmHostConnection = Connect-ViServer $vmhost -user $vmHostUser -password $vmHostPassword
        $vmsTomove = Get-VM | Where-Object { $_.Name -notlike "*vCLS*" }
        foreach ($vmToMove in $vmsTomove) {
            If ((Get-VM -Name $vmToMove | Get-NetworkAdapter).NetworkName -ne "vm_management") {
                LogMessage -type INFO -message "[$($vmToMove.name)] Moving to vm_management"
                Get-VM -Name $vmToMove | Get-NetworkAdapter | Set-NetworkAdapter -NetworkName "vm_management" -confirm:$false | Out-Null
            } else {
                LogMessage -type INFO -message "[$($vmToMove.name)] Already moved to vm_management. Skipping"
            }
        }
        Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
    }
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function Move-MgmtVmsToTempPg

Function Move-ClusterHostNetworkingTovSS {
    <#
    .SYNOPSIS
    Moves all hosts in a cluster from a vsphere Distributed switch to a vSphere Standard switch

    .DESCRIPTION
    The Move-ClusterHostNetworkingTovSS cmdlet moves all hosts in a cluster from a vsphere Distributed switch to a vSphere Standard switch

    .EXAMPLE
    Move-ClusterHostNetworkingTovSS -tempvCenterFqdn "sfo-m01-vc02.sfo.rainpole.io" -tempvCenterAdmin "administrator@vsphere.local" -tempvCenterAdminPassword "VMw@re1!" -extractedSDDCDataFile ".\extracted-sddc-data.json" -mtu 9000

    .PARAMETER vCenterFqdn
    FQDN of the vCenter instance hosting the cluster which should be moved

    .PARAMETER vCenterAdmin
    Admin user of the vCenter instance hosting the cluster which should be moved

    .PARAMETER vCenterAdminPassword
    Admin password for the vCenter instance hosting the cluster which should be moved

    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem

    .PARAMETER mtu
    MTU to be assigned to the temporary standard switch

    #>

    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFqdn,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $true)][String] $mtu

    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON
    $mgmtVmVlanId = ((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq "t" }).vdsDetails.portgroups | Where-Object { $_.transportType -eq "VM_MANAGEMENT" }).vlanID
    $mgmtVlanId = ((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq "t" }).vdsDetails.portgroups | Where-Object { $_.transportType -eq "MANAGEMENT" }).vlanID
    $vMotionVlanId = ((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq "t" }).vdsDetails.portgroups | Where-Object { $_.transportType -eq "VMOTION" }).vlanID
    $vSanVlanId = ((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq "t" }).vdsDetails.portgroups | Where-Object { $_.transportType -eq "VSAN" }).vlanID

    LogMessage -type INFO -message "[$vCenterFqdn] Establishing Connection"
    Connect-VIServer $vCenterFqdn -user $vCenterAdmin -password $vCenterAdminPassword *>$null
    $vmhostArray = Get-Cluster | Get-VMhost | Sort-Object -Property Name
    $clusterVdswitchNames = (Get-VDSwitch).name
    $clusterName = (Get-Cluster).name

    $existingAttribute = Get-CustomAttribute -Name vdsConfiguration -TargetType Cluster -erroraction SilentlyContinue
    If (!$existingAttribute) {
        New-CustomAttribute -Name vdsConfiguration -TargetType Cluster | Out-Null
    }

    $index = [System.Array]::IndexOf((Get-Cluster).customfields.keys, "vdsConfiguration")
    $storedVdsConfiguration = @((Get-Cluster).customfields.values)[$index] | ConvertFrom-Json
    If (!$storedVdsConfiguration) {
        $clustervdsConfiguration = @()
        Foreach ($vds in $clusterVdswitchNames) {
            # Gather data on VDS to migrate from
            $vds = Get-VDSwitch -Name $vds
            $vdsUUID = $vds.ExtensionData.Summary.Uuid
            $vdsReport = @()
            $vds.ExtensionData.Config.Host | ForEach-Object {
                $esx = Get-View $_.Config.Host
                $netSys = Get-View $esx.ConfigManager.NetworkSystem
                $netSys.NetworkConfig.ProxySwitch | where-object { $_.Uuid -eq $vdsUUID } | ForEach-Object {
                    $_.Spec.Backing.PnicSpec | ForEach-Object {
                        $row = "" | Select Host, dvSwitch, PNic
                        $row.Host = $esx.Name
                        $row.dvSwitch = $vds.Name
                        $row.PNic = $_.PnicDevice
                        $vdsReport += $row
                    }
                }
            }
            $clustervdsConfiguration += $vdsReport
        }
        $cluster = Get-Cluster -name $clusterName
        $cluster | Set-Annotation -CustomAttribute "vdsConfiguration" -Value ($clustervdsConfiguration | ConvertTo-Json) | Out-Null
        #$storedVdsConfiguration = (((Get-Cluster -name $clustername).customfields | Where-Object { $_.key -eq "vdsConfiguration" }).value) | ConvertFrom-Json
        $index = [System.Array]::IndexOf((Get-Cluster).customfields.keys, "vdsConfiguration")
        $storedVdsConfiguration = @((Get-Cluster).customfields.values)[$index] | ConvertFrom-Json
    }

    Foreach ($vdsName in $clusterVdswitchNames) {
        $vss_name = "$($vdsName)-vss"
        $vds = Get-VDSwitch -Name $vdsName
        $vdsUUID = $vds.ExtensionData.Summary.Uuid
        $vdsReport = @()
        $vds.ExtensionData.Config.Host | ForEach-Object {
            $esx = Get-View $_.Config.Host
            $netSys = Get-View $esx.ConfigManager.NetworkSystem
            $netSys.NetworkConfig.ProxySwitch | where-object { $_.Uuid -eq $vdsUUID } | ForEach-Object {
                $_.Spec.Backing.PnicSpec | ForEach-Object {
                    $row = "" | Select Host, dvSwitch, PNic
                    $row.Host = $esx.Name
                    $row.dvSwitch = $vds.Name
                    $row.PNic = $_.PnicDevice
                    $vdsReport += $row
                }
            }
        }
        foreach ($vmhost in $vmhostArray) {
            #Determine last NIC that was in VDS before any operation started
            $nicToMoveToVdsFirst = (($storedVdsConfiguration | Where-Object { ($_.host -eq $vmhost.name) -and ($_.dvSwitch -eq $vdsName) }).pnic)[-1]

            #Determine all NICs currently in VDS
            $nicsInVds = ($vdsReport | Where-Object { $_.host -eq $vmhost.name }).PNic

            #Remove last NIC from VDS if still part of VDS
            If ($nicToMoveToVdsFirst -in $nicsInVds) {
                LogMessage -type INFO -message "[$vmhost] Removing $nicToMoveToVdsFirst from VDS"
                Get-VMHostNetworkAdapter -VMHost $vmhost -Physical -Name $nicToMoveToVdsFirst | Remove-VDSwitchPhysicalNetworkAdapter -Confirm:$false | Out-Null
            } else {
                LogMessage -type INFO -message "[$vmhost] $nicToMoveToVdsFirst already removed from VDS. Skipping"
            }

            #Create corresponding VSS if not present
            $vssExists = Get-VMHost -Name $vmhost | Get-VirtualSwitch -Name $vss_name -errorAction silentlyContinue
            If (!($vssExists)) {
                LogMessage -type INFO -message "[$vmhost] Creating new VSS $vss_name"
                New-VirtualSwitch -VMHost $vmhost -Name $vss_name -mtu $mtu | Out-Null
            } else {
                LogMessage -type INFO -message "[$vmhost] VSS already exists. Skipping"
            }

            # NIC object to add to VSS
            $vmnicToMove = Get-VMHostNetworkAdapter -VMHost $vmhost -Name $nicToMoveToVdsFirst

            # VSS object to add NIC object to
            $vss = Get-VMHost -Name $vmhost | Get-VirtualSwitch -Name $vss_name

            #Add last NIC from VDS to VSS
            If ($vss.ExtensionData.Pnic -notlike "*$nicToMoveToVdsFirst") {
                LogMessage -type INFO -message "[$vmhost] Migrating $nicToMoveToVdsFirst from $vdsName to $vss_name"
                Add-VirtualSwitchPhysicalNetworkAdapter -VirtualSwitch $vss -VMHostPhysicalNic $vmnicToMove -confirm:$false
            } else {
                LogMessage -type INFO -message "[$vmhost] $nicToMoveToVdsFirst already part of VSS. Skipping"
            }
        }
    }

    $vm_mgmt_name = "vm_management"
    $esx_mgmt_name = "esx_management"
    $vmotion_name = "vmotion"
    $storage_name = "vsan"

    foreach ($vmhost in $vmhostArray) {
        #VM Management Portgroup
        $sourceVDSName = (Get-VDPortgroup -Name "$($clusterName)-vds01-pg-vm-mgmt").VDSwitch.name
        $targetVssName = "$($sourceVDSName)-vss"
        $tempMgmtPgExists = Get-VirtualPortGroup -VirtualSwitch (Get-VirtualSwitch -VMHost $vmhost -Name $targetVssName) -Name $vm_mgmt_name -errorAction SilentlyContinue
        If (!($tempMgmtPgExists)) {
            LogMessage -type INFO -message "[$vmhost] Creating VM management portgroup `'$vm_mgmt_name`'"
            New-VirtualPortGroup -VirtualSwitch (Get-VirtualSwitch -VMHost $vmhost -Name $targetVssName) -Name $vm_mgmt_name -VLanId $mgmtVmVlanId | Out-Null
        } else {
            LogMessage -type INFO -message "[$vmhost] VM management portgroup `'$vm_mgmt_name`' already exists. Skipping"
        }

        #ESX Management Portgroup
        #$sourceVDSName = (Get-VDPortgroup -Name "$($clusterName)-vds01-pg-esx-mgmt").VDSwitch.name
        $sourceVDSName = (Get-VDPortgroup -Name "vcfir-cl01-vds01-pg-esx-mgmt").VDSwitch.name
        $targetVssName = "$($sourceVDSName)-vss"
        $tempVsanPgExists = Get-VirtualPortGroup -VirtualSwitch (Get-VirtualSwitch -VMHost $vmhost -Name $targetVssName) -Name $esx_mgmt_name -errorAction SilentlyContinue
        If (!($tempVsanPgExists)) {
            LogMessage -type INFO -message "[$vmhost] Creating ESX Management portgroup `'$esx_mgmt_name`'"
            New-VirtualPortGroup -VirtualSwitch (Get-VirtualSwitch -VMHost $vmhost -Name $targetVssName) -Name $esx_mgmt_name -VLanId $mgmtVlanId | Out-Null
        } else {
            LogMessage -type INFO -message "[$vmhost] ESX Management portgroup `'$esx_mgmt_name`' already exists. Skipping"
        }
        #Migrate ESX Management vmKernel
        $vss = Get-VMHost -Name $vmhost | Get-VirtualSwitch -Name $targetVssName
        $vmks = $vmHost | Get-VMHostNetwork | Select-Object -ExpandProperty VirtualNic | Sort-Object Name
        $currentEsxManagementVmkPortgroup = ($vmks | Where-Object { $_.name -eq "vmk0" }).PortGroupName
        If ($currentEsxManagementVmkPortgroup -ne $esx_mgmt_name) {
            LogMessage -type INFO -message "[$vmhost] Migrating ESX Management vmKernel from $sourceVDSName to $targetVssName"
            Move-VMKernel -VMHost $vmhost -Interface "vmk0" -NetworkName $esx_mgmt_name
        } else {
            LogMessage -type INFO -message "[$vmhost] ESX Management vmKernel already on $targetVssName. Skipping"
        }

        #vMotion Portgroup
        #$sourceVDSName = (Get-VDPortgroup -Name "$($clusterName)-vds01-pg-vmotion").VDSwitch.name
        $sourceVDSName = (Get-VDPortgroup -Name "vcfir-cl01-vds01-pg-vmotion").VDSwitch.name
        $targetVssName = "$($sourceVDSName)-vss"
        $tempVmotionsPgExists = Get-VirtualPortGroup -VirtualSwitch (Get-VirtualSwitch -VMHost $vmhost -Name $targetVssName) -Name $vmotion_name -errorAction SilentlyContinue
        If (!($tempVmotionsPgExists)) {
            LogMessage -type INFO -message "[$vmhost] Creating vMotion portgroup `'$vmotion_name`'"
            New-VirtualPortGroup -VirtualSwitch (Get-VirtualSwitch -VMHost $vmhost -Name $targetVssName) -Name $vmotion_name -VLanId $vMotionVlanId | Out-Null
        } else {
            LogMessage -type INFO -message "[$vmhost] vMotion portgroup `'$vmotion_name`' already exists. Skipping"
        }
        #Migrate vMotion vmKernel
        $vss = Get-VMHost -Name $vmhost | Get-VirtualSwitch -Name $targetVssName
        $vmks = $vmHost | Get-VMHostNetwork | Select-Object -ExpandProperty VirtualNic | Sort-Object Name
        $currentVmotionVmkPortgroup = ($vmks | Where-Object { $_.name -eq "vmk1" }).PortGroupName
        If ($currentVmotionVmkPortgroup -ne $vmotion_name) {
            LogMessage -type INFO -message "[$vmhost] Migrating vMotion vmKernel from $sourceVDSName to $targetVssName"
            Move-VMKernel -VMHost $vmhost -Interface "vmk1" -NetworkName $vmotion_name
        } else {
            LogMessage -type INFO -message "[$vmhost] vMotion vmKernel already on $targetVssName. Skipping"
        }

        #vSAN Portgroup
        #$sourceVDSName = (Get-VDPortgroup -Name "$($clusterName)-vds01-pg-vsan").VDSwitch.name
        $sourceVDSName = (Get-VDPortgroup -Name "vcfir-cl01-vds01-pg-vsan").VDSwitch.name
        $targetVssName = "$($sourceVDSName)-vss"
        $tempVsanPgExists = Get-VirtualPortGroup -VirtualSwitch (Get-VirtualSwitch -VMHost $vmhost -Name $targetVssName) -Name $storage_name -errorAction SilentlyContinue
        If (!($tempVsanPgExists)) {
            LogMessage -type INFO -message "[$vmhost] Creating vSAN portgroup `'$storage_name`'"
            New-VirtualPortGroup -VirtualSwitch (Get-VirtualSwitch -VMHost $vmhost -Name $targetVssName) -Name "$storage_name" -VLanId $vSanVlanId | Out-Null
        } else {
            LogMessage -type INFO -message "[$vmhost] vSAN portgroup `'$storage_name`' already exists. Skipping"
        }
        #Migrate VSAN vmKernel
        $vss = Get-VMHost -Name $vmhost | Get-VirtualSwitch -Name $targetVssName
        $vmks = $vmHost | Get-VMHostNetwork | Select-Object -ExpandProperty VirtualNic | Sort-Object Name
        $currentStorageVmkPortgroup = ($vmks | Where-Object { $_.name -eq "vmk2" }).PortGroupName
        If ($currentStorageVmkPortgroup -ne $storage_name) {
            LogMessage -type INFO -message "[$vmhost] Migrating vSAN vmKernel from $sourceVDSName to $targetVssName"
            Move-VMKernel -VMHost $vmhost -Interface "vmk2" -NetworkName $storage_name
        } else {
            LogMessage -type INFO -message "[$vmhost] vSAN vmKernel already on $targetVssName. Skipping"
        }
        Start-Sleep 5
    }
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function Move-ClusterHostNetworkingTovSS

Function Move-ClusterVmnicTovSwitch {
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
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $vCenterConnection = connect-viserver $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    $esxiHosts = get-cluster -name $clusterName | get-vmhost
    Foreach ($esxiHost in $esxiHosts) {
        LogMessage -type INFO -message "[$esxiHost] Migrating `'$vmnic`' from vDS to vSwitch0"
        Get-VMHostNetworkAdapter -VMHost $esxiHost -Physical -Name $vmnic | Remove-VDSwitchPhysicalNetworkAdapter -Confirm:$false | Out-Null
        New-VirtualSwitch -VMHost $esxiHost -Name vSwitch0 -nic $vmnic -mtu $mtu | Out-Null
        New-VirtualPortGroup -VirtualSwitch (Get-VirtualSwitch -VMHost $esxiHost -Name "vSwitch0") -Name "mgmt_temp" -VLanId $VLanId | Out-Null
    }
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function Move-ClusterVmnicTovSwitch

Function Set-ClusterHostsvSanIgnoreClusterMemberList {
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
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    # prepare ESXi hosts for cluster migration - Tested
    $vCenterConnection = connect-viserver $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    Get-Cluster -name $clusterName | Get-VMHost | Get-VMHostService | Where-Object { $_.label -eq "SSH" } | Start-VMHostService | Out-Null
    $esxiHosts = get-cluster -name $clusterName | get-vmhost
    if ($setting -eq "enable") {
        $value = 1
    } else {
        $value = 0
    }
    $esxCommand = "esxcli system settings advanced set --int-value=$value --option=/VSAN/IgnoreClusterMemberListUpdates"
    foreach ($esxiHost in $esxiHosts) {
        $esxiRootPassword = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "ESXI") -and ($_.entityName -eq $esxiHost.Name) -and ($_.username -eq "root") }).password
        $password = ConvertTo-SecureString $esxiRootPassword -AsPlainText -Force
        $mycreds = New-Object System.Management.Automation.PSCredential ("root", $password)
        Get-SSHTrustedHost -HostName $esxiHost | Remove-SSHTrustedHost | Out-Null
        LogMessage -type INFO -message "[$esxiHost] Setting vSAN Ignore Cluster Member to `'$setting`'"
        $sshSession = New-SSHSession -computername $esxiHost -credential $mycreds -AcceptKey
        Invoke-SSHCommand -timeout 30 -sessionid $sshSession.SessionId -command $esxCommand | Out-Null
    }
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function Set-ClusterHostsvSanIgnoreClusterMemberList

Function Set-ClusterDRSLevel {
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
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $vCenterConnection = connect-viserver $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    set-cluster -cluster $clusterName -DrsAutomationLevel $DrsAutomationLevel -confirm:$false
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function Set-ClusterDRSLevel

Function Remove-NonResponsiveHosts {
    <#
    .SYNOPSIS
    Removes non-responsive hosts from a cluster and cleans up related transport nodes in NSX

    .DESCRIPTION
    The Remove-NonResponsiveHosts cmdlet removes non-responsive hosts from a cluster and cleans up related transport nodes in NSX

    .EXAMPLE
    Remove-NonResponsiveHosts -vCenterFQDN "sfo-m01-vc01.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01" -nsxManagerFqdn "sfo-m01-nsx01.sfo.rainpole.io" -nsxManagerAdmin "admin" -nsxManagerAdminPassword "VMw@re1!VMw@re1!" -nsxManagerRootPassword "VMw@re1!VMw@re1!"

    .PARAMETER vCenterFQDN
    FQDN of the vCenter instance hosting the cluster from which to remove non-responsive hosts

    .PARAMETER vCenterAdmin
    Admin user of the vCenter instance hosting the cluster from which to remove non-responsive hosts

    .PARAMETER vCenterAdminPassword
    Admin password for the vCenter instance hosting the cluster from which to remove non-responsive hosts

    .PARAMETER clusterName
    Name of the vSphere cluster instance from which to remove non-responsive hosts

    .PARAMETER nsxManagerFqdn
    FQDN of the NSX Manager where non responsive hosts exist

    .PARAMETER nsxManagerAdmin
    Admin user of the NSX Manager where non responsive hosts exist

    .PARAMETER nsxManagerAdminPassword
    Admin Password of the NSX Manager where non responsive hosts exist

    .PARAMETER nsxManagerRootPassword
    root Password of the NSX Manager where non responsive hosts exist
    #>

    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $nsxManagerFqdn,
        [Parameter (Mandatory = $true)][String] $nsxManagerAdmin,
        [Parameter (Mandatory = $true)][String] $nsxManagerAdminPassword,
        [Parameter (Mandatory = $true)][String] $nsxManagerRootPassword
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    #Get Non-Repsonsive Hosts from vCenter
    $vCenterConnection = Connect-Viserver $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    $nonResponsiveHosts = Get-Cluster -name $clusterName | Get-VMhost | Where-Object { $_.ConnectionState -in "NotResponding", "Disconnected" } | Sort-Object

    #Get Cluster MoRef
    $clusterMoRef = (Get-Cluster -name $clusterName).ExtensionData.MoRef.Value

    #Create NSX Header for API Calls
    $headers = VCFIRCreateHeader -username $nsxManagerAdmin -password $nsxManagerAdminPassword

    #Check NSX Manager version
    $uri = "https://$nsxManagerFqdn/api/v1/node"
    $nsxManagerVersion = [INT](((((Invoke-WebRequest -Method GET -URI $uri -ContentType application/json -headers $headers).content | ConvertFrom-Json).product_version).replace(".", "")).substring(0, 3))

    If ($nsxManagerVersion) {
        #Get Transport Nodes for Cluster
        $uri = "https://$nsxManagerFqdn/api/v1/transport-nodes/"
        LogMessage -type INFO -message "[$nsxManagerFqdn] Getting Transport Nodes"
        $transportNodeContents = (Invoke-WebRequest -Method GET -URI $uri -ContentType application/json -headers $headers).content | ConvertFrom-Json
        $allHostTransportNodes = ($transportNodeContents.results | Where-Object { ($_.resource_type -eq "TransportNode") -and ($_.node_deployment_info.os_type -eq "ESXI") })
        LogMessage -type INFO -message "[$nsxManagerFqdn] Filtering Transport Nodes to members of cluster $clusterName"
        $clusterHosts = $nonResponsiveHosts.name
        $hostIDs = ($allHostTransportNodes | Where-Object { $_.display_name -in $clusterHosts } | Sort-Object -property display_name).id

        #Attempt Remove NSX From Cluster to detach Transport Node Profile
        $uri = "https://$nsxManagerFqdn/api/v1/fabric/compute-collections"
        $computeCollections = (Invoke-WebRequest -Method GET -URI $uri -ContentType application/json -headers $headers).content | ConvertFrom-Json
        $clusterComputeCollectionId = ($computeCollections.results | Where-Object { $_.cm_local_id -eq $clusterMoRef }).external_id
        $clusterVlcmManaged = (($computeCollections.results | Where-Object { $_.cm_local_id -eq $clusterMoRef }).origin_properties | Where-Object { $_.key -eq "lifecycleManaged" }).value

        #Remove non-responsive hosts
        Foreach ($nonResponsiveHost in $nonResponsiveHosts) {
            LogMessage -type INFO -message "[$($nonResponsiveHost.name)] Removing from $clusterName"
            Get-VMHost | Where-Object { $_.Name -eq $nonResponsiveHost.Name } | Remove-VMHost -Confirm:$false
        }
        Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false

        $uri = "https://$nsxManagerFqdn/api/v1/fabric/compute-collections/$($clusterComputeCollectionId)?action=remove_nsx"

        If ($nsxManagerVersion -ge "412") {
            $detachTNP = Invoke-WebRequest -Method POST -URI $uri -ContentType application/json -headers $headers

            #Wait for Hosts to be Orphaned
            Foreach ($hostID in $hostIDs) {
                LogMessage -type WAIT -message "[$nsxManagerFqdn] Waiting for Host $(($allHostTransportNodes | Where-Object {$_.id -eq $hostID}).display_name) to be `'Orphaned`'"
                Do {
                    $uri = "https://$nsxManagerFqdn/api/v1/transport-nodes/$($hostID)/state"
                    $tnState = (Invoke-WebRequest -Method GET -URI $uri -ContentType application/json -headers $headers).content | ConvertFrom-Json
                } Until ($tnState.state -eq "orphaned")
            }
        }
        #Attempt to Force Delete the Transport Nodes
        Foreach ($hostID in $hostIDs) {
            $uri = "https://$nsxManagerFqdn/api/v1/transport-nodes/$($hostID)?force=true&unprepare_host=false"
            LogMessage -type INFO -message "[$nsxManagerFqdn] Removing Transport Node associated with $(($allHostTransportNodes | Where-Object {$_.id -eq $hostID}).display_name)"
            $deleteTN = Invoke-WebRequest -Method DELETE -URI $uri -ContentType application/json -headers $headers
        }

        #Wait for Transport Nodes to flush
        LogMessage -type WAIT -message "[$nsxManagerFqdn] Waiting for Transport Nodes to flush. This Task May Take Some Time To Complete"
        $body = '{"primary": {"resource_type": "HostTransportNode"}}'
        $uri = "https://$nsxManagerFqdn/policy/api/v1/search/aggregate?page_size=50"
        Do {
            $transportNodeContents = ((Invoke-WebRequest -Method POST -URI $uri -ContentType application/json -headers $headers -body $body).content | ConvertFrom-Json).results
            $deletedhostIDs = ($transportNodeContents.Primary | Where-Object { $_.display_name -in $clusterHosts }).id
        } Until(!$deletedhostIDs)

        #Reattach TNP
        #Get Transport Node Profiles
        $uri = "https://$nsxManagerFqdn/policy/api/v1/infra/host-transport-node-profiles"

        $transportNodeProfiles = ((Invoke-WebRequest -Method GET -URI $uri -ContentType application/json -headers $headers).content | ConvertFrom-Json).results
        $clusterTransportNodeProfile = $transportNodeProfiles | where-object { $_.display_name -like "*$clusterName*" }

        #Create Transport Node Collection
        $body = '{
        "resource_type": "TransportNodeCollection",
        "display_name": "' + $clusterName + '",
        "description": "' + $clusterName + '",
        "compute_collection_id": "'+ $clusterComputeCollectionId + '",
        "transport_node_profile_id": "'+ $clusterTransportNodeProfile.id + '"
        }'
        $uri = "https://$nsxManagerFqdn/api/v1/transport-node-collections"
        LogMessage -type INFO -message "[$nsxManagerFqdn] Reattaching Transport Node Profile to Cluster $clusterName"
        $response = Invoke-WebRequest -Method POST -URI $uri -ContentType application/json -headers $headers -body $body
    } else {
        LogMessage -type ERROR -message "[$jumpboxName] Unable to determine NSX Manager Version. Check that it was successfully restored."
        Break
    }
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function Remove-NonResponsiveHosts

Function Add-HostsToCluster {
    <#
    .SYNOPSIS
    Adds hosts to a vSphere cluster using data from the SDDC Manager backup

    .DESCRIPTION
    The Add-HostsToCluster cmdlet Adds hosts to a vSphere cluster using data from the SDDC Manager backup

    .EXAMPLE
    Add-HostsToCluster -vCenterFQDN "sfo-m01-vc02.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01" -extractedSDDCDataFile ".\extracted-sddc-data.json" -sddcManagerFQDN "sfo-vcf01.sfo.rainpole.io" -sddcManagerAdmin "administrator@vsphere.local" -sddcManagerAdminPassword "VMw@re1!"

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
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $sddcManagerConnection = Connect-VcfSddcManagerServer -server $sddcManagerFQDN -User $sddcManagerAdmin -Password $sddcManagerAdminPassword
    $newHosts = ((Invoke-VcfGetHosts).Elements | where-object { $_.id -in (((Invoke-VcfGetClusters).Elements | Where-Object { $_.Name -eq $clusterName }).Hosts.Id) }).fqdn | Sort-Object
    $vCenterConnection = connect-viserver $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    foreach ($newHost in $newHosts) {
        $vmHosts = (Get-cluster -name $clusterName | Get-VMHost).Name | Sort-Object
        if ($newHost -notin $vmHosts) {
            $esxiRootPassword = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "ESXI") -and ($_.entityName -eq $newHost) -and ($_.username -eq "root") }).password
            $esxiConnection = connect-viserver $newHost -user root -password $esxiRootPassword
            if ($esxiConnection) {
                LogMessage -type INFO -message "[$newHost] Adding to cluster $clusterName"
                Add-VMHost $newHost -username root -password $esxiRootPassword -Location $clusterName -Force -Confirm:$false | Out-Null
            } else {
                Write-Error "[$newHost] Unable to connect. Host will not be added to the cluster"
            }
        } else {
            LogMessage -type INFO -message "[$newHost] Already part of $clusterName. Skipping"
        }
    }
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
    Disconnect-VcfSddcManagerServer *
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function Add-HostsToCluster

Function Add-VMKernelsToHost {
    <#
    .SYNOPSIS
    Adds VMkernels to ESXi hosts using data from the SDDC Manager inventory to map the correct IP addresses

    .DESCRIPTION
    The Add-VMKernelsToHost cmdlet adds VMkernels to ESXi hosts using data from the SDDC Manager inventory to map the correct IP addresses

    .EXAMPLE
    Add-VMKernelsToHost -targetFQDN "sfo-m01-vc01.sfo.rainpole.io" -targetAdmin "administrator@vsphere.local" -targetAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01" -sddcManagerFQDN "sfo-vcf01.sfo.rainpole.io" -sddcManagerAdmin "administrator@vsphere.local" -sddcManagerAdminPassword "VMw@re1!"

    .PARAMETER targetFqdn
    FQDN of the target ESXi host or vCenter hosting the ESXi hosts to which VMkernels will be added

    .PARAMETER targetAdmin
    Admin user of the target ESXi host or vCenter hosting the ESXi hosts to which VMkernels will be added

    .PARAMETER targetAdminPassword
     Admin password of the target ESXi host or vCenter hosting the ESXi hosts to which VMkernels will be added

    .PARAMETER clusterName
    Name of the vSphere cluster instance hosting the ESXi hosts to which VMkernels will be added

    .PARAMETER sddcManagerFQDN
    FQDN of SDDC Manager

    .PARAMETER sddcManagerAdmin
    SDDC Manager API username with ADMIN role

    .PARAMETER sddcManagerAdminPassword
    SDDC Manager API username password

    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem
    #>

    Param(
        [Parameter (Mandatory = $false)][String] $targetFQDN,
        [Parameter (Mandatory = $true)][String] $targetAdmin,
        [Parameter (Mandatory = $true)][String] $targetAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $sddcManagerFQDN,
        [Parameter (Mandatory = $true)][String] $sddcManagerAdmin,
        [Parameter (Mandatory = $true)][String] $sddcManagerAdminPassword,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $false)][ValidateSet("vcenter", "esx")][String] $targetType = "vcenter"
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON
    $workloadDomain = $extractedSDDCData.workloadDomains | Where-Object { $_.vsphereClusterDetails.name -contains $clusterName }
    $vmHosts = ($workloadDomain.vsphereClusterDetails | Where-Object { $_.name -eq $clusterName }).hosts.hostname | Sort-Object # Can we just use this for both tracks?
    $sddcManagerConnection = Connect-VcfSddcManagerServer -server $sddcManagerFQDN -User $sddcManagerAdmin -Password $sddcManagerAdminPassword
    $allHostDetails = (Invoke-VcfGetHosts).Elements | Where-Object { $_.fqdn -in $vmHosts }
    $clusterDetails = (Invoke-VcfGetClusters).Elements | Where-Object { $_.Name -eq $clusterName }
    $clusterVdses = (Invoke-VcfGetVdses -ClusterId $clusterDetails.id)

    If ($targetType -eq "vCenter") {
        $vCenterConnection = Connect-VIServer $targetFQDN -user $targetAdmin -password $targetAdminPassword
    }

    foreach ($vmhost in $vmHosts) {
        $networkPoolId = ($workloadDomain.vsphereClusterDetails.hosts | Where-Object { $_.hostname -eq $vmhost }).networkPoolID
        $networkPoolDetails = (Invoke-VcfGetNetworksOfNetworkPool -id $networkPoolID).elements

        $vmotionIP = (($allHostDetails | Where-Object { $_.fqdn -eq $vmhost }).ipaddresses | Where-Object { $_.type -eq "VMOTION" })._IpAddress
        $vmotionMask = ($networkPoolDetails | Where-Object { $_.type -eq "VMOTION" }).Mask
        $vmotionMTU = ($networkPoolDetails | Where-Object { $_.type -eq "VMOTION" }).mtu
        $vmotionGW = ($networkPoolDetails | Where-Object { $_.type -eq "VMOTION" }).gateway
        $vmotionPG = ($clusterVdses.PortGroups | Where-Object { $_.TransportType -eq "VMOTION" }).Name

        $vsanIP = (($allHostDetails | Where-Object { $_.fqdn -eq $vmhost }).ipaddresses | Where-Object { $_.type -eq "VSAN" })._IpAddress
        $vsanMask = ($networkPoolDetails | Where-Object { $_.type -eq "VSAN" }).Mask
        $vsanMTU = ($networkPoolDetails | Where-Object { $_.type -eq "VSAN" }).mtu
        $vsanGW = ($networkPoolDetails | Where-Object { $_.type -eq "VSAN" }).gateway
        $vsanPG = ($clusterVdses.PortGroups | Where-Object { $_.TransportType -eq "VSAN" }).Name

        If ($targetType -eq "vCenter") {
            $vmotionVDSName = ((Invoke-VcfGetVdses -ClusterId ((Invoke-VcfGetClusters).Elements | Where-Object { $_.Name -eq $clusterName }).Id) | Where-Object { $_.Portgroups.TransportType -contains "VMOTION" }).Name
            $vsanVDSName = ((Invoke-VcfGetVdses -ClusterId ((Invoke-VcfGetClusters).Elements | Where-Object { $_.Name -eq $clusterName }).Id) | Where-Object { $_.Portgroups.TransportType -contains "VSAN" }).Name

        } else {
            $esxConnection = Connect-VIServer $vmhost -user $targetAdmin -password $targetAdminPassword
            $targetVssName = 'vSwitch0'
            $vMotionVlanId = ($networkPoolDetails | Where-Object { $_.type -eq "VMOTION" }).VlanId
            $vsanVlanId = ($networkPoolDetails | Where-Object { $_.type -eq "VSAN" }).VlanId
        }

        LogMessage -type INFO -message "[$vmhost] Creating vMotion vMK"
        $vmk1Exists = Get-VMHostNetworkAdapter -name "vmk1" -ErrorAction SilentlyContinue
        If ($targetType -eq "vCenter") {
            $dvportgroup = Get-VDPortgroup -name $vmotionPG -VDSwitch $vmotionVDSName
            If (!$vmk1Exists) {
                $vmk = New-VMHostNetworkAdapter -VMHost $vmhost -VirtualSwitch $vmotionVDSName -mtu $vmotionMTU -PortGroup $dvportgroup -ip $vmotionIP -SubnetMask $vmotionMask -NetworkStack (Get-VMHostNetworkStack -vmhost $vmhost | Where-Object { $_.id -eq "vmotion" })
            }
        } else {
            $vssVmotionPortgroupExists = Get-VirtualPortGroup -VirtualSwitch $targetVssName -Name $vmotionPG -errorAction SilentlyContinue
            If (!($vssVmotionPortgroupExists)) {
                LogMessage -type INFO -message "[$vmhost] Creating vMotion portgroup `'$vmotionPG`'"
                New-VirtualPortGroup -VirtualSwitch (Get-VirtualSwitch -VMHost $vmhost -Name $targetVssName) -Name $vmotionPG -VLanId $vMotionVlanId | Out-Null
            } else {
                LogMessage -type INFO -message "[$vmhost] vMotion portgroup `'$vmotionPG`' already exists. Skipping"
            }
            $vssVmotionPortgroup = Get-VirtualPortGroup -name $vmotionPG -VirtualSwitch $targetVssName
            If (!$vmk1Exists) {
                $vmk = New-VMHostNetworkAdapter -VMHost $vmhost -VirtualSwitch $targetVssName -mtu $vmotionMTU -PortGroup $vssVmotionPortgroup -ip $vmotionIP -SubnetMask $vmotionMask -NetworkStack (Get-VMHostNetworkStack -vmhost $vmhost | Where-Object { $_.id -eq "vmotion" })
            }
        }
        LogMessage -type INFO -message "[$vmhost] Setting vMotion Gateway"
        $vmkName = 'vmk1'
        $esx = Get-VMHost -Name $vmHost
        $esxcli = Get-EsxCli -VMHost $esx -V2
        $interface = $esxcli.network.ip.interface.ipv4.get.Invoke(@{interfacename = $vmkName })
        $interfaceArg = @{
            netmask       = $interface[0].IPv4Netmask
            type          = $interface[0].AddressType.ToLower()
            ipv4          = $interface[0].IPv4Address
            interfacename = $interface[0].Name
        }
        $esxcli.network.ip.interface.ipv4.set.Invoke($interfaceArg) *>$null
        $esxcli.network.ip.route.ipv4.add.Invoke(@{ netstack = 'vmotion'; network = 'default'; gateway = $vmotionGW }) *>$null

        LogMessage -type INFO -message "[$vmhost] Creating vSAN vMK"
        $vmk2Exists = Get-VMHostNetworkAdapter -name "vmk2" -ErrorAction SilentlyContinue
        If ($targetType -eq "vCenter") {
            $dvportgroup = Get-VDPortgroup -name $vsanPG -VDSwitch $vsanVDSName
            If (!$vmk1Exists) {
                $vmk = New-VMHostNetworkAdapter -VMHost $vmhost -VirtualSwitch $vsanVDSName -mtu $vsanMTU -PortGroup $dvportgroup -ip $vsanIP -SubnetMask $vsanMask -VsanTrafficEnabled:$true
            }
        } else {
            $vssVsanPortgroupExists = Get-VirtualPortGroup -VirtualSwitch $targetVssName -Name $vsanPG -errorAction SilentlyContinue
            If (!($vssVsanPortgroupExists)) {
                LogMessage -type INFO -message "[$vmhost] Creating vSAN portgroup `'$vsanPG`'"
                New-VirtualPortGroup -VirtualSwitch (Get-VirtualSwitch -VMHost $vmhost -Name $targetVssName) -Name $vsanPG -VLanId $vsanVlanId | Out-Null
            } else {
                LogMessage -type INFO -message "[$vmhost] vSAN portgroup `'$vsanPG`' already exists. Skipping"
            }
            $vssVsanPortgroup = Get-VirtualPortGroup -name $vsanPG -VirtualSwitch $targetVssName
            If (!$vmk1Exists) {
                $vmk = New-VMHostNetworkAdapter -VMHost $vmhost -VirtualSwitch $targetVssName -mtu $vsanMTU -PortGroup $vssVsanPortgroup -ip $vsanIP -SubnetMask $vsanMask -VsanTrafficEnabled $true
            }
        }

        LogMessage -type INFO -message "[$vmhost] Setting vSAN Gateway"
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
        If ($targetType -eq "esx") {
            Disconnect-VIServer * -confirm:$false
        }
    }
    If ($targetType -eq "vCenter") {
        Disconnect-VIServer * -confirm:$false
    }
    Disconnect-VcfSddcManagerServer *
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function Add-VMKernelsToHost

Function New-RebuiltVsanDatastore {
    <#
    .SYNOPSIS
    Guides the rebuild of a vSAN datastore on a recovered cluster. It leverages the first host in the cluster as a reference host for disk layout to allow the user to control the vSAN Diskgroup configuration

    .DESCRIPTION
    The New-RebuiltVsanDatastore cmdlet guides the rebuild of a vSAN datastore on a recovered cluster. It leverages the first host in the cluster as a reference host for disk layout to allow the user to control the vSAN Diskgroup configuration
    Should only be used if the disk configuration is standardized across the hosts

    .EXAMPLE
    New-RebuiltVsanDatastore -vCenterFQDN "sfo-m01-vc01.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01" -extractedSDDCDataFile ".\extracted-sddc-data.json"

    .PARAMETER vCenterFQDN
    FQDN of the vCenter instance hosting the cluster where the vSAN Datastore will be rebuilt

    .PARAMETER vCenterAdmin
    Admin user of the vCenter instance hosting the cluster where the vSAN Datastore will be rebuilt

    .PARAMETER vCenterAdminPassword
    Admin password for the vCenter instance hosting the cluster where the vSAN Datastore will be rebuilt

    .PARAMETER clusterName
    Name of the vSphere cluster instance where the vSAN Datastore will be rebuilt

    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem
    #>

    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON
    $datastoreName = ($extractedSddcData.workloadDomains.vsphereClusterDetails | Where-Object { $_.name -eq $clusterName }).primaryDatastoreName
    $datastoreType = ($extractedSddcData.workloadDomains.vsphereClusterDetails | Where-Object { $_.name -eq $clusterName }).primaryDatastoreType

    LogMessage -type INFO -message "[$jumpboxName] Connecting to Restored vCenter: $vCenterFQDN"
    $restoredvCenterConnection = Connect-ViServer $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    If ($datastoreType -ne "VSAN_ESA") {
        $vmhosts = (Get-Cluster -name $clusterName | Get-VMHost | Sort-Object -property Name)
        LogMessage -type INFO -message "[$($vmhosts[0].name)] Using host as reference for Eligible Physical Disks"

        $disks = ((Get-Cluster -name $clusterName | Get-VMHost | Sort-Object -property Name)[0] | Get-VMHostDisk) | Where-Object { $_.ScsiLun.VsanStatus -eq 'Eligible' } | Sort-Object -Property @{e = { $_.scsilun.runtimename } }
        $disksDisplayObject = @()
        $disksIndex = 1
        $disksDisplayObject += [pscustomobject]@{
            'ID'            = "ID"
            'canonicalName' = "Canonical Name"
            'size'          = "Size (GB)"
            'ssd'           = "SSD"
            'scsiLun'       = "SCSI LUN ID"
        }
        $disksDisplayObject += [pscustomobject]@{
            'ID'            = "--"
            'canonicalName' = "--------------------"
            'size'          = "-------------"
            'ssd'           = "------"
            'scsiLun'       = "-------------"
        }
        Foreach ($disk in $disks) {
            If ($disk.ScsiLun.CapacityGB -ne $null) {
                $disksDisplayObject += [pscustomobject]@{
                    'ID'            = $disksIndex
                    'canonicalName' = $disk.ScsiLun.CanonicalName
                    'size'          = $disk.ScsiLun.CapacityGB
                    'ssd'           = $disk.ScsiLun.IsSsd
                    'scsiLun'       = $disk.ScsiLun.RuntimeName
                }
                $disksIndex++
            }
        }

        $diskGroupConfiguration = @()
        $remainingDisksDisplayObject = $disksDisplayObject
        Write-Host ""; $remainingDisksDisplayObject | format-table -Property @{Expression = " " }, id, canonicalName, size, ssd, scsiLun -autosize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r", "`n") }
        Do {
            Write-Host ""; Write-Host " Enter the desired number of disk groups to create (between 1 and 5), or C to Cancel: " -ForegroundColor Yellow -nonewline
            $diskGroupNumber = Read-Host
        } Until (($diskGroupNumber -in "1", "2", "3", "4", "5") -or ($diskGroupNumber -eq "C"))
        If ($diskGroupNumber -eq "C") { Break }

        #Loop Through Disk Group Creation
        For ($i = 1; $i -le $diskGroupNumber; $i++) {
            If ($i -gt 1) {
                Write-Host ""; $remainingDisksDisplayObject | format-table -Property @{Expression = " " }, id, canonicalName, size, ssd -autosize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r", "`n") }
            }
            Do {
                If ($i -gt 1) { Write-Host "" }; Write-Host " Enter the ID of disk to use as Cache Disk for Disk Group $i, or C to Cancel: " -ForegroundColor Yellow -nonewline
                $cacheDiskSelection = Read-Host
            } Until (($cacheDiskSelection -in $remainingDisksDisplayObject.id) -OR ($cacheDiskSelection -eq "c"))
            If ($cacheDiskSelection -eq "c") { Break }
            $tempRemainingDisksDisplayObject = @()
            Foreach ( $displayDisk in $remainingDisksDisplayObject) {
                If ($displayDisk.id -ne $cacheDiskSelection) {
                    $tempRemainingDisksDisplayObject += $displayDisk
                }
            }
            $remainingDisksDisplayObject = $tempRemainingDisksDisplayObject
            Write-Host ""; $remainingDisksDisplayObject | format-table -Property @{Expression = " " }, id, canonicalName, size, ssd -autosize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r", "`n") }
            Do {
                Write-Host ""; Write-Host " Enter a comma seperated list of IDs to be used as Capacity Disks for Disk Group $i, or C to Cancel: " -ForegroundColor Yellow -nonewline
                $capacityDiskSelection = Read-Host
                If ($capacityDiskSelection -ne "C") {
                    $capacityDiskSelectionInvalid = $false
                    $capacityDiskArray = $capacityDiskSelection -split (",")
                    Foreach ($capacityDisk in $capacityDiskArray) {
                        If ($capacityDisk -notin $disksDisplayObject.id) {
                            $capacityDiskSelectionInvalid = $true
                        }
                    }
                }
            } Until (($capacityDiskSelectionInvalid -eq $false) -OR ($capacityDiskSelection -eq "c"))
            If ($capacityDiskSelection -eq "c") { Break }
            $diskGroupConfiguration += [PSCustomObject]@{
                'cacheDiskID'     = $cacheDiskSelection
                'capacityDiskIDs' = $capacityDiskArray
            }
            $tempRemainingDisksDisplayObject = @()
            Foreach ( $displayDisk in $remainingDisksDisplayObject) {
                If ($displayDisk.id -notin $capacityDiskArray) {
                    $tempRemainingDisksDisplayObject += $displayDisk
                }
            }
            $remainingDisksDisplayObject = $tempRemainingDisksDisplayObject
        }
        If (($cacheDiskSelection -eq "c") -or ($capacityDiskSelection -eq "c")) { Break }

        $proposedConfigDisplayObject = @()
        $configIndex = 1
        $proposedConfigDisplayObject += [pscustomobject]@{
            'diskGroup'         = "Disk Group"
            'cacheDiskID'       = "Cache Disk ID"
            'cacheDiskCN'       = "Cache Disk Canonical Name"
            'cacheDiskCapacity' = "Cache Disk (GB)"
            'capacityDiskIDs'   = "Capacity Disk IDs"
            'capacityCNs'       = "Capacity Disk Canonical Names"
            'capacityDiskSize'  = "Capacity Disks (GB)"
        }
        $proposedConfigDisplayObject += [pscustomobject]@{
            'diskGroup'         = "----------"
            'cacheDiskID'       = "-------------"
            'cacheDiskCN'       = "-------------------------"
            'cacheDiskCapacity' = "---------------"
            'capacityDiskIDs'   = "-----------------"
            'capacityCNs'       = "----------------------------------------"
            'capacityDiskSize'  = "-------------------"
        }
        Foreach ($config in $diskGroupConfiguration) {
            $proposedConfigDisplayObject += [pscustomobject]@{
                'diskGroup'         = $configIndex
                'cacheDiskID'       = $config.cacheDiskID
                'cacheDiskCN'       = ($disksDisplayObject | Where-Object { $_.id -eq $config.cacheDiskID }).canonicalName
                'cacheDiskCapacity' = ($disksDisplayObject | Where-Object { $_.id -eq $config.cacheDiskID }).size
                'capacityDiskIDs'   = $config.capacityDiskIDs -join (", ")
                'capacityCNs'       = (($disksDisplayObject | Where-Object { $_.id -in $config.capacityDiskIDs }).canonicalName) -join (", ")
                'capacityDiskSize'  = (($disksDisplayObject | Where-Object { $_.id -in $config.capacityDiskIDs }).size) -join (", ")
            }
            $configIndex++
        }
        Write-Host ""; Write-Host " Proposed Disk Group Configuration " -ForegroundColor Yellow
        Write-Host ""; $proposedConfigDisplayObject | format-table -Property @{Expression = " " }, diskGroup, cacheDiskID, cacheDiskCN, cacheDiskCapacity, capacityDiskIDs, capacityCNs, capacityDiskSize -autosize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r", "`n") }
        Write-Host ""; Write-Host " Do you wish to proceed with the proposed configuration? (Y/N): " -ForegroundColor Yellow -nonewline
        $proposedConfigAccepted = Read-Host
        $proposedConfigAccepted = $proposedConfigAccepted -replace "`t|`n|`r", ""
        If ($proposedConfigAccepted -eq "Y") {
            LogMessage -type INFO -message "[$clusterName] Starting Parallel Disk Group Creation across all hosts"
            Foreach ($vmHost in $vmHosts) {
                $scriptBlock = {
                    $moduleFunctions = Import-Module VMware.CloudFoundation.InstanceRecovery -passthru
                    $restoredvCenterConnection = Connect-ViServer $using:vCenterFQDN -user $using:vCenterAdmin -password $using:vCenterAdminPassword
                    $vmhost = Get-VMHost -name $using:vmhost.name
                    $disks = Get-VMHost -name $using:vmhost.name | Get-VMHostDisk | Where-Object { $_.ScsiLun.VsanStatus -eq 'Eligible' } | Sort-Object -Property @{e = { $_.scsilun.runtimename } }
                    $disksDisplayObject = @()
                    $disksIndex = 1
                    $disksDisplayObject += [pscustomobject]@{
                        'ID'            = "ID"
                        'canonicalName' = "Canonical Name"
                        'size'          = "Size (GB)"
                        'ssd'           = "SSD"
                        'scsiLun'       = "SCSI LUN ID"
                    }
                    $disksDisplayObject += [pscustomobject]@{
                        'ID'            = "--"
                        'canonicalName' = "--------------------"
                        'size'          = "-------------"
                        'ssd'           = "------"
                        'scsiLun'       = "-------------"
                    }
                    Foreach ($disk in $disks) {
                        If ($disk.ScsiLun.CapacityGB -ne $null) {
                            $disksDisplayObject += [pscustomobject]@{
                                'ID'            = $disksIndex
                                'canonicalName' = $disk.ScsiLun.CanonicalName
                                'size'          = $disk.ScsiLun.CapacityGB
                                'ssd'           = $disk.ScsiLun.IsSsd
                                'scsiLun'       = $disk.ScsiLun.RuntimeName
                            }
                            $disksIndex++
                        }
                    }
                    For ($i = 1; $i -le $using:diskGroupNumber; $i++) {
                        $diskGroupConfigurationIndex = ($i - 1)
                        $diskGroupConfiguration = $using:diskGroupConfiguration
                        $cacheDiskCanonicalName = (($disksDisplayObject | Where-Object { $_.id -eq $diskGroupConfiguration[$diskGroupConfigurationIndex].cacheDiskID }).canonicalName)
                        $capacityDiskCanonicalNames = (($disksDisplayObject | Where-Object { $_.id -in $diskGroupConfiguration[$diskGroupConfigurationIndex].capacityDiskIDs }).canonicalName)
                        & $moduleFunctions { LogMessage -type INFO -message "[$($vmhost.name)] Creating VSAN Disk Group $i" }
                        New-VsanDiskGroup -VMHost $vmhost -SsdCanonicalName $cacheDiskCanonicalName -DataDiskCanonicalName $capacityDiskCanonicalNames | Out-Null
                    }
                    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
                }
                Start-Job -scriptblock $scriptBlock -ArgumentList ($diskGroupNumber, $diskGroupConfiguration, $vmhost, $vCenterFQDN, $vCenterAdmin, $vCenterAdminPassword) | Out-Null
            }
            Get-Job | Receive-Job -Wait -AutoRemoveJob
        }
    }
    LogMessage -type INFO -message "[$clusterName] Renaming new datastore to original name: $datastoreName"
    Get-Cluster -name $clusterName | Get-Datastore -Name "vsanDatastore*" | Set-Datastore -Name $datastoreName | Out-Null
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function New-RebuiltVsanDatastore

Function Set-ManagementDatastorePolicy {
    <#
    .SYNOPSIS
    Sets the default storage policy on the vSAN datastore and applies it to all VMs in the cluster

    .DESCRIPTION
    The Set-ManagementDatastorePolicy cmdlet retrieves the primary datastore policy from the extracted SDDC data
    and applies it as the default policy on the vSAN datastore for the specified cluster. It also applies the
    policy to all discovered VMs on the cluster to ensure storage policy compliance.

    .EXAMPLE
    Set-ManagementDatastorePolicy -vCenterFQDN "sfo-m01-vc01.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01" -extractedSDDCDataFile ".\extracted-sddc-data.json"

    .PARAMETER vCenterFQDN
    FQDN of the vCenter instance hosting the cluster

    .PARAMETER vCenterAdmin
    Admin user of the vCenter instance hosting the cluster

    .PARAMETER vCenterAdminPassword
    Admin password for the vCenter instance hosting the cluster

    .PARAMETER clusterName
    Name of the vSphere cluster instance

    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem
    #>

    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $datastoreName = ($extractedSddcData.workloadDomains.vsphereClusterDetails | Where-Object { $_.name -eq $clusterName }).primaryDatastoreName
    $datastorePolicy = ($extractedSddcData.workloadDomains.vsphereClusterDetails | Where-Object { $_.name -eq $clusterName }).primaryDatastorePolicy

    If (-not $datastorePolicy) {
        LogMessage -type ERROR -message "[$clusterName] No primaryDatastorePolicy found in extracted data. Ensure Update-ExtractedSDDCData has been run."
        return
    }

    LogMessage -type INFO -message "[$jumpboxName] Connecting to vCenter: $vCenterFQDN"
    $vCenterConnection = Connect-ViServer $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword

    LogMessage -type INFO -message "[$clusterName] Retrieved storage policy from extracted data: $datastorePolicy"

    $storagePolicy = Get-SpbmStoragePolicy -Name $datastorePolicy -ErrorAction SilentlyContinue
    If (-not $storagePolicy) {
        LogMessage -type ERROR -message "[$clusterName] Storage policy '$datastorePolicy' not found in vCenter. Available policies:"
        Get-SpbmStoragePolicy | ForEach-Object { LogMessage -type INFO -message "  - $($_.Name)" }
        Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
        return
    }

    $datastore = Get-Cluster -Name $clusterName | Get-Datastore -Name $datastoreName -ErrorAction SilentlyContinue
    If (-not $datastore) {
        LogMessage -type ERROR -message "[$clusterName] Datastore '$datastoreName' not found"
        Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
        return
    }

    LogMessage -type INFO -message "[$datastoreName] Setting default storage policy to: $datastorePolicy"
    Get-SpbmEntityConfiguration -Datastore $datastore | Set-SpbmEntityConfiguration -StoragePolicy $storagePolicy | Out-Null

    $clusterVMs = Get-Cluster -Name $clusterName | Get-VM | Where-Object { $_.Name -notlike "*vCLS*" }
    $vmCount = ($clusterVMs | Measure-Object).Count
    LogMessage -type INFO -message "[$clusterName] Discovered $vmCount VMs to apply storage policy"

    Foreach ($vm in $clusterVMs) {
        $vmConfig = Get-SpbmEntityConfiguration -VM $vm -ErrorAction SilentlyContinue
        $currentVmPolicy = $vmConfig.StoragePolicy.Name
        If ($currentVmPolicy -ne $datastorePolicy) {
            LogMessage -type INFO -message "[$($vm.Name)] Applying storage policy: $datastorePolicy"
            $vmConfig | Set-SpbmEntityConfiguration -StoragePolicy $storagePolicy | Out-Null

            $vmHardDisks = $vm | Get-HardDisk
            Foreach ($hardDisk in $vmHardDisks) {
                $diskConfig = Get-SpbmEntityConfiguration -HardDisk $hardDisk -ErrorAction SilentlyContinue
                $diskPolicy = $diskConfig.StoragePolicy.Name
                If ($diskPolicy -ne $datastorePolicy) {
                    #LogMessage -type INFO -message "[$($vm.Name)] Applying storage policy to disk: $($hardDisk.Name)"
                    $diskConfig | Set-SpbmEntityConfiguration -StoragePolicy $storagePolicy | Out-Null
                }
            }
        } else {
            LogMessage -type INFO -message "[$($vm.Name)] Already has correct storage policy. Skipping"
        }
    }

    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function Set-ManagementDatastorePolicy

Function New-SingleHostVsanDatastore {
    <#
    .SYNOPSIS
    Guides the rebuild of a vSAN datastore on the first host in the default management cluster. Allows the user to control the vSAN configuration

    .DESCRIPTION
    The New-SingleHostVsanDatastore cmdlet guides the rebuild of a vSAN datastore on the first host in the default management cluster.
    It automatically identifies the first host and retrieves credentials from the extracted SDDC data.
    Should only be used if the disk configuration is standardized across the hosts

    .EXAMPLE
    New-SingleHostVsanDatastore -extractedSDDCDataFile ".\extracted-sddc-data.json"

    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem
    #>

    Param(
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $workloadDomain = $extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }
    $cluster = $workloadDomain.vsphereClusterDetails | Where-Object { $_.isDefault -eq "t" }

    $esxHostFqdn = $cluster.hosts[0].hostname
    $esxHostAdmin = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "ESXI") -and ($_.entityName -eq $esxHostFqdn) -and ($_.username -eq "root") }).username
    $esxHostPassword = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "ESXI") -and ($_.entityName -eq $esxHostFqdn) -and ($_.username -eq "root") }).password

    $datastoreName = $extractedSddcData.mgmtDomainInfrastructure.vsan_datastore
    $datastoreType = $cluster.primaryDatastoreType

    LogMessage -type INFO -message "[$jumpboxName] Using first host in default management cluster: $esxHostFqdn"
    LogMessage -type INFO -message "[$jumpboxName] Connecting to ESX host: $esxHostFqdn"
    $esxHostConnection = Connect-ViServer $esxHostFqdn -user $esxHostAdmin -password $esxHostPassword

    #get esxcli
    $vmhost = Get-VMHost
    $esxcli = Get-EsxCli -VMHost $vmhost -V2

    # Getting all disks and info
    $disks = $esxcli.storage.core.device.list.Invoke()
    $diskInfo = $esxcli.storage.core.path.list.Invoke()

    # Filter unused disks suitable for vSAN
    $eligibleDisks = $disks | Where-Object {
        $_.IsLocal -eq $true -and
        $_.IsBootDevice -eq $false
    }

    $disksDisplayObject = @()
    $disksIndex = 1
    $disksDisplayObject += [pscustomobject]@{
        'ID'            = "ID"
        'canonicalName' = "Canonical Name"
        'size'          = "Size (GB)"
        'ssd'           = "SSD"
        'scsiLun'       = "SCSI LUN ID"
    }
    $disksDisplayObject += [pscustomobject]@{
        'ID'            = "--"
        'canonicalName' = "--------------------"
        'size'          = "-------------"
        'ssd'           = "------"
        'scsiLun'       = "-------------"
    }
    Foreach ($disk in $eligibleDisks) {
        If ($disk.size -ne $null) {
            $disksDisplayObject += [pscustomobject]@{
                'ID'            = $disksIndex
                'canonicalName' = $disk.device
                'size'          = $disk.size
                'ssd'           = $disk.IsSsd
                'scsiLun'       = ($diskInfo | Where-Object { $_.device -eq $disk.device }).RuntimeName
            }
            $disksIndex++
        }
    }

    If ($datastoreType -ne "VSAN_ESA") {
        LogMessage -type INFO -message "[$esxHostFqdn] Enabling vSAN OSA"
        $diskGroupConfiguration = @()
        $remainingDisksDisplayObject = $disksDisplayObject
        Write-Host ""; $remainingDisksDisplayObject | format-table -Property @{Expression = " " }, id, canonicalName, size, ssd, scsiLun -autosize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r", "`n") }
        Do {
            Write-Host ""; Write-Host " Enter the desired number of disk groups to create (between 1 and 5), or C to Cancel: " -ForegroundColor Yellow -nonewline
            $diskGroupNumber = Read-Host
        } Until (($diskGroupNumber -in "1", "2", "3", "4", "5") -or ($diskGroupNumber -eq "C"))

        #Loop Through Disk Group Creation
        For ($i = 1; $i -le $diskGroupNumber; $i++) {
            If ($i -gt 1) {
                Write-Host ""; $remainingDisksDisplayObject | format-table -Property @{Expression = " " }, id, canonicalName, size, ssd -autosize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r", "`n") }
            }
            Do {
                If ($i -gt 1) { Write-Host "" }; Write-Host " Enter the ID of disk to use as Cache Disk for Disk Group $i, or C to Cancel: " -ForegroundColor Yellow -nonewline
                $cacheDiskSelection = Read-Host
            } Until (($cacheDiskSelection -in $remainingDisksDisplayObject.id) -OR ($cacheDiskSelection -eq "c"))
            If ($cacheDiskSelection -eq "c") { Break }
            $tempRemainingDisksDisplayObject = @()
            Foreach ( $displayDisk in $remainingDisksDisplayObject) {
                If ($displayDisk.id -ne $cacheDiskSelection) {
                    $tempRemainingDisksDisplayObject += $displayDisk
                }
            }
            $remainingDisksDisplayObject = $tempRemainingDisksDisplayObject
            Write-Host ""; $remainingDisksDisplayObject | format-table -Property @{Expression = " " }, id, canonicalName, size, ssd -autosize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r", "`n") }
            Do {
                Write-Host ""; Write-Host " Enter a comma seperated list of IDs to be used as Capacity Disks for Disk Group $i, or C to Cancel: " -ForegroundColor Yellow -nonewline
                $capacityDiskSelection = Read-Host
                If ($capacityDiskSelection -ne "C") {
                    $capacityDiskSelectionInvalid = $false
                    $capacityDiskArray = $capacityDiskSelection -split (",")
                    Foreach ($capacityDisk in $capacityDiskArray) {
                        If ($capacityDisk -notin $disksDisplayObject.id) {
                            $capacityDiskSelectionInvalid = $true
                        }
                    }
                }
            } Until (($capacityDiskSelectionInvalid -eq $false) -OR ($capacityDiskSelection -eq "c"))
            If ($capacityDiskSelection -eq "c") { Break }
            $diskGroupConfiguration += [PSCustomObject]@{
                'cacheDiskID'     = $cacheDiskSelection
                'capacityDiskIDs' = $capacityDiskArray
            }
            $tempRemainingDisksDisplayObject = @()
            Foreach ( $displayDisk in $remainingDisksDisplayObject) {
                If ($displayDisk.id -notin $capacityDiskArray) {
                    $tempRemainingDisksDisplayObject += $displayDisk
                }
            }
            $remainingDisksDisplayObject = $tempRemainingDisksDisplayObject
        }
        If (($cacheDiskSelection -eq "c") -or ($capacityDiskSelection -eq "c")) { Break }

        $proposedConfigDisplayObject = @()
        $configIndex = 1
        $proposedConfigDisplayObject += [pscustomobject]@{
            'diskGroup'         = "Disk Group"
            'cacheDiskID'       = "Cache Disk ID"
            'cacheDiskCN'       = "Cache Disk Canonical Name"
            'cacheDiskCapacity' = "Cache Disk (GB)"
            'capacityDiskIDs'   = "Capacity Disk IDs"
            'capacityCNs'       = "Capacity Disk Canonical Names"
            'capacityDiskSize'  = "Capacity Disks (GB)"
        }
        $proposedConfigDisplayObject += [pscustomobject]@{
            'diskGroup'         = "----------"
            'cacheDiskID'       = "-------------"
            'cacheDiskCN'       = "-------------------------"
            'cacheDiskCapacity' = "---------------"
            'capacityDiskIDs'   = "-----------------"
            'capacityCNs'       = "----------------------------------------"
            'capacityDiskSize'  = "-------------------"
        }
        Foreach ($config in $diskGroupConfiguration) {
            $proposedConfigDisplayObject += [pscustomobject]@{
                'diskGroup'         = $configIndex
                'cacheDiskID'       = $config.cacheDiskID
                'cacheDiskCN'       = ($disksDisplayObject | Where-Object { $_.id -eq $config.cacheDiskID }).canonicalName
                'cacheDiskCapacity' = ($disksDisplayObject | Where-Object { $_.id -eq $config.cacheDiskID }).size
                'capacityDiskIDs'   = $config.capacityDiskIDs -join (", ")
                'capacityCNs'       = (($disksDisplayObject | Where-Object { $_.id -in $config.capacityDiskIDs }).canonicalName) -join (", ")
                'capacityDiskSize'  = (($disksDisplayObject | Where-Object { $_.id -in $config.capacityDiskIDs }).size) -join (", ")
            }
            $configIndex++
        }
        Write-Host ""; Write-Host " Proposed Disk Group Configuration " -ForegroundColor Yellow
        Write-Host ""; $proposedConfigDisplayObject | format-table -Property @{Expression = " " }, diskGroup, cacheDiskID, cacheDiskCN, cacheDiskCapacity, capacityDiskIDs, capacityCNs, capacityDiskSize -autosize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r", "`n") }
        Write-Host ""; Write-Host " Do you wish to proceed with the proposed configuration? (Y/N): " -ForegroundColor Yellow -nonewline
        Do {
            $proposedConfigAccepted = Read-Host
        } Until ($proposedConfigAccepted -in "Y", "M")
        $proposedConfigAccepted = $proposedConfigAccepted -replace "`t|`n|`r", ""

        If ($proposedConfigAccepted -eq "Y") {
            $clusterArgs = $esxcli.vsan.cluster.new.CreateArgs()
            LogMessage -type INFO -message "[$esxHostFqdn] Initializing vSAN"
            $esxcli.vsan.cluster.new.Invoke($clusterArgs) *>$null

            $clusterStatus = $esxcli.vsan.cluster.get.Invoke()
            LogMessage -type INFO -message "[$esxHostFqdn] vSAN Enabled: $($clusterStatus.Enabled)"
            LogMessage -type INFO -message "[$esxHostFqdn] vSAN ESA Enabled: $($clusterStatus.VsanEsaEnabled)"

            For ($i = 2; $i -lt $proposedConfigDisplayObject.Length; $i++) {
                $config = $proposedConfigDisplayObject[$i]
                LogMessage -type INFO -message "[$esxHostFqdn] Creating DiskGroup $($config.diskGroup)"
                $cacheDisk = ($disksDisplayObject | Where-Object { $_.id -eq $config.cacheDiskID })
                LogMessage -type INFO -message "[$esxHostFqdn] Using $($cacheDisk.canonicalName) as cache disk for DiskGroup $($config.diskGroup)"
                $capacityDisks = ($disksDisplayObject | Where-Object { $_.id -in @($config.capacityDiskIDs -split ", ") })

                foreach ($disk in $capacityDisks) {
                    If ($disk.Ssd -eq $true) {
                        LogMessage -type INFO -message "[$esxHostFqdn] Tagging $($disk.canonicalName) as capacityFlash"
                        $tagArgs = $esxcli.vsan.storage.tag.add.CreateArgs()
                        $tagArgs.disk = $disk.canonicalName
                        $tagArgs.tag = "capacityFlash"
                        $esxcli.vsan.storage.tag.add.Invoke($tagArgs) *>$null
                    }
                    LogMessage -type INFO -message "[$esxHostFqdn] Adding Capacity Disk $($disk.canonicalName) to DiskGroup $($config.diskGroup)"
                    $osaargs = $esxcli.vsan.storage.add.CreateArgs()
                    $osaargs.ssd = $cacheDisk.canonicalName
                    $osaargs.disks = $disk.canonicalName
                    $esxcli.vsan.storage.add.Invoke($osaargs) *>$null

                }
            }
        }
    } else {
        $clusterArgs = $esxcli.vsan.cluster.new.CreateArgs()

        LogMessage -type INFO -message "[$esxHostFqdn] Enabling vSAN ESA"
        $clusterArgs.vsanesa = $true

        LogMessage -type INFO -message "[$esxHostFqdn] Initializing vSAN"
        $esxcli.vsan.cluster.new.Invoke($clusterArgs) *>$null

        $clusterStatus = $esxcli.vsan.cluster.get.Invoke()
        LogMessage -type INFO -message "[$esxHostFqdn] vSAN Enabled: $($clusterStatus.Enabled)"
        LogMessage -type INFO -message "[$esxHostFqdn] vSAN ESA Enabled: $($clusterStatus.VsanEsaEnabled)"

        foreach ($diskID in $eligibleDisks.device) {
            LogMessage -type INFO -message "[$esxHostFqdn] Adding disk $diskID to vSAN ESA Storage Pool"

            $esaArgs = $esxcli.vsan.storagepool.add.CreateArgs()
            $esaArgs.disk = $diskID
            try {
                $esxcli.vsan.storagepool.add.Invoke($esaArgs) *>$null
            } catch {
                Write-Error "Failed to add disk $diskID. Ensure it is NVMe/SSD and empty."
            }
        }
    }
    LogMessage -type INFO -message "[$esxHostFqdn] Renaming new datastore to original name: $datastoreName"
    Get-Datastore -Name "vsanDatastore" | Set-Datastore -Name $datastoreName | Out-Null
    Disconnect-VIServer * -Confirm:$false
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function New-SingleHostVsanDatastore

Function New-RebuiltVdsConfiguration {
    <#
    .SYNOPSIS
    Guides the rebuild of the VDS configuration on a recovered cluster based on the configuration present in the backup data

    .DESCRIPTION
    The New-RebuiltVdsConfiguration cmdlet guides the rebuild of the VDS configuration on a recovered cluster based on the configuration present in the backup data. It leverage the first host in the cluster as a reference host for NIC layout to allow the user to choose the NIC to VDS/Function mapping.
    Should only be used if the NIC configuration is standardized across the hosts.

    For the default management cluster, the function automatically determines the VDS to vSS mapping by parsing TRAFFIC_TYPES portgroups on the first host, eliminating the need for user interaction.

    .EXAMPLE
    New-RebuiltVdsConfiguration -vCenterFQDN "sfo-m01-vc01.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01" -extractedSDDCDataFile ".\extracted-sddc-data.json"

    .PARAMETER vCenterFQDN
    FQDN of the vCenter instance hosting the cluster where the VDS will be rebuilt

    .PARAMETER vCenterAdmin
    Admin user of the vCenter instance hosting the cluster where the VDS will be rebuilt

    .PARAMETER vCenterAdminPassword
    Admin password for the vCenter instance hosting the cluster where the VDS will be rebuilt

    .PARAMETER clusterName
    Name of the vSphere cluster instance where the VDS will be rebuilt

    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem
    #>

    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON
    $workloadDomain = ($extractedSddcData.workloadDomains | Where-Object { $_.vsphereClusterDetails.name -contains $clustername })
    $domainName = $workloadDomain.domainName
    $clusterVdsDetails = ($extractedSddcData.workloadDomains.vsphereClusterDetails | Where-Object { $_.name -eq $clusterName }).vdsDetails
    $isPrimaryCluster = ($extractedSddcData.workloadDomains.vsphereClusterDetails | Where-Object { $_.name -eq $clusterName }).isDefault
    $cluster = ($workloadDomain.vsphereClusterDetails | Where-Object { $_.name -eq $clustername })
    If (($workloadDomain.domainType -eq "MANAGEMENT") -and ($isPrimaryCluster -eq 't')) {
        $isPrimaryManagementCluster = $true
        LogMessage -type INFO -message "[$jumpboxName] Detected default management cluster. Using automatic VDS configuration"
    } else {
        $isPrimaryManagementCluster = $false
    }

    LogMessage -type INFO -message "[$jumpboxName] Connecting to Restored vCenter: $vCenterFQDN"
    $vCenterConnection = Connect-ViServer $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    $vmhosts = (Get-Cluster -name $clusterName | Get-VMHost | Sort-Object -property Name)
    LogMessage -type INFO -message "[$($vmhosts[0].name)] Using host as reference for Physical NICs"

    #$nics = ((Get-Cluster -name $clusterName | Get-VMHost | Sort-Object -property Name)[0] | Get-VMHostNetworkAdapter | Where-Object {$_.name -like "vmnic*"}) | Sort-Object -Property Name
    $nics = (Get-EsxCli -VMHost ((Get-Cluster -name $clusterName | Get-VMHost | Sort-Object -property Name)[0])).network.nic.list() | Select-Object Name, Driver, LinkStatus, Description

    $nicsDisplayObject = @()
    $nicsIndex = 1
    $nicsDisplayObject += [pscustomobject]@{
        'ID'          = "ID"
        'deviceName'  = "Device Name"
        'driver'      = "Driver"
        'linkStatus'  = "Link Status"
        'description' = "Description"
    }
    $nicsDisplayObject += [pscustomobject]@{
        'ID'          = "--"
        'deviceName'  = "-----------"
        'driver'      = "----------"
        'linkStatus'  = "-----------"
        'description' = "-----------------------------------------------"
    }
    Foreach ($nic in $nics) {
        $nicsDisplayObject += [pscustomobject]@{
            'ID'          = $nicsIndex
            'deviceName'  = $nic.name
            'driver'      = $nic.driver
            'linkStatus'  = $nic.linkStatus
            'description' = $nic.description
        }
        $nicsIndex++
    }

    $vdsConfiguration = @()
    $vssToDelete = @()

    If ($isPrimaryManagementCluster) {
        $existingAttribute = Get-CustomAttribute -Name intendedVdsConfiguration -TargetType Cluster -ErrorAction SilentlyContinue
        If (!$existingAttribute) {
            New-CustomAttribute -Name intendedVdsConfiguration -TargetType Cluster | Out-Null
        }

        $clusterObject = Get-Cluster -Name $clusterName
        $index = [System.Array]::IndexOf($clusterObject.CustomFields.Keys, "intendedVdsConfiguration")
        $storedVdsConfiguration = $null
        If ($index -ge 0) {
            $storedVdsConfiguration = @($clusterObject.CustomFields.Values)[$index] | ConvertFrom-Json
        }

        If ($storedVdsConfiguration) {
            LogMessage -type INFO -message "[$jumpboxName] Using VDS configuration stored on cluster"
            Foreach ($storedConfig in $storedVdsConfiguration) {
                $individualVds = [PSCustomObject]@{
                    'vdsName'           = $storedConfig.vdsName
                    'nicnames'          = @($storedConfig.nicnames)
                    'vdsNetworks'       = @($storedConfig.vdsNetworks)
                    'portgroups'        = $storedConfig.portgroups
                    'sourceVss'         = $storedConfig.sourceVss
                    'hasTransportZones' = $storedConfig.hasTransportZones
                }
                $vdsConfiguration += $individualVds

                If ($storedConfig.sourceVss -notin $vssToDelete) {
                    $vssToDelete += $storedConfig.sourceVss
                }
            }
        } else {
            LogMessage -type INFO -message "[$($vmhosts[0].name)] Discovering TRAFFIC_TYPES portgroups to determine VDS mapping"

            $referenceHost = $vmhosts[0]
            $allPortgroups = Get-VirtualPortGroup -VMHost $referenceHost
            $allVswitches = Get-VirtualSwitch -VMHost $referenceHost

            Foreach ($pg in $allPortgroups) {
                If ($pg.Name -like "TRAFFIC_TYPES-*") {
                    $vssName = $pg.VirtualSwitchName
                    $trafficTypes = $pg.Name -replace "TRAFFIC_TYPES-", ""
                    $trafficTypesArray = $trafficTypes -split "-"

                    LogMessage -type INFO -message "[$($referenceHost.name)] Found TRAFFIC_TYPES portgroup: $($pg.Name) on vSS: $vssName"

                    $matchingVds = $null
                    Foreach ($vdsDetail in $clusterVdsDetails) {
                        $vdsNetworksList = @($vdsDetail.networks | Where-Object { $_ })
                        If ($vdsDetail.transportZones) {
                            $vdsNetworksList += "OVERLAY"
                        }

                        $allMatch = $true
                        Foreach ($trafficType in $trafficTypesArray) {
                            If ($trafficType -notin $vdsNetworksList) {
                                $allMatch = $false
                                Break
                            }
                        }
                        If ($allMatch -and ($trafficTypesArray.Count -eq $vdsNetworksList.Count)) {
                            $matchingVds = $vdsDetail
                            Break
                        }
                    }

                    If ($matchingVds) {
                        LogMessage -type INFO -message "[$($referenceHost.name)] Matched vSS $vssName to VDS $($matchingVds.dvsName)"

                        $vssObject = $allVswitches | Where-Object { $_.Name -eq $vssName }
                        $vssNics = @()
                        If ($vssObject.Nic) {
                            $vssNics = @($vssObject.Nic) | Sort-Object
                        }

                        $individualVds = [PSCustomObject]@{
                            'vdsName'           = $matchingVds.dvsName
                            'nicnames'          = $vssNics
                            'vdsNetworks'       = $matchingVds.networks
                            'portgroups'        = $matchingVds.portgroups
                            'sourceVss'         = $vssName
                            'hasTransportZones' = [bool]$matchingVds.transportZones
                        }
                        $vdsConfiguration += $individualVds

                        If ($vssName -notin $vssToDelete) {
                            $vssToDelete += $vssName
                        }
                    } else {
                        LogMessage -type WARNING -message "[$($referenceHost.name)] Could not find matching VDS for vSS $vssName with traffic types: $trafficTypes"
                    }
                }
            }

            If ($vdsConfiguration.Count -eq 0) {
                LogMessage -type ERROR -message "[$jumpboxName] No TRAFFIC_TYPES portgroups found. Cannot proceed with automatic configuration."
                Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
                Return
            }

            LogMessage -type INFO -message "[$jumpboxName] Storing VDS configuration on cluster for idempotency"
            $clusterObject | Set-Annotation -CustomAttribute "intendedVdsConfiguration" -Value ($vdsConfiguration | ConvertTo-Json -Depth 5) | Out-Null
        }

        Write-Host ""; Write-Host " Automatic VDS Configuration (based on TRAFFIC_TYPES portgroups)" -ForegroundColor Yellow
        $proposedConfigDisplayObject = @()
        $proposedConfigDisplayObject += [pscustomobject]@{
            'vdsName'     = "VDS Name"
            'sourceVss'   = "Source vSS"
            'nicnames'    = "NIC Names"
            'vdsNetworks' = "VDS Networks"
        }
        $proposedConfigDisplayObject += [pscustomobject]@{
            'vdsName'     = "----------------------------------------"
            'sourceVss'   = "---------------"
            'nicnames'    = "---------------"
            'vdsNetworks' = "------------------------------"
        }
        Foreach ($config in $vdsConfiguration) {
            $networksList = @($config.vdsNetworks | Where-Object { $_ })
            If ($config.hasTransportZones) {
                $networksList += "OVERLAY"
            }
            $proposedConfigDisplayObject += [pscustomobject]@{
                'vdsName'     = $config.vdsName
                'sourceVss'   = $config.sourceVss
                'nicnames'    = $config.nicnames -join (", ")
                'vdsNetworks' = $networksList -join (", ")
            }
        }
        Write-Host ""; $proposedConfigDisplayObject | format-table -Property @{Expression = " " }, vdsName, sourceVss, nicnames, vdsNetworks -autosize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r", "`n") }

        Write-Host ""; LogMessage -type INFO -message "Virtual Switches that will be deleted after migration: " -nonewline
        Write-Host ($vssToDelete -join ", ") -ForegroundColor Cyan

        $proposedConfigAccepted = "Y"
    } else {
        Write-Host ""; Write-Host " Recreating Virtual Distributed Switches as per previous deployment" -ForegroundColor Yellow
        $remainingNicsDisplayObject = $nicsDisplayObject

        #Loop Through VDS Creation
        For ($i = 1; $i -le $clusterVdsDetails.count; $i++) {
            $vdsConfigurationIndex = ($i - 1)
            Do {
                $nicNamesArray = @()
                Write-Host ""; $remainingNicsDisplayObject | format-table -Property @{Expression = " " }, id, deviceName, driver, linkStatus, description -autosize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r", "`n") }
                If ($cluster.vdsDetails[$vdsConfigurationIndex].transportZones) {
                    $networksDisplay = (@($cluster.vdsDetails[$vdsConfigurationIndex].networks | Where-Object { $_ }) + "OVERLAY") -join (",")
                } else {
                    $networksDisplay = $cluster.vdsDetails[$vdsConfigurationIndex].networks -join (",")
                }
                Write-Host ""; Write-Host " Recreating " -ForegroundColor Yellow -nonewline; Write-Host "$($cluster.vdsDetails[$vdsConfigurationIndex].dvsName)" -ForegroundColor cyan -nonewline; Write-Host " which contained the networks: " -ForegroundColor Yellow -nonewline; Write-Host "$networksDisplay" -ForegroundColor Cyan
                Write-Host " Enter a comma seperated list of IDs to use as vmnics for this VDS, or C to Cancel: " -ForegroundColor Yellow -nonewline
                $nicSelection = Read-Host
                If ($nicSelection -ne "C") {
                    $nicSelectionInvalid = $false
                    $nicArray = $nicSelection -split (",")
                    Foreach ($nic in $nicArray) {
                        $nicNamesArray += ($nicsDisplayObject | Where-Object { $_.id -eq $nic }).deviceName
                        If ($nic -notin $nicsDisplayObject.id) {
                            $nicSelectionInvalid = $true
                        }
                    }
                }
            } Until (($nicSelectionInvalid -eq $false) -OR ($nicSelection -eq "c"))
            If ($nicSelection -eq "c") { Break }
            $individualVds = [PSCustomObject]@{
                'vdsName'           = $cluster.vdsDetails[$vdsConfigurationIndex].dvsName
                'nicnames'          = $nicNamesArray
                'vdsNetworks'       = $cluster.vdsDetails[$vdsConfigurationIndex].networks
                'portgroups'        = $cluster.vdsDetails[$vdsConfigurationIndex].portgroups
                'hasTransportZones' = [bool]$cluster.vdsDetails[$vdsConfigurationIndex].transportZones
            }
            $vdsConfiguration += $individualVds
            $tempremainingNicsDisplayObject = @()
            Foreach ( $displaynic in $remainingNicsDisplayObject) {
                If ($displaynic.id -notin $nicArray) {
                    $tempremainingNicsDisplayObject += $displaynic
                }
            }
            $remainingNicsDisplayObject = $tempremainingNicsDisplayObject
        }
        If (($nicSelection -eq "c") -or ($nicSelection -eq "c")) { Break }

        $proposedConfigDisplayObject = @()
        $configIndex = 1
        $proposedConfigDisplayObject += [pscustomobject]@{
            'vdsName'     = "VDS Name"
            'nicnames'    = "NIC Names"
            'vdsNetworks' = "VDS Networks"
        }
        $proposedConfigDisplayObject += [pscustomobject]@{
            'vdsName'     = "----------------------------------------"
            'nicnames'    = "---------------"
            'vdsNetworks' = "------------------------------"
        }
        Foreach ($config in $vdsConfiguration) {
            $networksList = @($config.vdsNetworks | Where-Object { $_ })
            If ($config.hasTransportZones) {
                $networksList += "OVERLAY"
            }
            $proposedConfigDisplayObject += [pscustomobject]@{
                'vdsName'     = $config.vdsName
                'nicnames'    = $config.nicnames -join (", ")
                'vdsNetworks' = $networksList -join (", ")
            }
            $configIndex++
        }
        Write-Host ""; Write-Host " Proposed VDS Configuration " -ForegroundColor Yellow
        Write-Host ""; $proposedConfigDisplayObject | format-table -Property @{Expression = " " }, vdsName, nicnames, vdsNetworks, -autosize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r", "`n") }
        Write-Host ""; Write-Host " Do you wish to proceed with the proposed configuration? (Y/N): " -ForegroundColor Yellow -nonewline
        $proposedConfigAccepted = Read-Host
        $proposedConfigAccepted = $proposedConfigAccepted -replace "`t|`n|`r", ""
    }

    If ($proposedConfigAccepted -eq "Y") {
        Foreach ($vds in $vdsConfiguration) {
            $vdsHosts = (Get-VDSwitch -name $vds.vdsName).extensionData.summary.hostmember.value
            Foreach ($vmHost in $vmHosts) {
                $vmNicArray = @()
                $portgroupArray = @()
                $vmnicMinusOne = $vmhost | Get-VMHostNetworkAdapter | Where-Object { $_.deviceName -eq $vds.nicNames[0] }
                If (($vds.portgroups | Where-Object { $_.transportType -eq 'VM_MANAGEMENT' }).name) {
                    $managementVmPortGroupName = ($vds.portgroups | Where-Object { $_.transportType -eq 'VM_MANAGEMENT' }).name
                } else {
                    $managementVmPortGroupName = ($vds.portgroups | Where-Object { $_.transportType -eq 'MANAGEMENT' }).name
                }
                $managementPortGroupName = ($vds.portgroups | Where-Object { $_.transportType -eq 'MANAGEMENT' }).name

                If ($vds.portgroups | Where-Object { $_.transportType -eq 'MANAGEMENT' }) {
                    $portgroupArray += $managementPortGroupName
                    $vmk0 = Get-VMHostNetworkAdapter -VMHost $vmHost -Name "vmk0"
                    $vmNicArray += $vmk0
                }
                If ($isPrimaryManagementCluster) {
                    If ($vds.portgroups | Where-Object { $_.transportType -eq 'VMOTION' }) {
                        $vmotionPortgroupName = ($vds.portgroups | Where-Object { $_.transportType -eq 'VMOTION' }).name
                        $portgroupArray += $vmotionPortgroupName
                        $vmk1 = Get-VMHostNetworkAdapter -VMHost $vmHost -Name "vmk1"
                        $vmNicArray += $vmk1
                    }
                    If ($vds.portgroups | Where-Object { $_.transportType -eq 'VSAN' }) {
                        $vsanPortgroupName = ($vds.portgroups | Where-Object { $_.transportType -eq 'VSAN' }).name
                        $portgroupArray += $vsanPortgroupName
                        $vmk2 = Get-VMHostNetworkAdapter -VMHost $vmHost -Name "vmk2"
                        $vmNicArray += $vmk2
                    }
                }

                $hostMoRef = $vmhost.ExtensionData.moref.value
                If ($hostMoRef -notin $vdsHosts) {
                    LogMessage -type INFO -message "[$($vmhost.name)] Adding to $($vds.vdsName)"
                    Get-VDSwitch -name $vds.vdsName | Add-VDSwitchVMHost -vmhost $vmHost -confirm:$false
                } else {
                    LogMessage -type INFO -message "[$($vmhost.name)] Already in $($vds.vdsName). Skipping"
                }

                $vmnicInVds = Get-VDPort -VDSwitch $vds.vdsName | Where-Object { $_.proxyHost.name -eq $vmhost.name -and $_.connectedEntity.name -eq $vmnicMinusOne }
                If (!$vmnicInVds) {
                    If ($portgroupArray.count -ne 0) {
                        LogMessage -type INFO -message "[$($vmhost.name)] Adding Physical Adapter $($vds.nicNames[0]) to $($vds.vdsName) and migrating $($vmNicArray.name -join(", "))"
                        Get-VDSwitch -name $vds.vdsName | Add-VDSwitchPhysicalNetworkAdapter -VMHostPhysicalNic $vmnicMinusOne -VMHostVirtualNic $vmNicArray -VirtualNicPortgroup $portgroupArray -confirm:$false
                    } else {
                        Get-VDSwitch -name $vds.vdsName | Add-VDSwitchPhysicalNetworkAdapter -VMHostPhysicalNic $vmnicMinusOne -confirm:$false
                    }
                } else {
                    LogMessage -type INFO -message "[$($vmhost.name)] Physical Adapter $($vds.nicNames[0]) already in $($vds.vdsName). Skipping"
                }

            }
            If (($vds.portgroups | Where-Object { $_.transportType -eq 'VM_MANAGEMENT' }) -OR ((!($vds.portgroups | Where-Object { $_.transportType -eq 'VM_MANAGEMENT' })) -and ($vds.portgroups | Where-Object { $_.transportType -eq 'MANAGEMENT' }))) {

                #Move Mgmt VMs to Management Portgroup
                If ($isPrimaryManagementCluster) {
                    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
                    Foreach ($vmhost in $vmhosts) {
                        $vmHostUser = ($extractedSddcData.passwords | where-object { ($_.domainName -eq $domainName) -and ($_.entityType -eq "ESXI") -and ($_.username -eq "root") -and ($_.entityName -eq $vmhost.name) }).username
                        $vmHostPassword = ($extractedSddcData.passwords | where-object { ($_.domainName -eq $domainName) -and ($_.entityType -eq "ESXI") -and ($_.username -eq "root") -and ($_.entityName -eq $vmhost.name) }).password
                        $vmHostConnection = Connect-ViServer $vmhost.name -user $vmHostUser -password $vmHostPassword
                        $vmsTomove = Get-VM | Where-Object { $_.Name -notlike "*vCLS*" }
                        foreach ($vmToMove in $vmsTomove) {

                            If ((Get-VM -Name $vmToMove | Get-NetworkAdapter).NetworkName -ne $managementVmPortGroupName) {
                                LogMessage -type INFO -message "[$($vmToMove.name)] Moving to $($managementVmPortGroupName)"
                                Get-VM -Name $vmToMove | Get-NetworkAdapter | Set-NetworkAdapter -NetworkName $managementVmPortGroupName -confirm:$false | Out-Null
                            } else {
                                LogMessage -type INFO -message "[$($vmToMove.name)] Already moved to $($managementVmPortGroupName). Skipping"
                            }
                        }
                        If (($vmsTomove.count -gt 0) -and ($vmhost.Manufacturer -eq "VMware, Inc.")) {
                            LogMessage -type WAIT -message "Aha! You are using nested hosts. Waiting 5 mins to stabilize connection between vCenter and nested hosts after vmk0 migration"
                            Sleep 300
                        }
                        Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
                    }

                    $vCenterConnection = Connect-ViServer $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
                }
            }
        }

        #Remove Virtual Switches
        Foreach ($vmHost in $vmHosts) {
            If ($isPrimaryManagementCluster) {
                LogMessage -type INFO -message "[$($vmhost.name)] Removing vSwitches: $($vssToDelete -join(","))"
                Foreach ($vssName in $vssToDelete) {
                    $vssExists = Get-VMHost -Name $vmhost | Get-VirtualSwitch -Name $vssName -ErrorAction SilentlyContinue
                    If ($vssExists) {                        
                        Get-VMHost -Name $vmhost | Get-VirtualSwitch -Name $vssName | Remove-VirtualSwitch -Confirm:$false | Out-Null
                    }
                }
            }
        }

        #Add Remaining NICS to VDS
        Foreach ($vds in $vdsConfiguration) {
            Foreach ($vmHost in $vmHosts) {
                $remainingVmnics = @()
                Foreach ($nic in $vds.nicNames) {
                    If ($nic -ne $vds.nicNames[0]) {
                        $remainingVmnics += $nic
                    }
                }
                Foreach ($nic in $remainingVmnics) {
                    $vmnicInVds = Get-VDPort -VDSwitch $vds.vdsName | Where-Object { $_.proxyHost.name -eq $vmhost.name -and $_.connectedEntity.name -eq $nic }
                    If (!$vmnicInVds) {
                        LogMessage -type INFO -message "[$($vmhost.name)] Adding Additional NIC $nic to $($vds.vdsName)"
                        $additionalNic = $vmhost | Get-VMHostNetworkAdapter -Physical -Name $nic
                        Get-VDSwitch -name $vds.vdsName | Add-VDSwitchPhysicalNetworkAdapter -VMHostPhysicalNic $additionalNic -confirm:$false
                    } else {
                        LogMessage -type INFO -message "[$($vmhost.name)] Physical Adapter $nic already in $($vds.vdsName). Skipping"
                    }
                }
            }
        }
        Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
    }
}
Export-ModuleMember -Function New-RebuiltVdsConfiguration

Function New-PrepareManagementHostNetworking {
    <#
    .SYNOPSIS
    Prepares host networking by creating vSphere Standard Switches based on the VDS configuration from backup data

    .DESCRIPTION
    The New-PrepareManagementHostNetworking cmdlet interrogates the first host in the default management cluster and presents the available NICs along with the discovered VDS configuration from the extracted SDDC data. It allows the user to create a matching number of virtual standard switches using the NIC mapping of their choice.
    Should only be used if the NIC configuration is standardized across the hosts.

    .EXAMPLE
    New-PrepareManagementHostNetworking -extractedSDDCDataFile ".\extracted-sddc-data.json"

    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem

    .PARAMETER mtu
    MTU to be assigned to the virtual standard switches. Default is 9000
    #>

    Param(
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $false)][String] $mtu = "9000"
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $workloadDomain = $extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }
    $cluster = $workloadDomain.vsphereClusterDetails | Where-Object { $_.isDefault -eq "t" }
    $clusterName = $cluster.name
    $clusterVdsDetails = $cluster.vdsDetails

    $vmMgmtVlanId = ($cluster.vdsDetails.portgroups | Where-Object { $_.transportType -eq "VM_MANAGEMENT" }).vlanId

    $hostFQDN = $cluster.hosts[0].hostname
    $hostAdmin = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "ESXI") -and ($_.entityName -eq $hostFQDN) -and ($_.username -eq "root") }).username
    $hostAdminPassword = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "ESXI") -and ($_.entityName -eq $hostFQDN) -and ($_.username -eq "root") }).password

    LogMessage -type INFO -message "[$jumpboxName] Connecting to Reference Host: $hostFQDN"
    $hostConnection = Connect-ViServer $hostFQDN -user $hostAdmin -password $hostAdminPassword
    LogMessage -type INFO -message "[$hostFQDN] Using host as reference for Physical NICs"

    $nics = (Get-EsxCli -VMHost $hostFQDN).network.nic.list() | Select-Object Name, Driver, LinkStatus, Description

    $existingVswitches = Get-VirtualSwitch -VMHost $hostFQDN -ErrorAction SilentlyContinue
    $nicToVssMapping = @{}
    $nicsInUse = @()
    $managementVss = $null
    $managementVssNics = @()
    Foreach ($vswitch in $existingVswitches) {
        $vswitchNics = $vswitch.Nic
        If ($vswitchNics) {
            $managementVss = $vswitch.Name
            $managementVssNics = @($vswitchNics)
            Foreach ($vswitchNic in $vswitchNics) {
                $nicToVssMapping[$vswitchNic] = $vswitch.Name
                $nicsInUse += $vswitchNic
            }
        }
    }

    $nicsDisplayObject = @()
    $selectableNicIds = @()
    $nicsIndex = 1
    $nicsDisplayObject += [pscustomobject]@{
        'ID'          = "ID"
        'deviceName'  = "Device Name"
        'driver'      = "Driver"
        'linkStatus'  = "Link Status"
        'status'      = "Status"
        'description' = "Description"
    }
    $nicsDisplayObject += [pscustomobject]@{
        'ID'          = "--"
        'deviceName'  = "-----------"
        'driver'      = "----------"
        'linkStatus'  = "-----------"
        'status'      = "---------------"
        'description' = "-----------------------------------------------"
    }

    Foreach ($nic in $nics) {
        $currentVss = $nicToVssMapping[$nic.name]
        If ($currentVss) {
            $status = $currentVss
        } else {
            $status = "Unused"
            $selectableNicIds += $nicsIndex
        }
        $nicsDisplayObject += [pscustomobject]@{
            'ID'          = $nicsIndex
            'deviceName'  = $nic.name
            'driver'      = $nic.driver
            'linkStatus'  = $nic.linkStatus
            'status'      = $status
            'description' = $nic.description
        }
        $nicsIndex++
    }

    If ($managementVss) {
        Write-Host ""; Write-Host " Discovered existing vSS: " -ForegroundColor Yellow -NoNewline; Write-Host "$managementVss" -ForegroundColor Cyan -NoNewline; Write-Host " with NIC(s): " -ForegroundColor Yellow -NoNewline; Write-Host "$($managementVssNics -join ', ')" -ForegroundColor Cyan
        Write-Host " This vSS will be used for the MANAGEMENT network." -ForegroundColor Yellow
    }

    Write-Host ""; Write-Host " Retrieved VDS Configuration from Backup Data" -ForegroundColor Yellow
    $vdsDisplayObject = @()
    $vdsDisplayObject += [pscustomobject]@{
        'vdsName'  = "VDS"
        'networks' = "Networks"
    }
    $vdsDisplayObject += [pscustomobject]@{
        'vdsName'  = "-----------"
        'networks' = "------------------------------"
    }
    $vdsIndex = 1
    Foreach ($vds in $clusterVdsDetails) {
        $networksList = @($vds.networks | Where-Object { $_ })
        If ($vds.transportZones) {
            $networksList += "OVERLAY"
        }
        $networksDisplay = $networksList -join (",")
        $ordinalDisplay = switch ($vdsIndex) { 1 { "1st" } 2 { "2nd" } 3 { "3rd" } 4 { "4th" } 5 { "5th" } 6 { "6th" } 7 { "7th" } 8 { "8th" } default { "$vdsIndex" + "th" } }
        $vdsDisplayObject += [pscustomobject]@{
            'vdsName'  = "$ordinalDisplay VDS"
            'networks' = $networksDisplay
        }
        $vdsIndex++
    }
    Write-Host ""; $vdsDisplayObject | format-table -Property @{Expression = " " }, vdsName, networks -autosize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r", "`n") }

    Write-Host ""; Write-Host " Creating Virtual Standard Switches to match VDS configuration" -ForegroundColor Yellow
    $vssConfiguration = @()
    $remainingSelectableNicIds = $selectableNicIds.Clone()
    $managementVdsIndex = $null

    For ($vdsLoopIndex = 0; $vdsLoopIndex -lt $clusterVdsDetails.count; $vdsLoopIndex++) {
        If ("MANAGEMENT" -in $cluster.vdsDetails[$vdsLoopIndex].networks) {
            $managementVdsIndex = $vdsLoopIndex
            Break
        }
    }

    $newVswitchIndex = 1
    For ($i = 1; $i -le $clusterVdsDetails.count; $i++) {
        $vdsConfigurationIndex = ($i - 1)
        $isManagementVds = ($vdsConfigurationIndex -eq $managementVdsIndex)

        $networksList = @($cluster.vdsDetails[$vdsConfigurationIndex].networks | Where-Object { $_ })
        If ($cluster.vdsDetails[$vdsConfigurationIndex].transportZones) {
            $networksList += "OVERLAY"
        }
        $networksDisplay = $networksList -join (",")
        $ordinal = switch ($i) { 1 { "1st" } 2 { "2nd" } 3 { "3rd" } 4 { "4th" } 5 { "5th" } 6 { "6th" } 7 { "7th" } 8 { "8th" } default { "$i" + "th" } }

        If ($isManagementVds -and $managementVss) {
            $vssName = $managementVss
        } else {
            $vssName = "vSwitch$newVswitchIndex"
            $newVswitchIndex++
        }

        Do {
            $nicNamesArray = @()
            Write-Host ""; Write-Host " Physical NICs (only 'Unused' NICs may be selected):" -ForegroundColor Yellow
            Write-Host ""; $nicsDisplayObject | format-table -Property @{Expression = " " }, id, deviceName, driver, linkStatus, status, description -autosize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r", "`n") }

            If ($isManagementVds -and $managementVss) {
                Write-Host ""; Write-Host " Configuring existing vSS " -ForegroundColor Yellow -nonewline; Write-Host "$vssName" -ForegroundColor cyan -nonewline; Write-Host " to match $ordinal VDS from backup" -ForegroundColor Yellow -nonewline; Write-Host " which contained the networks: " -ForegroundColor Yellow -nonewline; Write-Host "$networksDisplay" -ForegroundColor Cyan
                Write-Host " Enter a comma seperated list of IDs for ADDITIONAL vmnics for this vSS, leave blank for none, or C to Cancel: " -ForegroundColor Yellow -nonewline
            } else {
                Write-Host ""; Write-Host " Creating vSS " -ForegroundColor Yellow -nonewline; Write-Host "$vssName" -ForegroundColor cyan -nonewline; Write-Host " to match $ordinal VDS from backup" -ForegroundColor Yellow -nonewline; Write-Host " which contained the networks: " -ForegroundColor Yellow -nonewline; Write-Host "$networksDisplay" -ForegroundColor Cyan
                Write-Host " Enter a comma seperated list of IDs to use as vmnics for this vSS, or C to Cancel: " -ForegroundColor Yellow -nonewline
            }
            $nicSelection = Read-Host

            If ($nicSelection -eq "") {
                If ($isManagementVds -and $managementVss) {
                    $nicSelectionInvalid = $false
                    $nicArray = @()
                } else {
                    $nicSelectionInvalid = $true
                }
            } ElseIf ($nicSelection -ne "C") {
                $nicSelectionInvalid = $false
                $nicArray = $nicSelection -split (",")
                Foreach ($nic in $nicArray) {
                    $nicInt = [int]$nic
                    If ($nicInt -in $remainingSelectableNicIds) {
                        $selectedNicName = ($nicsDisplayObject | Where-Object { $_.id -eq $nicInt }).deviceName
                        If ($selectedNicName) {
                            $nicNamesArray += $selectedNicName
                        }
                    } else {
                        $nicSelectionInvalid = $true
                        Write-Host " Invalid selection: NIC ID $nic is either already in use or already assigned to another vSS" -ForegroundColor Red
                    }
                }
            }
        } Until (($nicSelectionInvalid -eq $false) -OR ($nicSelection -eq "c"))
        If ($nicSelection -eq "c") { Break }

        $allNicsForVss = $nicNamesArray
        If ($isManagementVds -and $managementVss) {
            $allNicsForVss = $managementVssNics + $nicNamesArray
        }

        $individualVss = [PSCustomObject]@{
            'vssName'         = $vssName
            'vdsName'         = $cluster.vdsDetails[$vdsConfigurationIndex].dvsName
            'nicnames'        = $allNicsForVss
            'newNicNames'     = $nicNamesArray
            'vdsNetworks'     = $networksList
            'isManagementVss' = $isManagementVds
            'existingVssName' = If ($isManagementVds -and $managementVss) { $managementVss } else { $null }
        }
        $vssConfiguration += $individualVss

        Foreach ($nic in $nicArray) {
            $nicInt = [int]$nic
            $remainingSelectableNicIds = @($remainingSelectableNicIds | Where-Object { $_ -ne $nicInt })
            $nicEntry = $nicsDisplayObject | Where-Object { $_.id -eq $nicInt }
            If ($nicEntry) {
                $nicEntry.status = $vssName
            }
        }
    }
    If (($nicSelection -eq "c") -or ($nicSelection -eq "C")) { Break }

    $proposedConfigDisplayObject = @()
    $configIndex = 1
    $proposedConfigDisplayObject += [pscustomobject]@{
        'vssName'     = "vSS Name"
        'vdsName'     = "Matching VDS"
        'nicnames'    = "NIC Names"
        'vdsNetworks' = "Networks"
    }
    $proposedConfigDisplayObject += [pscustomobject]@{
        'vssName'     = "----------------------------------------"
        'vdsName'     = "----------------------------------------"
        'nicnames'    = "---------------"
        'vdsNetworks' = "------------------------------"
    }
    Foreach ($config in $vssConfiguration) {
        $ordinalDisplay = switch ($configIndex) { 1 { "1st" } 2 { "2nd" } 3 { "3rd" } 4 { "4th" } 5 { "5th" } 6 { "6th" } 7 { "7th" } 8 { "8th" } default { "$configIndex" + "th" } }
        $proposedConfigDisplayObject += [pscustomobject]@{
            'vssName'     = $config.vssName
            'vdsName'     = "$ordinalDisplay VDS"
            'nicnames'    = $config.nicnames -join (", ")
            'vdsNetworks' = $config.vdsNetworks -join (", ")
        }
        $configIndex++
    }
    Write-Host ""; Write-Host " Proposed vSS Configuration (will be applied to all hosts in cluster)" -ForegroundColor Yellow
    Write-Host ""; $proposedConfigDisplayObject | format-table -Property @{Expression = " " }, vssName, vdsName, nicnames, vdsNetworks -autosize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r", "`n") }

    Write-Host ""; Write-Host " Hosts in cluster that will be configured:" -ForegroundColor Yellow
    Foreach ($clusterHost in $cluster.hosts) {
        Write-Host "   $($clusterHost.hostname)" -ForegroundColor Cyan
    }

    Write-Host ""; Write-Host " Do you wish to proceed with the proposed configuration? (Y/N): " -ForegroundColor Yellow -nonewline
    $proposedConfigAccepted = Read-Host
    $proposedConfigAccepted = $proposedConfigAccepted -replace "`t|`n|`r", ""
    If ($proposedConfigAccepted -eq "Y") {
        Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false -ErrorAction SilentlyContinue

        Foreach ($clusterHost in $cluster.hosts) {
            $currentHostFQDN = $clusterHost.hostname
            $currentHostAdmin = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "ESXI") -and ($_.entityName -eq $currentHostFQDN) -and ($_.username -eq "root") }).username
            $currentHostPassword = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "ESXI") -and ($_.entityName -eq $currentHostFQDN) -and ($_.username -eq "root") }).password

            LogMessage -type INFO -message "[$currentHostFQDN] Connecting to host"
            $hostConnection = Connect-ViServer $currentHostFQDN -user $currentHostAdmin -password $currentHostPassword -ErrorAction Stop

            Foreach ($vss in $vssConfiguration) {
                If ($vss.isManagementVss -and $vss.existingVssName) {
                    $vssObject = Get-VirtualSwitch -VMHost $currentHostFQDN -Name $vss.existingVssName -errorAction silentlyContinue
                    If ($vssObject) {
                        LogMessage -type INFO -message "[$currentHostFQDN] Using existing vSS $($vss.existingVssName) for MANAGEMENT network"
                        LogMessage -type INFO -message "[$currentHostFQDN] Updating MTU to $mtu on $($vss.existingVssName)"
                        Set-VirtualSwitch -VirtualSwitch $vssObject -Mtu $mtu -Confirm:$false | Out-Null
                    }
                    Foreach ($nic in $vss.newNicNames) {
                        $vssObject = Get-VirtualSwitch -VMHost $currentHostFQDN -Name $vss.existingVssName
                        If ($vssObject.ExtensionData.Pnic -notlike "*$nic") {
                            LogMessage -type INFO -message "[$currentHostFQDN] Adding $nic to $($vss.existingVssName)"
                            $vmnicToAdd = Get-VMHostNetworkAdapter -VMHost $currentHostFQDN -Physical -Name $nic
                            Add-VirtualSwitchPhysicalNetworkAdapter -VirtualSwitch $vssObject -VMHostPhysicalNic $vmnicToAdd -confirm:$false
                        } else {
                            LogMessage -type INFO -message "[$currentHostFQDN] $nic already part of $($vss.existingVssName). Skipping"
                        }
                    }
                    $trafficTypesPortgroupName = "TRAFFIC_TYPES-" + ($vss.vdsNetworks -join "-")
                    $vssObject = Get-VirtualSwitch -VMHost $currentHostFQDN -Name $vss.existingVssName
                    $pgExists = Get-VirtualPortGroup -VirtualSwitch $vssObject -Name $trafficTypesPortgroupName -ErrorAction SilentlyContinue
                    If (!$pgExists) {
                        LogMessage -type INFO -message "[$currentHostFQDN] Creating portgroup $trafficTypesPortgroupName on $($vss.existingVssName)"
                        New-VirtualPortGroup -VirtualSwitch $vssObject -Name $trafficTypesPortgroupName | Out-Null
                    } else {
                        LogMessage -type INFO -message "[$currentHostFQDN] Portgroup $trafficTypesPortgroupName already exists. Skipping"
                    }
                    If ("VM_MANAGEMENT" -in $vss.vdsNetworks) {
                        $vmMgmtPgExists = Get-VirtualPortGroup -VirtualSwitch $vssObject -Name "vm_mgmt" -ErrorAction SilentlyContinue
                        If (!$vmMgmtPgExists) {
                            LogMessage -type INFO -message "[$currentHostFQDN] Creating portgroup vm_mgmt on $($vss.existingVssName) with VLAN $vmMgmtVlanId"
                            New-VirtualPortGroup -VirtualSwitch $vssObject -Name "vm_mgmt" -VLanId $vmMgmtVlanId | Out-Null
                        } else {
                            LogMessage -type INFO -message "[$currentHostFQDN] Portgroup vm_mgmt already exists. Skipping"
                        }
                    }
                } else {
                    $vssExists = Get-VirtualSwitch -VMHost $currentHostFQDN -Name $vss.vssName -errorAction silentlyContinue
                    If (!($vssExists)) {
                        LogMessage -type INFO -message "[$currentHostFQDN] Creating new vSS $($vss.vssName) with MTU $mtu"
                        New-VirtualSwitch -VMHost $currentHostFQDN -Name $vss.vssName -mtu $mtu | Out-Null
                    } else {
                        LogMessage -type INFO -message "[$currentHostFQDN] vSS $($vss.vssName) already exists. Skipping creation"
                    }

                    $vssObject = Get-VirtualSwitch -VMHost $currentHostFQDN -Name $vss.vssName
                    Foreach ($nic in $vss.nicNames) {
                        If ($vssObject.ExtensionData.Pnic -notlike "*$nic") {
                            LogMessage -type INFO -message "[$currentHostFQDN] Adding $nic to $($vss.vssName)"
                            $vmnicToAdd = Get-VMHostNetworkAdapter -VMHost $currentHostFQDN -Physical -Name $nic
                            Add-VirtualSwitchPhysicalNetworkAdapter -VirtualSwitch $vssObject -VMHostPhysicalNic $vmnicToAdd -confirm:$false
                        } else {
                            LogMessage -type INFO -message "[$currentHostFQDN] $nic already part of $($vss.vssName). Skipping"
                        }
                    }
                    $trafficTypesPortgroupName = "TRAFFIC_TYPES-" + ($vss.vdsNetworks -join "-")
                    $vssObject = Get-VirtualSwitch -VMHost $currentHostFQDN -Name $vss.vssName
                    $pgExists = Get-VirtualPortGroup -VirtualSwitch $vssObject -Name $trafficTypesPortgroupName -ErrorAction SilentlyContinue
                    If (!$pgExists) {
                        LogMessage -type INFO -message "[$currentHostFQDN] Creating portgroup $trafficTypesPortgroupName on $($vss.vssName)"
                        New-VirtualPortGroup -VirtualSwitch $vssObject -Name $trafficTypesPortgroupName | Out-Null
                    } else {
                        LogMessage -type INFO -message "[$currentHostFQDN] Portgroup $trafficTypesPortgroupName already exists. Skipping"
                    }
                    If ("VM_MANAGEMENT" -in $vss.vdsNetworks) {
                        $vmMgmtPgExists = Get-VirtualPortGroup -VirtualSwitch $vssObject -Name "vm_mgmt" -ErrorAction SilentlyContinue
                        If (!$vmMgmtPgExists) {
                            LogMessage -type INFO -message "[$currentHostFQDN] Creating portgroup vm_mgmt on $($vss.vssName) with VLAN $vmMgmtVlanId"
                            New-VirtualPortGroup -VirtualSwitch $vssObject -Name "vm_mgmt" -VLanId $vmMgmtVlanId | Out-Null
                        } else {
                            LogMessage -type INFO -message "[$currentHostFQDN] Portgroup vm_mgmt already exists. Skipping"
                        }
                    }
                }
            }
            Disconnect-VIServer -Server $currentHostFQDN -Force -Confirm:$false
        }
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
    } else {
        Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false -ErrorAction SilentlyContinue
        LogMessage -type WARNING -message "[$jumpboxName] Configuration not accepted. Task aborted"
    }
}
Export-ModuleMember -Function New-PrepareManagementHostNetworking

Function Add-VMKernelsToManagementHosts {
    <#
    .SYNOPSIS
    Adds vMotion and vSAN VMkernels to ESXi hosts in the default management cluster using data from the extracted SDDC backup

    .DESCRIPTION
    The Add-VMKernelsToManagementHosts cmdlet connects directly to each ESXi host in the default management cluster,
    identifies the appropriate vSS based on TRAFFIC_TYPES portgroups, creates vMotion and vSAN portgroups with the
    correct VLAN IDs, and adds VMkernel adapters with IP addresses from the extracted SDDC backup data.

    .EXAMPLE
    Add-VMKernelsToManagementHosts -extractedSDDCDataFile ".\extracted-sddc-data.json"

    .PARAMETER extractedSDDCDataFile
    Relative or absolute path to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup)
    #>

    Param(
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile
    )

    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $workloadDomain = $extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }
    $cluster = $workloadDomain.vsphereClusterDetails | Where-Object { $_.isDefault -eq "t" }
    $clusterName = $cluster.name

    $vmotionNetwork = $cluster.hosts[0].networks | Where-Object { $_.type -eq "VMOTION" }
    $vsanNetwork = $cluster.hosts[0].networks | Where-Object { $_.type -eq "VSAN" }

    $vMotionVlanId = $vmotionNetwork.vlanId
    $vMotionMtu = $vmotionNetwork.mtu
    $vMotionMask = $vmotionNetwork.subnetMask
    $vMotionGateway = $vmotionNetwork.gateway

    $vsanVlanId = $vsanNetwork.vlanId
    $vsanMtu = $vsanNetwork.mtu
    $vsanMask = $vsanNetwork.subnetMask
    $vsanGateway = $vsanNetwork.gateway

    LogMessage -type INFO -message "[$jumpboxName] vMotion Network - VLAN: $vMotionVlanId, MTU: $vMotionMtu, Mask: $vMotionMask, Gateway: $vMotionGateway"
    LogMessage -type INFO -message "[$jumpboxName] vSAN Network - VLAN: $vsanVlanId, MTU: $vsanMtu, Mask: $vsanMask, Gateway: $vsanGateway"

    If ($global:DefaultVIServers) {
        Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false -ErrorAction SilentlyContinue
    }

    Foreach ($clusterHost in $cluster.hosts) {
        $currentHostFQDN = $clusterHost.hostname
        $currentHostAdmin = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "ESXI") -and ($_.entityName -eq $currentHostFQDN) -and ($_.username -eq "root") }).username
        $currentHostPassword = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "ESXI") -and ($_.entityName -eq $currentHostFQDN) -and ($_.username -eq "root") }).password

        $vmotionIP = $clusterHost.vmotionIP
        $vsanIP = $clusterHost.vsanIP

        LogMessage -type INFO -message "[$currentHostFQDN] Host IPs - vMotion: $vmotionIP, vSAN: $vsanIP"

        LogMessage -type INFO -message "[$currentHostFQDN] Connecting to host"
        $hostConnection = Connect-VIServer $currentHostFQDN -user $currentHostAdmin -password $currentHostPassword -ErrorAction Stop

        $allPortgroups = Get-VirtualPortGroup -VMHost $currentHostFQDN
        $vmotionVssName = $null
        $vsanVssName = $null

        Foreach ($pg in $allPortgroups) {
            If ($pg.Name -like "TRAFFIC_TYPES-*") {
                $trafficTypes = $pg.Name -replace "TRAFFIC_TYPES-", ""
                $trafficTypesArray = $trafficTypes -split "-"
                If ("VMOTION" -in $trafficTypesArray) {
                    $vmotionVssName = $pg.VirtualSwitchName
                    LogMessage -type INFO -message "[$currentHostFQDN] Found VMOTION traffic type on vSS: $vmotionVssName"
                }
                If ("VSAN" -in $trafficTypesArray) {
                    $vsanVssName = $pg.VirtualSwitchName
                    LogMessage -type INFO -message "[$currentHostFQDN] Found VSAN traffic type on vSS: $vsanVssName"
                }
            }
        }

        If (-not $vmotionVssName) {
            LogMessage -type WARNING -message "[$currentHostFQDN] Could not find vSS with VMOTION in TRAFFIC_TYPES portgroup. Skipping vMotion configuration"
        } else {
            $vmotionPgName = "vmotion"
            $vssVmotionPortgroupExists = Get-VirtualPortGroup -VMHost $currentHostFQDN -VirtualSwitch $vmotionVssName -Name $vmotionPgName -ErrorAction SilentlyContinue
            If (-not $vssVmotionPortgroupExists) {
                LogMessage -type INFO -message "[$currentHostFQDN] Creating vMotion portgroup '$vmotionPgName' on $vmotionVssName with VLAN $vMotionVlanId"
                New-VirtualPortGroup -VirtualSwitch (Get-VirtualSwitch -VMHost $currentHostFQDN -Name $vmotionVssName) -Name $vmotionPgName -VLanId $vMotionVlanId | Out-Null
            } else {
                LogMessage -type INFO -message "[$currentHostFQDN] vMotion portgroup '$vmotionPgName' already exists. Skipping creation"
            }

            $vmk1Exists = Get-VMHostNetworkAdapter -VMHost $currentHostFQDN -Name "vmk1" -ErrorAction SilentlyContinue
            If (-not $vmk1Exists) {
                LogMessage -type INFO -message "[$currentHostFQDN] Creating vMotion VMkernel (vmk1) with IP $vmotionIP"
                $vssVmotionPortgroup = Get-VirtualPortGroup -VMHost $currentHostFQDN -VirtualSwitch $vmotionVssName -Name $vmotionPgName
                New-VMHostNetworkAdapter -VMHost $currentHostFQDN -VirtualSwitch $vmotionVssName -mtu $vMotionMtu -PortGroup $vssVmotionPortgroup -ip $vmotionIP -SubnetMask $vMotionMask -NetworkStack (Get-VMHostNetworkStack -VMHost $currentHostFQDN | Where-Object { $_.id -eq "vmotion" }) | Out-Null
            } else {
                LogMessage -type INFO -message "[$currentHostFQDN] VMkernel vmk1 already exists. Skipping creation"
            }

            $vmk1Check = Get-VMHostNetworkAdapter -VMHost $currentHostFQDN -Name "vmk1" -ErrorAction SilentlyContinue
            If ($vmk1Check) {
                LogMessage -type INFO -message "[$currentHostFQDN] Setting vMotion Gateway to $vMotionGateway"
                $vmkName = 'vmk1'
                $esx = Get-VMHost -Name $currentHostFQDN
                $esxcli = Get-EsxCli -VMHost $esx -V2
                $interface = $esxcli.network.ip.interface.ipv4.get.Invoke(@{interfacename = $vmkName })
                If ($interface) {
                    $interfaceArg = @{
                        netmask       = $interface[0].IPv4Netmask
                        type          = $interface[0].AddressType.ToLower()
                        ipv4          = $interface[0].IPv4Address
                        interfacename = $interface[0].Name
                    }
                    $esxcli.network.ip.interface.ipv4.set.Invoke($interfaceArg) *>$null
                    $esxcli.network.ip.route.ipv4.add.Invoke(@{ netstack = 'vmotion'; network = 'default'; gateway = $vMotionGateway }) *>$null
                }
            }
        }

        If (-not $vsanVssName) {
            LogMessage -type WARNING -message "[$currentHostFQDN] Could not find vSS with VSAN in TRAFFIC_TYPES portgroup. Skipping vSAN configuration"
        } else {
            $vsanPgName = "vsan"
            $vssVsanPortgroupExists = Get-VirtualPortGroup -VMHost $currentHostFQDN -VirtualSwitch $vsanVssName -Name $vsanPgName -ErrorAction SilentlyContinue
            If (-not $vssVsanPortgroupExists) {
                LogMessage -type INFO -message "[$currentHostFQDN] Creating vSAN portgroup '$vsanPgName' on $vsanVssName with VLAN $vsanVlanId"
                New-VirtualPortGroup -VirtualSwitch (Get-VirtualSwitch -VMHost $currentHostFQDN -Name $vsanVssName) -Name $vsanPgName -VLanId $vsanVlanId | Out-Null
            } else {
                LogMessage -type INFO -message "[$currentHostFQDN] vSAN portgroup '$vsanPgName' already exists. Skipping creation"
            }

            $vmk2Exists = Get-VMHostNetworkAdapter -VMHost $currentHostFQDN -Name "vmk2" -ErrorAction SilentlyContinue
            If (-not $vmk2Exists) {
                LogMessage -type INFO -message "[$currentHostFQDN] Creating vSAN VMkernel (vmk2) with IP $vsanIP"
                $vssVsanPortgroup = Get-VirtualPortGroup -VMHost $currentHostFQDN -VirtualSwitch $vsanVssName -Name $vsanPgName
                New-VMHostNetworkAdapter -VMHost $currentHostFQDN -VirtualSwitch $vsanVssName -mtu $vsanMtu -PortGroup $vssVsanPortgroup -ip $vsanIP -SubnetMask $vsanMask -VsanTrafficEnabled $true | Out-Null
            } else {
                LogMessage -type INFO -message "[$currentHostFQDN] VMkernel vmk2 already exists. Skipping creation"
            }

            $vmk2Check = Get-VMHostNetworkAdapter -VMHost $currentHostFQDN -Name "vmk2" -ErrorAction SilentlyContinue
            If ($vmk2Check) {
                LogMessage -type INFO -message "[$currentHostFQDN] Setting vSAN Gateway to $vsanGateway"
                $vmkName = 'vmk2'
                $esx = Get-VMHost -Name $currentHostFQDN
                $esxcli = Get-EsxCli -VMHost $esx -V2
                $interface = $esxcli.network.ip.interface.ipv4.get.Invoke(@{interfacename = $vmkName })
                If ($interface) {
                    $interfaceArg = @{
                        netmask       = $interface[0].IPv4Netmask
                        type          = $interface[0].AddressType.ToLower()
                        ipv4          = $interface[0].IPv4Address
                        interfacename = $interface[0].Name
                        gateway       = $vsanGateway
                    }
                    $esxcli.network.ip.interface.ipv4.set.Invoke($interfaceArg) *>$null
                }
            }
        }

        Disconnect-VIServer -Server $currentHostFQDN -Force -Confirm:$false
    }

    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function Add-VMKernelsToManagementHosts

Function Backup-ClusterVMOverrides {
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
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
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
            'VmReactionOnAPDCleared'    = $vmMonitoringSettings.VmComponentProtectionSettings.VmReactionOnAPDCleared
            #PDL
            'VmStorageProtectionForPDL' = $vmMonitoringSettings.VmComponentProtectionSettings.VmStorageProtectionForPDL
        }
    }
    $overRiddenData | ConvertTo-Json -depth 10 | Out-File "$clusterName-vmOverrides.json"
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function Backup-ClusterVMOverrides

Function Backup-ClusterVMLocations {
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
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
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
    } Catch {
        catchWriter -object $_
    }
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function Backup-ClusterVMLocations

Function Backup-ClusterDRSGroupsAndRules {
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
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
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
    } Catch {
        catchWriter -object $_
    }
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function Backup-ClusterDRSGroupsAndRules

Function Backup-ClusterVMTags {
    <#
    .SYNOPSIS
    Backs up the VM tags for the specified cluster

    .DESCRIPTION
    The Backup-ClusterVMTags cmdlet backs up the VM tags for the specified cluster

    .EXAMPLE
    Backup-ClusterVMTags -clusterName "sfo-m01-cl01"

    .PARAMETER clusterName
    Cluster whose VM tags you wish to backup
    #>

    Param(
        [Parameter(Mandatory = $true)]
        [String]$clusterName
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    Try {

        $clusterVMTags = Get-Cluster -Name $clusterName | Get-VM | Get-TagAssignment
        $allVMs = @()
        Foreach ($vm in $clusterVMTags) {
            $vmSettings = @()
            $vmSettings += [pscustomobject]@{
                'Tag'      = $vm.Tag.Name
                'Category' = $vm.Tag.Category
                'Entity'   = $vm.Entity.Name
            }
            $allVMs += $vmSettings
        }
        $allVMs | ConvertTo-Json -depth 10 | Out-File "$clusterName-vmTags.json"
    } Catch {
        catchWriter -object $_
    }
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function Backup-ClusterVMTags

Function Restore-ClusterVMOverrides {
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
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    try {
        If (Test-Path -path $jsonFile) {
            $vmOverRideInstances = Get-Content -path $jsonFile | ConvertFrom-Json
            Foreach ($vmOverRideInstance in $vmOverRideInstances) {
                If ($vmOverRideInstance.name -notlike "vCLS*") {
                    LogMessage -type INFO -message "[$($vmOverRideInstance.name)] Restoring VM Overide Settings"
                    $dasVmConfigSpecRequired = $false
                    $drsVmConfigSpecRequired = $false
                    $vmOverRideInstanceOrchestrationSpecRequired = $false
                    $dasVmConfigSpecSettings = @("VmMonitoring", "ClusterSettings", "FailureInterval", "MinUpTime", "MaxFailures", "MaxFailureWindow", "VmStorageProtectionForAPD", "VmTerminateDelayForAPDSec", "VmReactionOnAPDCleared", "VmStorageProtectionForPDL", "RestartPriority", "RestartPriorityTimeout", "IsolationResponse")
                    $vmOverRideInstanceOrchestrationSpecSettings = @("readyCondition", "PostReadyDelay")

                    Foreach ($dasVmConfigSpecSetting in $dasVmConfigSpecSettings) {
                        If ($vmOverRideInstance.$dasVmConfigSpecSetting -ne $null) { $dasVmConfigSpecRequired = $true }
                    }
                    If (($vmOverRideInstance.DrsAutomationLevel -ne $null) -and ($vmOverRideInstance.DrsAutomationLevel -ne 'AsSpecifiedByCluster')) {
                        $drsVmConfigSpecRequired = $true
                    }
                    Foreach ($vmOverRideInstanceOrchestrationSpecSetting in $vmOverRideInstanceOrchestrationSpecSettings) {
                        If ($vmOverRideInstance.$vmOverRideInstanceOrchestrationSpecSetting -ne $null) { $vmOverRideInstanceOrchestrationSpecRequired = $true }
                    }
                    $cluster = Get-Cluster -Name $clusterName
                    $vm = Get-VM $vmOverRideInstance.name
                    $spec = New-Object VMware.Vim.ClusterConfigSpecEx
                    If ($dasVmConfigSpecRequired) {
                        $spec.dasVmConfigSpec = New-Object VMware.Vim.ClusterDasVmConfigSpec[] (1)
                        $spec.dasVmConfigSpec[0] = New-Object VMware.Vim.ClusterDasVmConfigSpec
                        $spec.dasVmConfigSpec[0].operation = "add"
                        $spec.dasVmConfigSpec[0].info = New-Object VMware.Vim.ClusterDasVmConfigInfo
                        $spec.dasVmConfigSpec[0].info.key = New-Object VMware.Vim.ManagedObjectReference
                        $spec.dasVmConfigSpec[0].info.key.type = "VirtualMachine"
                        $spec.dasVmConfigSpec[0].info.key.value = $vm.ExtensionData.MoRef.Value
                        $spec.dasVmConfigSpec[0].info.dasSettings = New-Object VMware.Vim.ClusterDasVmSettings
                    }
                    If ($drsVmConfigSpecRequired) {
                        $spec.drsVmConfigSpec = New-Object VMware.Vim.ClusterDrsVmConfigSpec[] (1)
                        $spec.drsVmConfigSpec[0] = New-Object VMware.Vim.ClusterDrsVmConfigSpec
                        $spec.drsVmConfigSpec[0].operation = "add"
                        $spec.drsVmConfigSpec[0].info = New-Object VMware.Vim.ClusterDrsVmConfigInfo
                        $spec.drsVmConfigSpec[0].info.key = New-Object VMware.Vim.ManagedObjectReference
                        $spec.drsVmConfigSpec[0].info.key.type = "VirtualMachine"
                        $spec.drsVmConfigSpec[0].info.key.value = $vm.ExtensionData.MoRef.Value
                    }
                    If ($vmOverRideInstanceOrchestrationSpecRequired) {
                        $spec.vmOrchestrationSpec = New-Object VMware.Vim.ClusterVmOrchestrationSpec[] (1)
                        $spec.vmOrchestrationSpec[0] = New-Object VMware.Vim.ClusterVmOrchestrationSpec
                        $spec.vmOrchestrationSpec[0].operation = "add"
                        $spec.vmOrchestrationSpec[0].info = New-Object VMware.Vim.ClusterVmOrchestrationInfo
                        $spec.vmOrchestrationSpec[0].info.vm = New-Object VMware.Vim.ManagedObjectReference
                        $spec.vmOrchestrationSpec[0].info.vm.type = "VirtualMachine"
                        $spec.vmOrchestrationSpec[0].info.vm.value = $vm.ExtensionData.MoRef.Value
                    }

                    #Set VM Monitoring settings [Done]
                    $vmOverRideInstanceMonitoringSettings = @("VmMonitoring", "ClusterSettings", "FailureInterval", "MinUpTime", "MaxFailures", "MaxFailureWindow")
                    $vmOverRideInstanceMonitoringRequired = $false
                    Foreach ($vmOverRideInstanceMonitoringSetting in $vmOverRideInstanceMonitoringSettings) {
                        If ($vmOverRideInstance.$vmOverRideInstanceMonitoringSetting -ne $null) { $vmOverRideInstanceMonitoringRequired = $true }
                    }
                    If ($vmOverRideInstanceMonitoringRequired) {
                        $spec.dasVmConfigSpec[0].info.dasSettings.vmToolsMonitoringSettings = New-Object VMware.Vim.ClusterVmToolsMonitoringSettings
                        Foreach ($vmOverRideInstanceMonitoringSetting in $vmOverRideInstanceMonitoringSettings) {
                            If ($vmOverRideInstance.$vmOverRideInstanceMonitoringSetting -ne $null) { $spec.dasVmConfigSpec[0].info.dasSettings.vmToolsMonitoringSettings.$vmOverRideInstanceMonitoringSetting = $vmOverRideInstance.$vmOverRideInstanceMonitoringSetting }
                        }
                    }

                    $vmOverRideInstanceComponentProtectionSettings = @("VmStorageProtectionForAPD", "VmTerminateDelayForAPDSec", "VmReactionOnAPDCleared", "VmStorageProtectionForPDL")
                    $vmOverRideInstanceComponentProtectionRequired = $false
                    Foreach ($vmOverRideInstanceComponentProtectionSetting in $vmOverRideInstanceComponentProtectionSettings) {
                        If ($vmOverRideInstance.$vmOverRideInstanceComponentProtectionSetting -ne $null) { $vmOverRideInstanceComponentProtectionRequired = $true }
                    }
                    If ($vmOverRideInstanceComponentProtectionRequired) {
                        $spec.dasVmConfigSpec[0].info.dasSettings.vmComponentProtectionSettings = New-Object VMware.Vim.ClusterVmComponentProtectionSettings
                        Foreach ($vmOverRideInstanceComponentProtectionSetting in $vmOverRideInstanceComponentProtectionSettings) {
                            If ($vmOverRideInstance.$vmOverRideInstanceComponentProtectionSetting -ne $null) { $spec.dasVmConfigSpec[0].info.dasSettings.vmComponentProtectionSettings.$vmOverRideInstanceComponentProtectionSetting = $vmOverRideInstance.$vmOverRideInstanceComponentProtectionSetting }
                        }
                    }

                    #Set DRS Level [Done]
                    If (($vmOverRideInstance.DrsAutomationLevel -ne "AsSpecifiedByCluster") -AND ($vmOverRideInstance.DrsAutomationLevel -ne $null)) {
                        $spec.drsVmConfigSpec[0].info.Behavior = $vmOverRideInstance.DrsAutomationLevel #$vmOverRideInstance.DrsAutomationLevel AsSpecifiedByCluster
                        $spec.drsVmConfigSpec[0].info.enabled = $true
                    }

                    #Set vSphere HA Settings [Done]
                    If ($vmOverRideInstanceOrchestrationSpecRequired) {
                        $spec.vmOrchestrationSpec[0].info.vmReadiness = New-Object VMware.Vim.ClusterVmReadiness
                        Foreach ($vmOverRideInstanceOrchestrationSpecSetting in $vmOverRideInstanceOrchestrationSpecSettings) {
                            If ($vmOverRideInstance.$vmOverRideInstanceOrchestrationSpecSetting -ne $null) { $spec.vmOrchestrationSpec[0].info.vmReadiness.$vmOverRideInstanceOrchestrationSpecSetting = $vmOverRideInstance.$vmOverRideInstanceOrchestrationSpecSetting }
                        }

                    }
                    $haDasVmConfigSpecSettings = @("RestartPriority", "RestartPriorityTimeout", "IsolationResponse")
                    Foreach ($haDasVmConfigSpecSetting in $haDasVmConfigSpecSettings) {
                        If ($vmOverRideInstance.$haDasVmConfigSpecSetting -ne $null) { $spec.dasVmConfigSpec[0].info.dasSettings.$haDasVmConfigSpecSetting = $vmOverRideInstance.$haDasVmConfigSpecSetting }
                    }

                    #Configure Cluster
                    $cluster.ExtensionData.ReconfigureComputeResource($spec, $True)
                }
            }
        } else {
            Write-Error "$jsonfile not found"
        }
    } catch {
        catchWriter -object $_
    }
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function Restore-ClusterVMOverrides

Function Restore-ClusterVMLocations {
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
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    try {
        If (Test-Path -path $jsonFile) {
            $vmLocations = Get-Content -path $jsonFile | ConvertFrom-Json
            Foreach ($vmLocation in $vmLocations) {
                If ($vmLocation.name -notlike "vCLS*") {
                    $vm = Get-VM -name $vmLocation.name -errorAction SilentlyContinue
                    If ($vm) {
                        If ($vm.folder -ne $vmLocation.folder) {
                            LogMessage -type INFO -message "[$($vmLocation.name)] Setting VM Folder Location to $($vmLocation.folder)"
                            Move-VM -VM $vm -InventoryLocation $vmLocation.folder -confirm:$false
                        }
                        If ($vm.resourcePool -ne $vmLocation.resourcePool) {
                            LogMessage -type INFO -message "[$($vmLocation.name)] Setting ResourcePool to $($vmLocation.resourcePool)"
                            Move-VM -VM $vm -Destination $vmLocation.resourcePool -confirm:$false
                        }
                    } else {
                        Write-Error "[$(Get-VM -name $vmLocation.name)] Not found. Check that it has been restored"
                    }
                }
            }
        } else {
            $jumpboxName = hostname
            Write-Error "[$jumpboxName] $jsonfile not found"
        }
    } catch {
        catchWriter -object $_
    }
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function Restore-ClusterVMLocations

Function Restore-ClusterDRSGroupsAndRules {
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
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    try {
        If (Test-Path -path $jsonFile) {
            $drsRulesAndGroups = Get-Content -path $jsonFile | ConvertFrom-Json
            Foreach ($vmDrsGroup in $drsRulesAndGroups.vmDrsGroups) {
                $group = Get-DrsClusterGroup -name $vmDrsGroup.name -errorAction SilentlyContinue
                If ($group) {
                    If ($vmDrsGroup.type -eq "VMHostGroup") {
                        Foreach ($member in $vmDrsGroup.members) {
                            LogMessage -type INFO -message "[$member] Adding to VMHostGroup $($vmDrsGroup.name)"
                            Set-DrsClusterGroup -DrsClusterGroup $vmDrsGroup.name -Add -VMHost $member -confirm:$false | Out-Null
                        }
                    } elseif ($vmDrsGroup.type -eq "VMGroup") {
                        Foreach ($member in $vmDrsGroup.members) {
                            LogMessage -type INFO -message "[$member] Adding to VMGroup $($vmDrsGroup.name)"
                            Set-DrsClusterGroup -DrsClusterGroup $vmDrsGroup.name -Add -VM $member -confirm:$false | Out-Null
                        }
                    }
                } else {
                    If ($vmDrsGroup.type -eq "VMHostGroup") {
                        LogMessage -type INFO -message "[$($vmDrsGroup.name)] Creating VMHostGroup with Members $($vmDrsGroup.members)"
                        New-DrsClusterGroup -Name $vmDrsGroup.name -VMHost $vmDrsGroup.members -Cluster $clusterName | Out-Null
                    } elseif ($vmDrsGroup.type -eq "VMGroup") {
                        LogMessage -type INFO -message "[$($vmDrsGroup.name)] Creating VMGroup with Members $($vmDrsGroup.members)"
                        New-DrsClusterGroup -Name $vmDrsGroup.name -VM $vmDrsGroup.members -Cluster $clusterName | Out-Null
                    }
                }
            }
            Foreach ($vmAffinityRule in $drsRulesAndGroups.vmAffinityRules) {
                If ($vmAffinityRule.members.count -gt 1) {
                    $vmRule = Get-DrsRule -name $vmAffinityRule.name -cluster $clusterName -errorAction SilentlyContinue
                    If ($vmRule) {
                        LogMessage -type INFO -message "[$($vmAffinityRule.name)] Setting VM Rule with Members $($vmAffinityRule.members)"
                        Set-DrsRule -rule $vmRule -VM $vmAffinityRule.members -Enabled $true -confirm:$false | Out-Null
                    } else {
                        LogMessage -type INFO -message "[$($vmAffinityRule.name)] Creating VM Rule with Members $($vmAffinityRule.members)"
                        New-DrsRule -cluster $clusterName -name $vmAffinityRule.name -VM $vmAffinityRule.members -keepTogether $vmAffinityRule.keepTogether -Enabled $true | Out-Null
                    }
                }
            }
            Foreach ($vmHostAffinityRule in $drsRulesAndGroups.vmHostAffinityRules) {
                $hostRule = Get-DrsVMHostRule -Cluster $clusterName -name $vmHostAffinityRule.name -errorAction SilentlyContinue
                If ($hostRule) {
                    LogMessage -type INFO -message "[$($vmHostAffinityRule.name)] Setting VMHost Rule with VM Group $($vmHostAffinityRule.vmGroupName) and Host Group $($vmHostAffinityRule.hostGroupName)"
                    Set-DrsVMHostRule -rule $hostRule -VMGroup $vmHostAffinityRule.vmGroupName -VMHostGroup $vmHostAffinityRule.hostGroupName -Type $vmHostAffinityRule.variant -confirm:$false | Out-Null
                } else {
                    LogMessage -type INFO -message "[$($vmHostAffinityRule.name)] Creating VMHost Rule with VM Group $($vmHostAffinityRule.vmGroupName) and Host Group $($vmHostAffinityRule.hostGroupName)"
                    New-DrsVMHostRule -Name $vmHostAffinityRule.name -Cluster $clusterName -VMGroup $vmHostAffinityRule.vmGroupName -VMHostGroup $vmHostAffinityRule.hostGroupName -Type $vmHostAffinityRule.variant | Out-Null
                }
            }
            Foreach ($vmToVmDependencyRule in $drsRulesAndGroups.vmToVmDependencyRules) {
                $dependencyRule = (Get-Cluster -Name $clusterName).ExtensionData.Configuration.Rule | Where-Object { $_.DependsOnVmGroup -and $_.name -eq $vmToVmDependencyRule.name -and $_.vmGroup -eq $vmToVmDependencyRule.vmGroup -and $_.DependsOnVmGroup -eq $vmToVmDependencyRule.DependsOnVmGroup }
                If (!$dependencyRule) {
                    LogMessage -type INFO -message "[$($vmToVmDependencyRule.vmGroup)] Creating VM to VM Dependency Rule to depend on $($vmToVmDependencyRule.DependsOnVmGroup) "
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
        } else {
            $jumpboxName = hostname
            Write-Error "[$jumpboxName] $jsonfile not found"
        }
    } catch {
        catchWriter -object $_
    }
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function Restore-ClusterDRSGroupsAndRules

Function Restore-ClusterVMTags {
    <#
    .SYNOPSIS
    Restores the VM tags for the specified cluster

    .DESCRIPTION
    The Restore-ClusterVMTags cmdlet restores the VM tags for the specified cluster

    .EXAMPLE
    Restore-ClusterVMTags -clusterName "sfo-m01-cl01" -jsonFile ".\sfo-m01-cl01-vmTags.json"

    .PARAMETER clusterName
    Cluster whose VM tags you wish to restore

    .PARAMETER jsonFile
    Path to the JSON File that contains the backup for the VM tags for the Cluster
    #>

    Param(
        [Parameter(Mandatory = $true)][String]$clusterName,
        [Parameter(Mandatory = $true)][String]$jsonFile
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    try {
        If (Test-Path -path $jsonFile) {
            $vmTags = Get-Content -path $jsonFile | ConvertFrom-Json
            Foreach ($vmTag in $vmTags) {
                If ($vmTag.Entity -notlike "vCLS*") {
                    $vm = Get-VM -name $vmTag.Entity -errorAction SilentlyContinue
                    If ($vm) {
                        LogMessage -type INFO -message "[$($vmTag.Entity)] Setting VM Tag to $($vmTag.Tag)"
                        New-TagAssignment -Entity $vm -Tag $vmTag.Tag -confirm:$false | Out-Null
                    } else {
                        Write-Error "[$(Get-VM -name $vmTag.Entity)] Not found. Check that it has been restored"
                    }
                }
            }
        } else {
            $jumpboxName = hostname
            Write-Error "[$jumpboxName] $jsonfile not found"
        }
    } catch {
        catchWriter -object $_
    }
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function Restore-ClusterVMTags

#EndRegion vCenter Functions

#Region NSXT Functions

Function Invoke-NSXManagerRestore {
    <#
    .SYNOPSIS
    Performs the restore of an NSX Manager from a user chosen backup presented from a list available on supplied SFTP server

    .DESCRIPTION
    The Invoke-NSXManagerRestore performs the restore of an NSX Manager from a user chosen backup presented from a list available on supplied SFTP server

    .EXAMPLE
    Invoke-NSXManagerRestore -extractedSDDCDataFile ".\extracted-sddc-data.json" -workloadDomain "sfo-m01" -sftpServer "10.50.5.66" -sftpUser svc-bkup-user -sftpPassword "VMw@re1!" -sftpServerBackupPath "/media/backups" -backupPassphrase "VMw@re1!VMw@re1!"

    .PARAMETER workloadDomain
    Name of the VCF workload domain that the NSX Manager to be restored is associated with

    .PARAMETER sftpServer
    Address of the SFTP server that hosts the NSX Manager backups

    .PARAMETER sftpUser
    Username for connection to the SFTP server that hosts the NSX Manager backups

    .PARAMETER sftpPassword
    Password for the user (passed as the stpUser parameter) for connection to the SFTP server that hosts the NSX Manager backups

    .PARAMETER sftpServerBackupPath
    Path to the folder on the server (passed as the sftpServer parameter) where the NSX Manager backups exist

    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem
    #>
    Param(
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $true)][String] $workloadDomain,
        [Parameter (Mandatory = $true)][String] $sftpServer,
        [Parameter (Mandatory = $true)][String] $sftpUser,
        [Parameter (Mandatory = $true)][String] $sftpPassword,
        [Parameter (Mandatory = $true)][String] $sftpServerBackupPath,
        [Parameter (Mandatory = $true)][String] $backupPassphrase
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON
    $workloadDomainDetails = ($extractedSDDCData.workloadDomains | Where-Object { $_.domainName -eq $workloadDomain })
    $nsxNodes = $workloadDomainDetails.nsxNodeDetails

    $nsxManagersDisplayObject = @()
    $nsxManagersIndex = 1
    $nsxManagersDisplayObject += [pscustomobject]@{
        'ID'      = "ID"
        'Manager' = "NSX Manager"
    }
    $nsxManagersDisplayObject += [pscustomobject]@{
        'ID'      = "--"
        'Manager' = "------------------"
    }
    Foreach ($nsxNode in $nsxNodes) {
        $nsxManagersDisplayObject += [pscustomobject]@{
            'ID'      = $nsxManagersIndex
            'Manager' = $nsxNode.vmName
        }
        $nsxManagersIndex++
    }
    Write-Host ""; $nsxManagersDisplayObject | format-table -Property @{Expression = " " }, id, Manager -autosize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r", "`n") }
    Do {
        Write-Host ""; Write-Host " Enter the ID of the Manager you wish to restore, or C to Cancel: " -ForegroundColor Yellow -nonewline
        $nsxManagerSelection = Read-Host
    } Until (($nsxManagerSelection -in $nsxManagersDisplayObject.ID) -OR ($nsxManagerSelection -eq "c"))
    If ($nsxManagerSelection -eq "c") { Break }
    $selectedNsxManager = $nsxNodes | Where-Object { $_.vmName -eq ($nsxManagersDisplayObject | Where-Object { $_.id -eq $nsxManagerSelection }).manager }

    $nsxManagerFQDN = $selectedNsxManager.hostname
    $nsxManagerIP = $selectedNsxManager.ip
    $nsxManagerAdminUsername = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "NSXT_MANAGER") -and ($_.domainName -eq $workloadDomain) -and ($_.username -eq "admin") }).username
    $nsxManagerAdminPassword = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "NSXT_MANAGER") -and ($_.domainName -eq $workloadDomain) -and ($_.username -eq "admin") }).password

    #Retrieve Key of SFTP Server
    LogMessage -type INFO -message "[$jumpboxName] Retrieving SSH Fingerprint of $sftpServer"
    Remove-Item keyscanOutput.txt -confirm:$false -erroraction silentlycontinue
    ssh-keyscan.exe -t ecdsa $sftpServer 2>$null | Out-File keyscanOutput.txt
    $sshFingerPrint = ((ssh-keygen -lf .\keyscanOutput.txt) -split (" "))[1]
    Remove-Item keyscanOutput.txt -confirm:$false

    #Get Backup Config (to ensure services are running)
    LogMessage -type WAIT -message "[$nsxManagerFQDN] Waiting for services to be started"
    $headers = VCFIRCreateHeader -username $nsxManagerAdminUsername -password $nsxManagerAdminPassword
    $uri = "https://$nsxManagerFQDN/api/v1/cluster/backups/config"
    Do {
        Try {
            $existingBackup = (Invoke-WebRequest -Method GET -URI $uri -ContentType application/json -headers $headers).content | ConvertFrom-Json
        } catch {
            Sleep 30
        }
    } Until ($existingBackup)

    #Configure the Backup
    LogMessage -type INFO -message "[$nsxManagerFQDN] Configuring $sftpServer as backup target"
    $body = "{
    `"backup_enabled`" : false,
    `"backup_schedule`":{
        `"resource_type`": `"IntervalBackupSchedule`",
        `"seconds_between_backups`":3600
    },
    `"remote_file_server`":{
        `"server`": `"$sftpServer`",
        `"port`":22,
        `"protocol`":{
            `"protocol_name`":`"sftp`",
            `"ssh_fingerprint`": `"$sshFingerPrint`",
            `"authentication_scheme`":{
                `"scheme_name`":`"PASSWORD`",
                `"username`":`"$sftpUser`",
                `"password`":`"$sftpPassword`"
            }
        },
        `"directory_path`":`"$sftpServerBackupPath`"
    },
    `"passphrase`":`"$backupPassphrase`",
    `"inventory_summary_interval`":300
    }"

    $uri = "https://$nsxManagerFQDN/api/v1/cluster/backups/config"
    $configureBackup = (Invoke-WebRequest -Method PUT -URI $uri -ContentType application/json -body $body -headers $headers).content | ConvertFrom-Json

    #Retrieve and Display Backup TimeStamps
    LogMessage -type INFO -message "[$nsxManagerFQDN] Retrieving Backups from $sftpServer"
    $uri = "https://$nsxManagerFQDN/api/v1/cluster/restore/backuptimestamps"
    $backupDetails = ((Invoke-WebRequest -Method GET -URI $uri -ContentType application/json -headers $headers).content | ConvertFrom-Json).results

    LogMessage -type INFO -message "[$jumpboxName] Filtering Backups to those relevant to $nsxManagerFQDN"
    $relevantBackups = $backupDetails | where-object { $_.ip_address -eq $nsxManagerIP }
    $relevantbackupsDisplayObject = @()
    $relevantbackupIndex = 1
    $relevantbackupsDisplayObject += [pscustomobject]@{
        'ID'        = "ID"
        'ipAddress' = "IP Address"
        'timeStamp' = "TimeStamp"
        'humanTime' = "Backup TimeStamp"
        'nodeID'    = "Node ID"
    }
    $relevantbackupsDisplayObject += [pscustomobject]@{
        'ID'        = "--"
        'ipAddress' = "---------------"
        'timeStamp' = "------------------"
        'humanTime' = "-------------------"
        'nodeID'    = "------------------------------------"
    }
    Foreach ($relevantBackup in $relevantBackups) {
        $relevantbackupsDisplayObject += [pscustomobject]@{
            'ID'        = $relevantbackupIndex
            'ipAddress' = $relevantBackup.ip_address
            'timeStamp' = $relevantBackup.timestamp
            'humanTime' = (Get-Date -Date "01-01-1970") + ([System.TimeSpan]::FromSeconds(($relevantBackup.timestamp -replace ".{3}$")))
            'nodeID'    = $relevantBackup.node_id
        }
        $relevantbackupIndex++
    }
    Write-Host ""; $relevantbackupsDisplayObject | format-table -Property @{Expression = " " }, id, ipAddress, nodeId, humanTime -autosize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r", "`n") }
    Do {
        Write-Host ""; Write-Host " Enter the ID of the Backup you wish to restore, or C to Cancel: " -ForegroundColor Yellow -nonewline
        $backupSelection = Read-Host
    } Until (($backupSelection -in $relevantbackupsDisplayObject.ID) -OR ($backupSelection -eq "c"))
    If ($backupSelection -eq "c") { Break }

    #Start Restore
    LogMessage -type INFO -message "[$nsxManagerFQDN] Starting Restore"
    $body = "{
    `"node_id`": `"$(($relevantbackupsDisplayObject | where-object {$_.id -eq $backupSelection}).nodeID)`",
    `"timestamp`" : $(($relevantbackupsDisplayObject | where-object {$_.id -eq $backupSelection}).timeStamp)
    }"
    $uri = "https://$nsxManagerFQDN/api/v1/cluster/restore?action=start"
    $startRestore = (Invoke-WebRequest -Method POST -URI $uri -ContentType application/json -body $body -headers $headers).content | ConvertFrom-Json

    #QueryRestore
    LogMessage -type INFO -message "[$nsxManagerFQDN] Polling restore status every 60 seconds"
    $queryUri = "https://$nsxManagerFQDN/api/v1/cluster/restore/status"
    Do {
        Sleep 60
        Try {
            $restoreStatus = (Invoke-WebRequest -Method GET -URI $queryUri -ContentType application/json -headers $headers).content | ConvertFrom-Json
            If ($restoreStatus.status.value -eq "SUSPENDED_FOR_USER_ACTION") {
                LogMessage -type INFO -message "[$nsxManagerFQDN] Resuming restore at step $($restoreStatus.step.step_number): $($restoreStatus.step.value)"
                $instructionIds = $restoreStatus.instructions.id
                $body = "{
                `"data`": [
                    {
                    `"id`": `"$instructionIds`",
                    `"resources`": [
                    ]
                    }
                    ]
                }"
                $resumeUri = "https://$nsxManagerFQDN/api/v1/cluster/restore?action=advance"
                $resumeRestore = (Invoke-WebRequest -Method POST -URI $resumeUri -ContentType application/json -body $body -headers $headers).content | ConvertFrom-Json
            } else {
                LogMessage -type INFO -message "[$nsxManagerFQDN] Restore is currently $($restoreStatus.status.value)"
            }
        } Catch {}
    } Until ($restoreStatus.status.value -eq "SUCCESS")
    LogMessage -type INFO -message "[$nsxManagerFQDN] Restore finished with status: $($restoreStatus.status.value)"
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function Invoke-NSXManagerRestore

Function Invoke-NSXEdgeClusterRecovery {
    <#
    .SYNOPSIS
    Redeploys the NSX Egdes from the provided vSphere Cluster

    .DESCRIPTION
    The Invoke-NSXEdgeClusterRecovery cmdlet redeploys the NSX Egdes from the provided vSphere Cluster

    .EXAMPLE
    Invoke-NSXEdgeClusterRecovery -nsxManagerFqdn "sfo-m01-nsx01.sfo.rainpole.io" -nsxManagerAdmin "admin" -nsxManagerAdminPassword "VMw@re1!VMw@re1!" -vCenterFQDN "sfo-m01-vc01.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01" -extractedSDDCDataFile ".\extracted-sddc-data.json"

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
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $vcenterConnection = Connect-VIServer -server $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword

    #Get all Resource Pool moRefs and add cluster moReg
    $resourcePools = @(Get-Cluster -name $clusterName | Get-ResourcePool | Where-Object { $_.name -ne "Resources" })
    $cluster = (Get-Cluster -name $clusterName)

    $edgeLocations = @()
    #$resourcePoolLocations = @()
    Foreach ($resourcePool in $resourcePools) {
        $edgeLocations += [PSCustomObject]@{
            'Type'  = 'ResourcePool'
            'Name'  = $resourcePool.Name
            'moRef' = $resourcePool.extensionData.moref.value
        }
        #$resourcePoolLocations += $resourcePool.extensionData.moref.value
    }
    $edgeLocations += [PSCustomObject]@{
        'Type'  = 'Cluster'
        'Name'  = $cluster.Name
        'moRef' = $cluster.extensionData.moref.value
    }

    Foreach ($edgeLocation in $edgeLocations) {
        #Get TransportNodes
        LogMessage -type INFO -message "[$nsxManagerFqdn] Looking for Edges to recover in $($edgeLocation.type): $($edgeLocation.name)"
        $headers = VCFIRCreateHeader -username $nsxManagerAdmin -password $nsxManagerAdminPassword
        $uri = "https://$nsxManagerFqdn/api/v1/transport-nodes/"
        $transportNodeContents = (Invoke-WebRequest -Method GET -URI $uri -ContentType application/json -headers $headers).content | ConvertFrom-Json
        #If ($edgeLocation.type -eq 'ResourcePool')
        #{
        $allEdgeTransportNodes = ($transportNodeContents.results | Where-Object { ($_.node_deployment_info.resource_type -eq "EdgeNode") -and ($_.node_deployment_info.deployment_config.vm_deployment_config.compute_id -eq $edgeLocation.MoRef) }) | Sort-Object -Property display_name
        #}
        #else
        #{
        #$allEdgeTransportNodes = ($transportNodeContents.results | Where-Object { ($_.node_deployment_info.resource_type -eq "EdgeNode") -and ($_.node_deployment_info.deployment_config.vm_deployment_config.compute_id -notin $resourcePoolLocations)}) | Sort-Object -Property display_name
        #}

        If ($allEdgeTransportNodes) {
            LogMessage -type INFO -message "[$nsxManagerFqdn] Found Edges to recover: $($allEdgeTransportNodes.display_name -join(","))"
        } else {
            LogMessage -type INFO -message "[$nsxManagerFqdn] No Edges found needing recovery"
        }
        #Redeploy Failed Edges
        Foreach ($edge in $allEdgeTransportNodes) {
            $edgeVmPresent = get-vm -name $edge.display_name -ErrorAction SilentlyContinue
            If (!$edgeVmPresent) {
                #Getting Existing Placement Details
                LogMessage -type INFO -message "[$($edge.display_name)] Getting Placement References"
                $uri = "https://$nsxManagerFqdn/api/v1/transport-nodes/$($edge.node_id)"
                $edgeConfig = (Invoke-WebRequest -Method GET -URI $uri -ContentType application/json -headers $headers).content | ConvertFrom-Json
                $vmDeploymentConfig = $edgeConfig.node_deployment_info.deployment_config.vm_deployment_config
                $NumCpu = $vmDeploymentConfig.resource_allocation.cpu_count
                $memoryGB = $vmDeploymentConfig.resource_allocation.memory_allocation_in_mb / 1024
                $cpuShareLevel = (($vmDeploymentConfig.reservation_info.cpu_reservation.reservation_in_shares -split ("_"))[0]).tolower()
                $attachedNetworks = $vmDeploymentConfig.data_network_ids

                #Create Dummy VM
                LogMessage -type INFO -message "[$($edge.display_name)] Preparing to Update Placement References"
                $portgroup = (($extractedSddcData.workloadDomains.vsphereClusterDetails | Where-Object { $_.name -eq $clusterName }).vdsdetails.portgroups | Where-Object { $_.transportType -eq 'VM_MANAGEMENT' }).NAME
                $clusterVdsName = (($extractedSddcData.workloadDomains.vsphereClusterDetails | Where-Object { $_.name -eq $clusterName }).vdsdetails | Where-Object { $_.portgroups.transportType -eq 'VM_MANAGEMENT' }).dvsName
                If (!$portgroup) {
                    $portgroup = (($extractedSddcData.workloadDomains.vsphereClusterDetails | Where-Object { $_.name -eq $clusterName }).vdsdetails.portgroups | Where-Object { $_.transportType -eq 'MANAGEMENT' }).NAME
                    $clusterVdsName = (($extractedSddcData.workloadDomains.vsphereClusterDetails | Where-Object { $_.name -eq $clusterName }).vdsdetails | Where-Object { $_.portgroups.transportType -eq 'MANAGEMENT' }).dvsName
                }
                $nestedNetworkPG = Get-VDPortGroup -name $portgroup -ErrorAction silentlyContinue | Where-Object { $_.VDSwitch -match $clusterVdsName }
                $datastore = ($extractedSddcData.workloadDomains.vsphereClusterDetails | Where-Object { $_.name -eq $clusterName }).primaryDatastoreName

                If ($edgeLocation.type -eq "ResourcePool") {
                    New-VM -VMhost (get-cluster -name $clusterName | Get-VMHost | Get-Random ) -Name $edge.display_name -Datastore $datastore -resourcePool $edgeLocation.name -DiskGB 200 -DiskStorageFormat Thin -MemoryGB $MemoryGB -NumCpu $NumCpu -portgroup $portgroup -GuestID "ubuntu64Guest" -Confirm:$false | Out-Null
                } else {
                    New-VM -VMhost (get-cluster -name $clusterName | Get-VMHost | Get-Random ) -Name $edge.display_name -Datastore $datastore -DiskGB 200 -DiskStorageFormat Thin -MemoryGB $MemoryGB -NumCpu $NumCpu -portgroup $portgroup -GuestID "ubuntu64Guest" -Confirm:$false | Out-Null
                }
                do {
                    Start-Sleep 1
                } until (Get-VM -Name $edge.display_name)
                Get-VM -Name $edge.display_name | Get-VMResourceConfiguration | Set-VMResourceConfiguration -MemReservationGB $memoryGB | Out-Null
                Get-VM -Name $edge.display_name | Get-VMResourceConfiguration | Set-VMResourceConfiguration -CpuSharesLevel $cpuShareLevel | Out-Null
                Foreach ($attachedNetwork in $attachedNetworks) {
                    $attachedNetworkPg = Get-VDPortGroup -id ("DistributedVirtualPortgroup-" + $attachedNetwork)
                    Get-VM -Name $edge.display_name | New-NetworkAdapter -portGroup $attachedNetworkPg -StartConnected -Type Vmxnet3 -Confirm:$false | Out-Null
                }
                $vmID = (get-vm -name $edge.display_name).extensionData.moref.value

                #Build Edge DeploymentSpec
                LogMessage -type INFO -message "[$($edge.display_name)] Updating Placement References"
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
                LogMessage -type INFO -message "[$($edge.display_name)] Getting Edge State"
                $uri = "https://$nsxManagerFqdn/api/v1/transport-nodes/$($edge.node_id)/state"
                $edgeState = (Invoke-WebRequest -Method GET -URI $uri -ContentType application/json -headers $headers).content | ConvertFrom-Json
                If ($edgeState.node_deployment_state.state -ne "success") {
                    LogMessage -type INFO -message "[$($edge.display_name)] State is $($edgeState.node_deployment_state.state)"
                    If ($edgeState.node_deployment_state.state -in "MPA_DISCONNECTED", "VM_PLACEMENT_REFRESH_FAILED", "NODE_READY") {
                        LogMessage -type INFO -message "[$($edge.display_name)] Redeploying Edge"
                        $uri = "https://$nsxManagerFqdn/api/v1/transport-nodes/$($edge.node_id)"
                        $edgeResponse = (Invoke-WebRequest -Method GET -URI $uri -ContentType application/json -headers $headers).content
                        $uri = "https://$nsxManagerFqdn/api/v1/transport-nodes/$($edge.node_id)?action=redeploy"
                        $edgeRedeploy = Invoke-WebRequest -Method POST -URI $uri -ContentType application/json -body $edgeResponse -headers $headers
                    } else {
                        LogMessage -type INFO -message "[$($edge.display_name)] Not in a suitable state for redeployment. Please review and retry"
                    }
                }
            }
        }
        LogMessage -type NOTE -message "[$jumpboxName] Discovered Edge Redeployments have been initiated. Please monitor in NSX UI for completion"
    }
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function Invoke-NSXEdgeClusterRecovery

Function Add-AdditionalNSXManagers {
    <#
    .SYNOPSIS
    Adds second and third NSX managers to a cluster after the restore of the first NSX Manager

    .DESCRIPTION
    The Add-AdditionalNSXManagers cmdlet adds second and third NSX managers to a cluster after the restore of the first NSX Manager

    .EXAMPLE
    Add-AdditionalNSXManagers -workloadDomain "sfo-m01" -extractedSDDCDataFile ".\extracted-sddc-data.json"

    .PARAMETER workloadDomain
    Name of the VCF workload domain that the NSX Managers to be added are associated with

    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem
    #>

    Param(
        [Parameter (Mandatory = $true)][String] $workloadDomain,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON
    $workloadDomainDetails = ($extractedSDDCData.workloadDomains | Where-Object { $_.domainName -eq $workloadDomain })
    $nsxNodes = $workloadDomainDetails.nsxNodeDetails

    $nsxManagersDisplayObject = @()
    $nsxManagersIndex = 1
    $nsxManagersDisplayObject += [pscustomobject]@{
        'ID'      = "ID"
        'Manager' = "NSX Manager"
    }
    $nsxManagersDisplayObject += [pscustomobject]@{
        'ID'      = "--"
        'Manager' = "------------------"
    }
    Foreach ($nsxNode in $nsxNodes) {
        $nsxManagersDisplayObject += [pscustomobject]@{
            'ID'      = $nsxManagersIndex
            'Manager' = $nsxNode.vmName
        }
        $nsxManagersIndex++
    }
    Write-Host ""; $nsxManagersDisplayObject | format-table -Property @{Expression = " " }, id, Manager -autosize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r", "`n") }
    Do {
        Write-Host ""; Write-Host " Enter the ID of the First NSX Manager (i.e. the one you peformed the restore on), or C to Cancel: " -ForegroundColor Yellow -nonewline
        $nsxManagerSelection = Read-Host
    } Until (($nsxManagerSelection -in $nsxManagersDisplayObject.ID) -OR ($nsxManagerSelection -eq "c"))
    If ($nsxManagerSelection -eq "c") { Break }
    $selectedNsxManager = $nsxNodes | Where-Object { $_.vmName -eq ($nsxManagersDisplayObject | Where-Object { $_.id -eq $nsxManagerSelection }).manager }
    $otherNsxManagers = $nsxNodes | Where-Object { $_.vmName -ne ($nsxManagersDisplayObject | Where-Object { $_.id -eq $nsxManagerSelection }).manager }


    $nsxManagerFQDN = $selectedNsxManager.hostname
    $nsxManagerAdminUsername = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "NSXT_MANAGER") -and ($_.domainName -eq $workloadDomain) -and ($_.username -eq "admin") }).username
    $nsxManagerAdminPassword = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "NSXT_MANAGER") -and ($_.domainName -eq $workloadDomain) -and ($_.username -eq "admin") }).password

    #Create Headers
    $headers = VCFIRCreateHeader -username $nsxManagerAdminUsername -password $nsxManagerAdminPassword

    #Check for Compatible NSX Manager version
    $uri = "https://$nsxManagerFqdn/api/v1/node"
    $nsxManagerVersion = [INT](((((Invoke-WebRequest -Method GET -URI $uri -ContentType application/json -headers $headers).content | ConvertFrom-Json).product_version).replace(".", "")).substring(0, 3))

    If ($nsxManagerVersion) {
        #Get NSX Nodes
        LogMessage -type INFO -message "[$nsxManagerFQDN] Getting Cluster Node Details"
        $uri = "https://$nsxManagerFQDN/api/v1/cluster/"
        $clusterNodes = ((Invoke-WebRequest -Method GET -URI $uri -ContentType application/json -headers $headers).content | ConvertFrom-Json).nodes
        $otherclusterNodeIDs = ($clusterNodes | Where-Object { $_.fqdn -in $otherNsxManagers.hostname }).node_uuid #Potentially only required in NSX 3

        #Get Certificates
        LogMessage -type INFO -message "[$nsxManagerFQDN] Getting Cluster Node Certificate Details"
        $uri = "https://$nsxManagerFQDN/api/v1/trust-management/certificates"
        $allcertificates = (Invoke-WebRequest -Method GET -URI $uri -ContentType application/json -headers $headers).content | ConvertFrom-Json
        $signedCertificates = $allcertificates.results | Where-Object { $_.resource_type -eq "certificate_signed" }

        LogMessage -type INFO -message "[$nsxManagerFQDN] Starting SSH"
        $uri = "https://$nsxManagerFqdn/api/v1/node/services/ssh?action=start"
        $startSSH = (Invoke-WebRequest -Method POST -URI $uri -ContentType application/json -headers $headers).content | ConvertFrom-Json

        LogMessage -type INFO -message "[$jumpboxName] Establishing SSH Connection to $nsxManagerFQDN"
        $SecurePassword = ConvertTo-SecureString -String $nsxManagerAdminPassword -AsPlainText -Force
        $mycreds = New-Object System.Management.Automation.PSCredential ($nsxManagerAdminUsername, $SecurePassword)
        $inmem = New-SSHMemoryKnownHost
        New-SSHTrustedHost -KnownHostStore $inmem -HostName $nsxManagerFQDN -FingerPrint ((Get-SSHHostKey -ComputerName $nsxManagerFQDN).fingerprint) | Out-Null
        Do {
            $sshSession = New-SSHSession -computername $nsxManagerFQDN -Credential $mycreds -KnownHost $inmem
        } Until ($sshSession)
        $stream = New-SSHShellStream -SSHSession $sshSession

        LogMessage -type INFO -message "[$nsxManagerFQDN] Getting Cluster ID"
        $unwantedOutput = $stream.Read()
        Start-Sleep 2
        $stream.writeline("get cluster config | find Id:")
        Start-Sleep 5
        #$unwantedOutput = $stream.Readline()
        #$unwantedOutput = $stream.Readline()
        $clusterIdOutput = $stream.Read()
        $clusterId = (($clusterIdOutput.split("Cluster Id: "))[1]).Substring(0, 36)
        LogMessage -type INFO -message "[$nsxManagerFQDN] Cluster ID: $clusterId retrieved"

        LogMessage -type INFO -message "[$nsxManagerFQDN] Getting Certificate API Thumbprint"
        $unwantedOutput = $stream.Read()
        Start-Sleep 2
        $stream.writeline("get certificate api thumbprint")
        Start-Sleep 5
        $unwantedOutput = $stream.Readline()
        $unwantedOutput = $stream.Readline()
        $certApiThumbprint = $stream.Readline()
        LogMessage -type INFO -message "[$nsxManagerFQDN] Cert Thumbprint: $certApiThumbprint retrieved"


        #Close SSH Session
        Remove-SSHSession -SSHSession $sshSession | Out-Null

        Foreach ($otherNsxManager in $otherNsxManagers) {
            $nsxManagerFQDN = $otherNsxManager.hostname

            #Create Headers
            $headers = VCFIRCreateHeader -username $nsxManagerAdminUsername -password $nsxManagerAdminPassword

            LogMessage -type INFO -message "[$nsxManagerFQDN] Starting SSH"
            $uri = "https://$nsxManagerFqdn/api/v1/node/services/ssh?action=start"
            $startSSH = Invoke-WebRequest -Method POST -URI $uri -ContentType application/json -headers $headers

            LogMessage -type INFO -message "[$jumpboxName] Establishing SSH Connection to $nsxManagerFQDN"
            $SecurePassword = ConvertTo-SecureString -String $nsxManagerAdminPassword -AsPlainText -Force
            $mycreds = New-Object System.Management.Automation.PSCredential ($nsxManagerAdminUsername, $SecurePassword)
            $inmem = New-SSHMemoryKnownHost
            New-SSHTrustedHost -KnownHostStore $inmem -HostName $nsxManagerFQDN -FingerPrint ((Get-SSHHostKey -ComputerName $nsxManagerFQDN).fingerprint) | Out-Null
            Do {
                $sshSession = New-SSHSession -computername $nsxManagerFQDN -Credential $mycreds -KnownHost $inmem
            } Until ($sshSession)

            #Join Manager to Cluster
            LogMessage -type INFO -message "[$nsxManagerFQDN] Joining Cluster"
            $stream = New-SSHShellStream -SSHSession $sshSession
            $joinCommand = "join $($selectedNsxManager.ip) cluster-id $clusterId thumbprint $certApiThumbprint username admin"
            $stream.writeline("$($joinCommand)")
            Start-Sleep 5
            $stream.writeline("yes")
            Start-Sleep 2
            $stream.writeline("$($nsxManagerAdminPassword)")
            Do {
                Start-Sleep 10
                $response = $stream.Read()

            } Until ($response -like "*Join operation successful*")
            <# Do {
                Start-Sleep 10
                $stream.writeline("get cluster status")
                Start-Sleep 5
                $response = $stream.Read()

            } Until ($response -notlike "*DOWN*")
 #>
            Do {
                <# Start-Sleep 10
                $stream.writeline("get cluster status")
                Start-Sleep 5
                $response = $stream.Read() #>
                LogMessage -type INFO -message "[$nsxManagerFQDN] Monitoring cluster rebuild status"
                $response = ((curl -k -s -u "admin:$nsxManagerAdminPassword" "https://$nsxManagerFqdn/api/v1/cluster/status") | ConvertFrom-Json).mgmt_cluster_status.status

            } Until ($response -eq "stable")
            #Close SSH Session
            Remove-SSHSession -SSHSession $sshSession | Out-Null
        }
    } else {
        LogMessage -type ERROR -message "[$jumpboxName] Unable to determine NSX Manager Version. Check that it was successfully restored."
    }
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function Add-AdditionalNSXManagers
#EndRegion NSXT Functions

#Region Marked for Deprecation
Function New-PrepareforPartialBringup {
    <#
    .SYNOPSIS
    Prepares a running Cloud Builder system to perform a partial VCF bringup suitable for VCF Instance Recovery

    .DESCRIPTION
    The New-PrepareforPartialBringup cmdlet prepares a running Cloud Builder system to perform a partial VCF bringup suitable for VCF Instance Recovery.

    .EXAMPLE
    New-PrepareforPartialBringup -extractedSDDCDataFile ".\extracted-sddc-data.json" -cloudBuilderFQDN "sfo-cb01.sfo.rainpole.io" -cloudBuilderAdminUserPassword "VMw@re1!" -cloudBuilderRootUserPassword "VMw@re1!"

    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem

    .PARAMETER cloudBuilderFQDN
    FQDN of the Cloud Builder system that should be prepared

    .PARAMETER cloudBuilderAdminUserPassword
    Password for the 'admin' user on the Cloud Builder system

    .PARAMETER cloudBuilderRootUserPassword
    Password for the 'root' user on the Cloud Builder system
    #>

    Param(
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $true)][String] $cloudBuilderFQDN,
        [Parameter (Mandatory = $true)][String] $cloudBuilderAdminUserPassword,
        [Parameter (Mandatory = $true)][String] $cloudBuilderRootUserPassword
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON
    LogMessage -type INFO -message "[$jumpboxName] Detected desired SDDC Manager version of: $($extractedSddcData.sddcManager.version)"

    $truncatedSddcManagerVersion = $extractedSddcData.sddcManager.version.replace(".", "").substring(0, 2)
    $modulePath = (Get-InstalledModule -Name VMware.CloudFoundation.InstanceRecovery).InstalledLocation
    $sourceFile = "$modulePath\reference-files\$($truncatedSddcManagerVersion)x-workflowspec-ems.json"

    LogMessage -type INFO -message "[$jumpboxName] Establishing Connection to $cloudBuilderFQDN"
    $SecurePassword = ConvertTo-SecureString -String $cloudBuilderAdminUserPassword -AsPlainText -Force
    $mycreds = New-Object System.Management.Automation.PSCredential ('admin', $SecurePassword)
    $inmem = New-SSHMemoryKnownHost
    New-SSHTrustedHost -KnownHostStore $inmem -HostName $cloudBuilderFQDN -FingerPrint ((Get-SSHHostKey -ComputerName $cloudBuilderFQDN).fingerprint) | Out-Null
    Do {
        $sshSession = New-SSHSession -computername $cloudBuilderFQDN -Credential $mycreds -KnownHost $inmem
    } Until ($sshSession)
    LogMessage -type INFO -message "[$jumpboxName] Backing up Standard BringUp Workflow"
    $stream = New-SSHShellStream -SSHSession $sshSession
    $stream.writeline("su -")
    Start-Sleep 2
    $stream.writeline("$cloudBuilderRootUserPassword")
    Start-Sleep 2
    $stream.writeline("cd /opt/vmware/bringup/webapps/bringup-app/conf/workflowconfig/")
    Start-Sleep 2
    $stream.writeline("cp workflowspec-ems.json workflowspec-ems.json.backup")
    Start-Sleep 2
    $stream.writeline("rm workflowspec-ems.json")
    Start-Sleep 2
    LogMessage -type INFO -message "[$jumpboxName] Modifying BringUp Workflow"
    $uploadFile = Set-SCPItem -ComputerName $cloudBuilderFQDN -Credential $mycreds -path $sourceFile -destination "/tmp" -KnownHost $inmem
    $stream.writeline("cp /tmp/$($truncatedSddcManagerVersion)x-workflowspec-ems.json /opt/vmware/bringup/webapps/bringup-app/conf/workflowconfig/workflowspec-ems.json")
    Start-Sleep 2
    $stream.writeline("chown vcf_bringup:vcf workflowspec-ems.json")
    Start-Sleep 2
    $stream.writeline("chmod 740 workflowspec-ems.json")
    Start-Sleep 2

    #Close SSH Session
    Remove-SSHSession -SSHSession $sshSession | Out-Null

    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
}
Export-ModuleMember -Function New-PrepareforPartialBringup

Function New-ReconstructedPartialBringupJsonSpec {
    <#
    .SYNOPSIS
    Reconstructs a management domain bringup JSON spec based on information scraped from the backup being restored from

    .DESCRIPTION
    The New-ReconstructedPartialBringupJsonSpec cmdlet Reconstructs a management domain bringup JSON spec based on information scraped from the backup being restored from

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
        [Parameter (Mandatory = $true)][String] $vcenterServerSize
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $domainName = ($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).domainName

    $esxiLicenseKeys = @(($extractedSddcData.licenseKeys | Where-Object { $_.productType -eq "ESXI" }).key)
    If ($esxiLicenseKeys.count -gt 1) {
        $esxiLicensesDisplayObject = @()
        $esxiLicensesIndex = 1
        $esxiLicensesDisplayObject += [pscustomobject]@{
            'ID'      = "ID"
            'License' = "License Key"
        }
        $esxiLicensesDisplayObject += [pscustomobject]@{
            'ID'      = "--"
            'License' = "------------------"
        }
        Foreach ($esxiLicense in $esxiLicenseKeys) {
            $esxiLicensesDisplayObject += [pscustomobject]@{
                'ID'      = $esxiLicensesIndex
                'License' = $esxiLicense
            }
            $esxiLicensesIndex++
        }
        Write-Host ""; $esxiLicensesDisplayObject | format-table -Property @{Expression = " " }, id, License -autosize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r", "`n") }
        Do {
            Write-Host ""; Write-Host " Multiple ESXi License Keys were discovered. Enter the ID of the ESXi License you wish to use to deploy, or C to Cancel: " -ForegroundColor Yellow -nonewline
            $esxiLicenseSelection = Read-Host
        } Until (($esxiLicenseSelection -in $esxiLicensesDisplayObject.ID) -OR ($esxiLicenseSelection -eq "c"))
        If ($esxiLicenseSelection -eq "c") { Break }
        $esxiLicenseToUse = ($esxiLicensesDisplayObject | Where-Object { $_.id -eq $esxiLicenseSelection }).license
    } else {
        $esxiLicenseToUse = $esxiLicenseKeys[0]
    }

    #Derive Primary Cluster
    $primaryCluster = ($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' }

    #Get managementNetworkSubnet
    [IPAddress] $ip = ((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' }).hosts[0].networks | Where-Object { $_.type -eq 'MANAGEMENT' }).mask
    $octets = $ip.IPAddressToString.Split('.')
    Foreach ($octet in $octets) { while (0 -ne $octet) { $octet = ($octet -shl 1) -band [byte]::MaxValue; $managementNetworkCidr++; } }
    $managementNetworkSubnet = (((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' }).hosts[0].networks | Where-Object { $_.type -eq 'MANAGEMENT' }).subnet + "/" + $managementNetworkCidr)

    #hostSpecs
    $mgmtHosts = ($extractedSddcData.passwords | where-object { ($_.domainName -eq $domainName) -and ($_.entityType -eq "ESXI") -and ($_.username -eq "root") -and (Test-MemberOfSubnet -IPAddress $_.entityIpAddress -Subnet $managementNetworkSubnet) }) | Sort-Object -Property entityName
    $hostSpecs = @()
    Foreach ($mgmtHost in $mgmtHosts) {
        $credentialObject = New-Object -type psobject
        $credentialObject | Add-Member -notepropertyname 'username' -notepropertyvalue $mgmtHost.username
        $credentialObject | Add-Member -notepropertyname 'password' -notepropertyvalue $mgmtHost.password
        $ipAddressPrivateObject = New-Object -type psobject
        $ipAddressPrivateObject | Add-Member -notepropertyname 'subnet' -notepropertyvalue ((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' }).hosts[0].networks | Where-Object { $_.type -eq 'MANAGEMENT' }).mask
        $ipAddressPrivateObject | Add-Member -notepropertyname 'ipAddress' -notepropertyvalue $mgmtHost.entityIpAddress
        $ipAddressPrivateObject | Add-Member -notepropertyname 'gateway' -notepropertyvalue ((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' }).hosts[0].networks | Where-Object { $_.type -eq 'MANAGEMENT' }).gateway

        $hostSpecs += [PSCustomObject]@{
            'hostname'         = $mgmtHost.entityName.split(".")[0]
            'vSwitch'          = "vSwitch0"
            'association'      = $extractedSddcData.mgmtDomainInfrastructure.datacenter
            'credentials'      = $credentialObject
            'ipAddressPrivate' = $ipAddressPrivateObject
        }
    }

    LogMessage -type INFO -message "[$jumpboxName] Connecting to Reference host $($mgmtHosts[0].entityName) as reference for Physical NICs"
    $hostConnection = Connect-ViServer $($mgmtHosts[0].entityName) -user $hostSpecs[0].credentials.username -password $hostSpecs[0].credentials.password
    $nics = (Get-EsxCli -VMHost $($mgmtHosts[0].entityName)).network.nic.list() | Select-Object Name, Driver, LinkStatus, Description

    $nicsDisplayObject = @()
    $nicsIndex = 1
    $nicsDisplayObject += [pscustomobject]@{
        'ID'          = "ID"
        'deviceName'  = "Device Name"
        'driver'      = "Driver"
        'linkStatus'  = "Link Status"
        'description' = "Description"
    }
    $nicsDisplayObject += [pscustomobject]@{
        'ID'          = "--"
        'deviceName'  = "-----------"
        'driver'      = "----------"
        'linkStatus'  = "-----------"
        'description' = "-----------------------------------------------"
    }
    Foreach ($nic in $nics) {
        $nicsDisplayObject += [pscustomobject]@{
            'ID'          = $nicsIndex
            'deviceName'  = $nic.name
            'driver'      = $nic.driver
            'linkStatus'  = $nic.linkStatus
            'description' = $nic.description
        }
        $nicsIndex++
    }
    Write-Host ""; Write-Host " Recreating Virtual Distributed Switches as per previous deployment" -ForegroundColor Yellow
    $vdsConfiguration = @()
    $remainingNicsDisplayObject = $nicsDisplayObject

    #Loop Through VDS Creation
    For ($i = 1; $i -le $primaryCluster.vdsDetails.count; $i++) {
        $vdsConfigurationIndex = ($i - 1)
        Do {
            $nicNamesArray = @()
            Write-Host ""; $remainingNicsDisplayObject | format-table -Property @{Expression = " " }, id, deviceName, driver, linkStatus, description -autosize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r", "`n") }
            If ($primaryCluster.vdsDetails[$vdsConfigurationIndex].transportZones) {
                $networksDisplay = ($primaryCluster.vdsDetails[$vdsConfigurationIndex].networks += "OVERLAY") -join (",")
            } else {
                $networksDisplay = $primaryCluster.vdsDetails[$vdsConfigurationIndex].networks -join (",")
            }
            Write-Host ""; Write-Host " Recreating " -ForegroundColor Yellow -nonewline; Write-Host "$($primaryCluster.vdsDetails[$vdsConfigurationIndex].dvsName)" -ForegroundColor cyan -nonewline; Write-Host " which contained the networks: " -ForegroundColor Yellow -nonewline; Write-Host "$networksDisplay" -ForegroundColor Cyan
            Write-Host " Enter a comma seperated list of IDs to use as vmnics for this VDS, or C to Cancel: " -ForegroundColor Yellow -nonewline
            $nicSelection = Read-Host
            If ($nicSelection -ne "C") {
                $nicSelectionInvalid = $false
                $nicArray = $nicSelection -split (",")
                Foreach ($nic in $nicArray) {
                    $nicNamesArray += ($nicsDisplayObject | Where-Object { $_.id -eq $nic }).deviceName
                    If ($nic -notin $nicsDisplayObject.id) {
                        $nicSelectionInvalid = $true
                    }
                }
            }
        } Until (($nicSelectionInvalid -eq $false) -OR ($nicSelection -eq "c"))
        If ($nicSelection -eq "c") { Break }
        $individualVds = [PSCustomObject]@{
            'vdsName'     = $primaryCluster.vdsDetails[$vdsConfigurationIndex].dvsName
            'nicnames'    = $nicNamesArray
            'vdsNetworks' = $primaryCluster.vdsDetails[$vdsConfigurationIndex].networks
            'portgroups'  = $primaryCluster.vdsDetails[$vdsConfigurationIndex].portgroups
        }
        $vdsConfiguration += $individualVds
        $tempremainingNicsDisplayObject = @()
        Foreach ( $displaynic in $remainingNicsDisplayObject) {
            If ($displaynic.id -notin $nicArray) {
                $tempremainingNicsDisplayObject += $displaynic
            }
        }
        $remainingNicsDisplayObject = $tempremainingNicsDisplayObject
    }
    If (($nicSelection -eq "c") -or ($nicSelection -eq "c")) { Break }

    $proposedConfigDisplayObject = @()
    $configIndex = 1
    $proposedConfigDisplayObject += [pscustomobject]@{
        'vdsName'     = "VDS Name"
        'nicnames'    = "NIC Names"
        'vdsNetworks' = "VDS Networks"
    }
    $proposedConfigDisplayObject += [pscustomobject]@{
        'vdsName'     = "----------------------------------------"
        'nicnames'    = "---------------"
        'vdsNetworks' = "------------------------------"
    }
    Foreach ($config in $vdsConfiguration) {
        $proposedConfigDisplayObject += [pscustomobject]@{
            'vdsName'     = $config.vdsName
            'nicnames'    = $config.nicnames -join (", ")
            'vdsNetworks' = $config.vdsNetworks -join (", ")
        }
        $configIndex++
    }
    Write-Host ""; Write-Host " Proposed VDS Configuration " -ForegroundColor Yellow
    Write-Host ""; $proposedConfigDisplayObject | format-table -Property @{Expression = " " }, vdsName, nicnames, vdsNetworks, -autosize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r", "`n") }
    Write-Host ""; Write-Host " Do you wish to proceed with the proposed configuration? (Y/N): " -ForegroundColor Yellow -nonewline
    $proposedConfigAccepted = Read-Host
    $proposedConfigAccepted = $proposedConfigAccepted -replace "`t|`n|`r", ""

    If ($proposedConfigAccepted -ieq "Y") {
        #Update Objects in Memory with chosen nics
        Foreach ($vds in $primaryCluster.vdsDetails) {
            $nicsToUse = ($proposedConfigDisplayObject | Where-Object { $_.vdsName -eq $vds.dvsName }).nicnames
            $vds.vmnics = @($nicsToUse -split (", "))
        }

        $mgmtDomainObject = New-Object -type psobject
        $mgmtDomainObject | Add-Member -notepropertyname 'taskName' -notepropertyvalue "workflowconfig/workflowspec-ems.json"
        $mgmtDomainObject | Add-Member -notepropertyname 'sddcId' -notepropertyvalue ($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).domainName
        $mgmtDomainObject | Add-Member -notepropertyname 'ceipEnabled' -notepropertyvalue "$($extractedSddcData.sddcManager.ceip_enabled)"
        $mgmtDomainObject | Add-Member -notepropertyname 'fipsEnabled' -notepropertyvalue "$($extractedSddcData.sddcManager.fips_enabled)"
        $mgmtDomainObject | Add-Member -notepropertyname 'managementPoolName' -notepropertyvalue ($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).networkPool
        $mgmtDomainObject | Add-Member -notepropertyname 'skipEsxThumbprintValidation' -notepropertyvalue $true # Review
        $mgmtDomainObject | Add-Member -notepropertyname 'esxLicense' -notepropertyvalue $esxiLicenseToUse
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
            'startIpAddress' = ((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' }).hosts[0].networks | Where-Object { $_.type -eq 'VMOTION' }).startIPAddress
            'endIpAddress'   = ((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' }).hosts[0].networks | Where-Object { $_.type -eq 'VMOTION' }).endIpAddress
        }
        $vsanIpObject = @()
        $vsanIpObject += [pscustomobject]@{
            'startIpAddress' = ((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' }).hosts[0].networks | Where-Object { $_.type -eq 'VSAN' }).startIPAddress
            'endIpAddress'   = ((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' }).hosts[0].networks | Where-Object { $_.type -eq 'VSAN' }).endIpAddress
        }

        $networkSpecsObject = @()

        #Conditional VM_MANAGEMENT network
        If ((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' }).vdsDetails.portgroups | Where-Object { $_.transportType -eq 'VM_MANAGEMENT' }) {
            [IPAddress] $ip = $extractedSddcData.mgmtDomainInfrastructure.netmask
            $octets = $ip.IPAddressToString.Split('.')
            Foreach ($octet in $octets) { while (0 -ne $octet) { $octet = ($octet -shl 1) -band [byte]::MaxValue; $managementVmNetworkCidr++; } }
            $managementVmNetworkSubnet = ($extractedSddcData.mgmtDomainInfrastructure.subnet + "/" + $managementVmNetworkCidr)
            $networkSpecsObject += [pscustomobject]@{
                'networkType'  = "VM_MANAGEMENT"
                'subnet'       = $managementVmNetworkSubnet
                'vlanId'       = ((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' }).vdsDetails.portgroups | Where-Object { $_.transportType -eq 'VM_MANAGEMENT' }).vlanId -as [string]
                'mtu'          = "1500"
                'gateway'      = $extractedSddcData.mgmtDomainInfrastructure.gateway
                'portGroupKey' = ((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' }).vdsDetails.portgroups | Where-Object { ($_.transportType -eq 'VM_MANAGEMENT') -and ($_.name -notlike "az2*") }).name
            }
        }

        #MANAGEMENT network
        #managementNetworkSubnet worked out earlier
        $networkSpecsObject += [pscustomobject]@{
            'networkType'  = "MANAGEMENT"
            'subnet'       = $managementNetworkSubnet
            'vlanId'       = ((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' }).vdsDetails.portgroups | Where-Object { $_.transportType -eq 'MANAGEMENT' }).vlanId -as [string]
            'mtu'          = ((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' }).hosts[0].networks | Where-Object { $_.type -eq 'MANAGEMENT' }).mtu -as [string]
            'gateway'      = ((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' }).hosts[0].networks | Where-Object { $_.type -eq 'MANAGEMENT' }).gateway
            'portGroupKey' = ((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' }).vdsDetails.portgroups | Where-Object { ($_.transportType -eq 'MANAGEMENT') -and ($_.name -notlike "az2*") }).name
        }

        #VMOTION network
        [IPAddress] $ip = ((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' }).hosts[0].networks | Where-Object { $_.type -eq 'VMOTION' }).subnetMask
        $octets = $ip.IPAddressToString.Split('.')
        Foreach ($octet in $octets) { while (0 -ne $octet) { $octet = ($octet -shl 1) -band [byte]::MaxValue; $vmotionNetworkCidr++; } }
        $vmotionNetworkSubnet = (((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' }).hosts[0].networks | Where-Object { $_.type -eq 'VMOTION' }).subnet + "/" + $vmotionNetworkCidr)
        $networkSpecsObject += [pscustomobject]@{
            'networkType'            = "VMOTION"
            'subnet'                 = $vmotionNetworkSubnet
            'includeIpAddressRanges' = $vmotionIpObject
            'vlanId'                 = ((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' }).hosts[0].networks | Where-Object { $_.type -eq 'VMOTION' }).vlanId -as [string]
            'mtu'                    = ((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' }).hosts[0].networks | Where-Object { $_.type -eq 'VMOTION' }).mtu -as [string]
            'gateway'                = ((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' }).hosts[0].networks | Where-Object { $_.type -eq 'VMOTION' }).gateway
            'portGroupKey'           = ((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' }).vdsDetails.portgroups | Where-Object { ($_.transportType -eq 'VMOTION') -and ($_.name -notlike "az2*") }).name
        }

        #VSAN network
        [IPAddress] $ip = ((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' }).hosts[0].networks | Where-Object { $_.type -eq 'VSAN' }).subnetMask
        $octets = $ip.IPAddressToString.Split('.')
        Foreach ($octet in $octets) { while (0 -ne $octet) { $octet = ($octet -shl 1) -band [byte]::MaxValue; $vsanNetworkCidr++; } }
        $vsanNetworkSubnet = (((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' }).hosts[0].networks | Where-Object { $_.type -eq 'VSAN' }).subnet + "/" + $vmotionNetworkCidr)
        $networkSpecsObject += [pscustomobject]@{
            'networkType'            = "VSAN"
            'subnet'                 = $vsanNetworkSubnet
            'includeIpAddressRanges' = $vsanIpObject
            'vlanId'                 = ((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' }).hosts[0].networks | Where-Object { $_.type -eq 'VSAN' }).vlanId -as [string]
            'mtu'                    = ((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' }).hosts[0].networks | Where-Object { $_.type -eq 'VSAN' }).mtu -as [string]
            'gateway'                = ((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' }).hosts[0].networks | Where-Object { $_.type -eq 'VSAN' }).gateway
            'portGroupKey'           = ((($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).vsphereClusterDetails | Where-Object { $_.isDefault -eq 't' }).vdsDetails.portgroups | Where-Object { ($_.transportType -eq 'VSAN') -and ($_.name -notlike "az2*") }).name
        }
        $mgmtDomainObject | Add-Member -notepropertyname 'networkSpecs' -notepropertyvalue $networkSpecsObject

        $nsxLicenseKeys = @(($extractedSddcData.licenseKeys | Where-Object { $_.productType -eq "NSXT" }).key)
        If ($nsxLicenseKeys.count -gt 1) {
            $nsxLicensesDisplayObject = @()
            $nsxLicensesIndex = 1
            $nsxLicensesDisplayObject += [pscustomobject]@{
                'ID'      = "ID"
                'License' = "License Key"
            }
            $nsxLicensesDisplayObject += [pscustomobject]@{
                'ID'      = "--"
                'License' = "------------------"
            }
            Foreach ($nsxLicense in $nsxLicenseKeys) {
                $nsxLicensesDisplayObject += [pscustomobject]@{
                    'ID'      = $nsxLicensesIndex
                    'License' = $nsxLicense
                }
                $nsxLicensesIndex++
            }
            Write-Host ""; $nsxLicensesDisplayObject | format-table -Property @{Expression = " " }, id, License -autosize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r", "`n") }
            Do {
                Write-Host ""; Write-Host " Multiple NSX License Keys were discovered. Enter the ID of the NSX License you wish to use to deploy, or C to Cancel: " -ForegroundColor Yellow -nonewline
                $nsxLicenseSelection = Read-Host
            } Until (($nsxLicenseSelection -in $nsxLicensesDisplayObject.ID) -OR ($nsxLicenseSelection -eq "c"))
            If ($nsxLicenseSelection -eq "c") { Break }
            $nsxLicenseToUse = ($nsxLicensesDisplayObject | Where-Object { $_.id -eq $nsxLicenseSelection }).license
        } else {
            $nsxLicenseToUse = $nsxLicenseKeys[0]
        }

        #nsxtSpec
        $nsxtManagersObject = @()
        Foreach ($nsxManager in (($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).nsxNodeDetails)) {
            $nsxtManagersObject += [pscustomobject]@{
                'hostname' = $nsxManager.vmName
                'ip'       = $nsxManager.ip
            }
        }
        $nsxtSpecObject = New-Object -type psobject
        $nsxtSpecObject | Add-Member -notepropertyname 'nsxtManagerSize' -notepropertyvalue "medium" #Review
        $nsxtSpecObject | Add-Member -notepropertyname 'nsxtManagers' -notepropertyvalue $nsxtManagersObject
        $nsxtSpecObject | Add-Member -notepropertyname 'rootNsxtManagerPassword' -notepropertyvalue ($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).nsxClusterDetails.rootNsxtManagerPassword
        $nsxtSpecObject | Add-Member -notepropertyname 'nsxtAdminPassword' -notepropertyvalue ($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).nsxClusterDetails.nsxtAdminPassword
        $nsxtSpecObject | Add-Member -notepropertyname 'nsxtAuditPassword' -notepropertyvalue ($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).nsxClusterDetails.nsxtAuditPassword
        $nsxtSpecObject | Add-Member -notepropertyname 'rootLoginEnabledForNsxtManager' -notepropertyvalue "true" #Review
        $nsxtSpecObject | Add-Member -notepropertyname 'sshEnabledForNsxtManager' -notepropertyvalue "true" #Review
        $nsxtSpecObject | Add-Member -notepropertyname 'vip' -notepropertyvalue ($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).nsxClusterDetails.clusterVip
        $nsxtSpecObject | Add-Member -notepropertyname 'vipFqdn' -notepropertyvalue ($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).nsxClusterDetails.clusterFqdn
        $nsxtSpecObject | Add-Member -notepropertyname 'nsxtLicense' -notepropertyvalue $nsxLicenseToUse
        $nsxtSpecObject | Add-Member -notepropertyname 'transportVlanId' -notepropertyvalue $transportVlanId
        $mgmtDomainObject | Add-Member -notepropertyname 'nsxtSpec' -notepropertyvalue $nsxtSpecObject

        $vsanLicenseKeys = @(($extractedSddcData.licenseKeys | Where-Object { $_.productType -eq "VSAN" }).key)
        If ($vsanLicenseKeys.count -gt 1) {
            $vsanLicensesDisplayObject = @()
            $vsanLicensesIndex = 1
            $vsanLicensesDisplayObject += [pscustomobject]@{
                'ID'      = "ID"
                'License' = "License Key"
            }
            $vsanLicensesDisplayObject += [pscustomobject]@{
                'ID'      = "--"
                'License' = "------------------"
            }
            Foreach ($vsanLicense in $vsanLicenseKeys) {
                $vsanLicensesDisplayObject += [pscustomobject]@{
                    'ID'      = $vsanLicensesIndex
                    'License' = $vsanLicense
                }
                $vsanLicensesIndex++
            }
            Write-Host ""; $vsanLicensesDisplayObject | format-table -Property @{Expression = " " }, id, License -autosize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r", "`n") }
            Do {
                Write-Host ""; Write-Host " Multiple vSAN License Keys were discovered. Enter the ID of the vSAN License you wish to use to deploy, or C to Cancel: " -ForegroundColor Yellow -nonewline
                $vsanLicenseSelection = Read-Host
            } Until (($vsanLicenseSelection -in $vsanLicensesDisplayObject.ID) -OR ($vsanLicenseSelection -eq "c"))
            If ($vsanLicenseSelection -eq "c") { Break }
            $vsanLicenseToUse = ($vsanLicensesDisplayObject | Where-Object { $_.id -eq $vsanLicenseSelection }).license
        } else {
            $vsanLicenseToUse = $vsanLicenseKeys[0]
        }

        #vsanSpec
        $vsanSpecObject = New-Object -type psobject
        $vsanSpecObject | Add-Member -notepropertyname 'vsanName' -notepropertyvalue "vsan-1"
        $vsanSpecObject | Add-Member -notepropertyname 'licenseFile' -notepropertyvalue $vsanLicenseToUse
        $vsanSpecObject | Add-Member -notepropertyname 'vsanDedup' -notepropertyvalue $dedupEnabled
        $vsanSpecObject | Add-Member -notepropertyname 'datastoreName' -notepropertyvalue $primaryCluster.primaryDatastoreName
        $mgmtDomainObject | Add-Member -notepropertyname 'vsanSpec' -notepropertyvalue $vsanSpecObject

        #dvsSpecs
        $clusterVDSs = @()
        #$vds = ($primaryCluster.vdsDetails)[0]
        Foreach ($vds in ($primaryCluster.vdsDetails)) {
            $clustervdsObject = New-Object -type psobject
            $clustervdsObject | Add-Member -notepropertyname 'mtu' -notepropertyvalue $vds.mtu
            #$clustervdsObject | Add-Member -notepropertyname 'niocSpecs' -notepropertyvalue $vds.niocSpecs
            $clustervdsObject | Add-Member -notepropertyname 'dvsName' -notepropertyvalue $vds.dvsName
            $clustervdsObject | Add-Member -notepropertyname 'vmnics' -notepropertyvalue $vds.vmnics
            $clustervdsObject | Add-Member -notepropertyname 'networks' -notepropertyvalue @($vds.networks | Where-Object { $_ -ne "OVERLAY" })
            If ($vds.transportZones) {
                $transportZoneContent = @()
                Foreach ($transportZone in $vds.transportZones) {
                    $transportZoneContent += [PSCustomObject]@{
                        'name'          = $transportZone.name
                        'transportType' = $transportZone.transportType
                    }
                }
                $nsxtSwitchConfigObject = New-Object -type psobject
                $nsxtSwitchConfigObject | Add-Member -notepropertyname 'hostSwitchOperationalMode' -notepropertyvalue $vds.hostSwitchOperationalMode
                $nsxtSwitchConfigObject | Add-Member -notepropertyname 'transportZones' -notepropertyvalue @($transportZoneContent)
                $clustervdsObject | Add-Member -notepropertyname 'nsxtSwitchConfig' -notepropertyvalue $nsxtSwitchConfigObject
            }
            $clusterVDSs += $clustervdsObject
        }
        $mgmtDomainObject | Add-Member -notepropertyname 'dvsSpecs' -notepropertyvalue $clusterVDSs

        #clusterSpec
        $vmFoldersObject = New-Object -type psobject
        $vmFoldersObject | Add-Member -notepropertyname 'MANAGEMENT' -notepropertyvalue (($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).domainName + "-fd-mgmt")
        $vmFoldersObject | Add-Member -notepropertyname 'NETWORKING' -notepropertyvalue (($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).domainName + "-fd-nsx")
        $vmFoldersObject | Add-Member -notepropertyname 'EDGENODES' -notepropertyvalue (($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).domainName + "-fd-edge")
        $clusterSpecObject = New-Object -type psobject
        $clusterSpecObject | Add-Member -notepropertyname 'vmFolders' -notepropertyvalue $vmFoldersObject
        $clusterSpecObject | Add-Member -notepropertyname 'clusterName' -notepropertyvalue $primaryCluster.name
        $clusterSpecObject | Add-Member -notepropertyname 'clusterEvcMode' -notepropertyvalue ""
        If ($primaryCluster.isImageBased -eq "t") {
            $clusterSpecObject | Add-Member -notepropertyname 'clusterImageEnabled' -notepropertyvalue "true"
        }
        $mgmtDomainObject | Add-Member -notepropertyname 'clusterSpec' -notepropertyvalue $clusterSpecObject

        #pscSpecs
        $pscSpecs = @()
        $ssoDomain = ($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).ssoDomain
        $psoSsoSpecObject = New-Object -type psobject
        $psoSsoSpecObject | Add-Member -notepropertyname 'ssoDomain' -notepropertyvalue $ssoDomain
        $pscSpecs += [PSCustomObject]@{
            'pscSsoSpec'           = $psoSsoSpecObject
            'adminUserSsoPassword' = ($extractedSddcData.passwords | Where-Object { ($_.credentialType -eq "SSO") -and ($_.username -like "*$ssoDomain") -and ($_.entityType -eq "PSC") }).password
        }
        $mgmtDomainObject | Add-Member -notepropertyname 'pscSpecs' -notepropertyvalue $pscSpecs

        $vCenterLicenseKeys = @(($extractedSddcData.licenseKeys | Where-Object { $_.productType -eq "vCenter" }).key)
        If ($vCenterLicenseKeys.count -gt 1) {
            $vCenterLicensesDisplayObject = @()
            $vCenterLicensesIndex = 1
            $vCenterLicensesDisplayObject += [pscustomobject]@{
                'ID'      = "ID"
                'License' = "License Key"
            }
            $vCenterLicensesDisplayObject += [pscustomobject]@{
                'ID'      = "--"
                'License' = "------------------"
            }
            Foreach ($vCenterLicense in $vCenterLicenseKeys) {
                $vCenterLicensesDisplayObject += [pscustomobject]@{
                    'ID'      = $vCenterLicensesIndex
                    'License' = $vCenterLicense
                }
                $vCenterLicensesIndex++
            }
            Write-Host ""; $vCenterLicensesDisplayObject | format-table -Property @{Expression = " " }, id, License -autosize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r", "`n") }
            Do {
                Write-Host ""; Write-Host " Multiple vCenter License Keys were discovered. Enter the ID of the vCenter License you wish to use to deploy, or C to Cancel: " -ForegroundColor Yellow -nonewline
                $vCenterLicenseSelection = Read-Host
            } Until (($vCenterLicenseSelection -in $vCenterLicensesDisplayObject.ID) -OR ($vCenterLicenseSelection -eq "c"))
            If ($vCenterLicenseSelection -eq "c") { Break }
            $vCenterLicenseToUse = ($vCenterLicensesDisplayObject | Where-Object { $_.id -eq $vCenterLicenseSelection }).license
        } else {
            $vCenterLicenseToUse = $vCenterLicenseKeys[0]
        }

        #vcenterSpec
        $vcenterSpecObject = New-Object -type psobject
        $vcenterSpecObject | Add-Member -notepropertyname 'vcenterIp' -notepropertyvalue $tempVcenterIp
        $vcenterSpecObject | Add-Member -notepropertyname 'vcenterHostname' -notepropertyvalue $tempVcenterHostname
        $vcenterSpecObject | Add-Member -notepropertyname 'licenseFile' -notepropertyvalue $vCenterLicenseToUse
        $vcenterSpecObject | Add-Member -notepropertyname 'rootVcenterPassword' -notepropertyvalue ($extractedSddcData.passwords | Where-Object { ($_.domainName -eq $domainName) -and ($_.entityType -eq "VCENTER") -and ($_.username -eq "root") }).password
        $vcenterSpecObject | Add-Member -notepropertyname 'vmSize' -notepropertyvalue $vcenterServerSize
        $mgmtDomainObject | Add-Member -notepropertyname 'vcenterSpec' -notepropertyvalue $vcenterSpecObject
        $mgmtDomainObject | Add-Member -notepropertyname 'hostSpecs' -notepropertyvalue $hostSpecs

        $licenseMode = ($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).licenseModel
        If ($licenseMode -eq "PERPETUAL") { $subscriptionLicensing = "False" } else { $subscriptionLicensing = "True" }
        $mgmtDomainObject | Add-Member -notepropertyname 'subscriptionLicensing' -notepropertyvalue $subscriptionLicensing

        LogMessage -type INFO -message "[$jumpboxName] Saving partial bringup JSON spec: $(($extractedSddcData.workloadDomains | Where-Object {$_.domainType -eq "MANAGEMENT"}).domainName + "-partial-bringup-spec.json")"
        ConvertTo-Json $mgmtDomainObject -depth 10 | Out-File (($extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }).domainName + "-partial-bringup-spec.json")
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
    } else {
        LogMessage -type WARNING -message "[$jumpboxName] Aborted Task $($MyInvocation.MyCommand)"
    }
}
Export-ModuleMember -Function New-ReconstructedPartialBringupJsonSpec
#EndRegion Marked for Deprecation
