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
        LogMessage -type INFO -message "[$jumpboxName] VCF PowerCLI Module found"
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
    New-ExtractDataFromSDDCBackup -backupFilePath "F:\backup\vcf-backup-sfo-vcf01-sfo-rainpole-io-2023-09-19-10-53-02.tar.gz" -encryptionPassword "VMw@re1!VMw@re1!" -credentialsFilePath "F:\backup\vcf-credentials-sfo-m01-20260707-150004.json"

    .PARAMETER vcfBackupFilePath
    Relative or absolute to the VMware Cloud Foundation SDDC manager backup file somewhere on the local filesystem

    .PARAMETER encryptionPassword
    The password that should be used to decrypt the VMware Cloud Foundation SDDC manager backup file ie the password that was used to encrypt it originally.

    .PARAMETER credentialsFilePath
    Relative or absolute path to a JSON file containing the credentials returned by the SDDC Manager credentials API (GET /v1/credentials). Used in place of security_password_vault.json, which is no longer included in the SDDC Manager backup.
    #>

    Param(
        [Parameter (Mandatory = $true)][String] $vcfBackupFilePath,
        [Parameter (Mandatory = $true)][String] $encryptionPassword,
        [Parameter (Mandatory = $true)][String] $credentialsFilePath
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    $backupFileFullPath = (Resolve-Path -Path $vcfBackupFilePath).path
    $credentialsFileFullPath = (Resolve-Path -Path $credentialsFilePath).path
    $backupFileName = (Get-ChildItem -path $backupFileFullPath).name
    $parentFolder = Split-Path -Path $backupFileFullPath
    $extractedBackupFolder = ($backupFileName -Split (".tar.gz"))[0]

    $filesToExtract = @(
        "$extractedBackupFolder/metadata.json"
        "$extractedBackupFolder/appliancemanager_dns_configuration.json"
        "$extractedBackupFolder/appliancemanager_ntp_configuration.json"
        "$extractedBackupFolder/database/sddc-postgres.bkp"
    )

    Push-Location
    Set-Location "$parentFolder"

    #Decrypt Backup (VCF prepends a 4-byte header before the openssl ciphertext; strip it before decrypting)
    LogMessage -type INFO -message "[$jumpboxName] Decrypting Backup"
    $strippedHeaderFile = "$parentFolder\$backupFileName.noheader"
    $inStream = [System.IO.File]::OpenRead($backupFileFullPath)
    try {
        $inStream.Seek(4, [System.IO.SeekOrigin]::Begin) | Out-Null
        $outStream = [System.IO.File]::Create($strippedHeaderFile)
        try {
            $inStream.CopyTo($outStream)
        } finally {
            $outStream.Close()
        }
    } finally {
        $inStream.Close()
    }

    $env:OPENSSL_FIPS = "1"
    try {
        $command = "openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -md sha256 -in `"$strippedHeaderFile`" -pass pass:`"$encryptionPassword`" -out `"$parentFolder\decrypted-sddc-manager-backup.tar.gz`""
        Invoke-Expression "& $command" *>$null
    } finally {
        Remove-Item Env:\OPENSSL_FIPS -ErrorAction SilentlyContinue
        Remove-Item -Path $strippedHeaderFile -Force -ErrorAction SilentlyContinue
    }

    #Extract Required Files From Backup Leveraging Windows tar.exe
    LogMessage -type INFO -message "[$jumpboxName] Extracting Backup"
    tar -xzf "$parentFolder\decrypted-sddc-manager-backup.tar.gz" $filesToExtract

    #Get Content of Credentials File (SDDC Manager credentials API output)
    LogMessage -type INFO -message "[$jumpboxName] Reading Credentials File"
    $credentialsJson = Get-Content $credentialsFileFullPath | ConvertFrom-JSON
    $passwordVaultObject = @()
    Foreach ($object in $credentialsJson) {
        $passwordVaultObject += [pscustomobject]@{
            'entityId'        = $object.resource.resourceId
            'entityName'      = $object.resource.resourceName
            'entityType'      = $object.resource.resourceType
            'credentialType'  = $object.credentialType
            'entityIpAddress' = $null
            'username'        = $object.username
            'domainName'      = $object.resource.domainName
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
        'ip'           = If (Resolve-DnsName $sddcManagerFqdn -errorAction SilentlyContinue) {(Resolve-DnsName $sddcManagerFqdn | Where-Object {$_.section -eq "Answer"}).IPAddress} else {$null}
        'fips_enabled' = $metadataJSON.fips_enabled
        'ceip_enabled' = $ceipStatus
        'version'      = $sddcManagerVersion
    }
    If ($sddcManagerObject.ip -eq $null) { LogMessage -type WARNING -message "DNS Resolution for $($sddcManagerObject.fqdn) failed, please correct and retry"}

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
            $nsxtManagerCluster = [pscustomobject]@{
                'clusterVip' = If (Resolve-DnsName $lineContent.split("`t")[5] -erroraction SilentlyContinue) {(Resolve-DnsName $lineContent.split("`t")[5] | Where-Object { $_.section -eq "Answer" }).IPAddress } else { $null}
                'clusterFqdn' = $lineContent.split("`t")[5]
                'domainIDs'   = $nodeContent.domainIds
                'nsxNodes'    = $nsxNodes
            }
            If ($nsxtManagerCluster.clusterVip -eq $null) { LogMessage -type WARNING -message "DNS Resolution for $($nsxtManagerCluster.clusterFqdn) failed, please correct and retry" }
            $nsxtManagerClusters += $nsxtManagerCluster
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
    $hostMoRefColumn = $columns.IndexOf('source_id')
    $hostVsanIpColumn = $columns.IndexOf('vsan_ip_address')

    $hostsLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.host " | Select-Object Line, LineNumber).LineNumber
    $hostsLineIndex = $hostsLineNumber
    $hosts = @()
    Do {
        $lineContent = $psqlContent | Select-Object -Index $hostsLineIndex
        If ($lineContent -ne '\.') {
            $hostId = $lineContent.split("`t")[$hostIdColumn]
            $hostName = $lineContent.split("`t")[$hostNameColumn]
            $hostMgmtIp = If (Resolve-DnsName $lineContent.split("`t")[$hostnameColumn] -errorAction SilentlyContinue) { (Resolve-DnsName $lineContent.split("`t")[$hostnameColumn] | Where-Object { $_.section -eq "Answer" }).IPAddress } else { $null }
            $hostVersion = $lineContent.split("`t")[$hostVersionColumn]
            $hostVmotionIp = $lineContent.split("`t")[$hostVmotionIpColumn]
            $hostVsanIP = $lineContent.split("`t")[$hostVsanIpColumn]
            $hostMoRef = $lineContent.split("`t")[$hostMoRefColumn]

            #Calculate Managment Subnet (Management Domain Hosts Only)
            <#  If (($gateway -ne "\N") -AND ($hostMask -ne "\N")) {

                $ip = [ipaddress]$hostMgmtIp
                $subnet = [ipaddress]$hostMask
                $netid = [ipaddress]($ip.address -band $subnet.address)
                $hostManagementSubnet = $($netid.ipaddresstostring)
            } #>

            $hostInstance = [pscustomobject]@{
                'id'        = $hostId
                'hostMoRef' = $hostMoRef
                #'gateway'   = $gateway
                'hostName'  = $hostName
                'mgmtIp'    = $hostMgmtIp
                #'mask'      = $hostMask
                #'subnet'    = $hostManagementSubnet
                'version'   = $hostVersion
                'vmotionIP' = $hostVmotionIp
                'vsanIP'    = $hostVsanIP
            }
            $hosts += $hostInstance
            If ($hostInstance.mgmtIp -eq $null) { LogMessage -type WARNING -message "DNS Resolution for $($hostInstance.hostName) failed, please correct and retry" }
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
            $vCenterIp = If (Resolve-DnsName $vCenterFqdn -errorAction silentlyContinue) { (Resolve-DnsName $vCenterFqdn | Where-Object { $_.section -eq "Answer" }).IPAddress } else { $null }
            $vCenterVMname = $lineContent.split("`t")[$vCenterVMnameColumn]
            $vCenterDomainID = ($hostsAndDomains | Where-Object { $_.hostId -eq (($hostsandVcenters | Where-Object { $_.vCenterID -eq $vCenterID })[0].hostID) }).domainID
            $vCenter = [pscustomobject]@{
                'vCenterID'       = $vCenterID
                'vCenterVersion'  = $vCenterVersion
                'vCenterFqdn'     = $vCenterFqdn
                'vCenterIp'       = $vCenterIp
                'vCenterVMname'   = $vCenterVMname
                'vCenterDomainID' = $vCenterDomainID
            }
            $vCenters += $vCenter
            If ($vCenter.vCenterIp -eq $null) { LogMessage -type WARNING -message "DNS Resolution for $($vCenter.vCenterFqdn) failed, please correct and retry" }
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
                'Name'       = $null
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
    $primaryDatastoreTypeColumn = $columns.IndexOf('primary_datastore_type')
    $primaryDatastoreSourceIDColumn = $columns.IndexOf('primary_datastore_source_id')
    $sourceIDColumn = $columns.IndexOf('source_id')
    $isImagedBasedColumn = $columns.IndexOf('is_image_based')

    $clustersLineNumber = ($psqlContent | Select-String -SimpleMatch "COPY public.cluster " | Select-Object Line, LineNumber).LineNumber
    $clustersLineIndex = $clustersLineNumber
    $clusters = @()
    Do {
        $lineContent = $psqlContent | Select-Object -Index $clustersLineIndex
        If ($lineContent -ne '\.') {
            $id = $lineContent.split("`t")[$idColumn]
            $ftt = $lineContent.split("`t")[$fttColumn]
            $isDefault = $lineContent.split("`t")[$isDefaultColumn]
            $isStretched = $lineContent.split("`t")[$isStretchedColumn]
            $vCenterID = $lineContent.split("`t")[$vCenterIDColumn]
            $primaryDatastoreType = $lineContent.split("`t")[$primaryDatastoreTypeColumn]
            $primaryDatastoreMoRef = $lineContent.split("`t")[$primaryDatastoreSourceIDColumn]
            $sourceID = $lineContent.split("`t")[$sourceIDColumn]
            $isImagedBased = $lineContent.split("`t")[$isImagedBasedColumn]
            $vdsDetails = @()

            #Experimental
            $clusterHosts = $hostAndCluster | Where-Object { $_.clusterID -eq $id }
            $hostsArray = @()
            Foreach ($clusterHost in $clusterHosts) {
                $hostname = ($hosts | Where-Object { $_.id -eq $clusterHost.hostId }).hostname
                $hostMoRef = ($hosts | Where-Object { $_.id -eq $clusterHost.hostId }).hostMoRef
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
                    'hostMoRef'      = $hostMoRef
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
                $vdsObject | Add-Member -NotePropertyName 'dvsName' -NotePropertyValue $null
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

            # Determine AZ host membership directly from the backup, with no live vCenter connection
            # required. Each host's network pool contains its VMOTION/VSAN networks (MANAGEMENT is not
            # network-pool-scoped), each tagged with a VLAN. The cluster's VDS portgroups carry the same
            # VLAN per transport type alongside a faultLevel (PRIMARY/SECONDARY for stretched clusters,
            # NONE for non-stretched). Matching a host's VMOTION network VLAN against the VDS VMOTION
            # portgroup VLAN yields that portgroup's faultLevel, which identifies the host's AZ. Verified
            # against a real stretched cluster backup: VMOTION and VSAN VLANs independently agreed, and the
            # result matched live vCenter portgroup-membership lookups exactly.
            $allPortgroups = @($vdsDetails.portgroups)
            $azHostMappingObject = New-Object -type psobject
            If ($isStretched -eq 't') {
                $az1Hosts = @()
                $az2Hosts = @()
                Foreach ($hostEntry in $hostsArray) {
                    $hostVmotionNetwork = $hostEntry.networks | Where-Object { $_.type -eq "VMOTION" } | Select-Object -First 1
                    $matchingPortgroup = $allPortgroups | Where-Object { ($_.transportType -eq "VMOTION") -and ($_.vlanId -eq $hostVmotionNetwork.vlanId) } | Select-Object -First 1
                    If ($matchingPortgroup.faultLevel -eq "PRIMARY") {
                        $az1Hosts += $hostEntry.hostname
                    } ElseIf ($matchingPortgroup.faultLevel -eq "SECONDARY") {
                        $az2Hosts += $hostEntry.hostname
                    }
                }
                $azHostMappingObject | Add-Member -NotePropertyName "az1" -NotePropertyValue (@($az1Hosts) | Sort-Object)
                $azHostMappingObject | Add-Member -NotePropertyName "az2" -NotePropertyValue (@($az2Hosts) | Sort-Object)
            } Else {
                $az1Hosts = @()
                Foreach ($hostEntry in $hostsArray) {
                    $hostVmotionNetwork = $hostEntry.networks | Where-Object { $_.type -eq "VMOTION" } | Select-Object -First 1
                    $matchingPortgroup = $allPortgroups | Where-Object { ($_.transportType -eq "VMOTION") -and ($_.vlanId -eq $hostVmotionNetwork.vlanId) } | Select-Object -First 1
                    If ($matchingPortgroup.faultLevel -eq "NONE") {
                        $az1Hosts += $hostEntry.hostname
                    }
                }
                $azHostMappingObject | Add-Member -NotePropertyName "az1" -NotePropertyValue (@($az1Hosts) | Sort-Object)
            }

            $clusters += [pscustomobject]@{
                'id'                     = $id
                'datacenter'             = $null
                'ftt'                    = $ftt
                'isDefault'              = $isDefault
                'isStretched'            = $isStretched
                'name'                   = $null
                'vCenterID'              = $vCenterID
                'primaryDatastoreName'   = $null
                'primaryDatastoreType'   = $primaryDatastoreType
                'primaryDatastoreMoRef'  = $primaryDatastoreMoRef
                'primaryDatastorePolicy' = $null
                'isImageBased'           = $isImagedBased
                'sourceID'               = $sourceID
                'vdsDetails'             = $vdsDetails
                'hosts'                  = @($hostsArray | Sort-Object -Property hostname)
                'azHostMapping'          = $azHostMappingObject
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
            $pscId = ($vCentersAndPscs | where-object { $_.vCenterId -eq $vCenter.vCenterID }).pscId
            $ssoDomain = ($pscs | where-object { $_.id -eq $pscId }).ssoDomain
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
    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
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
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON
    $sddcManagerConnection = Connect-VcfSddcManagerServer -server $sddcManagerFQDN -User $sddcManagerAdmin -Password $sddcManagerAdminPassword

    Foreach ($workloadDomain in $extractedSddcData.workloadDomains | Where-Object { $_.vcenterDetails.fqdn -eq $vCenterFQDN }) {
        $vCenterAdmin = ($extractedSddcData.passwords | Where-Object { ($_.credentialType -eq "SSO") -and ($_.entityName -eq $vCenterFQDN) -and ($_.entityType -eq "PSC") }).username
        $vCenterAdminPassword = ($extractedSddcData.passwords | Where-Object { ($_.credentialType -eq "SSO") -and ($_.entityName -eq $vCenterFQDN) -and ($_.entityType -eq "PSC") }).password
        $vCenterConnection = Connect-VIServer -server $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword

        Foreach ($cluster in $workloadDomain.vsphereClusterDetails) {
            # Resolve cluster and primary datastore names directly from vCenter using the MoRefs
            # captured from the SDDC Manager backup (cluster.source_id / cluster.primary_datastore_source_id),
            # rather than calling Invoke-VcfGetClusters against SDDC Manager.
            $clusterView = Get-View -Id "ClusterComputeResource-$($cluster.sourceID)"
            $clusterName = $clusterView.Name
            LogMessage -type INFO -message "Injecting cluster name $clusterName into $($workloadDomain.domainName)"
            $cluster.name = $clusterName
            $datastoreView = Get-View -Id "Datastore-$($cluster.primaryDatastoreMoRef)"
            $primaryDatastoreName = $datastoreView.Name
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
                    #Az1 PortGroups
                    if (($portGroup.TransportType -eq "MANAGEMENT") -AND ($portGroup.faultLevel -in "PRIMARY","NONE")) {
                        $managementPGName = ((Invoke-VcfGetVdses -ClusterId $cluster.id).PortGroups | Where-Object { ($_.TransportType -eq "MANAGEMENT") -AND ($_.id -eq $portGroup.id) }).Name
                        LogMessage -type INFO -message "Injecting portgroup name $managementPGName on $($vds.dvsName)"
                        $portGroup | Add-Member -NotePropertyName "Name" -NotePropertyValue $managementPGName -Force
                    }
                    if (($portGroup.TransportType -eq "VMOTION") -AND ($portGroup.faultLevel -in "PRIMARY","NONE")) {
                        $vMotionPGName = ((Invoke-VcfGetVdses -ClusterId $cluster.id).PortGroups | Where-Object { ($_.TransportType -eq "VMOTION") -AND ($_.id -eq $portGroup.id) }).Name
                        LogMessage -type INFO -message "Injecting portgroup name $vMotionPGName on $($vds.dvsName)"
                        $portGroup | Add-Member -NotePropertyName "Name" -NotePropertyValue $vMotionPGName -Force
                    }
                    if (($portGroup.TransportType -eq "VSAN") -AND ($portGroup.faultLevel -in "PRIMARY", "NONE")) {
                        $vSanPGName = ((Invoke-VcfGetVdses -ClusterId $cluster.id).PortGroups | Where-Object { ($_.TransportType -eq "VSAN") -AND ($_.id -eq $portGroup.id) }).Name
                        LogMessage -type INFO -message "Injecting portgroup name $vSanPGName on $($vds.dvsName)"
                        $portGroup | Add-Member -NotePropertyName "Name" -NotePropertyValue $vSanPGName -Force
                    }

                    If ($cluster.isStretched -eq 't')
                    {
                        #Az2 PortGroups
                        if (($portGroup.TransportType -eq "MANAGEMENT") -AND ($portGroup.faultLevel -eq "SECONDARY")) {
                            $managementPGName = ((Invoke-VcfGetVdses -ClusterId $cluster.id).PortGroups | Where-Object { ($_.TransportType -eq "MANAGEMENT") -AND ($_.id -eq $portGroup.id) }).Name
                            LogMessage -type INFO -message "Injecting portgroup name $managementPGName on $($vds.dvsName)"
                            $portGroup | Add-Member -NotePropertyName "Name" -NotePropertyValue $managementPGName -Force
                        }
                        if (($portGroup.TransportType -eq "VMOTION") -AND ($portGroup.faultLevel -eq "SECONDARY")) {
                            $vMotionPGName = ((Invoke-VcfGetVdses -ClusterId $cluster.id).PortGroups | Where-Object { ($_.TransportType -eq "VMOTION") -AND ($_.id -eq $portGroup.id) }).Name
                            LogMessage -type INFO -message "Injecting portgroup name $vMotionPGName on $($vds.dvsName)"
                            $portGroup | Add-Member -NotePropertyName "Name" -NotePropertyValue $vMotionPGName -Force
                        }
                        if (($portGroup.TransportType -eq "VSAN") -AND ($portGroup.faultLevel -eq "SECONDARY")) {
                            $vSanPGName = ((Invoke-VcfGetVdses -ClusterId $cluster.id).PortGroups | Where-Object { ($_.TransportType -eq "VSAN") -AND ($_.id -eq $portGroup.id) }).Name
                            LogMessage -type INFO -message "Injecting portgroup name $vSanPGName on $($vds.dvsName)"
                            $portGroup | Add-Member -NotePropertyName "Name" -NotePropertyValue $vSanPGName -Force
                        }
                    }

                }
            }

            If ($cluster.isStretched -eq 't')
            {
                #Get Witness Fqdn
                $clusterObject = Get-Cluster -Name $clusterName
                $stretchedClusterSystem = Get-VsanView -Id "VimClusterVsanVcStretchedClusterSystem-vsan-stretched-cluster-system"
                $witnessInfo = $stretchedClusterSystem.VSANVcGetWitnessHosts($clusterObject.ExtensionData.MoRef)
                $witnessFqdn = (Get-View -Id $witnessInfo.Host).Name

                #Get Witness deployment details
                $witnessHost = Get-VMHost -Name $witnessFqdn
                $witnessVmkernels = $witnessHost.ExtensionData.Config.Network.Vnic | Select-Object Device, Portgroup, @{n = "IpAddress"; e = { $_.Spec.Ip.IpAddress } }, @{n = "SubnetMask"; e = { $_.Spec.Ip.SubnetMask } }
                $witnessVersion = $witnessHost | Select-Object Version, Build

                #Record Witness Details
                $witnessObject = New-Object -type psobject
                $witnessObject | Add-Member -NotePropertyName "fqdn" -NotePropertyValue $witnessFqdn
                $witnessObject | Add-Member -NotePropertyName "addresses" -NotePropertyValue $witnessVmkernels
                $witnessObject | Add-Member -NotePropertyName "version" -NotePropertyValue $witnessVersion
                LogMessage -type INFO -message "Injecting Witness Details for $clusterName"
                $cluster | Add-Member -NotePropertyName "witness" -NotePropertyValue $witnessObject
            }
        }
        Disconnect-VIServer * -confirm:$false
    }
    LogMessage -type INFO -message "[$jumpboxName] Updating Extracted Data"
    $extractedSddcData | ConvertTo-Json -Depth 20 | Out-File $extractedSDDCDataFile
    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
}
Export-ModuleMember -Function Update-ExtractedSDDCData

Function Update-ExtractedSDDCDataWithSupervisorDetails {
    <#
    .SYNOPSIS
    Updates extracted SDDC Data JSON file with Supervisor Cluster details from a restored vCenter.

    .DESCRIPTION
    The Update-ExtractedSDDCDataWithSupervisorDetails cmdlet queries the restored vCenter for Supervisor Clusters associated with the workload domain matching the provided vCenter FQDN, determines the associated content library and its backing datastore details, and stores this data in a new 'supervisor' child property of that workload domain in the extracted SDDC data JSON file.

    .EXAMPLE
    Update-ExtractedSDDCDataWithSupervisorDetails -extractedSDDCDataFile ".\extracted-sddc-data.json" -vCenterFQDN "sfo-m01-vc01.sfo.rainpole.io"

    .PARAMETER extractedSDDCDataFile
    Relative or absolute path to the extracted-sddc-data.json file

    .PARAMETER vCenterFQDN
    FQDN of the restored vCenter to query
    #>

    Param(
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $true)][String] $vCenterFQDN
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()

    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-Json

    # Locate the workload domain for the provided vCenter FQDN
    $workloadDomain = $extractedSddcData.workloadDomains | Where-Object { $_.vcenterDetails.fqdn -eq $vCenterFQDN }
    if (-not $workloadDomain) {
        LogMessage -type ERROR -message "[$jumpboxName] Could not find a workload domain with vCenter FQDN '$vCenterFQDN' in extracted data"
        return
    }
    LogMessage -type INFO -message "[$vCenterFQDN] Processing workload domain '$($workloadDomain.domainName)'"

    # Derive credentials from extracted data using the same method as Update-ExtractedSDDCData
    $vCenterAdmin = ($extractedSddcData.passwords | Where-Object { ($_.credentialType -eq "SSO") -and ($_.entityName -eq $vCenterFQDN) -and ($_.entityType -eq "PSC") }).username
    $vCenterAdminPassword = ($extractedSddcData.passwords | Where-Object { ($_.credentialType -eq "SSO") -and ($_.entityName -eq $vCenterFQDN) -and ($_.entityType -eq "PSC") }).password

    # Connect CIS and PowerCLI for all queries
    LogMessage -type INFO -message "[$vCenterFQDN] Connecting to CIS and vCenter"
    $cisConnection = Connect-CisServer -Server $vCenterFQDN -User $vCenterAdmin -Password $vCenterAdminPassword
    $supervisorService    = Get-CisService 'com.vmware.vcenter.namespace_management.clusters'
    $contentLibraryService = Get-CisService 'com.vmware.content.library'
    $viConnection = Connect-VIServer -Server $vCenterFQDN -User $vCenterAdmin -Password $vCenterAdminPassword

    # Retrieve all enabled supervisor clusters via CIS
    LogMessage -type INFO -message "[$vCenterFQDN] Querying supervisor clusters"
    $supervisorSummaries = $supervisorService.list()

    $supervisorsArray = @()
    Foreach ($supervisorSummary in $supervisorSummaries) {
        $supervisorId   = $supervisorSummary.cluster
        $supervisorName = $supervisorSummary.cluster_name

        # Collect all vSphere clusters in this workload domain that match this supervisor by name
        $associatedClusters = $workloadDomain.vsphereClusterDetails | Where-Object { $_.name -eq $supervisorName }
        if (-not $associatedClusters) {
            continue
        }
        LogMessage -type INFO -message "[$vCenterFQDN] Found supervisor '$supervisorName'"

        # Get full supervisor detail
        $supervisor = $supervisorService.get($supervisorId)

        # Build the associated clusters array using the SDDC Manager cluster details
        $clusterArray = @()
        Foreach ($cluster in $associatedClusters) {
            $clusterEntry = New-Object -TypeName PSObject
            $clusterEntry | Add-Member -NotePropertyName 'id'       -NotePropertyValue $cluster.id
            $clusterEntry | Add-Member -NotePropertyName 'name'     -NotePropertyValue $cluster.name
            $clusterEntry | Add-Member -NotePropertyName 'moRef'    -NotePropertyValue $supervisorId
            $clusterArray += $clusterEntry
        }

        # Resolve content library and its datastore backing
        $contentLibraryId = $supervisor.default_kubernetes_service_content_library
        $contentLibraryDetail = $null
        if (-not $contentLibraryId) {
            LogMessage -type WARNING -message "[$vCenterFQDN] Supervisor '$supervisorName' has no associated content library"
        } else {
            $library = $contentLibraryService.get($contentLibraryId)
            $contentLibraryName = $library.name
            LogMessage -type INFO -message "[$vCenterFQDN] Content library: '$contentLibraryName'"

            # Resolve datastore backing — may be DATASTORE (vSphere) or OTHER (NFS)
            $datastoreBacking = $library.storage_backings | Select-Object -First 1
            $datastoreDetail = New-Object -TypeName PSObject

            if ($datastoreBacking.type -eq 'DATASTORE') {
                $datastoreMoRef = $datastoreBacking.datastore_id
                $datastore = Get-Datastore | Where-Object { $_.Id -eq $datastoreMoRef } | Select-Object -First 1
                $datastoreDetail | Add-Member -NotePropertyName 'type'       -NotePropertyValue $datastore.Type
                $datastoreDetail | Add-Member -NotePropertyName 'name'       -NotePropertyValue $datastore.Name
                $datastoreDetail | Add-Member -NotePropertyName 'moRef'      -NotePropertyValue $datastoreMoRef
                $datastoreDetail | Add-Member -NotePropertyName 'server'     -NotePropertyValue $null
                $datastoreDetail | Add-Member -NotePropertyName 'mountPoint' -NotePropertyValue $null
                LogMessage -type INFO -message "[$vCenterFQDN] Datastore backing: '$($datastore.Name)' (Type: $($datastore.Type))"
            } else {
                # OTHER type — NFS or similar, parse server and mount point from storage_url
                $storageUrl = $datastoreBacking.storage_url
                $uri = [System.Uri]$storageUrl
                $datastoreDetail | Add-Member -NotePropertyName 'type'       -NotePropertyValue $datastoreBacking.type
                $datastoreDetail | Add-Member -NotePropertyName 'name'       -NotePropertyValue $null
                $datastoreDetail | Add-Member -NotePropertyName 'moRef'      -NotePropertyValue $null
                $datastoreDetail | Add-Member -NotePropertyName 'server'     -NotePropertyValue $uri.Host
                $datastoreDetail | Add-Member -NotePropertyName 'mountPoint' -NotePropertyValue $uri.AbsolutePath
                LogMessage -type INFO -message "[$vCenterFQDN] Datastore backing: $($uri.Host)$($uri.AbsolutePath) (Type: $($datastoreBacking.type))"
            }

            $contentLibraryDetail = New-Object -TypeName PSObject
            $contentLibraryDetail | Add-Member -NotePropertyName 'id'        -NotePropertyValue $contentLibraryId
            $contentLibraryDetail | Add-Member -NotePropertyName 'name'      -NotePropertyValue $contentLibraryName
            $contentLibraryDetail | Add-Member -NotePropertyName 'datastore' -NotePropertyValue $datastoreDetail
        }

        $supervisorDetail = New-Object -TypeName PSObject
        $supervisorDetail | Add-Member -NotePropertyName 'supervisorName'    -NotePropertyValue $supervisorName
        $supervisorDetail | Add-Member -NotePropertyName 'vsphereClusters'   -NotePropertyValue $clusterArray
        $supervisorDetail | Add-Member -NotePropertyName 'contentLibrary'    -NotePropertyValue $contentLibraryDetail
        $supervisorsArray += $supervisorDetail
    }

    if ($supervisorsArray.Count -gt 0) {
        LogMessage -type INFO -message "[$vCenterFQDN] Injecting $($supervisorsArray.Count) supervisor(s) into workload domain '$($workloadDomain.domainName)'"
        $workloadDomain | Add-Member -NotePropertyName 'supervisors' -NotePropertyValue $supervisorsArray -Force
    } else {
        LogMessage -type INFO -message "[$vCenterFQDN] No supervisor clusters found for workload domain '$($workloadDomain.domainName)'"
    }

    Disconnect-CisServer -Server $cisConnection -Confirm:$false
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false

    LogMessage -type INFO -message "[$jumpboxName] Updating Extracted Data"
    $extractedSddcData | ConvertTo-Json -Depth 20 | Out-File $extractedDataFilePath

    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($StopWatch.Elapsed.Minutes) minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Update-ExtractedSDDCDataWithSupervisorDetails

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
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
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
    If ($targetType -eq 'esx') {
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
    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
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
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $workloadDomainDetails = ($extractedSDDCData.workloadDomains | Where-Object { $_.domainName -eq $workloadDomain })
    $vmDatastore = $extractedSDDCData.mgmtDomainInfrastructure.vsan_datastore
    If ($targetType -eq 'esx') {
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
    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
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
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
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
    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
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
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
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
    $vcfVersion = $extractedSddcData.sddcManager.version

    #Upload Backup
    $viConnection = Connect-VIServer -server $targetFqdn -user $targetAdmin -password $targetAdminPassword
    LogMessage -type INFO -message "[$jumpboxName] Uploading Backup File to SDDC Manager Appliance"
    $copyFile = Copy-VMGuestFile -Source $backupFileFullPath -Destination "/tmp/$backupFileName" -LocalToGuest -VM $sddcManagerVmName -GuestUser "root" -GuestPassword $rootUserPassword -Force -WarningAction SilentlyContinue -WarningVariable WarnMsg

    If (($vcfVersion -like "9.0*") -or ($vcfVersion -like "9.1.0*"))
    {
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

        #Determine new SSH Keys
        $newNistKey = '"' + (($result | Where-Object { $_ -like "*ecdsa-sha2-nistp256*" }).split("ecdsa-sha2-nistp256 "))[1] + '"'
        If ($newNistKey) { LogMessage -type INFO -message "[$sddcManagerFQDN] New ecdsa-sha2-nistp256 key for $mgmtVcenterFqdn retrieved" }
        $newRSAKey = '"' + (($result | Where-Object { $_ -like "*ssh-rsa*" }).split("ssh-rsa "))[1] + '"'
        If ($newRSAKey) { LogMessage -type INFO -message "[$sddcManagerFQDN] New ssh-rsa key for $mgmtVcenterFqdn retrieved" }

        #Close SSH Session
        Remove-SSHSession -SSHSession $sshSession | Out-Null

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
    }

    #Disconnect from vCenter
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
}
Export-ModuleMember -Function New-UploadAndModifySDDCManagerBackup

Function Get-BackupsFromSFTPServer {
    <#
    .SYNOPSIS
    Retrieves and displays VCF Fleet component backup information from a remote SFTP server.

    .DESCRIPTION
    The Get-BackupsFromSFTPServer cmdlet connects to a remote SFTP server and walks the backup folder structure
    (<sftpServerBackupPath>/<vspId>/<version>/<component>/<subId>/<version>/<dated backup>) to find backups
    for the specified component types, groups them by backup rank (rank 1 = most recent backup of each component,
    rank 2 = second most recent, and so on), and lets the user interactively select a backup group. Output includes
    component type, version, backup name, age, and path, mirroring the behaviour of Get-ServicesRuntimeComponentBackups.

    .EXAMPLE
    Get-BackupsFromSFTPServer -sftpServer "10.50.5.66" -sftpUser svc-bkup-user -sftpPassword "VMw@re1!" -sftpServerBackupPath "/media/backups/vcf/backups" -vspId "e6b2ad0a-b76f-4080-b9db-aa338bacdc64"

    .EXAMPLE
    Get-BackupsFromSFTPServer -sftpServer "10.50.5.66" -sftpUser svc-bkup-user -sftpPassword "VMw@re1!" -sftpServerBackupPath "/media/backups/vcf/backups" -vspId "e6b2ad0a-b76f-4080-b9db-aa338bacdc64" -componentNames "vcf-fleet-lcm","salt-raas"

    .PARAMETER sftpServer
    Address of the SFTP server that hosts the VCF Fleet backups

    .PARAMETER sftpUser
    Username for connection to the SFTP server that hosts the VCF Fleet backups

    .PARAMETER sftpPassword
    Password for the user (passed as the sftpUser parameter) for connection to the SFTP server that hosts the VCF Fleet backups

    .PARAMETER sftpServerBackupPath
    Path on the SFTP server under which the VCF instance backup folder (named for its instance ID) resides. If the path
    does not already end with /vcf/backups, it is appended automatically

    .PARAMETER vspId
    ID of the VCF instance (the top level folder under sftpServerBackupPath) whose backups should be searched

    .PARAMETER componentNames
    Names of the components to find backups for. Defaults to vcf-fleet-lcm, vcf-fleet-depot, salt-raas, and vidb
    #>
    Param(
        [Parameter (Mandatory = $true)][String] $sftpServer,
        [Parameter (Mandatory = $true)][String] $sftpUser,
        [Parameter (Mandatory = $true)][String] $sftpPassword,
        [Parameter (Mandatory = $true)][String] $sftpServerBackupPath,
        [Parameter (Mandatory = $true)][String] $vspId,
        [Parameter (Mandatory = $false)][String[]] $componentNames = @("vcf-fleet-lcm", "vcf-fleet-depot", "salt-raas", "vidb")
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()

    $sftpServerBackupPath = $sftpServerBackupPath.TrimEnd('/')
    If ($sftpServerBackupPath -notlike "*/vcf/backups") {
        $sftpServerBackupPath = "$sftpServerBackupPath/vcf/backups"
        LogMessage -type INFO -message "[$jumpboxName] sftpServerBackupPath did not end with /vcf/backups, using $sftpServerBackupPath"
    }

    #Establish SFTP Connection
    LogMessage -type INFO -message "[$jumpboxName] Establishing SFTP Connection to $sftpServer"
    $SecurePassword = ConvertTo-SecureString -String $sftpPassword -AsPlainText -Force
    $mycreds = New-Object System.Management.Automation.PSCredential ($sftpUser, $SecurePassword)
    Get-SSHTrustedHost | Remove-SSHTrustedHost | Out-Null
    $inmem = New-SSHMemoryKnownHost
    New-SSHTrustedHost -KnownHostStore $inmem -HostName $sftpServer -FingerPrint ((Get-SSHHostKey -ComputerName $sftpServer).fingerprint) | Out-Null
    Do {
        $sftpSession = New-SFTPSession -ComputerName $sftpServer -Credential $mycreds -KnownHost $inmem
    } Until ($sftpSession)

    # Walk the backup folder structure and parse every backup found for the requested component types
    $parsedBackups = @()
    $instancePath = "$sftpServerBackupPath/$vspId"

    Try {
        Foreach ($componentName in $componentNames) {
            LogMessage -type INFO -message "[$sftpServer] Searching for $componentName backups under $instancePath"

            $versionFolders = Get-SFTPChildItem -SessionId $sftpSession.SessionId -Path $instancePath | Where-Object { $_.IsDirectory }
            Foreach ($versionFolder in $versionFolders) {
                $componentPath = "$($versionFolder.FullName)/$componentName"
                If (!(Test-SFTPPath -SessionId $sftpSession.SessionId -Path $componentPath)) { Continue }

                $subIdFolders = Get-SFTPChildItem -SessionId $sftpSession.SessionId -Path $componentPath | Where-Object { $_.IsDirectory }
                Foreach ($subIdFolder in $subIdFolders) {
                    $version2Folders = Get-SFTPChildItem -SessionId $sftpSession.SessionId -Path $subIdFolder.FullName | Where-Object { $_.IsDirectory }
                    Foreach ($version2Folder in $version2Folders) {
                        $backupFolders = Get-SFTPChildItem -SessionId $sftpSession.SessionId -Path $version2Folder.FullName | Where-Object { $_.IsDirectory }
                        Foreach ($backupFolder in $backupFolders) {
                            $parsedBackups += [PSCustomObject]@{
                                ComponentType = $componentName
                                Version       = $version2Folder.Name
                                Name          = $backupFolder.Name
                                BackupDate    = $backupFolder.LastWriteTime
                                DaysOld       = [math]::Floor(((Get-Date) - $backupFolder.LastWriteTime).TotalDays)
                                Path          = $backupFolder.FullName
                            }
                        }
                    }
                }
            }
        }
    } Finally {
        Remove-SFTPSession -SFTPSession $sftpSession | Out-Null
    }

    if ($parsedBackups.Count -eq 0) {
        LogMessage -type WARNING -message "[$sftpServer] No backups found for components: $($componentNames -join ', ')"
        return
    }

    # Build rank-based backup groups: rank 1 = most recent backup of each component,
    # rank 2 = second most recent, and so on. Components backed up at different times
    # within the same scheduled window are still placed in the same rank group.
    $byComponent = @{}
    foreach ($b in $parsedBackups) {
        if (-not $byComponent.ContainsKey($b.ComponentType)) {
            $byComponent[$b.ComponentType] = [System.Collections.Generic.List[PSCustomObject]]::new()
        }
        $byComponent[$b.ComponentType].Add($b)
    }
    foreach ($key in @($byComponent.Keys)) {
        $byComponent[$key] = @($byComponent[$key] | Sort-Object BackupDate -Descending)
    }

    $maxRank   = ($byComponent.Values | ForEach-Object { $_.Count } | Measure-Object -Maximum).Maximum
    $groupList = [System.Collections.Generic.List[PSCustomObject]]::new()

    for ($rank = 0; $rank -lt $maxRank; $rank++) {
        $entries = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($componentType in ($byComponent.Keys | Sort-Object)) {
            if ($rank -lt $byComponent[$componentType].Count) {
                $entries.Add($byComponent[$componentType][$rank])
            }
        }
        if ($entries.Count -gt 0) {
            $groupList.Add([PSCustomObject]@{ Index = ($rank + 1); Entries = $entries })
        }
    }

    LogMessage -type INFO -message "[$sftpServer] Found $($parsedBackups.Count) backup(s) across $($groupList.Count) backup group(s)"

    # Display numbered list of backup groups
    Write-Host ""
    Write-Host " Available Backup Groups" -ForegroundColor Cyan
    Write-Host " ────────────────────────────────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host ("  {0,3}  {1,-25}  {2,-14}  {3}" -f "ID", "Newest Backup (UTC)", "Age", "Components") -ForegroundColor Gray
    Write-Host ""

    foreach ($group in $groupList) {
        $newest      = $group.Entries | Sort-Object BackupDate -Descending | Select-Object -First 1
        $ageStr      = if ($null -ne $newest.DaysOld) { "$($newest.DaysOld) days ago" } else { "unknown" }
        $uniqueTypes = @($group.Entries | Select-Object -ExpandProperty ComponentType | Sort-Object -Unique)
        Write-Host ("  {0,3}  {1,-25}  {2,-14}  {3} ({4})" -f $group.Index, $newest.Name, $ageStr, ($uniqueTypes -join ', '), $uniqueTypes.Count) -ForegroundColor White
    }

    Write-Host " ────────────────────────────────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host ""

    # User selects a backup group
    $selectedGroup = $null
    Do {
        Write-Host " Enter the ID of the backup group to use, or C to Cancel: " -ForegroundColor Yellow -NoNewline
        $selection = Read-Host
        if ($selection -in @("C", "c")) {
            LogMessage -type INFO -message "[$jumpboxName] Cancelled by user."
            $StopWatch.Stop()
            $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
            LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
            return
        }
        $selNum = 0
        if ([int]::TryParse($selection, [ref]$selNum) -and $selNum -ge 1 -and $selNum -le $groupList.Count) {
            $selectedGroup = $groupList | Where-Object { $_.Index -eq $selNum }
        } else {
            Write-Host " Invalid selection. Enter a number between 1 and $($groupList.Count), or C to Cancel." -ForegroundColor Yellow
        }
    } Until ($null -ne $selectedGroup)

    $groupLabel = ($selectedGroup.Entries | Sort-Object BackupDate -Descending | Select-Object -First 1).Name
    LogMessage -type INFO -message "[$jumpboxName] Selected backup group $($selectedGroup.Index) ($groupLabel)"

    # Show what is available in the selected backup group
    Write-Host ""
    Write-Host " Components in backup group $($selectedGroup.Index) ($groupLabel)" -ForegroundColor Cyan
    Write-Host " ────────────────────────────────────────────────────────────────────" -ForegroundColor Cyan
    $selectedGroup.Entries | Sort-Object ComponentType | ForEach-Object {
        Write-Host ("  {0,-22}  {1,-15}  {2}" -f $_.ComponentType, $_.Version, $_.Path) -ForegroundColor White
    }
    Write-Host " ────────────────────────────────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host ""

    # Offer to construct a restore JSON for the selected backup group
    Do {
        Write-Host " Would you like to construct a restore JSON for this backup group? (Y/N): " -ForegroundColor Yellow -NoNewline
        $buildJson = Read-Host
    } Until ($buildJson -in @("Y", "y", "N", "n"))

    if ($buildJson -in @("Y", "y")) {
        $sftpUriPrefix = "sftp://$sftpUser@${sftpServer}:22"
        $restoreComponents = @(
            foreach ($componentType in $componentNames) {
                $entry = $selectedGroup.Entries | Where-Object { $_.ComponentType -eq $componentType } | Select-Object -First 1
                if ($entry) { @{ path = "$sftpUriPrefix$($entry.Path)"; point = $entry.Name } }
            }
        )

        $restorePayload = @{ components = $restoreComponents } | ConvertTo-Json -Depth 5
        $outputFile     = ".\restore-payload.json"
        $restorePayload | Out-File -FilePath $outputFile -Encoding utf8
        LogMessage -type INFO -message "[$jumpboxName] Restore JSON saved to $outputFile ($($restoreComponents.Count) component(s))"
        Write-Host ""
        Write-Host " Restore JSON contents:" -ForegroundColor Cyan
        Write-Host $restorePayload
        Write-Host ""
    }

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
    Return $selectedGroup.Entries
}
Export-ModuleMember -Function Get-BackupsFromSFTPServer

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
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
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

    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
}
Export-ModuleMember -Function Invoke-SDDCManagerRestore

Function Resolve-PhysicalHostServiceAccounts {
    <#
    .SYNOPSIS
    Creates a new VCF Service Account on each ESXi host and remediates the SDDC Manager inventory

    .DESCRIPTION
    The Resolve-PhysicalHostServiceAccounts cmdlet creates a new VCF Service Account on each ESXi host and remediates the SDDC Manager inventory

    .EXAMPLE
    Resolve-PhysicalHostServiceAccounts -targetFQDN "sfo-w01-vc01.sfo.rainpole.io" -targetAdmin "administrator@vsphere.local" -targetAdminPassword "VMw@re1!" -clusterName "sfo-w01-cl01" -svcAccountPassword "VMw@re123!" -sddcManagerFQDN "sfo-vcf01.sfo.rainpole.io" -sddcManagerAdmin "administrator@vsphere.local" -sddcManagerAdminPassword "VMw@re1!"

    .PARAMETER targetFQDN
    FQDN of the vCenter instance hosting the ESXi hosts to be updated

    .PARAMETER targetAdmin
    Admin user of the vCenter instance hosting the ESXi hosts to be updated

    .PARAMETER targetAdminPassword
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
        [Parameter (Mandatory = $true)][String] $targetFQDN,
        [Parameter (Mandatory = $true)][String] $targetAdmin,
        [Parameter (Mandatory = $true)][String] $targetAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $svcAccountPassword,
        [Parameter (Mandatory = $true)][String] $sddcManagerFQDN,
        [Parameter (Mandatory = $true)][String] $sddcManagerAdmin,
        [Parameter (Mandatory = $true)][String] $sddcManagerAdminPassword
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    $vCenterConnection = Connect-VIServer -server $targetFQDN -username $targetAdmin -password $targetAdminPassword
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
    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"

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
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()

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

    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
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
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()

    LogMessage -type INFO -message "[$sddcManagerFqdn] Retrieving Original Configuration from JSON file"
    $servicesConfigBody = Get-Content -path $originalConfigurationFile -Raw

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
    Invoke-RestMethod -Uri $depotUri -Method DELETE -Headers $headers -SkipCertificateCheck *>$null

    #Set services config URI
    $servicesConfigUri = "https://$sddcManagerFqdn/v1/services-config"

    LogMessage -type INFO -message "[$sddcManagerFqdn] Reinstating Fleet Depot Configuration"
    Invoke-RestMethod -Uri $servicesConfigUri -Method PUT -Headers $headers -Body $servicesConfigBody -SkipCertificateCheck *>$null

    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
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
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()

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
        #@{ Name = 'VRA'; Var = 'automationBundleId' }
        #@{ Name = 'TELEMETRY_ACCEPTOR'; Var = 'telemetryAcceptor' }
        @{ Name = 'VSP'; Var = 'vsp' }
        #@{ Name = 'VCF_FLEET_LCM'; Var = 'fleetLcm' }
        #@{ Name = 'DEPOT_SERVICE'; Var = 'depotService' }
        #@{ Name = 'VCF_SDDC_LCM'; Var = 'sddcLcm' }
        #@{ Name = 'VCF_SALT'; Var = 'vcfSalt' }
        #@{ Name = 'VCF_SALT_RAAS'; Var = 'vcfSaltRaas' }
        #@{ Name = 'VIDB'; Var = 'vidb' }
        #@{ Name = 'VCF_SERVICE_VCD_MIGRATION_BACKEND'; Var = 'migrationServiceEngine' }
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

    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
}
Export-ModuleMember -Function Invoke-SddcManagerBundleDownload
#EndRegion SDDC Manager Functions

#Region vCenter Functions

Function Invoke-vCenterRestore {
    <#
    .SYNOPSIS
    Restores a vCenter appliance using the specified backup via REST API

    .DESCRIPTION
    The Invoke-vCenterRestore restores a vCenter appliance using the VAMI REST API instead of SSH shell streams.
    This approach provides better output capture and error handling compared to the SSH-based method.

    .EXAMPLE
    Invoke-vCenterRestore -extractedSDDCDataFile ".\extracted-sddc-data.json" -workloadDomain "sfo-m01" -vCenterBackupPath "10.50.5.63/F$/Backups/vcenter-backup/sn_sfo-m01-vc01.sfo.rainpole.io/M_9.0.0.0_20250922-105520_" -locationtype "SMB" -locationUser "Administrator" -locationPassword "VMw@re1!"

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

    .PARAMETER locationPassword
    Password for connecting to the backup location

    .PARAMETER backupPassword
    Password to decrypt an encrypted vCenter Server backup file
    #>

    Param(
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $true)][String] $workloadDomain,
        [Parameter (Mandatory = $true)][String] $vCenterBackupPath,
        [Parameter (Mandatory = $true)][ValidateSet("FTP", "FTPS", "HTTP", "HTTPS", "SFTP", "NFS", "SMB")][String] $locationtype,
        [Parameter (Mandatory = $true)][String] $locationUser,
        [Parameter (Mandatory = $true)][String] $locationPassword,
        [Parameter (Mandatory = $false)][String] $backupPassword
    )

    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()

    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $restoredVcenterFqdn = ($extractedSddcData.workloadDomains | Where-Object { $_.domainName -eq $workloadDomain }).vCenterDetails.fqdn
    $restoredvCenterRootPassword = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "VCENTER") -and ($_.domainName -eq $workloadDomain) -and ($_.credentialType -eq "SSH") }).password
    $ssoDomain = ($extractedSddcData.workloadDomains | Where-Object { $_.domainName -eq $workloadDomain }).ssoDomain
    $ssoAdminUserName = ($extractedSddcData.passwords | Where-Object { $_.entityType -eq "PSC" -and $_.username -like "*$($ssoDomain)" -and $_.domainName -eq $workloadDomain }).username
    $ssoAdminUserPassword = ($extractedSddcData.passwords | Where-Object { $_.entityType -eq "PSC" -and $_.username -like "*$($ssoDomain)" -and $_.domainName -eq $workloadDomain }).password

    # Wait for successful ping test
    LogMessage -type WAIT -message "[$restoredVcenterFqdn] Waiting for successful ping test"
    Do {
        Start-Sleep 10
        $pingTest = Test-Connection -ComputerName $restoredVcenterFqdn -count 1 -ErrorAction SilentlyContinue
    } Until ($pingTest)

    # Create authentication header for VAMI API (uses root credentials)
    $headers = VCFIRCreateHeader -username "root" -password $restoredvCenterRootPassword

    # Wait for VAMI API to become available
    LogMessage -type WAIT -message "[$restoredVcenterFqdn] Waiting for VAMI API to become available"
    $vamiAvailable = $false
    $maxAttempts = 60
    $attempt = 0
    Do {
        $attempt++
        Try {
            $uri = "https://$restoredVcenterFqdn`:5480/rest/appliance/health/system"
            $healthCheck = Invoke-WebRequest -Method GET -URI $uri -ContentType "application/json" -Headers $headers -ErrorAction Stop
            If ($healthCheck.StatusCode -eq 200) {
                $vamiAvailable = $true
                LogMessage -type INFO -message "[$restoredVcenterFqdn] VAMI API is available"
            }
        } Catch {
            If ($attempt % 6 -eq 0) {
                LogMessage -type INFO -message "[$restoredVcenterFqdn] VAMI API not yet available, continuing to wait... (attempt $attempt of $maxAttempts)"
            }
            Start-Sleep 10
        }
    } Until ($vamiAvailable -or $attempt -ge $maxAttempts)

    If (-not $vamiAvailable) {
        LogMessage -type ERROR -message "[$restoredVcenterFqdn] VAMI API did not become available after $maxAttempts attempts"
        Return
    }

    # Wait for RPM initialization to complete by monitoring /rest/vcenter/deployment
    LogMessage -type WAIT -message "[$restoredVcenterFqdn] Waiting for appliance to finish RPM initialization"
    $rpmInitComplete = $false
    $rpmAttempt = 0
    $maxRpmAttempts = 120  # 20 minutes max (120 * 10 seconds)
    $lastProgress = -1
    Do {
        $rpmAttempt++
        Try {
            $deploymentUri = "https://$restoredVcenterFqdn`:5480/rest/vcenter/deployment"
            $deploymentResponse = Invoke-WebRequest -Method GET -URI $deploymentUri -ContentType "application/json" -Headers $headers -SkipCertificateCheck -ErrorAction Stop
            $deployment = $deploymentResponse.Content | ConvertFrom-Json

            # Check if RPM install subtask exists and get its progress
            $rpmSubtask = $deployment.subtasks | Where-Object { $_.key -eq "rpminstall" }
            $currentProgress = If ($rpmSubtask) { $rpmSubtask.value.progress.completed } Else { 0 }

            # RPM initialization is complete when:
            # 1. State is no longer NOT_INITIALIZED, OR
            # 2. rpminstall subtask status is SUCCEEDED
            If ($deployment.state -ne "NOT_INITIALIZED") {
                $rpmInitComplete = $true
                LogMessage -type INFO -message "[$restoredVcenterFqdn] RPM initialization complete (state: $($deployment.state))"
            } ElseIf ($rpmSubtask -and $rpmSubtask.value.status -eq "SUCCEEDED") {
                $rpmInitComplete = $true
                LogMessage -type INFO -message "[$restoredVcenterFqdn] RPM initialization complete"
            } Else {
                # Log progress updates when percentage changes or periodically
                If ($currentProgress -ne $lastProgress) {
                    $lastProgress = $currentProgress
                    $progressMsg = If ($rpmSubtask) { $rpmSubtask.value.progress.message.default_message } Else { "Initializing..." }
                    LogMessage -type INFO -message "[$restoredVcenterFqdn] RPM initialization progress: $currentProgress% - $progressMsg"
                } ElseIf ($rpmAttempt % 12 -eq 0) {
                    LogMessage -type INFO -message "[$restoredVcenterFqdn] RPM initialization still in progress ($currentProgress%)... (attempt $rpmAttempt of $maxRpmAttempts)"
                }
            }
        } Catch {
            # API might not be ready yet - just continue waiting
            If ($rpmAttempt % 12 -eq 0) {
                LogMessage -type INFO -message "[$restoredVcenterFqdn] Waiting for deployment status... (attempt $rpmAttempt of $maxRpmAttempts)"
            }
        }

        If (-not $rpmInitComplete) {
            Start-Sleep 10
        }
    } Until ($rpmInitComplete -or $rpmAttempt -ge $maxRpmAttempts)

    If (-not $rpmInitComplete) {
        LogMessage -type ERROR -message "[$restoredVcenterFqdn] RPM initialization did not complete after $maxRpmAttempts attempts (20 minutes)"
        Return
    }

    # Build the restore request body with 'piece' wrapper (required for vSphere 9 /rest/ API)
    $restoreSpec = @{
        piece = @{
            location                = $vCenterBackupPath
            location_type           = $locationtype
            location_user           = $locationUser
            location_password       = $locationPassword
            sso_admin_user_name     = $ssoAdminUserName
            sso_admin_user_password = $ssoAdminUserPassword
            ignore_warnings         = $true
        }
    }

    If ($backupPassword) {
        $restoreSpec.piece.backup_password = $backupPassword
    }

    $body = $restoreSpec | ConvertTo-Json -Depth 5

    # Helper function to format VAMI API messages (replaces %(0)s, %(1)s placeholders with args)
    Function Format-VAMIMessage {
        Param([object]$msg)
        $formattedMsg = $msg.default_message
        If ($msg.args -and $msg.args.Count -gt 0) {
            For ($i = 0; $i -lt $msg.args.Count; $i++) {
                $formattedMsg = $formattedMsg -replace "%\($i\)s", $msg.args[$i]
            }
        }
        # Remove trailing period to match module style
        $formattedMsg = $formattedMsg.TrimEnd('.')
        Return $formattedMsg
    }

    # vCenter Server Appliance sizing table (vSphere 9)
    # MemoryGB is the official spec; MemoryReported is what the validation API reports (1GB less)
    $vCenterSizes = @(
        @{ Name = "Tiny"; vCPU = 2; MemoryGB = 14; MemoryReported = 13; Hosts = 10; VMs = 100 }
        @{ Name = "Small"; vCPU = 4; MemoryGB = 21; MemoryReported = 20; Hosts = 100; VMs = 1000 }
        @{ Name = "Medium"; vCPU = 8; MemoryGB = 30; MemoryReported = 29; Hosts = 400; VMs = 4000 }
        @{ Name = "Large"; vCPU = 16; MemoryGB = 39; MemoryReported = 38; Hosts = 1000; VMs = 10000 }
        @{ Name = "X-Large"; vCPU = 24; MemoryGB = 58; MemoryReported = 57; Hosts = 2000; VMs = 35000 }
    )

    # Helper function to recommend appliance size based on required resources
    # Note: Validation API reports memory ~1GB less than actual spec, so we match against MemoryReported
    Function Get-RecommendedApplianceSize {
        Param(
            [int]$RequiredCPU,
            [int]$RequiredMemoryGB
        )
        Foreach ($size in $vCenterSizes) {
            If ($size.vCPU -ge $RequiredCPU -and $size.MemoryReported -ge $RequiredMemoryGB) {
                Return $size
            }
        }
        Return $vCenterSizes[-1]  # Return X-Large if nothing else fits
    }

    # Helper function to identify current appliance size from reported values
    Function Get-CurrentApplianceSize {
        Param(
            [int]$CurrentCPU,
            [int]$CurrentMemoryGB
        )
        Foreach ($size in $vCenterSizes) {
            If ($size.vCPU -eq $CurrentCPU -and $size.MemoryReported -eq $CurrentMemoryGB) {
                Return $size
            }
        }
        Return $null
    }

    # Submit the restore request
    LogMessage -type INFO -message "[$restoredVcenterFqdn] Submitting restore request via REST API"
    Try {
        $restoreUri = "https://$restoredVcenterFqdn`:5480/rest/appliance/recovery/restore/job"
        $restoreResponse = Invoke-WebRequest -Method POST -URI $restoreUri -ContentType "application/json" -Headers $headers -Body $body -ErrorAction Stop
        $restoreResult = $restoreResponse.Content | ConvertFrom-Json

        # Analyze the response for errors or successful job start
        If ($restoreResult.state -eq "FAILED") {
            # Analyze messages for specific blocking issues
            $hasSizeIssues = $false
            $hasBackupPasswordIssue = $false
            $sizeIssueMessages = @()
            $requiredCPU = 0
            $requiredMemoryGB = 0
            $currentCPU = 0
            $currentMemoryGB = 0

            Foreach ($msg in $restoreResult.messages) {
                $formattedMsg = Format-VAMIMessage -msg $msg
                $msgId = $msg.id

                # Check for size/resource mismatch issues and extract values
                If ($msgId -match "resize" -or $formattedMsg -match "resize|resource type|memory|cpu|disk") {
                    $hasSizeIssues = $true
                    $sizeIssueMessages += $formattedMsg

                    # Extract CPU requirements: "Resize 'cpu' from X to Y"
                    If ($msg.args -and $msg.args[0] -eq "cpu" -and $msg.args.Count -ge 3) {
                        $currentCPU = [int]$msg.args[1]
                        $requiredCPU = [int]$msg.args[2]
                    }
                    # Extract Memory requirements: "Resize 'memory' from XGB to YGB"
                    If ($msg.args -and $msg.args[0] -eq "memory" -and $msg.args.Count -ge 3) {
                        $currentMemoryGB = [int]$msg.args[1]
                        $requiredMemoryGB = [int]$msg.args[2]
                    }
                }
                # Check for backup password issues
                ElseIf ($msgId -match "backup.*password|password.*backup|decrypt" -or $formattedMsg -match "backup.*password|password.*required|decrypt|encrypt") {
                    $hasBackupPasswordIssue = $true
                }
            }

            # Report size issues and exit with recommendation
            If ($hasSizeIssues) {
                LogMessage -type ERROR -message "[$restoredVcenterFqdn] Restore failed - appliance size mismatch detected"
                LogMessage -type ERROR -message "[$restoredVcenterFqdn] The deployed vCenter appliance size does not match the backup source."

                # Provide sizing recommendation if we extracted the required resources
                If ($requiredCPU -gt 0 -or $requiredMemoryGB -gt 0) {
                    $currentSize = Get-CurrentApplianceSize -CurrentCPU $currentCPU -CurrentMemoryGB $currentMemoryGB
                    $recommendedSize = Get-RecommendedApplianceSize -RequiredCPU $requiredCPU -RequiredMemoryGB $requiredMemoryGB

                    $currentSizeName = If ($currentSize) { $currentSize.Name } Else { "Unknown" }

                    LogMessage -type INFO -message "[$restoredVcenterFqdn] Current appliance size: $currentSizeName ($currentCPU vCPU, $($currentMemoryGB + 1) GB RAM)"
                    LogMessage -type INFO -message "[$restoredVcenterFqdn] Required appliance size: $($recommendedSize.Name) ($($recommendedSize.vCPU) vCPU, $($recommendedSize.MemoryGB) GB RAM)"
                    LogMessage -type INFO -message "[$restoredVcenterFqdn] "
                    LogMessage -type INFO -message "[$restoredVcenterFqdn] vCenter Server Appliance Sizes (vSphere 9):"
                    LogMessage -type INFO -message "[$restoredVcenterFqdn]   Tiny:     2 vCPU,  14 GB RAM (up to 10 hosts, 100 VMs)"
                    LogMessage -type INFO -message "[$restoredVcenterFqdn]   Small:    4 vCPU,  21 GB RAM (up to 100 hosts, 1,000 VMs)"
                    LogMessage -type INFO -message "[$restoredVcenterFqdn]   Medium:   8 vCPU,  30 GB RAM (up to 400 hosts, 4,000 VMs)"
                    LogMessage -type INFO -message "[$restoredVcenterFqdn]   Large:   16 vCPU,  39 GB RAM (up to 1,000 hosts, 10,000 VMs)"
                    LogMessage -type INFO -message "[$restoredVcenterFqdn]   X-Large: 24 vCPU,  58 GB RAM (up to 2,000 hosts, 35,000 VMs)"
                } Else {
                    Foreach ($sizeMsg in $sizeIssueMessages) {
                        LogMessage -type ERROR -message "[$restoredVcenterFqdn] $sizeMsg"
                    }
                }
                LogMessage -type ERROR -message "[$restoredVcenterFqdn] Please redeploy the vCenter OVA with the correct size and retry."
                $StopWatch.Stop()
                LogMessage -type NOTE -message "[$jumpboxName] Task $($MyInvocation.MyCommand) exited after $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
                Return
            }

            # Report backup password issues and exit
            If ($hasBackupPasswordIssue) {
                LogMessage -type ERROR -message "[$restoredVcenterFqdn] Restore failed - backup password issue detected"
                If ($backupPassword) {
                    LogMessage -type ERROR -message "[$restoredVcenterFqdn] A backup password was provided but may be incorrect, or the backup is not encrypted."
                    LogMessage -type ERROR -message "[$restoredVcenterFqdn] Try running the command again WITHOUT the -backupPassword parameter."
                } Else {
                    LogMessage -type ERROR -message "[$restoredVcenterFqdn] The backup appears to be encrypted."
                    LogMessage -type ERROR -message "[$restoredVcenterFqdn] Try running the command again WITH the -backupPassword parameter."
                }
                $StopWatch.Stop()
                LogMessage -type NOTE -message "[$jumpboxName] Task $($MyInvocation.MyCommand) exited after $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
                Return
            }

            # Generic failure - show all messages
            LogMessage -type ERROR -message "[$restoredVcenterFqdn] Restore job failed:"
            Foreach ($msg in $restoreResult.messages) {
                $formattedMsg = Format-VAMIMessage -msg $msg
                LogMessage -type ERROR -message "[$restoredVcenterFqdn] $formattedMsg"
            }
            $StopWatch.Stop()
            LogMessage -type NOTE -message "[$jumpboxName] Task $($MyInvocation.MyCommand) failed after $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
            Return
        }

        # Job started successfully
        If ($restoreResult.messages) {
            Foreach ($msg in $restoreResult.messages) {
                $formattedMsg = Format-VAMIMessage -msg $msg
                LogMessage -type INFO -message "[$restoredVcenterFqdn] $formattedMsg"
            }
        }
    } Catch {
        $errorMessage = $_.Exception.Message
        Try {
            $errorBody = $_.ErrorDetails.Message | ConvertFrom-Json
            If ($errorBody.messages) {
                $errorMessage = ($errorBody.messages | ForEach-Object { Format-VAMIMessage -msg $_ }) -join "; "
            }
        } Catch {}

        # Check for common error patterns and provide helpful guidance
        If ($errorMessage -match "list index out of range") {
            LogMessage -type ERROR -message "[$restoredVcenterFqdn] Restore request failed: $errorMessage"
            If ($backupPassword) {
                LogMessage -type ERROR -message "[$restoredVcenterFqdn] A backup password was provided but the backup may not be encrypted."
                LogMessage -type ERROR -message "[$restoredVcenterFqdn] Try running the command again WITHOUT the -backupPassword parameter."
            } Else {
                LogMessage -type ERROR -message "[$restoredVcenterFqdn] The backup may be encrypted and require a password."
                LogMessage -type ERROR -message "[$restoredVcenterFqdn] Try running the command again WITH the -backupPassword parameter."
            }
        } Else {
            LogMessage -type ERROR -message "[$restoredVcenterFqdn] Failed to submit restore job: $errorMessage"
        }
        $StopWatch.Stop()
        LogMessage -type NOTE -message "[$jumpboxName] Task $($MyInvocation.MyCommand) exited after $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
        Return
    }

    # Poll the restore job status
    LogMessage -type WAIT -message "[$restoredVcenterFqdn] Monitoring restore progress"
    $statusUri = "https://$restoredVcenterFqdn`:5480/rest/appliance/recovery/restore/job"
    $healthUri = "https://$restoredVcenterFqdn`:5480/rest/appliance/health/system"
    $lastProgress = -1
    $consecutiveFailures = 0
    $maxConsecutiveFailures = 10
    $lastStatusMessage = ""

    Do {
        Start-Sleep 20

        Try {
            $statusResponse = Invoke-WebRequest -Method GET -URI $statusUri -ContentType "application/json" -Headers $headers -ErrorAction Stop
            $statusResult = $statusResponse.Content | ConvertFrom-Json
            $consecutiveFailures = 0

            $state = $statusResult.state
            $progress = $statusResult.progress

            # Get the current status message (if any)
            $currentStatusMessage = ""
            If ($statusResult.messages) {
                Foreach ($msg in $statusResult.messages) {
                    If ($msg.default_message -and $msg.default_message -ne "") {
                        $currentStatusMessage = Format-VAMIMessage -msg $msg
                        Break
                    }
                }
            }

            # Only log when progress changes or status message changes (skip if SUCCEEDED - final status logged separately)
            If ($state -ne "SUCCEEDED" -and ($progress -ne $lastProgress -or $currentStatusMessage -ne $lastStatusMessage)) {
                If ($currentStatusMessage) {
                    LogMessage -type INFO -message "[$restoredVcenterFqdn] Restore State: $state, Progress: $progress% - $currentStatusMessage"
                } Else {
                    LogMessage -type INFO -message "[$restoredVcenterFqdn] Restore State: $state, Progress: $progress%"
                }
                $lastProgress = $progress
                $lastStatusMessage = $currentStatusMessage
            }
        } Catch {
            $consecutiveFailures++
            If ($consecutiveFailures -ge $maxConsecutiveFailures) {
                LogMessage -type WARNING -message "[$restoredVcenterFqdn] Lost connection to VAMI API after $maxConsecutiveFailures attempts. This may be normal during restore reboot phase."
                LogMessage -type WAIT -message "[$restoredVcenterFqdn] Waiting for appliance to come back online after restore..."

                # Wait for appliance to come back online
                $backOnline = $false
                $rebootWaitAttempts = 0
                $maxRebootWaitAttempts = 90

                Do {
                    $rebootWaitAttempts++
                    Start-Sleep 20

                    # First check if we can ping
                    $pingTest = Test-Connection -ComputerName $restoredVcenterFqdn -count 1 -ErrorAction SilentlyContinue
                    If ($pingTest) {
                        Try {
                            $healthCheck = Invoke-WebRequest -Method GET -URI $healthUri -ContentType "application/json" -Headers $headers -ErrorAction Stop
                            If ($healthCheck.StatusCode -eq 200) {
                                $backOnline = $true
                                LogMessage -type INFO -message "[$restoredVcenterFqdn] Appliance is back online"
                            }
                        } Catch {
                            If ($rebootWaitAttempts % 6 -eq 0) {
                                LogMessage -type INFO -message "[$restoredVcenterFqdn] Appliance responding to ping but VAMI not yet available... (attempt $rebootWaitAttempts of $maxRebootWaitAttempts)"
                            }
                        }
                    }
                } Until ($backOnline -or $rebootWaitAttempts -ge $maxRebootWaitAttempts)

                If ($backOnline) {
                    $consecutiveFailures = 0
                    $state = "CHECKING"
                    Continue
                } Else {
                    LogMessage -type ERROR -message "[$restoredVcenterFqdn] Appliance did not come back online after restore. Please check manually."
                    Break
                }
            } Else {
                LogMessage -type INFO -message "[$restoredVcenterFqdn] Waiting for VAMI API during service restart (attempt $consecutiveFailures of $maxConsecutiveFailures)"
            }
        }
    } Until ($state -eq "SUCCEEDED" -or $state -eq "FAILED")

    # Report final status
    If ($state -eq "SUCCEEDED") {
        LogMessage -type INFO -message "[$restoredVcenterFqdn] Restore completed successfully"
    } ElseIf ($state -eq "FAILED") {
        LogMessage -type ERROR -message "[$restoredVcenterFqdn] Restore failed"
        If ($statusResult.messages) {
            Foreach ($msg in $statusResult.messages) {
                $formattedMsg = Format-VAMIMessage -msg $msg
                LogMessage -type ERROR -message "[$restoredVcenterFqdn] $formattedMsg"
            }
        }
    }

    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
}
Export-ModuleMember -Function Invoke-vCenterRestore

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
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()

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
    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
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
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON
    $workloadDomain = $extractedSDDCData.workloadDomains | where-object { $_.vCenterDetails.fqdn -eq $vCenterFQDN }
    $clusterDetails = $workloadDomain.vsphereClusterDetails | Where-Object { $_.name -eq $clusterName }
    $sddcManagerConnection = Connect-VcfSddcManagerServer -server $sddcManagerFQDN -User $sddcManagerAdmin -Password $sddcManagerAdminPassword
    $vCenterConnection = connect-viserver $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    $clusterObj = Get-Cluster -Name $ClusterName

    # Add Az1 Hosts
    If ($clusterDetails.isStretched -eq 't') {
        LogMessage -type NOTE -message "[$clusterName] Rebuilding Availability Zone 1"
    }
    $az1Hosts = $clusterDetails.azHostMapping.az1
    foreach ($newHost in $az1Hosts) {
        $vmHosts = (Get-cluster -name $clusterName | Get-VMHost).Name | Sort-Object
        if ($newHost -notin $vmHosts) {
            $esxiRootPassword = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "ESXI") -and ($_.entityName -eq $newHost) -and ($_.username -eq "root") }).password
            $esxiConnection = connect-viserver $newHost -user root -password $esxiRootPassword
            if ($esxiConnection) {
                LogMessage -type INFO -message "[$newHost] Adding to cluster $clusterName"
                Add-VMHost $newHost -username root -password $esxiRootPassword -Location $clusterName -Force -Confirm:$false | Out-Null
            } else {
                LogMessage -type ERROR -message "[$newHost] Unable to connect. Host will not be added to the cluster"
            }
        } else {
            LogMessage -type INFO -message "[$newHost] Already part of $clusterName. Skipping"
        }
    }
    # Add AZ2 Hosts
    If ($clusterDetails.isStretched -eq 't') {
        If ($clusterDetails.isStretched -eq 't') {
            LogMessage -type NOTE -message "[$clusterName] Rebuilding Availability Zone 2"
        }
        $az2Hosts = $clusterDetails.azHostMapping.az2

        $nsxManagerFqdn = $workloadDomain.nsxClusterDetails.clusterFqdn
        $nsxManagerAdmin = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "NSXT_MANAGER") -and ($_.domainName -eq $workloadDomain.domainName) -and ($_.username -eq "admin") }).username
        $nsxManagerAdminPassword = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "NSXT_MANAGER") -and ($_.domainName -eq $workloadDomain.domainName) -and ($_.username -eq "admin") }).password
        $headers = VCFIRCreateHeader -username $nsxManagerAdmin -password $nsxManagerAdminPassword
        $subClusterMeta = Get-NSXSubClustersAndSubTNP -NSXManager $nsxManagerFqdn -ClusterName $ClusterName -username $nsxManagerAdmin -password $nsxManagerAdminPassword

        if (-not $subClusterMeta) {
            Throw "Failed to resolve Sub-Cluster metadata via Get-NSXSubClustersAndSubTNP for cluster '$ClusterName'."
        }

        $targetSubCluster = $subClusterMeta | Select-Object -First 1
        $subClusterId     = $targetSubCluster.SubClusterId

        # Extract origin GUID from ComputeCollectionId ("37681f70-6760-40a6-b173-7baa522c301c:domain-c40" -> "37681f70-6760-40a6-b173-7baa522c301c")
        $clusterOriginId  = $targetSubCluster.ComputeCollectionId.Split(':')[0]

        LogMessage -type INFO -message "[$clusterName] Discovered Sub-Cluster: $($targetSubCluster.SubClusterName) ($subClusterId)"

        $maxAttempts = 10
        $az2HostState = foreach ($hostFqdn in $az2Hosts) {
            [pscustomobject]@{
                hostFqdn         = $hostFqdn
                esxiRootPassword = $null
                vmhost           = $null
                discId           = $null
                failed           = $false
                failureReason    = $null
            }
        }

        foreach ($hostState in $az2HostState) {
            $hostFqdn = $hostState.hostFqdn
            $hostState.esxiRootPassword = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "ESXI") -and ($_.entityName -eq $hostFqdn) -and ($_.username -eq "root") }).password
            $vmhost = Get-VMHost -Name $hostFqdn -ErrorAction SilentlyContinue
            if ($vmhost) {
                LogMessage -type INFO -message "[$hostFqdn] Already managed by this vCenter. Reusing existing host object."
            } else {
                LogMessage -type INFO -message "[$hostFqdn] Adding to $ClusterName"
                $vmhost = Add-VMHost -Name $hostFqdn -Location $clusterObj `
                    -User 'root' -Password $hostState.esxiRootPassword `
                    -Force -Confirm:$false
            }
            $hostState.vmhost = $vmhost
        }

        foreach ($hostState in ($az2HostState | Where-Object { -not $_.failed })) {
            $hostMoRef = $hostState.vmhost.ExtensionData.MoRef.Value
            $hostState.discId = "${clusterOriginId}:${hostMoRef}"
        }

        $pendingHostStates = $az2HostState | Where-Object { -not $_.failed }
        if ($pendingHostStates) {
            $pendingDiscIds = $pendingHostStates.discId
            $scSingleUrl = "https://$nsxManagerFqdn/policy/api/v1/infra/sites/default/enforcement-points/default/sub-clusters/$subClusterId"

            $registered = $false
            for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
                try {
                    $subClusterObj = Invoke-RestMethod -Uri $scSingleUrl -Headers $headers -Method Get -SkipCertificateCheck -ErrorAction Stop

                    $newDiscIds = $pendingDiscIds | Where-Object { $_ -notin $subClusterObj.sub_cluster_info.discovered_node_ids }
                    if ($newDiscIds) {
                        $subClusterObj.sub_cluster_info.discovered_node_ids += $newDiscIds
                        $jsonSC = $subClusterObj | ConvertTo-Json -Depth 10
                        Invoke-RestMethod -Uri $scSingleUrl -Headers $headers -Method Put -Body $jsonSC -ContentType "application/json" -SkipCertificateCheck -ErrorAction Stop | Out-Null
                    }
                    $registered = $true
                    break
                } catch {
                    $errorDetail = $_.ErrorDetails.Message
                    if (-not $errorDetail) {
                        $errorDetail = $_.Exception.Message
                    }
                    LogMessage -type ERROR -message "[$clusterName] Attempt $attempt/$maxAttempts to register Sub-Cluster MoRefs failed: $errorDetail"
                    if ($attempt -lt $maxAttempts) {
                        Start-Sleep -Seconds 1
                    }
                }
            }

            if (-not $registered) {
                foreach ($hostState in $pendingHostStates) {
                    $hostState.failed = $true
                    $hostState.failureReason = "Failed to register with NSX Sub-Cluster DB after $maxAttempts attempts."
                }
                LogMessage -type ERROR -message "[$clusterName] Failed to register Sub-Cluster MoRefs after $maxAttempts attempts. AZ2 hosts remain in $ClusterName but are not registered to the Sub-Cluster."
            } else {
                foreach ($hostState in $pendingHostStates) {
                    LogMessage -type INFO -message "[$($hostState.hostFqdn)] Registered to Sub-Cluster."
                }
            }
        }

        $failedHostStates = $az2HostState | Where-Object { $_.failed }
        if ($failedHostStates) {
            $failureSummary = ($failedHostStates | ForEach-Object { "$($_.hostFqdn) ($($_.failureReason))" }) -join '; '
            LogMessage -type ERROR -message "[$clusterName] The following AZ2 hosts require manual follow-up: $failureSummary"
        }

        $subClusterPath = "/infra/sites/default/enforcement-points/default/sub-clusters/$subClusterId"
        $tncListUrl = "https://$nsxManagerFqdn/policy/api/v1/infra/sites/default/enforcement-points/default/transport-node-collections"
        $tnc = ((Invoke-RestMethod -Uri $tncListUrl -Headers $headers -Method Get -SkipCertificateCheck -ErrorAction Stop).results | Where-Object { $_.compute_collection_id -eq $targetSubCluster.ComputeCollectionId } | Select-Object -First 1)
        if (-not $tnc) {
            LogMessage -type ERROR -message "[$clusterName] Could not resolve a TransportNodeCollection for compute collection '$($targetSubCluster.ComputeCollectionId)'. Skipping Sub-Cluster to TransportNodeCollection mapping."
        } else {
            $tncUrl = "https://$nsxManagerFqdn/policy/api/v1/infra/sites/default/enforcement-points/default/transport-node-collections/$($tnc.id)"
            $tncObj = Invoke-RestMethod -Uri $tncUrl -Headers $headers -Method Get -SkipCertificateCheck -ErrorAction Stop
            $existingSubClusterConfig = @($tncObj.sub_cluster_config | Where-Object { $_ })
            if ($existingSubClusterConfig | Where-Object { $_.sub_cluster_id -eq $subClusterPath }) {
                LogMessage -type INFO -message "[$clusterName] TransportNodeCollection $($tnc.id) already maps Sub-Cluster '$($targetSubCluster.SubClusterName)'. Nothing to do."
            } else {
                $tnpUrl = "https://$nsxManagerFqdn/policy/api/v1$($tnc.transport_node_profile_id)"
                $tnp = Invoke-RestMethod -Uri $tnpUrl -Headers $headers -Method Get -SkipCertificateCheck -ErrorAction Stop
                $hostSwitchName = $tnp.host_switch_spec.host_switches[0].host_switch_name
                if ([string]::IsNullOrWhiteSpace($hostSwitchName)) {
                    Throw "Could not resolve a host_switch_name from TransportNodeProfile $($tnc.transport_node_profile_id)."
                }

                $vdSwitch = Get-VDSwitch -Name $hostSwitchName -ErrorAction Stop
                $hostSwitchId = $vdSwitch.ExtensionData.Uuid
                if ([string]::IsNullOrWhiteSpace($hostSwitchId)) {
                    Throw "Get-VDSwitch -Name '$hostSwitchName' did not return a UUID via .ExtensionData.Uuid."
                }

                $newSubClusterConfigEntry = @{
                    host_switch_config_sources = @(
                        @{
                            host_switch_id                         = $hostSwitchId
                            transport_node_profile_sub_config_name = $targetSubCluster.SubClusterName
                        }
                    )
                    sub_cluster_id = $subClusterPath
                }
                $tncObj | Add-Member -NotePropertyName "sub_cluster_config" -NotePropertyValue (@($existingSubClusterConfig) + $newSubClusterConfigEntry) -Force
                $tncBody = $tncObj | ConvertTo-Json -Depth 10
                Invoke-RestMethod -Uri $tncUrl -Headers $headers -Method Put -Body $tncBody -ContentType "application/json" -SkipCertificateCheck -ErrorAction Stop | Out-Null
                LogMessage -type INFO -message "[$clusterName] Mapped Sub-Cluster to TransportNodeCollection $($tnc.id)"
            }
        }
    }

    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
    Disconnect-VcfSddcManagerServer *
    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
}
Export-ModuleMember -Function Add-HostsToCluster

Function Get-NSXSubClustersAndSubTNP {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][string]$NSXManager,
        [Parameter(Mandatory = $true)][string]$username,
        [Parameter(Mandatory = $true)][string]$password,
        [Parameter(Mandatory = $true)][string]$ClusterName
    )

    process {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        $skipCert = @{ SkipCertificateCheck = $true }

        $authHeader = "Basic " + [Convert]::ToBase64String(
            [Text.Encoding]::ASCII.GetBytes("$($UserName):$($Password)")
        )
        $headers = @{
            "Authorization" = $authHeader
            "Content-Type"  = "application/json"
        }

        try {
            # 1. Resolve vSphere Cluster Name to Compute Collection External ID
            $ccUrl = "https://$NSXManager/api/v1/fabric/compute-collections"
            $ccResponse = Invoke-RestMethod -Uri $ccUrl -Headers $headers -Method Get @skipCert

            $targetCluster = $ccResponse.results | Where-Object { $_.display_name -eq $ClusterName }

            if (-not $targetCluster) {
                Write-Error "Cluster '$ClusterName' not found in NSX Compute Collections."
                return
            }

            $clusterExternalId = $targetCluster.external_id

            # 2. Query Enforcement Point Sub-Clusters
            $subClustersUrl = "https://$NSXManager/policy/api/v1/infra/sites/default/enforcement-points/default/sub-clusters"
            $subClusterResponse = Invoke-RestMethod -Uri $subClustersUrl -Headers $headers -Method Get @skipCert

            $matchedSubClusters = $subClusterResponse.results | Where-Object {
                $_.compute_collection_id -eq $clusterExternalId -or $_.display_name -like "*$ClusterName*"
            }

            if (-not $matchedSubClusters) {
                Write-Warning "No sub-clusters found under compute collection '$ClusterName' ($clusterExternalId)."
                return
            }

            # 3. Retrieve Transport Node Profiles for mapping
            $tnpUrl = "https://$NSXManager/policy/api/v1/infra/host-transport-node-profiles"
            $allTNPs = Invoke-RestMethod -Uri $tnpUrl -Headers $headers -Method Get @skipCert -ErrorAction SilentlyContinue

            # 4. Return Output
            $results = foreach ($sc in $matchedSubClusters) {
                $parentTnp = $allTNPs.results | Where-Object { $_.display_name -like "*$ClusterName*" }

                [PSCustomObject]@{
                    ClusterName         = $ClusterName
                    SubClusterName      = $sc.display_name
                    SubClusterId        = $sc.id
                    SubClusterType      = $sc.sub_cluster_info.sub_cluster_type
                    NodeCount           = if ($sc.sub_cluster_info.discovered_node_ids) {
                        $sc.sub_cluster_info.discovered_node_ids.Count
                    } else {
                        0
                    }
                    ParentTNP           = if ($parentTnp) {
                        $parentTnp.display_name
                    } else {
                        "N/A"
                    }
                    ComputeCollectionId = $sc.compute_collection_id
                    Path                = $sc.path
                }
            }

            return $results
        } catch {
            Write-Error "API Query Failed: $_"
        }
    }
}

Function Add-VMKernelsToHost {
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

    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem
    #>

    Param(
        [Parameter (Mandatory = $true)][String] $targetFQDN,
        [Parameter (Mandatory = $true)][String] $targetAdmin,
        [Parameter (Mandatory = $true)][String] $targetAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $sddcManagerFQDN,
        [Parameter (Mandatory = $true)][String] $sddcManagerAdmin,
        [Parameter (Mandatory = $true)][String] $sddcManagerAdminPassword,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON
    $sddcManagerConnection = Connect-VcfSddcManagerServer -server $sddcManagerFQDN -User $sddcManagerAdmin -Password $sddcManagerAdminPassword

    $vCenterConnection = connect-viserver $targetFQDN -user $targetAdmin -password $targetAdminPassword
    #$vmHosts = (Get-cluster -name $clusterName | Get-VMHost).Name | Sort-Object
    $workloadDomain = $extractedSDDCData.workloadDomains | where-object { $_.vCenterDetails.fqdn -eq $targetFQDN }
    $clusterDetails = $workloadDomain.vsphereClusterDetails | Where-Object { $_.name -eq $clusterName }

    If ($clusterDetails.isStretched -eq "t") {
        $azs = @("az1","az2")
    } else {
        $azs = @("az1")
    }
    Foreach ($az in $azs) {
        If ($clusterDetails.isStretched -eq "t"){
            LogMessage -type NOTE "[$clusterName] Adding VMkernels to $($az.toUpper()) Hosts"
        }
        $vmHosts = $clusterDetails.azHostMapping.$($az)
        If ($az -eq "az1") {
            $faultLevelArray = @("PRIMARY", "NONE")
        } else {
            $faultLevelArray = @("SECONDARY")
        }
        foreach ($vmhost in $vmHosts) {
            $vmotionPG = ($clusterDetails.vdsDetails.portgroups | Where-Object { ($_.TransportType -eq "VMOTION") -AND ($_.faultLevel -in $faultLevelArray) }).Name
            $vmotionVDSName = ($clusterDetails.vdsDetails | Where-Object { $_.portgroups.name -eq $vmotionPG }).dvsName
            $vmotionIP = ($clusterDetails.hosts | Where-Object { $_.hostname -eq $vmhost }).vmotionIp
            $networkPoolId = ($workloadDomain.vsphereClusterDetails.hosts | Where-Object { $_.hostname -eq $vmhost }).networkPoolID
            $vmotionMask = ((Invoke-VcfGetNetworksOfNetworkPool -id $networkPoolID).elements | ? { $_.type -eq "VMOTION" }).Mask
            $vmotionMTU = ((Invoke-VcfGetNetworksOfNetworkPool -id $networkPoolID).elements | ? { $_.type -eq "VMOTION" }).mtu
            $vmotionGW = ((Invoke-VcfGetNetworksOfNetworkPool -id $networkPoolID).elements | ? { $_.type -eq "VMOTION" }).gateway

            $vsanPG = ($clusterDetails.vdsDetails.portgroups | Where-Object { ($_.TransportType -eq "VSAN") -AND ($_.faultLevel -in $faultLevelArray) }).Name
            $vsanVDSName = ($clusterDetails.vdsDetails | Where-Object { $_.portgroups.name -eq $vsanPG }).dvsName
            $vsanIP = ($clusterDetails.hosts | Where-Object { $_.hostname -eq $vmhost }).vsanIp
            $vsanMask = ((Invoke-VcfGetNetworksOfNetworkPool -id $networkPoolID).elements | ? { $_.type -eq "VSAN" }).Mask
            $vsanMTU = ((Invoke-VcfGetNetworksOfNetworkPool -id $networkPoolID).elements | ? { $_.type -eq "VSAN" }).mtu
            $vsanGW = ((Invoke-VcfGetNetworksOfNetworkPool -id $networkPoolID).elements | ? { $_.type -eq "VSAN" }).gateway

            #Get Host Details
            $esx = Get-VMHost -Name $vmHost
            $hostVmkernelInfo = $esx | Get-View -Property Name, Config.Network.Vnic | ForEach-Object {
                $HostName = $_.Name
                foreach ($Vmk in $_.Config.Network.Vnic) {
                    [PSCustomObject]@{
                        VMHost     = $HostName
                        Device     = $Vmk.Device
                        Portgroup  = $Vmk.Portgroup
                        IPAddress  = $Vmk.Spec.Ip.IpAddress
                        SubnetMask = $Vmk.Spec.Ip.SubnetMask
                        MacAddress = $Vmk.Spec.Mac
                    }
                }
            }

            #create vmk1 if necessary
            $dvportgroup = Get-VDPortgroup -name $vmotionPG -VDSwitch $vmotionVDSName
            $vmk1Exists = $hostVmkernelInfo | Where-Object { $_.device -eq "vmk1" }
            If (!$vmk1Exists) {
                LogMessage -type INFO -message "[$vmhost] Creating vMotion vMK"
                $vmk = New-VMHostNetworkAdapter -VMHost $esx -VirtualSwitch $vmotionVDSName -mtu $vmotionMTU -PortGroup $dvportgroup -ip $vmotionIP -SubnetMask $vmotionMask -NetworkStack (Get-VMHostNetworkStack -vmhost $esx | Where-Object { $_.id -eq "vmotion" })
            } else {
                LogMessage -type INFO -message "[$vmhost] vMotion vMK already present"
            }

            #create vmk1 gateway if necessary
            $vmkName = 'vmk1'
            $esxcli = Get-EsxCli -VMHost $esx -V2
            $interface = $esxcli.network.ip.interface.ipv4.get.Invoke(@{interfacename = $vmkName })
            If ($interface[0].Gateway -ne $vmotionGW) {
                LogMessage -type INFO -message "[$vmhost] Setting vMotion Gateway"
                $interfaceArg = @{
                    netmask       = $interface[0].IPv4Netmask
                    type          = $interface[0].AddressType.ToLower()
                    ipv4          = $interface[0].IPv4Address
                    interfacename = $interface[0].Name
                }
                $esxcli.network.ip.interface.ipv4.set.Invoke($interfaceArg) *>$null
                $esxcli.network.ip.route.ipv4.add.Invoke(@{ netstack = 'vmotion'; network = 'default'; gateway = $vmotionGW }) *>$null
            } else {
                LogMessage -type INFO -message "[$vmhost] vMotion Gateway already configured"
            }

            #create vmk2 if necessary
            $dvportgroup = Get-VDPortgroup -name $vsanPG -VDSwitch $vsanVDSName
            $vmk2Exists = $hostVmkernelInfo | Where-Object { $_.device -eq "vmk2" }
            If (!$vmk2Exists) {
                LogMessage -type INFO -message "[$vmhost] Creating vSAN vMK"
                $vmk = New-VMHostNetworkAdapter -VMHost $esx -VirtualSwitch $vsanVDSName -mtu $vsanMTU -PortGroup $dvportgroup -ip $vsanIP -SubnetMask $vsanMask -VsanTrafficEnabled:$true
            } else {
                LogMessage -type INFO -message "[$vmhost] vSAN vMK already present"
            }

            #create vmk2 gateway if necessary
            $vmkName = 'vmk2'
            $esxcli = Get-EsxCli -VMHost $esx -V2
            $interface = $esxcli.network.ip.interface.ipv4.get.Invoke(@{interfacename = $vmkName })
            If ($interface[0].Gateway -ne $vsanGW) {
                LogMessage -type INFO -message "[$vmhost] Setting vSAN Gateway"
                $interfaceArg = @{
                    netmask       = $interface[0].IPv4Netmask
                    type          = $interface[0].AddressType.ToLower()
                    ipv4          = $interface[0].IPv4Address
                    interfacename = $interface[0].Name
                    gateway       = $vsanGW
                }
                $esxcli.network.ip.interface.ipv4.set.Invoke($interfaceArg) *>$null
            } else {
                LogMessage -type INFO -message "[$vmhost] vSAN Gateway already configured"
            }
        }
    }


    Disconnect-VcfSddcManagerServer *
    Disconnect-VIServer * -confirm:$false
    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
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
    New-RebuiltVsanDatastore -targetFQDN "sfo-m01-vc01.sfo.rainpole.io" -targetAdmin "administrator@vsphere.local" -targetAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01" -extractedSDDCDataFile ".\extracted-sddc-data.json"

    .PARAMETER targetFQDN
    FQDN of the vCenter instance hosting the cluster where the vSAN Datastore will be rebuilt

    .PARAMETER targetAdmin
    Admin user of the vCenter instance hosting the cluster where the vSAN Datastore will be rebuilt

    .PARAMETER targetAdminPassword
    Admin password for the vCenter instance hosting the cluster where the vSAN Datastore will be rebuilt

    .PARAMETER clusterName
    Name of the vSphere cluster instance where the vSAN Datastore will be rebuilt

    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem
    #>

    Param(
        [Parameter (Mandatory = $true)][String] $targetFQDN,
        [Parameter (Mandatory = $true)][String] $targetAdmin,
        [Parameter (Mandatory = $true)][String] $targetAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $workloadDomain = $extractedSDDCData.workloadDomains | where-object { $_.vCenterDetails.fqdn -eq $targetFQDN }
    $clusterDetails = $workloadDomain.vsphereClusterDetails | Where-Object { $_.name -eq $clusterName }

    $datastoreName = ($extractedSddcData.workloadDomains.vsphereClusterDetails | Where-Object { $_.name -eq $clusterName }).primaryDatastoreName
    $datastoreType = ($extractedSddcData.workloadDomains.vsphereClusterDetails | Where-Object { $_.name -eq $clusterName }).primaryDatastoreType

    LogMessage -type INFO -message "[$jumpboxName] Connecting to Restored vCenter: $targetFQDN"
    $restoredvCenterConnection = Connect-ViServer $targetFQDN -user $targetAdmin -password $targetAdminPassword
    If ($datastoreType -ne "VSAN_ESA") {
        $vmhosts = (Get-Cluster -name $clusterName | Get-VMHost | Sort-Object -property Name)
        $az1Hosts = $vmhosts | Where-Object { $_.name -in $clusterDetails.azHostMapping.az1 }
        LogMessage -type INFO -message "[$($az1Hosts[0].name)] Using host as reference for Eligible Physical Disks"

        $disks = (Get-VMHost -name $az1Hosts[0].name | Get-VMHostDisk) | Where-Object { $_.ScsiLun.VsanStatus -eq 'Eligible' } | Sort-Object -Property @{e = { $_.scsilun.runtimename } }
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
        If ($diskGroupNumber -eq "C") {
            Break
        }

        #Loop Through Disk Group Creation
        For ($i = 1; $i -le $diskGroupNumber; $i++) {
            If ($i -gt 1) {
                Write-Host ""; $remainingDisksDisplayObject | format-table -Property @{Expression = " " }, id, canonicalName, size, ssd -autosize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r", "`n") }
            }
            Do {
                If ($i -gt 1) {
                    Write-Host ""
                }; Write-Host " Enter the ID of disk to use as Cache Disk for Disk Group $i, or C to Cancel: " -ForegroundColor Yellow -nonewline
                $cacheDiskSelection = Read-Host
            } Until (($cacheDiskSelection -in $remainingDisksDisplayObject.id) -OR ($cacheDiskSelection -eq "c"))
            If ($cacheDiskSelection -eq "c") {
                Break
            }
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
            If ($capacityDiskSelection -eq "c") {
                Break
            }
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
        If (($cacheDiskSelection -eq "c") -or ($capacityDiskSelection -eq "c")) {
            Break
        }

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
            If ($clusterDetails.isStretched -eq 't')
            {
                $azs = @("az1","az2")
            }
            else
            {
                $azs = @("az1")
            }
            Foreach ($az in $azs)
            {
                $azHosts = $clusterDetails.azHostMapping.$($az)
                $azVmHosts = $vmhosts | Where-Object { $_.name -in $azHosts }
                If ($clusterDetails.isStretched -eq 't')
                {
                    LogMessage -type NOTE -message "[$clusterName] Starting Parallel Disk Group Creation across all $($az.ToUpper()) hosts"
                }
                else
                {
                    LogMessage -type NOTE -message "[$clusterName] Starting Parallel Disk Group Creation across all hosts"
                }
                Foreach ($vmHost in $azVmHosts) {
                    $scriptBlock = {
                        $moduleFunctions = Import-Module VMware.CloudFoundation.InstanceRecovery -passthru
                        $restoredvCenterConnection = Connect-ViServer $using:targetFQDN -user $using:targetAdmin -password $using:targetAdminPassword
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
                    Start-Job -scriptblock $scriptBlock -ArgumentList ($diskGroupNumber, $diskGroupConfiguration, $vmhost, $targetFQDN, $targetAdmin, $targetAdminPassword) | Out-Null
                }
                Get-Job | Receive-Job -Wait -AutoRemoveJob
            }
        }
    }
    LogMessage -type INFO -message "[$clusterName] Renaming new datastore to original name: $datastoreName"
    Get-Cluster -name $clusterName | Get-Datastore -Name "vsanDatastore*" | Set-Datastore -Name $datastoreName | Out-Null
    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
}
Export-ModuleMember -Function New-RebuiltVsanDatastore

Function Add-DiskgroupsToManagementHosts {
    <#
    .SYNOPSIS
    Expands a single-host vSAN OSA datastore to the remaining hosts in the cluster by replicating the disk group configuration from the first host.

    .DESCRIPTION
    The Add-DiskgroupsToManagementHosts cmdlet reads the existing vSAN OSA disk group configuration from the first host in the cluster (which was previously configured by New-SingleHostVsanDatastore) and uses it as a reference to create matching disk groups on all remaining hosts that do not yet have disk groups. Disk matching across hosts is done positionally by runtime name sort order, which assumes a standardized disk layout across all hosts.

    After disk groups are confirmed/created, the cmdlet also verifies that every host in the cluster has a vSAN unicast agent entry for every other host, adding any that are missing. vCenter does not reliably build this peer mesh automatically for hosts whose vSAN cluster membership originated outside its own "enable vSAN on this cluster" workflow (notably the bootstrap host created by New-SingleHostVsanDatastore) — without it, hosts can share the same Sub-Cluster UUID yet never discover each other, each electing itself master of its own single-host partition. This step connects to each host over SSH as root, using credentials looked up from the extracted SDDC data, so SSH must be enabled on every host in the cluster.

    .EXAMPLE
    Add-DiskgroupsToManagementHosts -targetFQDN "sfo-m01-vc01.sfo.rainpole.io" -targetAdmin "administrator@vsphere.local" -targetAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01" -extractedSDDCDataFile ".\extracted-sddc-data.json"

    .PARAMETER targetFQDN
    FQDN of the vCenter instance hosting the cluster where the vSAN datastore will be expanded

    .PARAMETER targetAdmin
    Admin user of the vCenter instance hosting the cluster where the vSAN datastore will be expanded

    .PARAMETER targetAdminPassword
    Admin password for the vCenter instance hosting the cluster where the vSAN datastore will be expanded

    .PARAMETER clusterName
    Name of the vSphere cluster instance where the vSAN datastore will be expanded

    .PARAMETER extractedSDDCDataFile
    Relative or absolute path to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem
    #>

    Param(
        [Parameter (Mandatory = $true)][String] $targetFQDN,
        [Parameter (Mandatory = $true)][String] $targetAdmin,
        [Parameter (Mandatory = $true)][String] $targetAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON
    $datastoreType = ($extractedSddcData.workloadDomains.vsphereClusterDetails | Where-Object { $_.name -eq $clusterName }).primaryDatastoreType

    If ($datastoreType -eq "VSAN_ESA") {
        LogMessage -type ERROR -message "[$clusterName] This function is for vSAN OSA clusters only. Use the appropriate ESA expansion function for VSAN_ESA clusters."
        return
    }

    LogMessage -type INFO -message "[$jumpboxName] Connecting to vCenter: $targetFQDN"
    $vCenterConnection = Connect-ViServer $targetFQDN -user $targetAdmin -password $targetAdminPassword

    $vmHosts = Get-Cluster -Name $clusterName | Get-VMHost | Sort-Object -Property Name
    $referenceHost = $vmHosts[0]
    LogMessage -type INFO -message "[$($referenceHost.Name)] Using as reference host for disk group configuration"

    # Read existing disk group configuration from the reference host using Get-VsanDiskGroup,
    # which provides strongly-typed SSDDisk (cache) and DataDisk (capacity) properties and is
    # available via the vCenter connection — avoiding esxcli field name variance across ESXi versions.
    $referenceDiskGroups = Get-VsanDiskGroup -VMHost $referenceHost -ErrorAction SilentlyContinue

    If (-not $referenceDiskGroups) {
        LogMessage -type ERROR -message "[$($referenceHost.Name)] No existing vSAN OSA disk groups found on reference host. Ensure New-SingleHostVsanDatastore has been run successfully."
        Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
        return
    }

    # Build a structured reference configuration. ExtensionData exposes .Ssd (HostScsiDisk) for
    # the cache disk and .NonSsd (HostScsiDisk[]) for capacity disks. Capacity in bytes is derived
    # from Block * BlockSize. RuntimeName (e.g. vmhba1:C0:T1:L0) is parsed for CTL display.
    $referenceConfig = @()
    Foreach ($diskGroup in $referenceDiskGroups) {
        $ssd = $diskGroup.ExtensionData.Ssd
        $nonSsds = @($diskGroup.ExtensionData.NonSsd | Sort-Object -Property RuntimeName)
        $referenceConfig += [PSCustomObject]@{
            'cacheDiskCanonicalName'     = $ssd.CanonicalName
            'cacheDiskRuntimeName'       = $ssd.RuntimeName
            'cacheDiskType'              = If ($ssd.Ssd) {
                "SSD"
            } Else {
                "HDD"
            }
            'cacheDiskCapacityGB'        = [math]::Round(($ssd.Capacity.Block * $ssd.Capacity.BlockSize) / 1GB, 0)
            'capacityDiskCanonicalNames' = @($nonSsds.CanonicalName)
            'capacityDiskRuntimeNames'   = @($nonSsds.RuntimeName)
            'capacityDiskTypes'          = @($nonSsds | ForEach-Object { If ($_.Ssd) {
                        "SSD"
                    } Else {
                        "HDD"
                    } })
            'capacityDiskCapacitiesGB'   = @($nonSsds | ForEach-Object { [math]::Round(($_.Capacity.Block * $_.Capacity.BlockSize) / 1GB, 0) })
        }
    }

    # Helper function to format a HostScsiDisk runtime name into SCSI Address notation
    Function Format-CTL ($runtimeName) {
        If ($runtimeName -match '(\w+):C(\d+):T(\d+):L(\d+)') {
            return "$($Matches[1]) C$($Matches[2]):T$($Matches[3]):L$($Matches[4])"
        }
        return $runtimeName
    }

    # --- Reference host disk group table ---
    # Use Get-VMHostDisk (InUse disks) for the reference host to get the same RuntimeName format
    # (vmhbaX:CY:TZ:LW) as the proposed hosts — ExtensionData.Ssd.RuntimeName uses a different format.
    $referenceHostAllDisks = $referenceHost | Get-VMHostDisk | Sort-Object -Property @{e = { $_.ScsiLun.RuntimeName } }
    $referenceDisplayRows = @()
    $referenceDisplayRows += [pscustomobject]@{ 'DG' = "DiskGroup"; 'CTL' = "SCSI Address"; 'Type' = "Type"; 'Role' = "Role"; 'CapacityGB' = "Capacity (GB)" }
    $referenceDisplayRows += [pscustomobject]@{ 'DG' = "---------"; 'CTL' = "------------"; 'Type' = "----"; 'Role' = "-------"; 'CapacityGB' = "------------" }
    $configIndex = 1
    Foreach ($config in $referenceConfig) {
        $cacheLun = ($referenceHostAllDisks | Where-Object { $_.ScsiLun.CanonicalName -eq $config.cacheDiskCanonicalName }).ScsiLun
        $referenceDisplayRows += [pscustomobject]@{
            'DG'         = $configIndex
            'Role'       = "Cache"
            'CTL'        = (Format-CTL $cacheLun.RuntimeName)
            'Type'       = If ($cacheLun.IsSsd) {
                "SSD"
            } Else {
                "HDD"
            }
            'CapacityGB' = [math]::Round($cacheLun.CapacityGB, 0)
        }
        Foreach ($capCN in $config.capacityDiskCanonicalNames) {
            $capLun = ($referenceHostAllDisks | Where-Object { $_.ScsiLun.CanonicalName -eq $capCN }).ScsiLun
            $referenceDisplayRows += [pscustomobject]@{
                'DG'         = ""
                'Role'       = "Capacity"
                'CTL'        = (Format-CTL $capLun.RuntimeName)
                'Type'       = If ($capLun.IsSsd) {
                    "SSD"
                } Else {
                    "HDD"
                }
                'CapacityGB' = [math]::Round($capLun.CapacityGB, 0)
            }
        }
        $configIndex++
    }
    Write-Host ""
    Write-Host " Reference Disk Group Configuration — $($referenceHost.Name)" -ForegroundColor Yellow
    Write-Host ""
    $referenceDisplayRows | Format-Table -Property @{Expression = " " }, DG, CTL, Type, Role, CapacityGB -AutoSize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r", "`n") }
    Write-Host ""

    # --- Scan all hosts and build the proposed config table ---
    LogMessage -type INFO -message "[$clusterName] Querying remaining hosts for disk configuration"
    $hostsNeedingDiskGroups = @()
    $proposedDisplayRows = @()
    $proposedDisplayRows += [pscustomobject]@{ 'Host' = "Host"; 'DG' = "DiskGroup"; 'Status' = "Status"; 'CTL' = "SCSI Address"; 'Type' = "Type"; 'Role' = "Role"; 'CapacityGB' = "Capacity (GB)" }
    $proposedDisplayRows += [pscustomobject]@{ 'Host' = "----"; 'DG' = "---------"; 'Status' = "------"; 'CTL' = "------------"; 'Type' = "----"; 'Role' = "-------"; 'CapacityGB' = "------------" }

    Foreach ($vmHost in $vmHosts) {
        $hostDiskGroups = Get-VsanDiskGroup -VMHost $vmHost -ErrorAction SilentlyContinue
        If ($hostDiskGroups) {
            # Show existing disk groups using Get-VMHostDisk for consistent RuntimeName format
            $hostAllDisks = $vmHost | Get-VMHostDisk | Sort-Object -Property @{e = { $_.ScsiLun.RuntimeName } }
            $dgIndex = 1
            Foreach ($dg in $hostDiskGroups) {
                $existingSsdCN = $dg.ExtensionData.Ssd.CanonicalName
                $existingNonSsdCNs = @($dg.ExtensionData.NonSsd | Sort-Object -Property RuntimeName | ForEach-Object { $_.CanonicalName })
                $existingSsdLun = ($hostAllDisks | Where-Object { $_.ScsiLun.CanonicalName -eq $existingSsdCN }).ScsiLun
                $proposedDisplayRows += [pscustomobject]@{
                    'Host'       = $vmHost.Name
                    'Status'     = "Existing"
                    'DG'         = "  $dgIndex"
                    'Role'       = "Cache"
                    'CTL'        = (Format-CTL $existingSsdLun.RuntimeName)
                    'Type'       = If ($existingSsdLun.IsSsd) {
                        "SSD"
                    } Else {
                        "HDD"
                    }
                    'CapacityGB' = [math]::Round($existingSsdLun.CapacityGB, 0)
                }
                Foreach ($nonSsdCN in $existingNonSsdCNs) {
                    $nonSsdLun = ($hostAllDisks | Where-Object { $_.ScsiLun.CanonicalName -eq $nonSsdCN }).ScsiLun
                    $proposedDisplayRows += [pscustomobject]@{
                        'Host'       = ""
                        'Status'     = ""
                        'DG'         = ""
                        'Role'       = "Capacity"
                        'CTL'        = (Format-CTL $nonSsdLun.RuntimeName)
                        'Type'       = If ($nonSsdLun.IsSsd) {
                            "SSD"
                        } Else {
                            "HDD"
                        }
                        'CapacityGB' = [math]::Round($nonSsdLun.CapacityGB, 0)
                    }
                }
                $dgIndex++
            }
        } Else {
            $hostsNeedingDiskGroups += $vmHost
            $hostEligibleDisks = $vmHost | Get-VMHostDisk | Where-Object { $_.ScsiLun.VsanStatus -eq 'Eligible' } | Sort-Object -Property @{e = { $_.ScsiLun.RuntimeName } }
            $allRefCanonicalNames = ($referenceConfig | ForEach-Object { @($_.cacheDiskCanonicalName) + @($_.capacityDiskCanonicalNames) })
            $dgIndex = 1
            Foreach ($config in $referenceConfig) {
                $cachePositionIndex = [Array]::IndexOf($allRefCanonicalNames, $config.cacheDiskCanonicalName)
                $cacheLun = $hostEligibleDisks[$cachePositionIndex].ScsiLun
                $proposedDisplayRows += [pscustomobject]@{
                    'Host'       = $vmHost.Name
                    'Status'     = "Proposed"
                    'DG'         = "  $dgIndex"
                    'Role'       = "Cache"
                    'CTL'        = (Format-CTL $cacheLun.RuntimeName)
                    'Type'       = If ($cacheLun.IsSsd) {
                        "SSD"
                    } Else {
                        "HDD"
                    }
                    'CapacityGB' = [math]::Round($cacheLun.CapacityGB, 0)
                }
                Foreach ($refCapCN in $config.capacityDiskCanonicalNames) {
                    $capPositionIndex = [Array]::IndexOf($allRefCanonicalNames, $refCapCN)
                    $capLun = $hostEligibleDisks[$capPositionIndex].ScsiLun
                    $proposedDisplayRows += [pscustomobject]@{
                        'Host'       = ""
                        'Status'     = ""
                        'DG'         = ""
                        'Role'       = "Capacity"
                        'CTL'        = (Format-CTL $capLun.RuntimeName)
                        'Type'       = If ($capLun.IsSsd) {
                            "SSD"
                        } Else {
                            "HDD"
                        }
                        'CapacityGB' = [math]::Round($capLun.CapacityGB, 0)
                    }
                }
                $dgIndex++
            }
        }
    }

    If ($hostsNeedingDiskGroups.Count -eq 0) {
        LogMessage -type INFO -message "[$clusterName] All hosts already have disk groups configured. Nothing to do."
    } else {
        Write-Host ""
        Write-Host " Proposed Disk Group Configuration — All Hosts" -ForegroundColor Yellow
        Write-Host ""
        $proposedDisplayRows | Format-Table -Property @{Expression = " " }, Host, DG, Status, CTL, Type, Role, CapacityGB -AutoSize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r", "`n") }
        Write-Host ""
        Write-Host " Do you wish to proceed? (Y/N): " -ForegroundColor Yellow -nonewline
        Do {
            $proceedAccepted = Read-Host
        } Until ($proceedAccepted -in "Y", "N")

        If ($proceedAccepted -eq "N") {
            LogMessage -type INFO -message "[$clusterName] User cancelled. No changes made."
            Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
            $StopWatch.Stop()
            LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
            return
        }

        LogMessage -type INFO -message "[$clusterName] Starting parallel disk group creation across hosts requiring configuration"
        $diskGroupNumber = $referenceConfig.Count
        Foreach ($vmHost in $hostsNeedingDiskGroups) {
            $scriptBlock = {
                $moduleFunctions = Import-Module VMware.CloudFoundation.InstanceRecovery -PassThru
                $restoredvCenterConnection = Connect-ViServer $using:targetFQDN -user $using:targetAdmin -password $using:targetAdminPassword
                $vmhost = Get-VMHost -Name $using:vmHost.Name

                # Get this host's eligible disks (VsanStatus = Eligible) sorted by runtime name.
                # Canonical names are matched positionally against the reference config, which was
                # also sorted by runtime name — so disk layout must be standardized across all hosts.
                $hostEligibleDisks = $vmhost | Get-VMHostDisk | Where-Object { $_.ScsiLun.VsanStatus -eq 'Eligible' } | Sort-Object -Property @{e = { $_.ScsiLun.RuntimeName } }

                $referenceConfig = $using:referenceConfig
                For ($i = 1; $i -le $using:diskGroupNumber; $i++) {
                    $diskGroupConfigurationIndex = ($i - 1)
                    $config = $referenceConfig[$diskGroupConfigurationIndex]

                    # The reference config stores canonical names from the reference host sorted by
                    # runtime name. We use the same positional index to pick disks on this host.
                    $allRefCanonicalNames = ($referenceConfig | ForEach-Object { @($_.cacheDiskCanonicalName) + @($_.capacityDiskCanonicalNames) })
                    $cachePositionIndex = [Array]::IndexOf($allRefCanonicalNames, $config.cacheDiskCanonicalName)
                    $cacheDiskCanonicalName = ($hostEligibleDisks[$cachePositionIndex]).ScsiLun.CanonicalName

                    $capacityDiskCanonicalNames = @()
                    Foreach ($refCapacityCanonicalName in $config.capacityDiskCanonicalNames) {
                        $capacityPositionIndex = [Array]::IndexOf($allRefCanonicalNames, $refCapacityCanonicalName)
                        $capacityDiskCanonicalNames += ($hostEligibleDisks[$capacityPositionIndex]).ScsiLun.CanonicalName
                    }

                    & $moduleFunctions { LogMessage -type INFO -message "[$($vmhost.Name)] Creating vSAN OSA Disk Group $i (cache: $cacheDiskCanonicalName)" }
                    New-VsanDiskGroup -VMHost $vmhost -SsdCanonicalName $cacheDiskCanonicalName -DataDiskCanonicalName $capacityDiskCanonicalNames | Out-Null
                }
                Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
            }
            Start-Job -ScriptBlock $scriptBlock -ArgumentList ($diskGroupNumber, $referenceConfig, $vmHost, $targetFQDN, $targetAdmin, $targetAdminPassword) | Out-Null
        }
        Get-Job | Receive-Job -Wait -AutoRemoveJob
    }

    # -------------------------------------------------------------------------
    # Ensure every host in the cluster has a vSAN unicast agent entry for every
    # other host. vCenter does not reliably build this peer mesh automatically
    # for hosts whose vSAN cluster membership originated outside its own
    # "enable vSAN on this cluster" workflow (e.g. the bootstrap host created by
    # New-SingleHostVsanDatastore). Hosts can end up sharing the same
    # Sub-Cluster UUID yet never discover each other, each electing itself
    # master of its own single-host partition. Requires SSH access to each
    # host as root, using credentials from the extracted SDDC data.
    # -------------------------------------------------------------------------
    LogMessage -type INFO -message "[$clusterName] Verifying vSAN unicast agent mesh across all hosts"

    $vsanPeers = @()
    Foreach ($vmHost in $vmHosts) {
        $nodeUuid = $vmHost.ExtensionData.Config.VsanHostConfig.ClusterInfo.NodeUuid
        if (-not $nodeUuid) {
            LogMessage -type WARNING -message "[$($vmHost.Name)] Could not resolve vSAN Node UUID (vSAN may not be enabled on this host) — skipping for unicast mesh"
            continue
        }

        $esxcli = Get-EsxCli -VMHost $vmHost -V2
        $vsanNetwork = @($esxcli.vsan.network.list.Invoke() | Where-Object { ($_.TrafficType -join ',') -match 'vsan' }) | Select-Object -First 1
        if (-not $vsanNetwork) {
            LogMessage -type WARNING -message "[$($vmHost.Name)] Could not resolve a vmknic tagged for vSAN traffic — skipping for unicast mesh"
            continue
        }

        $vsanVmk = Get-VMHostNetworkAdapter -VMHost $vmHost -VMKernel -Name $vsanNetwork.VmkNicName -ErrorAction SilentlyContinue
        if (-not $vsanVmk -or -not $vsanVmk.IP) {
            LogMessage -type WARNING -message "[$($vmHost.Name)] Could not resolve an IP address for vSAN vmknic '$($vsanNetwork.VmkNicName)' — skipping for unicast mesh"
            continue
        }

        $rootPassword = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "ESXI") -and ($_.entityName -eq $vmHost.Name) -and ($_.username -eq "root") }).password
        if (-not $rootPassword) {
            LogMessage -type WARNING -message "[$($vmHost.Name)] Could not resolve root password from extracted SDDC data — skipping for unicast mesh"
            continue
        }

        $vsanPeers += [PSCustomObject]@{
            Name         = $vmHost.Name
            NodeUuid     = $nodeUuid
            VsanIp       = $vsanVmk.IP
            RootPassword = $rootPassword
        }
    }

    Foreach ($peer in $vsanPeers) {
        $otherPeers = @($vsanPeers | Where-Object { $_.Name -ne $peer.Name })
        if ($otherPeers.Count -eq 0) { continue }

        $sshSession = $null
        Try {
            $SecurePassword = ConvertTo-SecureString -String $peer.RootPassword -AsPlainText -Force
            $rootCreds      = New-Object System.Management.Automation.PSCredential ("root", $SecurePassword)
            $inmem          = New-SSHMemoryKnownHost
            New-SSHTrustedHost -KnownHostStore $inmem -HostName $peer.Name `
                -FingerPrint ((Get-SSHHostKey -ComputerName $peer.Name).fingerprint) | Out-Null
            Do {
                $sshSession = New-SSHSession -ComputerName $peer.Name -Credential $rootCreds -KnownHost $inmem
            } Until ($sshSession)

            Foreach ($otherPeer in $otherPeers) {
                $addCmd = "esxcli vsan cluster unicastagent add -t node -u $($otherPeer.NodeUuid) -U true -p 12321 -a $($otherPeer.VsanIp)"
                $result = Invoke-SSHCommand -SessionId $sshSession.SessionId -Command $addCmd -TimeOut 30
                if ($result.ExitStatus -eq 0) {
                    LogMessage -type INFO -message "[$($peer.Name)] Added/confirmed unicast agent for $($otherPeer.Name) ($($otherPeer.VsanIp))"
                } else {
                    LogMessage -type WARNING -message "[$($peer.Name)] unicastagent add for $($otherPeer.Name) exited $($result.ExitStatus): $(($result.Output + $result.Error) -join ' ')"
                }
            }
        } Catch {
            LogMessage -type ERROR -message "[$($peer.Name)] Failed to configure vSAN unicast agents: $($_.Exception.Message)"
        } Finally {
            if ($sshSession) { Remove-SSHSession -SSHSession $sshSession | Out-Null }
        }
    }

    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
}
Export-ModuleMember -Function Add-DiskgroupsToManagementHosts

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
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
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
    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
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
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $workloadDomain = $extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }
    $cluster = $workloadDomain.vsphereClusterDetails | Where-Object { $_.isDefault -eq "t" }
    $azHosts = $cluster.azHostMapping.az1
    $esxHostFqdn = ($cluster.hosts | where-object {$_.hostname -in $azHosts})[0].hostname
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
        $_.IsBootDevice -eq $false -and
        $_.deviceType -eq "Direct-Access"
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
                If ($i -gt 1) {
                    Write-Host ""
                }; Write-Host " Enter the ID of disk to use as Cache Disk for Disk Group $i, or C to Cancel: " -ForegroundColor Yellow -nonewline
                $cacheDiskSelection = Read-Host
            } Until (($cacheDiskSelection -in $remainingDisksDisplayObject.id) -OR ($cacheDiskSelection -eq "c"))
            If ($cacheDiskSelection -eq "c") {
                Break
            }
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
            If ($capacityDiskSelection -eq "c") {
                Break
            }
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
        If (($cacheDiskSelection -eq "c") -or ($capacityDiskSelection -eq "c")) {
            Break
        }

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

            # Set the vSAN default policy to FTT=0 (no redundancy) so that files can be written
            # to the single-host OSA datastore during the bootstrap phase. Without this, vSAN
            # rejects all object creation because the default policy (FTT=1, RAID-1) requires a
            # minimum of 3 fault domains / hosts.
            # SPBM is a vCenter service and is not available on a direct ESXi connection, so the
            # policy is applied via esxcli instead. After vCenter is restored and the cluster is
            # expanded, run Set-ManagementDatastorePolicy to restore the original policy.
            LogMessage -type INFO -message "[$esxHostFqdn] Setting vSAN default policy to FTT=0 across all policy classes for single-host OSA bootstrap via esxcli"
            foreach ($policyClass in @("cluster", "vdisk", "vmnamespace", "vmswap", "vmem")) {
                try {
                    $policyArgs = $esxcli.vsan.policy.setdefault.CreateArgs()
                    $policyArgs.policy = '(("hostFailuresToTolerate" i0))'
                    $policyArgs.policyclass = $policyClass
                    $esxcli.vsan.policy.setdefault.Invoke($policyArgs) *>$null
                    LogMessage -type INFO -message "[$esxHostFqdn] vSAN default policy set to FTT=0 for class: $policyClass"
                } catch {
                    LogMessage -type WARNING -message "[$esxHostFqdn] Failed to set vSAN default policy for class '$policyClass': $($_.Exception.Message)"
                }
            }
            LogMessage -type INFO -message "[$esxHostFqdn] All vSAN policy classes set to FTT=0. Remember to run Set-ManagementDatastorePolicy after the cluster is expanded to restore the original policy."
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
    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
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
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
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
    $azHosts = $cluster.azHostMapping.az1
    $vmhosts = (Get-Cluster -name $clusterName | Get-VMHost | Sort-Object -property Name | Where-Object { $_.name -in $azHosts })
    #$vmhosts = (Get-Cluster -name $clusterName | Get-VMHost | Sort-Object -property Name)
    LogMessage -type INFO -message "[$($vmhosts[0].name)] Using host as reference for Physical NICs"

    #$nics = ((Get-Cluster -name $clusterName | Get-VMHost | Sort-Object -property Name)[0] | Get-VMHostNetworkAdapter | Where-Object {$_.name -like "vmnic*"}) | Sort-Object -Property Name
    $nics = (Get-EsxCli -VMHost ((Get-Cluster -name $clusterName | Get-VMHost | Sort-Object -property Name)[0])).network.nic.list() | Select-Object Name, Driver, LinkStatus, Description

    $nicsDisplayObject = @()
    $nicsIndex = 0
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
            If ($nicSelection -eq "c") {
                Break
            }
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
        If (($nicSelection -eq "c") -or ($nicSelection -eq "c")) {
            Break
        }

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
        If ($cluster.isStretched -eq "t") {
            $azs = @("az1","az2")
        } else {
            $azs = @("az1")
        }
        Foreach ($az in $azs) {
            If ($cluster.isStretched -eq "t"){
                LogMessage -type NOTE "[$clusterName] Adding $($az.toUpper()) Hosts to Virtual Distributed Switches"
            }
            $azHosts = $cluster.azHostMapping.$($az)
            $vmhosts = (Get-Cluster -name $clusterName | Get-VMHost | Sort-Object -property Name | Where-Object { $_.name -in $azHosts })
            If ($az -eq "az1") {
                $faultLevelArray = @("PRIMARY", "NONE")
            } else {
                $faultLevelArray = @("SECONDARY")
            }
            Foreach ($vds in $vdsConfiguration) {
                $vdsHosts = (Get-VDSwitch -name $vds.vdsName).extensionData.summary.hostmember.value
                Foreach ($vmHost in $vmHosts) {
                    $vmNicArray = @()
                    $portgroupArray = @()
                    $vmnicMinusOne = $vmhost | Get-VMHostNetworkAdapter | Where-Object { $_.deviceName -eq $vds.nicNames[0] }
                    If (($vds.portgroups | Where-Object { $_.transportType -eq 'VM_MANAGEMENT' }).name) {
                        $managementVmPortGroupName = ($vds.portgroups | Where-Object { ($_.transportType -eq 'VM_MANAGEMENT' -and ($_.faultLevel -in $faultLevelArray)) }).name
                    } else {
                        $managementVmPortGroupName = ($vds.portgroups | Where-Object { ($_.transportType -eq 'MANAGEMENT') -and ($_.faultLevel -in $faultLevelArray) }).name
                    }
                    $managementPortGroupName = ($vds.portgroups | Where-Object { ($_.transportType -eq 'MANAGEMENT') -and ($_.faultLevel -in $faultLevelArray) }).name

                    If ($vds.portgroups | Where-Object { ($_.transportType -eq 'MANAGEMENT') -and ($_.faultLevel -in $faultLevelArray) }) {
                        $portgroupArray += $managementPortGroupName
                        $vmk0 = Get-VMHostNetworkAdapter -VMHost $vmHost -Name "vmk0"
                        $vmNicArray += $vmk0
                    }
                    If ($isPrimaryManagementCluster) {
                        If ($vds.portgroups | Where-Object { ($_.transportType -eq 'VMOTION') -and ($_.faultLevel -in $faultLevelArray) }) {
                            $vmotionPortgroupName = ($vds.portgroups | Where-Object { ($_.transportType -eq 'VMOTION') -and ($_.faultLevel -in $faultLevelArray) }).name
                            $portgroupArray += $vmotionPortgroupName
                            $vmk1 = Get-VMHostNetworkAdapter -VMHost $vmHost -Name "vmk1"
                            $vmNicArray += $vmk1
                        }
                        If ($vds.portgroups | Where-Object { ($_.transportType -eq 'VSAN') -and ($_.faultLevel -in $faultLevelArray) }) {
                            $vsanPortgroupName = ($vds.portgroups | Where-Object { ($_.transportType -eq 'VSAN') -and ($_.faultLevel -in $faultLevelArray) }).name
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
                If (($vds.portgroups | Where-Object { ($_.transportType -eq 'VM_MANAGEMENT') -and ($_.faultLevel -in "PRIMARY", "NONE") }) -OR ((!($vds.portgroups | Where-Object { ($_.transportType -eq 'VM_MANAGEMENT') -and ($_.faultLevel -in "PRIMARY", "NONE") })) -and ($vds.portgroups | Where-Object { ($_.transportType -eq 'MANAGEMENT') -and ($_.faultLevel -in "PRIMARY", "NONE") }))) {

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
                                LogMessage -type WAIT -message "Nested hosts detected. Allowing 5 mins for vCenter <-> ESX connection to stabilize after vmk0 / vm_mgmt portgroup migration"
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
        }

        #region Retry NSX Transport Node Profile Realization
        # NSX does not reliably auto-trigger host transport node installation immediately after hosts are
        # added to a VDS backing an NSX-prepared cluster. Observed live: the parent/sub Transport Node
        # Profile mapping was already correct, but installation only started after manually re-running
        # "Configure NSX (Advanced)" in the UI with no changes. This calls the documented NSX API that the
        # UI action invokes, to force NSX to retry realization of the profile against the cluster.
        LogMessage -type INFO -message "[$jumpboxName] Requesting NSX to retry Transport Node Profile realization for '$clusterName'"
        $nsxManagerFqdn = $workloadDomain.nsxClusterDetails.clusterFqdn
        $nsxManagerAdmin = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "NSXT_MANAGER") -and ($_.domainName -eq $workloadDomain.domainName) -and ($_.username -eq "admin") }).username
        $nsxManagerAdminPassword = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "NSXT_MANAGER") -and ($_.domainName -eq $workloadDomain.domainName) -and ($_.username -eq "admin") }).password
        $nsxHeaders = VCFIRCreateHeader -username $nsxManagerAdmin -password $nsxManagerAdminPassword

        Try {
            $clusterComputeCollection = (Invoke-RestMethod -Uri "https://$nsxManagerFqdn/api/v1/fabric/compute-collections" -Headers $nsxHeaders -Method Get -SkipCertificateCheck -ErrorAction Stop).results | Where-Object { $_.display_name -eq $clusterName }

            If (!$clusterComputeCollection) {
                LogMessage -type WARNING -message "[$nsxManagerFqdn] No compute collection found matching cluster name '$clusterName'. Skipping Transport Node Profile realization retry."
            } Else {
                $clusterTransportNodeCollection = (Invoke-RestMethod -Uri "https://$nsxManagerFqdn/policy/api/v1/infra/sites/default/enforcement-points/default/transport-node-collections" -Headers $nsxHeaders -Method Get -SkipCertificateCheck -ErrorAction Stop).results | Where-Object { $_.compute_collection_id -eq $clusterComputeCollection.external_id } | Select-Object -First 1

                If (!$clusterTransportNodeCollection) {
                    LogMessage -type WARNING -message "[$nsxManagerFqdn] No Transport Node Collection found for cluster '$clusterName'. Skipping Transport Node Profile realization retry."
                } Else {
                    LogMessage -type INFO -message "[$nsxManagerFqdn] Triggering Transport Node Profile realization for Transport Node Collection $($clusterTransportNodeCollection.id)"
                    Invoke-RestMethod -Uri "https://$nsxManagerFqdn/api/v1/transport-node-collections/$($clusterTransportNodeCollection.id)?action=retry_profile_realization" -Headers $nsxHeaders -Method Post -SkipCertificateCheck -ErrorAction Stop | Out-Null
                }
            }
        } Catch {
            LogMessage -type WARNING -message "[$nsxManagerFqdn] Failed to trigger NSX Transport Node Profile realization retry: $($_.Exception.Message)"
        }
        #endregion Retry NSX Transport Node Profile Realization

        Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
        $StopWatch.Stop()
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
    }
}
Export-ModuleMember -Function New-RebuiltVdsConfiguration

Function Watch-NsxHostTransportNodeInstallation {
    <#
    .SYNOPSIS
    Monitors the installation of NSX on all host transport nodes in a cluster until NSX Configuration state reads 'success'

    .DESCRIPTION
    The Watch-NsxHostTransportNodeInstallation cmdlet polls the NSX Manager API for every host transport node belonging to the specified vSphere cluster and waits until the top-level state for each node reports 'success' and the node status reports 'UP'. Progress is logged for each host on every poll cycle and the function exits cleanly once all nodes have satisfied both conditions or the optional timeout is reached.

    .EXAMPLE
    Watch-NsxHostTransportNodeInstallation -clusterName "sfo-m01-cl01" -extractedSDDCDataFile ".\extracted-sddc-data.json"

    .PARAMETER clusterName
    Name of the vSphere cluster whose host transport nodes will be monitored

    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (the output of Export-VCFRecoveryRunbook) on the local filesystem

    #>

    Param(
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile
    )

    $timeoutMinutes = 60
    $pollIntervalSeconds = 30
    $reportEveryNCycles = 2
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()

    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    #Determine the expected number of host transport nodes from the extracted data
    $expectedClusterDetails = $extractedSddcData.workloadDomains.vsphereClusterDetails | Where-Object { $_.name -eq $clusterName }
    $expectedNodeCount = @($expectedClusterDetails.hosts).Count

    If ($expectedNodeCount -eq 0) {
        LogMessage -type WARNING -message "[$jumpboxName] No hosts found for cluster '$clusterName' in the extracted SDDC data. Verify the cluster name is correct."
    } Else {
        LogMessage -type INFO -message "[$jumpboxName] Extracted SDDC data indicates cluster '$clusterName' should contain $expectedNodeCount host transport node(s)"
    }

    #Resolve the workload domain and NSX Manager details from the extracted data
    $workloadDomain = ($extractedSddcData.workloadDomains | Where-Object { $_.vsphereClusterDetails.name -contains $clusterName })
    If (!$workloadDomain) {
        LogMessage -type WARNING -message "[$jumpboxName] Could not find a workload domain containing cluster '$clusterName' in the extracted SDDC data."
        $StopWatch.Stop()
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
        Return
    }
    $nsxManagerFqdn = $workloadDomain.nsxClusterDetails.clusterFqdn
    $nsxManagerAdmin = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "NSXT_MANAGER") -and ($_.domainName -eq $workloadDomain.domainName) -and ($_.username -eq "admin") }).username
    $nsxManagerAdminPassword = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "NSXT_MANAGER") -and ($_.domainName -eq $workloadDomain.domainName) -and ($_.username -eq "admin") }).password

    $headers = VCFIRCreateHeader -username $nsxManagerAdmin -password $nsxManagerAdminPassword

    #Resolve the cluster's compute collection external_id from NSX fabric
    LogMessage -type INFO -message "[$nsxManagerFqdn] Resolving compute collection for cluster '$clusterName'"
    $uri = "https://$nsxManagerFqdn/api/v1/fabric/compute-collections"
    $computeCollections = ((Invoke-WebRequest -Method GET -URI $uri -ContentType application/json -headers $headers).content | ConvertFrom-Json).results
    $clusterComputeCollection = $computeCollections | Where-Object { $_.display_name -eq $clusterName }

    If (!$clusterComputeCollection) {
        LogMessage -type WARNING -message "[$nsxManagerFqdn] No compute collection found matching cluster name '$clusterName'. Verify the cluster name is correct."
        $StopWatch.Stop()
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
        Return
    }

    $clusterComputeCollectionId = $clusterComputeCollection.external_id

    $startTime = Get-Date
    $timeout = New-TimeSpan -Minutes $timeoutMinutes

    #Get all ESXi host transport nodes and filter to those belonging to the resolved cluster
    #Wait until every expected host transport node has been registered before monitoring installation
    LogMessage -type INFO -message "[$nsxManagerFqdn] Retrieving host transport nodes for cluster '$clusterName'"
    $registrationCycle = 0
    LogMessage -type WAIT -message "[$nsxManagerFqdn] Waiting for the correct number of transport nodes to be present"
    Do {
        $uri = "https://$nsxManagerFqdn/api/v1/transport-nodes/"
        $allTransportNodes = ((Invoke-WebRequest -Method GET -URI $uri -ContentType application/json -headers $headers).content | ConvertFrom-Json).results
        $clusterTransportNodes = @($allTransportNodes | Where-Object {
                ($_.resource_type -eq "TransportNode") -and
                ($_.node_deployment_info.os_type -eq "ESXI") -and
                ($_.node_deployment_info.compute_collection_id -eq $clusterComputeCollectionId)
            } | Sort-Object)

        If ($expectedNodeCount -gt 0 -and $clusterTransportNodes.Count -lt $expectedNodeCount) {
            $elapsed = (Get-Date) - $startTime
            If ($elapsed -ge $timeout) {
                LogMessage -type ERROR -message "[$nsxManagerFqdn] Timeout of $timeoutMinutes minutes reached while waiting for host transport nodes to register. Found $($clusterTransportNodes.Count) of $expectedNodeCount expected node(s) in cluster '$clusterName'"
                $StopWatch.Stop()
                LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
                Return
            }
            $registrationCycle++
            If ($registrationCycle % $reportEveryNCycles -eq 0) {
                LogMessage -type INFO -message "[$nsxManagerFqdn] Found $($clusterTransportNodes.Count) of $expectedNodeCount expected host transport node(s)"
            }
            Start-Sleep -Seconds $pollIntervalSeconds
        } Else {
            Break
        }
    } While ($true)

    If ($clusterTransportNodes.Count -eq 0) {
        LogMessage -type WARNING -message "[$nsxManagerFqdn] No host transport nodes found for cluster '$clusterName'. Verify that the transport node collection has been applied."
        $StopWatch.Stop()
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
        Return
    }

    LogMessage -type WAIT -message "[$nsxManagerFqdn] Monitoring NSX installation on $($clusterTransportNodes.Count) host transport node(s) in cluster '$clusterName'"

    $completedIds = @()
    $monitorCycle = 0

    Do {
        $monitorCycle++
        $pendingNodes = @()

        Foreach ($transportNode in $clusterTransportNodes) {
            If ($transportNode.id -in $completedIds) { Continue }

            $stateUri = "https://$nsxManagerFqdn/api/v1/transport-nodes/$($transportNode.id)/state"
            $statusUri = "https://$nsxManagerFqdn/api/v1/transport-nodes/$($transportNode.id)/status"
            Try {
                $nodeState = (Invoke-WebRequest -Method GET -URI $stateUri -ContentType application/json -headers $headers).content | ConvertFrom-Json
                $nodeStatus = (Invoke-WebRequest -Method GET -URI $statusUri -ContentType application/json -headers $headers).content | ConvertFrom-Json

                $configState = $nodeState.state
                $connectivity = $nodeStatus.status

                If (($configState -eq "success") -and ($connectivity -eq "UP")) {
                    #LogMessage -type INFO -message "[$($transportNode.display_name)] NSX Configuration State: $configState | Status: $connectivity"
                    $completedIds += $transportNode.id
                } ElseIf ($monitorCycle % $reportEveryNCycles -eq 0) {
                    #LogMessage -type WAIT -message "[$($transportNode.display_name)] NSX Configuration State: $configState | Status: $connectivity"
                    $pendingNodes += $transportNode.display_name
                } Else {
                    $pendingNodes += $transportNode.display_name
                }
            } Catch {
                LogMessage -type WARNING -message "[$($transportNode.display_name)] Unable to retrieve transport node state/status: $($_.Exception.Message)"
                $pendingNodes += $transportNode.display_name
            }
        }

        If ($pendingNodes.Count -eq 0) {
            LogMessage -type INFO -message "[$nsxManagerFqdn] All host transport nodes in cluster '$clusterName' have reached NSX Configuration State: success and Status: UP"
            Break
        }

        $elapsed = (Get-Date) - $startTime
        If ($elapsed -ge $timeout) {
            LogMessage -type ERROR -message "[$nsxManagerFqdn] Timeout of $timeoutMinutes minutes reached. The following host transport node(s) have not yet reached NSX Configuration State 'success' and Status 'UP': $($pendingNodes -join ', ')"
            Break
        }

        If ($monitorCycle % $reportEveryNCycles -eq 0) {
            LogMessage -type INFO -message "[$nsxManagerFqdn] $($pendingNodes.Count) node(s) still pending."
        }
        Start-Sleep -Seconds $pollIntervalSeconds

    } While ($true)

    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
}
Export-ModuleMember -Function Watch-NsxHostTransportNodeInstallation

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
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $workloadDomain = $extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }
    $cluster = $workloadDomain.vsphereClusterDetails | Where-Object { $_.isDefault -eq "t" }
    $clusterVdsDetails = $cluster.vdsDetails

    $vmMgmtVlanId = ($cluster.vdsDetails.portgroups | Where-Object { $_.transportType -eq "VM_MANAGEMENT" }).vlanId

    $az1Hosts = $cluster.azHostMapping.az1
    $hostFQDN = $az1Hosts[0]
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
    $nicsIndex = 0
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

        If ($cluster.isStretched -eq "t") {
            $azs = @("az1","az2")
        } else {
            $azs = @("az1")
        }

        Foreach ($az in $azs) {
            $azHosts = $cluster.azHostMapping.$($az)
            $clusterHostDetails = $cluster.hosts | Where-Object {$_.hostname -in $azHosts}

            Foreach ($clusterHost in $clusterHostDetails) {
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
        }

        $StopWatch.Stop()
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
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
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $workloadDomain = $extractedSddcData.workloadDomains | Where-Object { $_.domainType -eq "MANAGEMENT" }
    $cluster = $workloadDomain.vsphereClusterDetails | Where-Object { $_.isDefault -eq "t" }

    If ($cluster.isStretched -eq "t") {
        $azs = @("az1","az2")
    } else {
        $azs = @("az1")
    }

    Foreach ($az in $azs) {
        If ($cluster.isStretched -eq "t"){
            LogMessage -type NOTE "[Managment Cluster] Adding VMkernels to $($az.toUpper()) Hosts"
        }

        # Host networks (vcf_network rows) carry no faultLevel -- that only exists on VDS portgroup
        # objects, a separate structure. Network pool assignment is inherently AZ-specific though: an
        # AZ1 host's pool only contains AZ1's VMOTION/VSAN network, an AZ2 host's only AZ2's -- so any
        # host from the target AZ's azHostMapping list gives the correct network, no faultLevel needed.
        $azReferenceHostname = $cluster.azHostMapping.$az | Select-Object -First 1
        $azReferenceHost = $cluster.hosts | Where-Object { $_.hostname -eq $azReferenceHostname }
        $vmotionNetwork = $azReferenceHost.networks | Where-Object { $_.type -eq "VMOTION" } | Select-Object -First 1
        $vsanNetwork = $azReferenceHost.networks | Where-Object { $_.type -eq "VSAN" } | Select-Object -First 1

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

        $azHosts = $cluster.azHostMapping.$($az)
        $vmHosts = $cluster.hosts | Where-Object {$_.hostname -in $azHosts}

        Foreach ($clusterHost in $vmHosts) {
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

    }

    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
}
Export-ModuleMember -Function Add-VMKernelsToManagementHosts

Function New-ReconfiguredVsanStretchedCluster {
    <#
    .SYNOPSIS
    Creates the AZ1/AZ2 vSAN fault domains and enables stretched cluster configuration on a vSphere cluster using data from the SDDC Manager backup

    .DESCRIPTION
    The New-ReconfiguredVsanStretchedCluster cmdlet creates a vSAN fault domain for each of the cluster's AZ1 and AZ2 host sets (as recorded in the extracted SDDC data) and enables the vSAN stretched cluster configuration against them, using the cluster's own witness host (also recorded in the extracted SDDC data) as the witness. AZ1 is always configured as the preferred fault domain. If a fault domain already exists with the expected name, it is reused rather than recreated. If the cluster is already configured as a stretched cluster with the expected witness host, no change is made.

    All AZ1, AZ2, and witness hosts must already exist in the vCenter inventory before running this cmdlet (AZ1/AZ2 hosts added via Add-HostsToCluster, the witness host via its own restore/redeploy process).

    .EXAMPLE
    New-ReconfiguredVsanStretchedCluster -vCenterFQDN "sfo-w02-vc01.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -clusterName "sfo-w02-cl02" -extractedSDDCDataFile ".\extracted-sddc-data.json"

    .PARAMETER vCenterFQDN
    FQDN of the vCenter instance hosting the cluster to be stretched

    .PARAMETER vCenterAdmin
    Admin user of the vCenter instance hosting the cluster to be stretched

    .PARAMETER vCenterAdminPassword
    Admin password for the vCenter instance hosting the cluster to be stretched

    .PARAMETER clusterName
    Name of the stretched vSphere cluster instance to configure

    .PARAMETER extractedSDDCDataFile
    Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem

    .PARAMETER disableVsanWitnessTrafficSeperation
    By default, vmk0 on every AZ1 and AZ2 host is tagged for vSAN witness traffic (equivalent to `esxcli vsan network ipv4 set -i vmk0 -T witness`), since the original host-to-vmknic witness traffic separation mapping recorded by the source SDDC Manager cannot be reliably recovered after a full host rebuild. Pass this switch to skip that step entirely (e.g. if witness traffic separation should not be configured, or will be configured some other way).
    #>

    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $false)][Switch] $disableVsanWitnessTrafficSeperation
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()

    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON
    $workloadDomain = $extractedSddcData.workloadDomains | Where-Object { $_.vCenterDetails.fqdn -eq $vCenterFQDN }
    if (!$workloadDomain) {
        LogMessage -type WARNING -message "[$jumpboxName] Could not find a workload domain with vCenter FQDN '$vCenterFQDN' in the extracted SDDC data."
        $StopWatch.Stop()
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
        Return
    }

    $clusterDetails = $workloadDomain.vsphereClusterDetails | Where-Object { $_.name -eq $clusterName }
    if (!$clusterDetails) {
        LogMessage -type WARNING -message "[$jumpboxName] Could not find cluster '$clusterName' in the extracted SDDC data."
        $StopWatch.Stop()
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
        Return
    }
    if ($clusterDetails.isStretched -ne 't') {
        LogMessage -type WARNING -message "[$jumpboxName] Cluster '$clusterName' is not recorded as stretched in the extracted SDDC data. Nothing to do."
        $StopWatch.Stop()
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
        Return
    }

    $az1Hosts = $clusterDetails.azHostMapping.az1
    $az2Hosts = $clusterDetails.azHostMapping.az2
    $witnessFqdn = $clusterDetails.witness.fqdn
    if (!$witnessFqdn) {
        LogMessage -type WARNING -message "[$jumpboxName] No witness host recorded for cluster '$clusterName' in the extracted SDDC data. Run Update-ExtractedSDDCData against the source environment first."
        $StopWatch.Stop()
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
        Return
    }

    LogMessage -type INFO -message "[$vCenterFQDN] Connecting to vCenter"
    Connect-VIServer -Server $vCenterFQDN -User $vCenterAdmin -Password $vCenterAdminPassword -ErrorAction Stop | Out-Null

    $clusterObj = Get-Cluster -Name $clusterName -ErrorAction Stop

    $clusterMoRef = $clusterObj.ExtensionData.MoRef
    $stretchedClusterSystem = Get-VsanView -Id "VimClusterVsanVcStretchedClusterSystem-vsan-stretched-cluster-system"
    LogMessage -type INFO -message "[$clusterName] Querying persisted vSAN witness host info"
    $staleWitnessInfo = @($stretchedClusterSystem.VSANVcGetWitnessHosts($clusterMoRef))
    if ($staleWitnessInfo.Count -eq 0) {
        LogMessage -type INFO -message "[$clusterName] No stale witness host reference found in the cluster's persisted vSAN configuration."
    } else {
        Foreach ($staleWitness in $staleWitnessInfo) {
            LogMessage -type INFO -message "[$clusterName] Removing stale witness reference - Host MoRef: $($staleWitness.Host.Value), UnicastAgentAddr: $($staleWitness.UnicastAgentAddr)"
            $witnessRemovalTaskMoRef = $stretchedClusterSystem.VSANVcRemoveWitnessHost($clusterMoRef, $staleWitness.Host, $staleWitness.UnicastAgentAddr)

            if ($witnessRemovalTaskMoRef.Type -eq 'Task') {
                $witnessRemovalTask = Get-View -Id $witnessRemovalTaskMoRef
                Do {
                    Start-Sleep -Seconds 2
                    $witnessRemovalTask.UpdateViewData("Info")
                } While ($witnessRemovalTask.Info.State -in "running", "queued")
                If ($witnessRemovalTask.Info.State -eq "success") {
                    LogMessage -type INFO -message "[$clusterName] Stale witness reference removed successfully"
                } else {
                    LogMessage -type ERROR -message "[$clusterName] Witness removal task ended with state '$($witnessRemovalTask.Info.State)': $($witnessRemovalTask.Info.Error.LocalizedMessage)"
                }
            } else {
                LogMessage -type INFO -message "[$clusterName] Witness removal call returned MoRef type '$($witnessRemovalTaskMoRef.Type)' (not a Task) -- treating as already complete"
            }
        }
    }

    $az1VMHosts = @(Get-VMHost -Name $az1Hosts -ErrorAction Stop)
    $az2VMHosts = @(Get-VMHost -Name $az2Hosts -ErrorAction Stop)

    if ($disableVsanWitnessTrafficSeperation) {
        LogMessage -type INFO -message "[$clusterName] -disableVsanWitnessTrafficSeperation specified. Skipping vSAN Witness Traffic Separation configuration on vmk0."
    } else {
        LogMessage -type INFO -message "[$clusterName] Configuring vSAN Witness Traffic Separation on vmk0 for all AZ1/AZ2 hosts"
        Foreach ($dataHost in (@($az1VMHosts) + @($az2VMHosts))) {
            Try {
                $esxcli = Get-EsxCli -VMHost $dataHost -V2
                $vmk0VsanNetwork = @($esxcli.vsan.network.list.Invoke() | Where-Object { $_.VmkNicName -eq 'vmk0' }) | Select-Object -First 1
                $vmk0AlreadyWitnessTagged = $vmk0VsanNetwork -and (($vmk0VsanNetwork.TrafficType -join ',') -match 'witness')
                if ($vmk0AlreadyWitnessTagged) {
                    LogMessage -type INFO -message "[$($dataHost.Name)] vmk0 already tagged for vSAN witness traffic. Skipping"
                } elseif (!$vmk0VsanNetwork) {
                    LogMessage -type INFO -message "[$($dataHost.Name)] Enabling vSAN Witness traffic on vmk0"
                    $witnessTrafficArgs = $esxcli.vsan.network.ip.add.CreateArgs()
                    $witnessTrafficArgs.interfacename = "vmk0"
                    $witnessTrafficArgs.traffictype = @("witness")
                    $esxcli.vsan.network.ip.add.Invoke($witnessTrafficArgs) | Out-Null
                } else {
                    LogMessage -type INFO -message "[$($dataHost.Name)] Updating vmk0's existing vSAN network entry to include witness traffic type"
                    $witnessTrafficArgs = $esxcli.vsan.network.ipv4.set.CreateArgs()
                    $witnessTrafficArgs.interfacename = "vmk0"
                    $witnessTrafficArgs.traffictype = @("witness")
                    $esxcli.vsan.network.ipv4.set.Invoke($witnessTrafficArgs) | Out-Null
                }
            } Catch {
                LogMessage -type ERROR -message "[$($dataHost.Name)] Failed to configure vSAN Witness Traffic Separation on vmk0: $($_.Exception.Message)"
            }
        }
    }

    $witnessVMHost = Get-VMHost -Name $witnessFqdn -ErrorAction SilentlyContinue
    if (!$witnessVMHost) {
        LogMessage -type WARNING -message "[$witnessFqdn] Witness host not found in the vCenter inventory. Ensure the witness has been restored/redeployed and registered with $vCenterFQDN before running this cmdlet."
        Disconnect-VIServer -Server $vCenterFQDN -Force -Confirm:$false
        $StopWatch.Stop()
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
        Return
    }

    $az1FaultDomain = Get-VsanFaultDomain -Cluster $clusterObj -Name "$($clustername)_primary-az-faultdomain (preferred)" -ErrorAction SilentlyContinue
    if (!$az1FaultDomain) {
        LogMessage -type INFO -message "[$clusterName] Creating AZ1 fault domain with hosts: $($az1Hosts -join ', ')"
        $az1FaultDomain = New-VsanFaultDomain -Name "$($clustername)_primary-az-faultdomain (preferred)" -VMHost $az1VMHosts
    } else {
        LogMessage -type INFO -message "[$clusterName] AZ1 fault domain already exists. Reusing"
    }

    $az2FaultDomain = Get-VsanFaultDomain -Cluster $clusterObj -Name "$($clustername)_secondary-az-faultdomain" -ErrorAction SilentlyContinue
    if (!$az2FaultDomain) {
        LogMessage -type INFO -message "[$clusterName] Creating AZ2 fault domain with hosts: $($az2Hosts -join ', ')"
        $az2FaultDomain = New-VsanFaultDomain -Name "$($clustername)_secondary-az-faultdomain" -VMHost $az2VMHosts
    } else {
        LogMessage -type INFO -message "[$clusterName] AZ2 fault domain already exists. Reusing"
    }

    LogMessage -type INFO -message "[$clusterName] Reconciling AZ1 host membership in DRS group 'sddc-manager_primary-az-hostgroup'"
    $primaryAzHostGroup = Get-DrsClusterGroup -Cluster $clusterObj -Name "sddc-manager_primary-az-hostgroup"
    $az1HostsToAddToGroup = @($az1VMHosts | Where-Object { $_.Name -notin $primaryAzHostGroup.Member.Name })
    if ($az1HostsToAddToGroup.Count -gt 0) {
        Set-DrsClusterGroup -DrsClusterGroup $primaryAzHostGroup -Add -VMHost $az1HostsToAddToGroup -Confirm:$false | Out-Null
        LogMessage -type INFO -message "[$clusterName] Added to 'sddc-manager_primary-az-hostgroup': $($az1HostsToAddToGroup.Name -join ', ')"
    } else {
        LogMessage -type INFO -message "[$clusterName] All AZ1 hosts already members of 'sddc-manager_primary-az-hostgroup'"
    }

    LogMessage -type INFO -message "[$clusterName] Reconciling AZ2 host membership in DRS group 'sddc-manager_secondary-az-hostgroup'"
    $secondaryAzHostGroup = Get-DrsClusterGroup -Cluster $clusterObj -Name "sddc-manager_secondary-az-hostgroup"
    $az2HostsToAddToGroup = @($az2VMHosts | Where-Object { $_.Name -notin $secondaryAzHostGroup.Member.Name })
    if ($az2HostsToAddToGroup.Count -gt 0) {
        Set-DrsClusterGroup -DrsClusterGroup $secondaryAzHostGroup -Add -VMHost $az2HostsToAddToGroup -Confirm:$false | Out-Null
        LogMessage -type INFO -message "[$clusterName] Added to 'sddc-manager_secondary-az-hostgroup': $($az2HostsToAddToGroup.Name -join ', ')"
    } else {
        LogMessage -type INFO -message "[$clusterName] All AZ2 hosts already members of 'sddc-manager_secondary-az-hostgroup'"
    }

    $vsanConfig = Get-VsanClusterConfiguration -Cluster $clusterObj
    if (($vsanConfig.StretchedClusterEnabled -eq $true) -and ($vsanConfig.WitnessHost.Name -eq $witnessVMHost.Name)) {
        LogMessage -type INFO -message "[$clusterName] Stretched cluster already configured with witness '$witnessFqdn'. Nothing to do."
    } else {
        $witnessDiskGroup = Get-VsanDiskGroup -VMHost $witnessVMHost -ErrorAction SilentlyContinue
        if ($witnessDiskGroup) {
            LogMessage -type INFO -message "[$witnessFqdn] Witness already has a vSAN disk group (shared witness). Enabling stretched cluster configuration without claiming disks"
            Set-VsanClusterConfiguration -Configuration $clusterObj -StretchedClusterEnabled $true -PreferredFaultDomain $az1FaultDomain -WitnessHost $witnessVMHost -ErrorAction Stop | Out-Null
        } else {
            LogMessage -type INFO -message "[$witnessFqdn] Resolving witness disk group disks"
            $witnessEligibleDisks = @($witnessVMHost | Get-VMHostDisk | Where-Object { $_.ScsiLun.VsanStatus -eq 'Eligible' } | Sort-Object -Property @{e = { $_.ScsiLun.CapacityGB } })
            if ($witnessEligibleDisks.Count -lt 1) {
                Throw "[$witnessFqdn] Expected at least 1 eligible disk on the witness host, found 0."
            }

            if ($clusterDetails.primaryDatastoreType -eq "VSAN_ESA") {
                LogMessage -type INFO -message "[$witnessFqdn] Using $(($witnessEligibleDisks.ScsiLun.CanonicalName) -join ', ') as ESA storage pool disk(s)"

                LogMessage -type INFO -message "[$clusterName] Enabling stretched cluster configuration (ESA) with preferred fault domain and witness '$witnessFqdn'"
                Set-VsanClusterConfiguration -Configuration $clusterObj -StretchedClusterEnabled $true -PreferredFaultDomain $az1FaultDomain -WitnessHost $witnessVMHost -WitnessHostStoragePoolDisk $witnessEligibleDisks -ErrorAction Stop | Out-Null
            } else {
                if ($witnessEligibleDisks.Count -lt 2) {
                    Throw "[$witnessFqdn] Expected at least 2 eligible disks (1 cache, 1+ capacity) on the witness host, found $($witnessEligibleDisks.Count)."
                }
                $witnessCacheDisk = $witnessEligibleDisks[0]
                $witnessCapacityDisks = @($witnessEligibleDisks | Select-Object -Skip 1)
                LogMessage -type INFO -message "[$witnessFqdn] Using $($witnessCacheDisk.ScsiLun.CanonicalName) as cache disk and $(($witnessCapacityDisks.ScsiLun.CanonicalName) -join ', ') as capacity disk(s)"

                LogMessage -type INFO -message "[$clusterName] Enabling stretched cluster configuration with preferred fault domain and witness '$witnessFqdn'"
                Set-VsanClusterConfiguration -Configuration $clusterObj -StretchedClusterEnabled $true -PreferredFaultDomain $az1FaultDomain -WitnessHost $witnessVMHost -WitnessHostCacheDisk $witnessCacheDisk -WitnessHostCapacityDisk $witnessCapacityDisks -ErrorAction Stop | Out-Null
            }
        }
        LogMessage -type INFO -message "[$clusterName] Stretched cluster configuration enabled"
    }

    Disconnect-VIServer -Server $vCenterFQDN -Force -Confirm:$false
    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
}
Export-ModuleMember -Function New-ReconfiguredVsanStretchedCluster

Function Remove-VsanStretchedClusterWitness {
    <#
    .SYNOPSIS
    Clears a stale vSAN stretched cluster witness reference from vCenter's persisted cluster configuration.

    .DESCRIPTION
    The Remove-VsanStretchedClusterWitness cmdlet automates the remediation documented in Broadcom KB 326817
    (https://knowledge.broadcom.com/external/article/326817) for a stretched cluster whose witness host was
    removed from vCenter inventory without first disabling stretched cluster mode, leaving a stale witness
    reference in the cluster's persisted vSAN configuration. That stale reference causes subsequent
    Set-VsanClusterConfiguration calls to fail with errors such as "Witness host already configured in
    stretched cluster." even though the cluster no longer appears stretched in the vSphere Client.

    Rather than requiring RVC (vsan.stretchedcluster.witness_info / vsan.stretchedcluster.remove_witness), this
    cmdlet calls the same underlying vCenter vSAN API directly via PowerCLI's Get-VsanView against the
    VimClusterVsanVcStretchedClusterSystem managed object: VSANVcGetWitnessHosts to read the stale witness
    entry (MoRef + unicast agent address), then VSANVcRemoveWitnessHost to clear it.

    .EXAMPLE
    Remove-VsanStretchedClusterWitness -vCenterFQDN "sfo-w02-vc01.sfo.rainpole.io" -vCenterAdmin "administrator@sfo-w02.local" -vCenterAdminPassword "VMw@re1!VMw@re1!" -clusterName "sfo-w02-cl02"

    .PARAMETER vCenterFQDN
    FQDN of the vCenter instance hosting the cluster with the stale witness reference

    .PARAMETER vCenterAdmin
    Admin user of the vCenter instance

    .PARAMETER vCenterAdminPassword
    Admin password for the vCenter instance

    .PARAMETER clusterName
    Name of the vSphere cluster instance whose stale witness reference should be cleared
    #>

    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $clusterName
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()

    LogMessage -type INFO -message "[$vCenterFQDN] Connecting to vCenter"
    Connect-VIServer -Server $vCenterFQDN -User $vCenterAdmin -Password $vCenterAdminPassword -ErrorAction Stop | Out-Null
    $clusterObj = Get-Cluster -Name $clusterName -ErrorAction Stop
    $clusterMoRef = $clusterObj.ExtensionData.MoRef

    $stretchedClusterSystem = Get-VsanView -Id "VimClusterVsanVcStretchedClusterSystem-vsan-stretched-cluster-system"

    LogMessage -type INFO -message "[$clusterName] Querying persisted vSAN witness host info"
    $witnessInfo = @($stretchedClusterSystem.VSANVcGetWitnessHosts($clusterMoRef))

    if ($witnessInfo.Count -eq 0) {
        LogMessage -type INFO -message "[$clusterName] No witness host reference found in the cluster's persisted vSAN configuration. Nothing to clear."
        Disconnect-VIServer -Server $vCenterFQDN -Force -Confirm:$false
        $StopWatch.Stop()
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
        Return
    }

    Foreach ($witness in $witnessInfo) {
        LogMessage -type INFO -message "[$clusterName] Removing stale witness reference - Host MoRef: $($witness.Host.Value), UnicastAgentAddr: $($witness.UnicastAgentAddr)"
        $taskMoRef = $stretchedClusterSystem.VSANVcRemoveWitnessHost($clusterMoRef, $witness.Host, $witness.UnicastAgentAddr)

        # VSANVc* mutation calls on this vSAN VC internal API return a ManagedObjectReference to a Task;
        # confirm the type before waiting on it rather than assuming, since this is an undocumented/private API.
        if ($taskMoRef.Type -eq 'Task') {
            $task = Get-View -Id $taskMoRef
            Do {
                Start-Sleep -Seconds 2
                $task.UpdateViewData("Info")
            } While ($task.Info.State -in "running", "queued")
            If ($task.Info.State -eq "success") {
                LogMessage -type INFO -message "[$clusterName] Witness reference removed successfully"
            } else {
                LogMessage -type ERROR -message "[$clusterName] Witness removal task ended with state '$($task.Info.State)': $($task.Info.Error.LocalizedMessage)"
            }
        } else {
            LogMessage -type INFO -message "[$clusterName] Witness removal call returned MoRef type '$($taskMoRef.Type)' (not a Task) -- treating as already complete"
        }
    }

    $remainingWitnessInfo = @($stretchedClusterSystem.VSANVcGetWitnessHosts($clusterMoRef))
    If ($remainingWitnessInfo.Count -eq 0) {
        LogMessage -type INFO -message "[$clusterName] Verified no witness host references remain"
    } else {
        LogMessage -type WARNING -message "[$clusterName] $($remainingWitnessInfo.Count) witness host reference(s) still present after removal attempt."
    }

    Disconnect-VIServer -Server $vCenterFQDN -Force -Confirm:$false
    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
}
Export-ModuleMember -Function Remove-VsanStretchedClusterWitness

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
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
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
    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
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
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
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
    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
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
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
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
    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
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
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
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
    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
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
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
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
    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
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
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
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
    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
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
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
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
    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
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
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
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
    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
}
Export-ModuleMember -Function Restore-ClusterVMTags

Function Clear-vCenterAlarms
{
    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type INFO -Message "[$jumpboxName] Connecting to $vCenterFQDN"
    $vcenterConnection = Connect-VIServer -server $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword

    LogMessage -type INFO -Message "[$vcenterFQDN] Clearing all Alarms"
    # Get the AlarmManager view
    $alarmManager = Get-View AlarmManager

    # Create the mandatory Filter Specification object expected by the API
    $filter = New-Object VMware.Vim.AlarmFilterSpec

    # Execute the bulk clear (Passing NO specific flags inside the filter clears ALL active alarms)
    try {
        $alarmManager.ClearTriggeredAlarms($filter)
        LogMessage -type INFO -message "[$vcenterFQDN] Successfully cleared all active alarms"
    } catch {
        LogMessage -type ERROR -message "$vcenterFQDN] Failed to clear alarms: $_"
    }
    Disconnect-VIServer * -confirm:$false
    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
}
Export-ModuleMember -Function Clear-vCenterAlarms

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
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
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
    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
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
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
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
                $portgroup = (Get-VDPortGroup | Where-Object {$_.ExtensionData.MoRef.Value -eq $vmDeploymentConfig.management_network_id} | Select-Object Name).Name
                $clusterVdsName = (Get-View -Id (Get-View -Id "DistributedVirtualPortgroup-$($vmDeploymentConfig.management_network_id)").Config.DistributedVirtualSwitch).Name

                #Create Dummy VM
                LogMessage -type INFO -message "[$($edge.display_name)] Preparing to Update Placement References"
                If (!$portgroup) {
                    $portgroup = (($extractedSddcData.workloadDomains.vsphereClusterDetails | Where-Object { $_.name -eq $clusterName }).vdsdetails.portgroups | Where-Object { $_.transportType -eq 'MANAGEMENT' }).NAME
                    $clusterVdsName = (($extractedSddcData.workloadDomains.vsphereClusterDetails | Where-Object { $_.name -eq $clusterName }).vdsdetails | Where-Object { $_.portgroups.transportType -eq 'MANAGEMENT' }).dvsName
                }
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
    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
}
Export-ModuleMember -Function Invoke-NSXEdgeClusterRecovery

Function Invoke-NSXEdgeClusterRecoverySelective {
    <#
    .SYNOPSIS
    Selectively redeploys NSX Edges from the provided vSphere Cluster based on user selection

    .DESCRIPTION
    The Invoke-NSXEdgeClusterRecoverySelective cmdlet discovers all NSX Edges associated with the provided vSphere Cluster, presents a list showing which Edge VMs are present or missing from the vCenter inventory, and allows the user to enter a comma-separated list of IDs to selectively redeploy only the missing Edges

    .EXAMPLE
    Invoke-NSXEdgeClusterRecoverySelective -nsxManagerFqdn "sfo-m01-nsx01.sfo.rainpole.io" -nsxManagerAdmin "admin" -nsxManagerAdminPassword "VMw@re1!VMw@re1!" -vCenterFQDN "sfo-m01-vc01.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01" -extractedSDDCDataFile ".\extracted-sddc-data.json"

    .PARAMETER nsxManagerFqdn
    FQDN of the NSX Manager whose Edges need to be redeployed

    .PARAMETER nsxManagerAdmin
    Admin user of the NSX Manager whose Edges need to be redeployed

    .PARAMETER nsxManagerAdminPassword
    Admin Password of the NSX Manager whose Edges need to be redeployed

    .PARAMETER vCenterFQDN
    FQDN of the vCenter instance that hosts the cluster whose Edges need to be redeployed

    .PARAMETER vCenterAdmin
    Admin user of the vCenter instance that hosts the cluster whose Edges need to be redeployed

    .PARAMETER vCenterAdminPassword
    Admin password for the vCenter instance that hosts the cluster whose Edges need to be redeployed

    .PARAMETER clusterName
    Name of the vSphere cluster instance whose Edges need to be redeployed

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
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $vcenterConnection = Connect-VIServer -server $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword

    $resourcePools = @(Get-Cluster -name $clusterName | Get-ResourcePool | Where-Object { $_.name -ne "Resources" })
    $cluster = (Get-Cluster -name $clusterName)

    $edgeLocations = @()
    Foreach ($resourcePool in $resourcePools) {
        $edgeLocations += [PSCustomObject]@{
            'Type'  = 'ResourcePool'
            'Name'  = $resourcePool.Name
            'moRef' = $resourcePool.extensionData.moref.value
        }
    }
    $edgeLocations += [PSCustomObject]@{
        'Type'  = 'Cluster'
        'Name'  = $cluster.Name
        'moRef' = $cluster.extensionData.moref.value
    }

    $headers = VCFIRCreateHeader -username $nsxManagerAdmin -password $nsxManagerAdminPassword
    $uri = "https://$nsxManagerFqdn/api/v1/transport-nodes/"
    $transportNodeContents = (Invoke-WebRequest -Method GET -URI $uri -ContentType application/json -headers $headers).content | ConvertFrom-Json

    # Build a complete list of all edges across all locations
    $allEdges = @()
    Foreach ($edgeLocation in $edgeLocations) {
        $locationEdges = ($transportNodeContents.results | Where-Object { ($_.node_deployment_info.resource_type -eq "EdgeNode") -and ($_.node_deployment_info.deployment_config.vm_deployment_config.compute_id -eq $edgeLocation.MoRef) }) | Sort-Object -Property display_name
        Foreach ($edge in $locationEdges) {
            $allEdges += [PSCustomObject]@{
                'Edge'         = $edge
                'LocationType' = $edgeLocation.Type
                'LocationName' = $edgeLocation.Name
            }
        }
    }

    If ($allEdges.Count -eq 0) {
        LogMessage -type INFO -message "[$nsxManagerFqdn] No Edges found associated with cluster $clusterName"
        Disconnect-VIServer * -confirm:$false
        $StopWatch.Stop()
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
        return
    }

    # Build display object showing presence status of each edge
    $edgeDisplayObject = @()
    $edgeDisplayObject += [PSCustomObject]@{
        'ID'       = "ID"
        'Location' = "Location"
        'Edge'     = "Edge Display Name"
        'Present'  = "VM in vCenter"
    }
    $edgeDisplayObject += [PSCustomObject]@{
        'ID'       = "--"
        'Location' = "--------------------"
        'Edge'     = "--------------------"
        'Present'  = "--------------"
    }
    $edgeIndex = 1
    $indexedEdges = @()
    Foreach ($edgeEntry in $allEdges) {
        $vmPresent = Get-VM -Name $edgeEntry.Edge.display_name -ErrorAction SilentlyContinue
        $presentString = If ($vmPresent) { "Yes" } Else { "No" }
        $edgeDisplayObject += [PSCustomObject]@{
            'ID'       = $edgeIndex
            'Location' = "$($edgeEntry.LocationType): $($edgeEntry.LocationName)"
            'Edge'     = $edgeEntry.Edge.display_name
            'Present'  = $presentString
        }
        $indexedEdges += [PSCustomObject]@{
            'ID'           = $edgeIndex
            'Edge'         = $edgeEntry.Edge
            'LocationType' = $edgeEntry.LocationType
            'LocationName' = $edgeEntry.LocationName
            'VmPresent'    = [bool]$vmPresent
        }
        $edgeIndex++
    }

    Write-Host ""
    $edgeDisplayObject | Format-Table -Property @{Expression = " " }, ID, Location, Edge, Present -AutoSize -HideTableHeaders | Out-String | ForEach-Object { $_.Trim("`r", "`n") }
    Write-Host ""
    Write-Host " Enter a comma-separated list of Edge IDs to recover (e.g. 1,3), or C to Cancel: " -ForegroundColor Yellow -NoNewline
    $userInput = Read-Host

    If ($userInput -match "^[Cc]$") {
        LogMessage -type INFO -message "[$jumpboxName] Recovery cancelled by user"
        Disconnect-VIServer * -confirm:$false
        $StopWatch.Stop()
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
        return
    }

    $selectedIDs = $userInput -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -match "^\d+$" } | ForEach-Object { [int]$_ }
    $selectedEdges = $indexedEdges | Where-Object { $_.ID -in $selectedIDs }

    If ($selectedEdges.Count -eq 0) {
        LogMessage -type INFO -message "[$jumpboxName] No valid Edge IDs selected. Exiting"
        Disconnect-VIServer * -confirm:$false
        $StopWatch.Stop()
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
        return
    }

    Foreach ($selectedEdge in $selectedEdges) {
        $edge = $selectedEdge.Edge
        LogMessage -type INFO -message "[$($edge.display_name)] Getting Placement References"
        $uri = "https://$nsxManagerFqdn/api/v1/transport-nodes/$($edge.node_id)"
        $edgeConfig = (Invoke-WebRequest -Method GET -URI $uri -ContentType application/json -headers $headers).content | ConvertFrom-Json
        $vmDeploymentConfig = $edgeConfig.node_deployment_info.deployment_config.vm_deployment_config
        $NumCpu = $vmDeploymentConfig.resource_allocation.cpu_count
        $memoryGB = $vmDeploymentConfig.resource_allocation.memory_allocation_in_mb / 1024
        $cpuShareLevel = (($vmDeploymentConfig.reservation_info.cpu_reservation.reservation_in_shares -split ("_"))[0]).tolower()
        $attachedNetworks = $vmDeploymentConfig.data_network_ids
        $portgroup = (Get-VDPortGroup | Where-Object {$_.ExtensionData.MoRef.Value -eq $vmDeploymentConfig.management_network_id} | Select-Object Name).Name
        $clusterVdsName = (Get-View -Id (Get-View -Id "DistributedVirtualPortgroup-$($vmDeploymentConfig.management_network_id)").Config.DistributedVirtualSwitch).Name

        LogMessage -type INFO -message "[$($edge.display_name)] Preparing to Update Placement References"
        If (!$portgroup) {
            $portgroup = (($extractedSddcData.workloadDomains.vsphereClusterDetails | Where-Object { $_.name -eq $clusterName }).vdsdetails.portgroups | Where-Object { $_.transportType -eq 'MANAGEMENT' }).NAME
            $clusterVdsName = (($extractedSddcData.workloadDomains.vsphereClusterDetails | Where-Object { $_.name -eq $clusterName }).vdsdetails | Where-Object { $_.portgroups.transportType -eq 'MANAGEMENT' }).dvsName
        }
        $datastore = ($extractedSddcData.workloadDomains.vsphereClusterDetails | Where-Object { $_.name -eq $clusterName }).primaryDatastoreName

        If ($selectedEdge.LocationType -eq "ResourcePool") {
            New-VM -VMhost (Get-Cluster -name $clusterName | Get-VMHost | Get-Random) -Name $edge.display_name -Datastore $datastore -resourcePool $selectedEdge.LocationName -DiskGB 200 -DiskStorageFormat Thin -MemoryGB $MemoryGB -NumCpu $NumCpu -portgroup $portgroup -GuestID "ubuntu64Guest" -Confirm:$false | Out-Null
        } else {
            New-VM -VMhost (Get-Cluster -name $clusterName | Get-VMHost | Get-Random) -Name $edge.display_name -Datastore $datastore -DiskGB 200 -DiskStorageFormat Thin -MemoryGB $MemoryGB -NumCpu $NumCpu -portgroup $portgroup -GuestID "ubuntu64Guest" -Confirm:$false | Out-Null
        }
        do {
            Start-Sleep 1
        } until (Get-VM -Name $edge.display_name -ErrorAction SilentlyContinue)
        Get-VM -Name $edge.display_name | Get-VMResourceConfiguration | Set-VMResourceConfiguration -MemReservationGB $memoryGB | Out-Null
        Get-VM -Name $edge.display_name | Get-VMResourceConfiguration | Set-VMResourceConfiguration -CpuSharesLevel $cpuShareLevel | Out-Null
        Foreach ($attachedNetwork in $attachedNetworks) {
            $attachedNetworkPg = Get-VDPortGroup -id ("DistributedVirtualPortgroup-" + $attachedNetwork)
            Get-VM -Name $edge.display_name | New-NetworkAdapter -portGroup $attachedNetworkPg -StartConnected -Type Vmxnet3 -Confirm:$false | Out-Null
        }
        $vmID = (Get-VM -Name $edge.display_name).extensionData.moref.value

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
        $vmDeploymentConfigJson = $edgeRefreshObject | ConvertTo-Json -depth 10
        $uri = "https://$nsxManagerFqdn/api/v1/transport-nodes/$($edge.node_id)?action=addOrUpdatePlacementReferences"
        $edgeReConfig = (Invoke-WebRequest -Method POST -URI $uri -ContentType application/json -body $vmDeploymentConfigJson -headers $headers).content | ConvertFrom-Json

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
    LogMessage -type NOTE -message "[$jumpboxName] Selected Edge Redeployments have been initiated. Please monitor in NSX UI for completion"
    Disconnect-VIServer * -confirm:$false
    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
}
Export-ModuleMember -Function Invoke-NSXEdgeClusterRecoverySelective

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
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
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
    $StopWatch.Stop()
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $($Stopwatch.Elapsed.Minutes) minutes and $($Stopwatch.Elapsed.seconds) seconds"
}
Export-ModuleMember -Function Add-AdditionalNSXManagers

Function Wait-NSXTEdgeDeployment {
    Param (
        [Parameter (Mandatory = $true)][ValidateNotNullOrEmpty()][String]$nsxtManagerFqdn,
        [Parameter (Mandatory = $true)][ValidateNotNullOrEmpty()][String]$nsxtUsername,
        [Parameter (Mandatory = $true)][ValidateNotNullOrEmpty()][String]$nsxtPassword,
        [Parameter (Mandatory = $true)][ValidateNotNullOrEmpty()][String]$edgeNamePattern,
        [Parameter (Mandatory = $false)][Int]$expectedEdgeCount = 2,
        [Parameter (Mandatory = $false)][Int]$pollIntervalSeconds = 30,
        [Parameter (Mandatory = $false)][Int]$timeoutMinutes = 30
    )

    $headers = VCFIRCreateHeader -username $nsxtUsername -password $nsxtPassword
    $startTime = Get-Date
    $timeout = New-TimeSpan -Minutes $timeoutMinutes

    LogMessage -Type WAIT -Message "[$nsxtManagerFqdn] Waiting for $expectedEdgeCount Edge(s) matching '$edgeNamePattern*' to deploy and reach UP status"

    Do {
        Try {
            $upCount = 0
            $foundCount = 0

            # Get edges from Management API
            $edgeUri = "https://$nsxtManagerFqdn/api/v1/transport-nodes?node_types=EdgeNode"
            $edgeResponse = Invoke-WebRequest -Method GET -URI $edgeUri -ContentType "application/json" -Headers $headers
            $allEdges = ($edgeResponse.Content | ConvertFrom-Json).results

            $targetEdges = $allEdges | Where-Object { $_.display_name -like "$edgeNamePattern*" }

            If ($targetEdges) {
                $foundCount = $targetEdges.Count

                ForEach ($edge in $targetEdges) {
                    Try {
                        $statusUri = "https://$nsxtManagerFqdn/api/v1/transport-nodes/$($edge.id)/status"
                        $statusResponse = Invoke-WebRequest -Method GET -URI $statusUri -ContentType "application/json" -Headers $headers
                        $status = $statusResponse.Content | ConvertFrom-Json

                        $nodeStatus = $status.status
                        $controlStatus = $status.control_connection_status.status

                        If ($nodeStatus -eq "UP" -and $controlStatus -eq "UP") {
                            $upCount++
                        }
                    }
                    Catch {
                        # Edge status not yet available, continue polling
                    }
                }

                If ($foundCount -ge $expectedEdgeCount -and $upCount -ge $expectedEdgeCount) {
                    LogMessage -Type INFO -Message "[$nsxtManagerFqdn] $expectedEdgeCount Edge(s) deployed successfully and connectivity is UP"
                    Return
                }
            }
        }
        Catch {
            # Silent catch during polling - edges may not exist yet
        }

        $currentTime = Get-Date
        If (($currentTime - $startTime) -ge $timeout) {
            LogMessage -Type ERROR -Message "[$nsxtManagerFqdn] Timeout reached after $timeoutMinutes minutes waiting for Edge deployment"
            Return
        }

        Start-Sleep -Seconds $pollIntervalSeconds

    } While ($true)
}
Export-ModuleMember -Function Wait-NSXTEdgeDeployment
#EndRegion NSXT Functions

#Region Services Runtime
Function ConvertFrom-VcfmsTaskTimestampToUtc {
    <#
    Normalizes task timestamps from the VCFMS API to UTC for elapsed-time math.

    Invoke-RestMethod often deserializes ISO-8601 instants as [DateTime] with Kind=Unspecified.
    [DateTime]::ToUniversalTime() treats Unspecified as *local*, which skews elapsed by the
    zone offset (often one hour vs UTC). VCFMS task times are UTC; Unspecified is treated as UTC.
    #>
    Param ($Timestamp)
    if ($null -eq $Timestamp) { return $null }
    try {
        if ($Timestamp -is [DateTimeOffset]) {
            return $Timestamp.UtcDateTime
        }
        if ($Timestamp -is [DateTime]) {
            switch ($Timestamp.Kind) {
                ([DateTimeKind]::Utc) { return $Timestamp }
                ([DateTimeKind]::Local) { return $Timestamp.ToUniversalTime() }
                default {
                    return [DateTime]::SpecifyKind($Timestamp, [DateTimeKind]::Utc)
                }
            }
        }
        $s = ([string]$Timestamp).Trim()
        if ([string]::IsNullOrWhiteSpace($s)) { return $null }
        return [DateTimeOffset]::Parse($s, [CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
            [System.Globalization.DateTimeStyles]::AdjustToUniversal).UtcDateTime
    } catch {
        return $null
    }
}

Function Format-TimeSpanElapsedColons {
    Param ([TimeSpan]$Span)
    if ($Span -lt [TimeSpan]::Zero) { $Span = [TimeSpan]::Zero }
    '{0:00}:{1:00}:{2:00}' -f [int][Math]::Floor($Span.TotalHours), $Span.Minutes, $Span.Seconds
}

Function Remove-SddcManagerVspClusterEntry {
    <#
    .SYNOPSIS
    Removes a vsp_cluster entry and its corresponding credential from the SDDC Manager Postgres database.

    .DESCRIPTION
    The Remove-SddcManagerVspClusterEntry cmdlet connects to the SDDC Manager appliance via SSH as the vcf user, elevates to root, queries the Postgres platform database for the vsp_cluster entry matching the specified type (MANAGEMENT or CONSUMPTION), shows a short summary of the rows that will be removed, prompts for confirmation, then deletes both the cluster row and its associated service credential (where username = 'vsp/<vsp_cluster_id>/svc-sddc-manager-admin').

    .EXAMPLE
    Remove-SddcManagerVspClusterEntry -SddcManagerFqdn "sfo-vcf01.sfo.rainpole.io" -VcfUserPassword "VMw@re1!VMw@re1!" -RootPassword "VMw@re1!VMw@re1!" -ClusterType "MANAGEMENT"

    .EXAMPLE
    Remove-SddcManagerVspClusterEntry -SddcManagerFqdn "sfo-vcf01.sfo.rainpole.io" -VcfUserPassword "VMw@re1!VMw@re1!" -RootPassword "VMw@re1!VMw@re1!" -ClusterType "CONSUMPTION"

    .PARAMETER SddcManagerFqdn
    FQDN of the SDDC Manager appliance to connect to.

    .PARAMETER VcfUserPassword
    Password for the vcf SSH user on the SDDC Manager appliance.

    .PARAMETER RootPassword
    Root password for the SDDC Manager appliance (used for su elevation).

    .PARAMETER ClusterType
    Type of vsp_cluster entry to remove. Valid values are MANAGEMENT or CONSUMPTION.
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $SddcManagerFqdn,
        [Parameter(Mandatory = $true)][String] $VcfUserPassword,
        [Parameter(Mandatory = $true)][String] $RootPassword,
        [Parameter(Mandatory = $true)][ValidateSet("MANAGEMENT", "CONSUMPTION")][String] $ClusterType
    )

    $jumpboxName = hostname
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    # Establish SSH connection as vcf user
    LogMessage -type INFO -message "[$jumpboxName] Establishing SSH connection to $SddcManagerFqdn"
    $SecurePassword = ConvertTo-SecureString -String $VcfUserPassword -AsPlainText -Force
    $mycreds = New-Object System.Management.Automation.PSCredential ('vcf', $SecurePassword)
    $inmem = New-SSHMemoryKnownHost
    New-SSHTrustedHost -KnownHostStore $inmem -HostName $SddcManagerFqdn -FingerPrint ((Get-SSHHostKey -ComputerName $SddcManagerFqdn).fingerprint) | Out-Null
    Do {
        $sshSession = New-SSHSession -ComputerName $SddcManagerFqdn -Credential $mycreds -KnownHost $inmem
    } Until ($sshSession)

    # Create shell stream with wide terminal to avoid line-wrapping corruption
    $stream = New-SSHShellStream -SSHSession $sshSession -TerminalName "xterm" -Columns 250
    Start-Sleep 1
    $stream.Read() | Out-Null

    # Elevate to root
    $stream.WriteLine("su -")
    Start-Sleep 2
    $stream.WriteLine("$RootPassword")
    Start-Sleep 2
    $stream.Read() | Out-Null

    # Filter to strip shell prompts and echo'd commands from SSH output
    $cleanSshOutput = {
        param([String]$raw)
        ($raw -split "`n" | Where-Object {
            $_ -notmatch 'root@' -and
            $_ -notmatch 'vcf@' -and
            $_ -notmatch 'echo\s+"' -and
            $_ -notmatch '^\s*\$\s*$'
        }) -join "`n"
    }

    # Query the vsp_cluster table for the entry matching the specified type
    LogMessage -type INFO -message "[$SddcManagerFqdn] Querying vsp_cluster table for $ClusterType entry"
    $stream.WriteLine("echo `"SELECT vsp_cluster_id FROM vsp_cluster WHERE type='$ClusterType';`" | psql -U postgres -h localhost -d platform -t -A")
    Start-Sleep 5
    $rawOutput = $stream.Read()

    # Parse the UUID from the output
    $guidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    $vspClusterId = ($rawOutput | Select-String -Pattern $guidPattern -AllMatches).Matches | Select-Object -First 1 -ExpandProperty Value

    if (-not $vspClusterId) {
        LogMessage -type WARNING -message "[$SddcManagerFqdn] No $ClusterType entry found in vsp_cluster table. Nothing to delete."
        LogMessage -type INFO -message "[$SddcManagerFqdn] Raw output for diagnostics:"
        Write-Host (& $cleanSshOutput $rawOutput)
        Remove-SSHSession -SSHSession $sshSession | Out-Null
        return
    }

    $credentialUsername = "vsp/$vspClusterId/svc-sddc-manager-admin"

    # Summary only (no full table dump); user must confirm before any DELETE runs
    Write-Host ""
    Write-Host " Summary - the following will be deleted on $SddcManagerFqdn" -ForegroundColor Yellow
    Write-Host "   Cluster type:     $ClusterType"
    Write-Host "   vsp_cluster_id:   $vspClusterId"
    Write-Host "   Credential user:  $credentialUsername"
    Write-Host ""
    Do {
        Write-Host " Proceed with deletion? (Y/N): " -ForegroundColor Yellow -NoNewline
        $confirmation = Read-Host
    } Until ($confirmation -in @("Y", "y", "N", "n"))

    if ($confirmation -in @("N", "n")) {
        LogMessage -type INFO -message "[$SddcManagerFqdn] Operation cancelled by user."
        Remove-SSHSession -SSHSession $sshSession | Out-Null
        return
    }

    # Delete the entry from vsp_cluster
    LogMessage -type INFO -message "[$SddcManagerFqdn] Deleting $ClusterType entry from vsp_cluster"
    $stream.WriteLine("echo `"DELETE FROM vsp_cluster WHERE vsp_cluster_id='$vspClusterId';`" | psql -U postgres -h localhost -d platform")
    Start-Sleep 5
    $deleteClusterOutput = $stream.Read()
    $cleanDeleteCluster = & $cleanSshOutput $deleteClusterOutput
    Write-Host $cleanDeleteCluster
    LogMessage -type INFO -message "[$SddcManagerFqdn] vsp_cluster DELETE result: $($cleanDeleteCluster.Trim())"

    # Delete the corresponding credential by username
    LogMessage -type INFO -message "[$SddcManagerFqdn] Deleting credential with username: $credentialUsername"
    $stream.WriteLine("echo `"DELETE FROM credential WHERE username='$credentialUsername';`" | psql -U postgres -h localhost -d platform")
    Start-Sleep 5
    $deleteCredOutput = $stream.Read()
    $cleanDeleteCred = & $cleanSshOutput $deleteCredOutput
    Write-Host $cleanDeleteCred
    LogMessage -type INFO -message "[$SddcManagerFqdn] credential DELETE result: $($cleanDeleteCred.Trim())"

    # Close SSH session
    Remove-SSHSession -SSHSession $sshSession | Out-Null

    LogMessage -type INFO -message "[$SddcManagerFqdn] $ClusterType vsp_cluster_id was: $vspClusterId"
    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
    return $vspClusterId
}
Export-ModuleMember -Function Remove-SddcManagerVspClusterEntry

Function Update-DomainDatastoreID {
    <#
    .SYNOPSIS
    Updates the primary_datastore_source_id in the SDDC Manager platform database for a specified cluster.

    .DESCRIPTION
    The Update-DomainDatastoreID cmdlet locates the workload domain whose vCenter matches the supplied FQDN,
    finds the named cluster within that domain, reads its primary datastore name from the extracted SDDC data,
    queries vCenter for the current MoRef of that datastore, then connects to the SDDC Manager appliance via
    SSH and updates the primary_datastore_source_id column in the cluster table. If the value is already
    correct no change is made. A confirmation prompt is shown before any change is written.

    .EXAMPLE
    Update-DomainDatastoreID -extractedSDDCDataFile ".\extracted-sddc-data.json" -vCenterFQDN "sfo-m01-vc01.sfo.rainpole.io" -clusterName "sfo-m01-cl01" -VcfUserPassword "VMw@re1!VMw@re1!" -RootPassword "VMw@re1!VMw@re1!"

    .PARAMETER extractedSDDCDataFile
    Relative or absolute path to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup).

    .PARAMETER vCenterFQDN
    FQDN of the vCenter whose associated domain contains the target cluster.

    .PARAMETER clusterName
    Name of the vSphere cluster whose primary_datastore_source_id should be updated.

    .PARAMETER VcfUserPassword
    Password for the vcf SSH user on the SDDC Manager appliance.

    .PARAMETER RootPassword
    Root password for the SDDC Manager appliance (used for su elevation).
    #>

    Param(
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $VcfUserPassword,
        [Parameter (Mandatory = $true)][String] $RootPassword
    )

    $jumpboxName = hostname
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    # Load extracted SDDC data
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $SddcManagerFqdn = $extractedSddcData.sddcManager.fqdn
    if (-not $SddcManagerFqdn) {
        LogMessage -type ERROR -message "[$jumpboxName] Could not determine SDDC Manager FQDN from extracted data"
        return
    }

    # Locate the domain for the supplied vCenter FQDN
    $workloadDomain = $extractedSddcData.workloadDomains | Where-Object { $_.vCenterDetails.fqdn -eq $vCenterFQDN }
    if (-not $workloadDomain) {
        LogMessage -type ERROR -message "[$jumpboxName] No workload domain found with vCenter FQDN '$vCenterFQDN' in extracted SDDC data"
        return
    }

    # Locate the named cluster within that domain
    $domainCluster = $workloadDomain.vsphereClusterDetails | Where-Object { $_.name -eq $clusterName }
    if (-not $domainCluster) {
        LogMessage -type ERROR -message "[$jumpboxName] No cluster named '$clusterName' found in domain '$($workloadDomain.domainName)'"
        return
    }

    $clusterId = $domainCluster.id
    $datastoreName = $domainCluster.primaryDatastoreName

    if (-not $datastoreName) {
        LogMessage -type ERROR -message "[$jumpboxName] No primaryDatastoreName found in extracted data for cluster '$clusterName'. Ensure Update-ExtractedSDDCData has been run."
        return
    }

    $vCenterAdmin = ($extractedSddcData.passwords | Where-Object { ($_.credentialType -eq "SSO") -and ($_.entityName -eq $vCenterFQDN) -and ($_.entityType -eq "PSC") }).username
    $vCenterAdminPassword = ($extractedSddcData.passwords | Where-Object { ($_.credentialType -eq "SSO") -and ($_.entityName -eq $vCenterFQDN) -and ($_.entityType -eq "PSC") }).password

    if (-not $vCenterAdmin -or -not $vCenterAdminPassword) {
        LogMessage -type ERROR -message "[$vCenterFQDN] Could not find SSO credentials for vCenter in extracted data"
        return
    }

    LogMessage -type INFO -message "[$jumpboxName] Domain: $($workloadDomain.domainName) | Cluster: $clusterName (id: $clusterId)"
    LogMessage -type INFO -message "[$jumpboxName] Primary datastore name from extracted data: $datastoreName"

    # Connect to vCenter and resolve the datastore MoRef
    LogMessage -type INFO -message "[$vCenterFQDN] Connecting to vCenter"
    Connect-VIServer -Server $vCenterFQDN -User $vCenterAdmin -Password $vCenterAdminPassword -ErrorAction Stop | Out-Null

    $datastore = Get-Datastore -Name $datastoreName -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $datastore) {
        LogMessage -type ERROR -message "[$vCenterFQDN] Datastore '$datastoreName' not found in vCenter"
        Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
        return
    }

    $newDatastoreMoRef = $datastore.ExtensionData.moref.value
    LogMessage -type INFO -message "[$vCenterFQDN] Datastore '$datastoreName' resolved with MoRef: $newDatastoreMoRef"
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false

    # Establish SSH connection to SDDC Manager as vcf user
    LogMessage -type INFO -message "[$SddcManagerFqdn] Establishing SSH connection"
    $SecurePassword = ConvertTo-SecureString -String $VcfUserPassword -AsPlainText -Force
    $mycreds = New-Object System.Management.Automation.PSCredential ('vcf', $SecurePassword)
    $inmem = New-SSHMemoryKnownHost
    New-SSHTrustedHost -KnownHostStore $inmem -HostName $SddcManagerFqdn -FingerPrint ((Get-SSHHostKey -ComputerName $SddcManagerFqdn).fingerprint) | Out-Null
    Do {
        $sshSession = New-SSHSession -ComputerName $SddcManagerFqdn -Credential $mycreds -KnownHost $inmem
    } Until ($sshSession)

    # Create shell stream with wide terminal to avoid line-wrapping corruption
    $stream = New-SSHShellStream -SSHSession $sshSession -TerminalName "xterm" -Columns 250
    Start-Sleep 1
    $stream.Read() | Out-Null

    # Elevate to root
    $stream.WriteLine("su -")
    Start-Sleep 2
    $stream.WriteLine("$RootPassword")
    Start-Sleep 2
    $stream.Read() | Out-Null

    # Filter to strip shell prompts and echo'd commands from SSH output
    $cleanSshOutput = {
        param([String]$raw)
        ($raw -split "`n" | Where-Object {
            $_ -notmatch 'root@' -and
            $_ -notmatch 'vcf@' -and
            $_ -notmatch 'echo\s+"' -and
            $_ -notmatch '^\s*\$\s*$'
        }) -join "`n"
    }

    # Query the cluster table by ID to get the current primary_datastore_source_id
    LogMessage -type INFO -message "[$SddcManagerFqdn] Querying cluster table for id '$clusterId'"
    $stream.WriteLine("echo `"SELECT primary_datastore_source_id FROM cluster WHERE id='$clusterId';`" | psql -U postgres -h localhost -d platform -t -A")
    Start-Sleep 5
    $rawOutput = $stream.Read()
    $currentDatastoreMoRef = ($rawOutput | Select-String -Pattern 'datastore-\d+' -AllMatches).Matches | Select-Object -First 1 -ExpandProperty Value

    if ($currentDatastoreMoRef -eq $newDatastoreMoRef) {
        LogMessage -type INFO -message "[$SddcManagerFqdn] primary_datastore_source_id is already '$newDatastoreMoRef' — nothing to do"
        Remove-SSHSession -SSHSession $sshSession | Out-Null
        $StopWatch.Stop()
        $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
        return
    }

    # Show summary and prompt for confirmation before writing any change
    Write-Host ""
    Write-Host " Summary - the following update will be applied on $SddcManagerFqdn" -ForegroundColor Yellow
    Write-Host "   Cluster name:              $clusterName"
    Write-Host "   Cluster id:                $clusterId"
    Write-Host "   Current datastore MoRef:   $(if ($currentDatastoreMoRef) { $currentDatastoreMoRef } else { '(not set / NULL)' })"
    Write-Host "   New datastore MoRef:       $newDatastoreMoRef"
    Write-Host "   Datastore name:            $datastoreName"
    Write-Host ""
    Do {
        Write-Host " Proceed with update? (Y/N): " -ForegroundColor Yellow -NoNewline
        $confirmation = Read-Host
    } Until ($confirmation -in @("Y", "y", "N", "n"))

    if ($confirmation -in @("N", "n")) {
        LogMessage -type INFO -message "[$SddcManagerFqdn] Operation cancelled by user."
        Remove-SSHSession -SSHSession $sshSession | Out-Null
        return
    }

    # Execute the UPDATE
    LogMessage -type INFO -message "[$SddcManagerFqdn] Updating primary_datastore_source_id for cluster '$clusterName'"
    $stream.WriteLine("echo `"UPDATE cluster SET primary_datastore_source_id='$newDatastoreMoRef' WHERE id='$clusterId';`" | psql -U postgres -h localhost -d platform")
    Start-Sleep 5
    $updateOutput = $stream.Read()
    $cleanUpdate = & $cleanSshOutput $updateOutput
    LogMessage -type INFO -message "[$SddcManagerFqdn] UPDATE result: $($cleanUpdate.Trim())"

    # Verify the update
    LogMessage -type INFO -message "[$SddcManagerFqdn] Verifying update"
    $stream.WriteLine("echo `"SELECT primary_datastore_source_id FROM cluster WHERE id='$clusterId';`" | psql -U postgres -h localhost -d platform -t -A")
    Start-Sleep 5
    $verifyRaw = $stream.Read()
    $verifiedMoRef = ($verifyRaw | Select-String -Pattern 'datastore-\d+' -AllMatches).Matches | Select-Object -First 1 -ExpandProperty Value
    if ($verifiedMoRef -eq $newDatastoreMoRef) {
        LogMessage -type INFO -message "[$SddcManagerFqdn] UPDATE verified: primary_datastore_source_id = $verifiedMoRef"
    } else {
        LogMessage -type WARNING -message "[$SddcManagerFqdn] UPDATE could not be verified. Expected: $newDatastoreMoRef | Got: $verifiedMoRef"
    }

    Remove-SSHSession -SSHSession $sshSession | Out-Null

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Update-DomainDatastoreID

Function Update-ClusterHostSourceIDs {
    <#
    .SYNOPSIS
    Updates the source_id (vCenter host MoRef) in the SDDC Manager platform database for each host
    currently in a specified cluster.

    .DESCRIPTION
    The Update-ClusterHostSourceIDs cmdlet locates the workload domain whose vCenter matches the
    supplied FQDN, finds the named cluster within that domain, connects to vCenter and enumerates
    every host currently in that cluster along with its current MoRef, then connects to the SDDC
    Manager appliance via SSH and compares each host's persisted source_id (in the public.host table,
    keyed by hostname) against the live MoRef. Hosts already matching are skipped. A summary of all
    planned changes is shown and confirmed once before any UPDATE is executed, then each change is
    applied and verified individually.

    This mirrors the same class of problem Update-DomainDatastoreID resolves for
    cluster.primary_datastore_source_id -- after a cluster's hosts are rebuilt (new vCenter, new
    MoRefs), SDDC Manager's database still references the pre-disaster MoRefs recorded in
    public.host.source_id, which is confirmed via the SDDC Manager Postgres backup to be a bare
    MoRef string (e.g. "host-87"), keyed by the SDDC Manager host UUID in public.host.id, with the
    full FQDN stored in public.host.hostname.

    .EXAMPLE
    Update-ClusterHostSourceIDs -extractedSDDCDataFile ".\extracted-sddc-data.json" -vCenterFQDN "sfo-w02-vc01.sfo.rainpole.io" -clusterName "sfo-w02-cl02" -VcfUserPassword "VMw@re1!VMw@re1!" -RootPassword "VMw@re1!VMw@re1!"

    .PARAMETER extractedSDDCDataFile
    Relative or absolute path to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup).

    .PARAMETER vCenterFQDN
    FQDN of the vCenter whose associated domain contains the target cluster.

    .PARAMETER clusterName
    Name of the vSphere cluster whose hosts' source_id values should be updated.

    .PARAMETER VcfUserPassword
    Password for the vcf SSH user on the SDDC Manager appliance.

    .PARAMETER RootPassword
    Root password for the SDDC Manager appliance (used for su elevation).
    #>

    Param(
        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $clusterName,
        [Parameter (Mandatory = $true)][String] $VcfUserPassword,
        [Parameter (Mandatory = $true)][String] $RootPassword
    )

    $jumpboxName = hostname
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    # Load extracted SDDC data
    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $SddcManagerFqdn = $extractedSddcData.sddcManager.fqdn
    if (-not $SddcManagerFqdn) {
        LogMessage -type ERROR -message "[$jumpboxName] Could not determine SDDC Manager FQDN from extracted data"
        return
    }

    # Locate the domain for the supplied vCenter FQDN
    $workloadDomain = $extractedSddcData.workloadDomains | Where-Object { $_.vCenterDetails.fqdn -eq $vCenterFQDN }
    if (-not $workloadDomain) {
        LogMessage -type ERROR -message "[$jumpboxName] No workload domain found with vCenter FQDN '$vCenterFQDN' in extracted SDDC data"
        return
    }

    # Locate the named cluster within that domain
    $domainCluster = $workloadDomain.vsphereClusterDetails | Where-Object { $_.name -eq $clusterName }
    if (-not $domainCluster) {
        LogMessage -type ERROR -message "[$jumpboxName] No cluster named '$clusterName' found in domain '$($workloadDomain.domainName)'"
        return
    }

    $vCenterAdmin = ($extractedSddcData.passwords | Where-Object { ($_.credentialType -eq "SSO") -and ($_.entityName -eq $vCenterFQDN) -and ($_.entityType -eq "PSC") }).username
    $vCenterAdminPassword = ($extractedSddcData.passwords | Where-Object { ($_.credentialType -eq "SSO") -and ($_.entityName -eq $vCenterFQDN) -and ($_.entityType -eq "PSC") }).password

    if (-not $vCenterAdmin -or -not $vCenterAdminPassword) {
        LogMessage -type ERROR -message "[$vCenterFQDN] Could not find SSO credentials for vCenter in extracted data"
        return
    }

    LogMessage -type INFO -message "[$jumpboxName] Domain: $($workloadDomain.domainName) | Cluster: $clusterName"

    # Connect to vCenter and enumerate every host currently in the cluster with its live MoRef
    LogMessage -type INFO -message "[$vCenterFQDN] Connecting to vCenter"
    Connect-VIServer -Server $vCenterFQDN -User $vCenterAdmin -Password $vCenterAdminPassword -ErrorAction Stop | Out-Null

    $clusterHosts = @(Get-Cluster -Name $clusterName -ErrorAction Stop | Get-VMHost -ErrorAction Stop)
    if ($clusterHosts.Count -eq 0) {
        LogMessage -type ERROR -message "[$vCenterFQDN] No hosts found in cluster '$clusterName'"
        Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
        return
    }

    $hostMoRefMap = @()
    Foreach ($vmHost in $clusterHosts) {
        $hostMoRefMap += [PSCustomObject]@{
            Hostname   = $vmHost.Name
            NewMoRef   = $vmHost.ExtensionData.moref.value
        }
        LogMessage -type INFO -message "[$vCenterFQDN] $($vmHost.Name) resolved with live MoRef: $($vmHost.ExtensionData.moref.value)"
    }
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false

    # Establish SSH connection to SDDC Manager as vcf user
    LogMessage -type INFO -message "[$SddcManagerFqdn] Establishing SSH connection"
    $SecurePassword = ConvertTo-SecureString -String $VcfUserPassword -AsPlainText -Force
    $mycreds = New-Object System.Management.Automation.PSCredential ('vcf', $SecurePassword)
    $inmem = New-SSHMemoryKnownHost
    New-SSHTrustedHost -KnownHostStore $inmem -HostName $SddcManagerFqdn -FingerPrint ((Get-SSHHostKey -ComputerName $SddcManagerFqdn).fingerprint) | Out-Null
    Do {
        $sshSession = New-SSHSession -ComputerName $SddcManagerFqdn -Credential $mycreds -KnownHost $inmem
    } Until ($sshSession)

    # Create shell stream with wide terminal to avoid line-wrapping corruption
    $stream = New-SSHShellStream -SSHSession $sshSession -TerminalName "xterm" -Columns 250
    Start-Sleep 1
    $stream.Read() | Out-Null

    # Elevate to root
    $stream.WriteLine("su -")
    Start-Sleep 2
    $stream.WriteLine("$RootPassword")
    Start-Sleep 2
    $stream.Read() | Out-Null

    # Filter to strip shell prompts and echo'd commands from SSH output
    $cleanSshOutput = {
        param([String]$raw)
        ($raw -split "`n" | Where-Object {
            $_ -notmatch 'root@' -and
            $_ -notmatch 'vcf@' -and
            $_ -notmatch 'echo\s+"' -and
            $_ -notmatch '^\s*\$\s*$'
        }) -join "`n"
    }

    # Query the host table for each host's current SDDC Manager id and source_id
    $plannedChanges = @()
    Foreach ($hostEntry in $hostMoRefMap) {
        LogMessage -type INFO -message "[$SddcManagerFqdn] Querying host table for '$($hostEntry.Hostname)'"
        $stream.WriteLine("echo `"SELECT id, source_id FROM host WHERE hostname='$($hostEntry.Hostname)';`" | psql -U postgres -h localhost -d platform -t -A")
        Start-Sleep 5
        $rawOutput = $stream.Read()

        $guidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
        $sddcManagerHostId = ($rawOutput | Select-String -Pattern $guidPattern -AllMatches).Matches | Select-Object -First 1 -ExpandProperty Value
        $currentSourceId = ($rawOutput | Select-String -Pattern 'host-\d+' -AllMatches).Matches | Select-Object -First 1 -ExpandProperty Value

        if (-not $sddcManagerHostId) {
            LogMessage -type WARNING -message "[$SddcManagerFqdn] No host row found with hostname='$($hostEntry.Hostname)'. Skipping."
            continue
        }

        if ($currentSourceId -eq $hostEntry.NewMoRef) {
            LogMessage -type INFO -message "[$($hostEntry.Hostname)] source_id already '$($hostEntry.NewMoRef)' -- nothing to do"
            continue
        }

        $plannedChanges += [PSCustomObject]@{
            Hostname          = $hostEntry.Hostname
            SddcManagerHostId = $sddcManagerHostId
            CurrentSourceId   = if ($currentSourceId) { $currentSourceId } else { '(not set / NULL)' }
            NewSourceId       = $hostEntry.NewMoRef
        }
    }

    if ($plannedChanges.Count -eq 0) {
        LogMessage -type INFO -message "[$SddcManagerFqdn] All host source_id values already match their live vCenter MoRef -- nothing to do"
        Remove-SSHSession -SSHSession $sshSession | Out-Null
        $StopWatch.Stop()
        $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
        return
    }

    # Show summary and prompt for confirmation before writing any change
    Write-Host ""
    Write-Host " Summary - the following updates will be applied on $SddcManagerFqdn" -ForegroundColor Yellow
    $plannedChanges | Format-Table -Property Hostname, SddcManagerHostId, CurrentSourceId, NewSourceId -AutoSize | Out-String | Write-Host
    Do {
        Write-Host " Proceed with update of $($plannedChanges.Count) host(s)? (Y/N): " -ForegroundColor Yellow -NoNewline
        $confirmation = Read-Host
    } Until ($confirmation -in @("Y", "y", "N", "n"))

    if ($confirmation -in @("N", "n")) {
        LogMessage -type INFO -message "[$SddcManagerFqdn] Operation cancelled by user."
        Remove-SSHSession -SSHSession $sshSession | Out-Null
        return
    }

    # Execute and verify each UPDATE
    Foreach ($change in $plannedChanges) {
        LogMessage -type INFO -message "[$($change.Hostname)] Updating source_id to '$($change.NewSourceId)'"
        $stream.WriteLine("echo `"UPDATE host SET source_id='$($change.NewSourceId)' WHERE id='$($change.SddcManagerHostId)';`" | psql -U postgres -h localhost -d platform")
        Start-Sleep 5
        $updateOutput = $stream.Read()
        $cleanUpdate = & $cleanSshOutput $updateOutput
        LogMessage -type INFO -message "[$($change.Hostname)] UPDATE result: $($cleanUpdate.Trim())"

        $stream.WriteLine("echo `"SELECT source_id FROM host WHERE id='$($change.SddcManagerHostId)';`" | psql -U postgres -h localhost -d platform -t -A")
        Start-Sleep 5
        $verifyRaw = $stream.Read()
        $verifiedSourceId = ($verifyRaw | Select-String -Pattern 'host-\d+' -AllMatches).Matches | Select-Object -First 1 -ExpandProperty Value
        if ($verifiedSourceId -eq $change.NewSourceId) {
            LogMessage -type INFO -message "[$($change.Hostname)] UPDATE verified: source_id = $verifiedSourceId"
        } else {
            LogMessage -type WARNING -message "[$($change.Hostname)] UPDATE could not be verified. Expected: $($change.NewSourceId) | Got: $verifiedSourceId"
        }
    }

    Remove-SSHSession -SSHSession $sshSession | Out-Null

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Update-ClusterHostSourceIDs

Function Invoke-SddcManagerSSHKeyRefresh {
    <#
    .SYNOPSIS
    Enables SSH on a workload domain's appliances or a cluster's ESXi hosts, then runs SDDC Manager's
    refreshsshkeys.py to refresh its stored known_hosts SSH keys for them.

    .DESCRIPTION
    The Invoke-SddcManagerSSHKeyRefresh cmdlet enables SSH on a target set chosen by which parameters
    are supplied:
      -workloadDomain -- resolves the named workload domain's vCenter appliance and NSX Manager
                         node(s) directly from the extracted SDDC data (no live vCenter connection
                         required), then enables SSH on the vCenter appliance (via its VAMI REST API)
                         and each NSX Manager node (via the NSX Manager API).
      -clusterName    -- connects to the vCenter identified by -vCenterFQDN/-vCenterAdmin/
                         -vCenterAdminPassword, resolves every ESXi host in the named cluster, and
                         enables SSH on each one via PowerCLI (Start-VMHostService on the TSM-SSH
                         service).
      -all            -- skips target resolution/SSH-enablement entirely and shows every known_hosts
                         entry SDDC Manager tracks, unfiltered. Mutually exclusive with -workloadDomain
                         and -clusterName.
    -workloadDomain and -clusterName may be supplied together in the same call (their SSH-enablement
    and output-filtering targets are additive); -all cannot be combined with either.

    It then uploads scripts\refreshsshkeys.py to /tmp on the SDDC Manager appliance, makes it
    executable, and runs it as `yes yes | python refreshsshkeys.py`. That script queries SDDC
    Manager's internal known_hosts API (covering every component SDDC Manager tracks -- all hosts,
    vCenter(s), NSX Manager(s)). Unless -all was used, the same hostname/FQDN targets enabled above are
    passed to the script's own --targets flag, so it only fetches/confirms/updates keys for those
    targets rather than every known_hosts entry; with -all, --targets is omitted and every entry is
    processed, matching the script's original behavior. Output filtering mirrors this: each line is
    only printed via LogMessage if it contains one of the enabled targets (or, with -all, unconditionally);
    the generic header/footer/status lines the script prints are always shown regardless of target.

    The script prompts once per mismatched key with "Are you sure you want to update <key type> key
    (yes/no)?", not once per run -- a single piped "yes" only answers the first such prompt, and every
    subsequent one then hits closed stdin and fails with "EOF when reading a line" (confirmed live: a
    cluster with multiple hosts each needing new keys failed on every prompt after the first). Using
    the `yes` utility (aliased to repeat the literal string "yes", since the prompt requires that exact
    word rather than "y") keeps answering every prompt for as long as the script keeps asking.

    .EXAMPLE
    Invoke-SddcManagerSSHKeyRefresh -workloadDomain "sfo-w02" -extractedSDDCDataFile ".\extracted-sddc-data.json" -VcfUserPassword "VMw@re1!VMw@re1!"

    .EXAMPLE
    Invoke-SddcManagerSSHKeyRefresh -vCenterFQDN "sfo-w02-vc01.sfo.rainpole.io" -vCenterAdmin "administrator@sfo-w02.local" -vCenterAdminPassword "VMw@re1!VMw@re1!" -clusterName "sfo-w02-cl02" -extractedSDDCDataFile ".\extracted-sddc-data.json" -VcfUserPassword "VMw@re1!VMw@re1!"

    .EXAMPLE
    Invoke-SddcManagerSSHKeyRefresh -workloadDomain "sfo-w02" -vCenterFQDN "sfo-w02-vc01.sfo.rainpole.io" -vCenterAdmin "administrator@sfo-w02.local" -vCenterAdminPassword "VMw@re1!VMw@re1!" -clusterName "sfo-w02-cl02" -extractedSDDCDataFile ".\extracted-sddc-data.json" -VcfUserPassword "VMw@re1!VMw@re1!"

    .EXAMPLE
    Invoke-SddcManagerSSHKeyRefresh -all -extractedSDDCDataFile ".\extracted-sddc-data.json" -VcfUserPassword "VMw@re1!VMw@re1!"

    .PARAMETER workloadDomain
    Name of the VCF workload domain whose vCenter appliance and NSX Manager(s) should be targeted. May
    be combined with -clusterName. Mutually exclusive with -all.

    .PARAMETER clusterName
    Name of the vSphere cluster whose ESXi hosts should be targeted. Requires -vCenterFQDN,
    -vCenterAdmin, and -vCenterAdminPassword. May be combined with -workloadDomain. Mutually exclusive
    with -all.

    .PARAMETER vCenterFQDN
    FQDN of the vCenter instance hosting -clusterName

    .PARAMETER vCenterAdmin
    SSO admin user of the vCenter instance hosting -clusterName

    .PARAMETER vCenterAdminPassword
    SSO admin password for the vCenter instance hosting -clusterName

    .PARAMETER all
    Skip target resolution/SSH-enablement and show every known_hosts entry SDDC Manager tracks,
    unfiltered. Mutually exclusive with -workloadDomain and -clusterName.

    .PARAMETER extractedSDDCDataFile
    Relative or absolute path to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup)

    .PARAMETER VcfUserPassword
    Password for the vcf SSH user on the SDDC Manager appliance
    #>

    Param(
        [Parameter (Mandatory = $true, ParameterSetName = "All")][Switch] $all,

        [Parameter (Mandatory = $false, ParameterSetName = "Targeted")][String] $workloadDomain,
        [Parameter (Mandatory = $false, ParameterSetName = "Targeted")][String] $vCenterFQDN,
        [Parameter (Mandatory = $false, ParameterSetName = "Targeted")][String] $vCenterAdmin,
        [Parameter (Mandatory = $false, ParameterSetName = "Targeted")][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $false, ParameterSetName = "Targeted")][String] $clusterName,

        [Parameter (Mandatory = $true)][String] $extractedSDDCDataFile,
        [Parameter (Mandatory = $true)][String] $VcfUserPassword
    )

    $jumpboxName = hostname
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    LogMessage -type INFO -message "[$jumpboxName] Reading Extracted Data"
    $extractedDataFilePath = (Resolve-Path -Path $extractedSDDCDataFile).path
    $extractedSddcData = Get-Content $extractedDataFilePath | ConvertFrom-JSON

    $SddcManagerFqdn = $extractedSddcData.sddcManager.fqdn
    if (-not $SddcManagerFqdn) {
        LogMessage -type ERROR -message "[$jumpboxName] Could not determine SDDC Manager FQDN from extracted data"
        return
    }

    $matchAllOutput = ($PSCmdlet.ParameterSetName -eq "All")

    if (-not $matchAllOutput) {
        if (-not $workloadDomain -and -not $clusterName) {
            LogMessage -type ERROR -message "[$jumpboxName] Specify -workloadDomain, -clusterName (with -vCenterFQDN/-vCenterAdmin/-vCenterAdminPassword), or -all"
            return
        }
        if ($clusterName -and (-not $vCenterFQDN -or -not $vCenterAdmin -or -not $vCenterAdminPassword)) {
            LogMessage -type ERROR -message "[$jumpboxName] -clusterName requires -vCenterFQDN, -vCenterAdmin, and -vCenterAdminPassword"
            return
        }
    }

    # Each entry in $sshTargets is one host/appliance whose SSH we enable below: a display Label plus
    # every token (FQDN, short name, VM name) that might identify it in refreshsshkeys.py's output.
    # Used later both to build the script's --targets argument and to interpret its output per target.
    # Left empty when -all is used, since that mode shows every known_hosts entry unfiltered.
    $sshTargets = @()

    if ($workloadDomain) {
        $domainByNameDetails = $extractedSddcData.workloadDomains | Where-Object { $_.domainName -eq $workloadDomain }
        if (-not $domainByNameDetails) {
            LogMessage -type ERROR -message "[$jumpboxName] No workload domain named '$workloadDomain' found in extracted SDDC data"
            return
        }

        $domainVCenterFqdn = $domainByNameDetails.vCenterDetails.fqdn
        LogMessage -type INFO -message "[$domainVCenterFqdn] Enabling SSH on the vCenter appliance"
        $vCenterRootPassword = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "VCENTER") -and ($_.domainName -eq $workloadDomain) -and ($_.credentialType -eq "SSH") }).password
        if (-not $vCenterRootPassword) {
            LogMessage -type ERROR -message "[$domainVCenterFqdn] Could not find a VCENTER/SSH credential for domain '$workloadDomain' in extracted data"
            return
        }
        $vamiHeaders = VCFIRCreateHeader -username "root" -password $vCenterRootPassword
        Invoke-WebRequest -Method PUT -Uri "https://$domainVCenterFqdn`:5480/rest/appliance/access/ssh" -Headers $vamiHeaders -ContentType "application/json" -Body '{"enabled":true}' -SkipCertificateCheck | Out-Null
        $sshTargets += [PSCustomObject]@{ Label = $domainVCenterFqdn; Tokens = @($domainVCenterFqdn, ($domainVCenterFqdn -split '\.')[0]) }

        $nsxNodes = @($domainByNameDetails.nsxNodeDetails)
        if ($nsxNodes.Count -eq 0) {
            LogMessage -type WARNING -message "[$workloadDomain] No NSX Manager nodes recorded for this domain in extracted data. Skipping NSX SSH enablement."
        } else {
            $nsxManagerAdmin = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "NSXT_MANAGER") -and ($_.domainName -eq $workloadDomain) -and ($_.username -eq "admin") }).username
            $nsxManagerAdminPassword = ($extractedSddcData.passwords | Where-Object { ($_.entityType -eq "NSXT_MANAGER") -and ($_.domainName -eq $workloadDomain) -and ($_.username -eq "admin") }).password
            $nsxHeaders = VCFIRCreateHeader -username $nsxManagerAdmin -password $nsxManagerAdminPassword
            Foreach ($nsxNode in $nsxNodes) {
                LogMessage -type INFO -message "[$($nsxNode.hostname)] Enabling SSH on NSX Manager node"
                Invoke-WebRequest -Method POST -Uri "https://$($nsxNode.hostname)/api/v1/node/services/ssh?action=start" -Headers $nsxHeaders -ContentType "application/json" -SkipCertificateCheck | Out-Null
                $sshTargets += [PSCustomObject]@{ Label = $nsxNode.hostname; Tokens = @($nsxNode.hostname, ($nsxNode.hostname -split '\.')[0], $nsxNode.vmName) }
            }
        }
    }

    if ($clusterName) {
        $domainByVCenterDetails = $extractedSddcData.workloadDomains | Where-Object { $_.vCenterDetails.fqdn -eq $vCenterFQDN }
        if (-not $domainByVCenterDetails) {
            LogMessage -type ERROR -message "[$jumpboxName] No workload domain found with vCenter FQDN '$vCenterFQDN' in extracted SDDC data"
            return
        }
        $domainCluster = $domainByVCenterDetails.vsphereClusterDetails | Where-Object { $_.name -eq $clusterName }
        if (-not $domainCluster) {
            LogMessage -type ERROR -message "[$jumpboxName] No cluster named '$clusterName' found in domain '$($domainByVCenterDetails.domainName)'"
            return
        }

        LogMessage -type INFO -message "[$vCenterFQDN] Connecting to vCenter"
        Connect-VIServer -Server $vCenterFQDN -User $vCenterAdmin -Password $vCenterAdminPassword -ErrorAction Stop | Out-Null

        LogMessage -type INFO -message "[$vCenterFQDN] Resolving hosts for cluster '$clusterName'"
        $targetVMHosts = @(Get-Cluster -Name $clusterName -ErrorAction Stop | Get-VMHost -ErrorAction Stop | Sort-Object -Property Name)

        Foreach ($vmHost in $targetVMHosts) {
            $sshService = Get-VMHostService -VMHost $vmHost | Where-Object { $_.Key -eq "TSM-SSH" }
            if ($sshService.Running) {
                LogMessage -type INFO -message "[$($vmHost.Name)] SSH already running. Skipping"
            } else {
                LogMessage -type INFO -message "[$($vmHost.Name)] Starting SSH service"
                Start-VMHostService -HostService $sshService -Confirm:$false | Out-Null
            }
            $sshTargets += [PSCustomObject]@{ Label = $vmHost.Name; Tokens = @($vmHost.Name, ($vmHost.Name -split '\.')[0]) }
        }

        Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
    }

    $matchTokens = @($sshTargets | ForEach-Object { $_.Tokens } | Where-Object { $_ } | Sort-Object -Unique)

    # Upload refreshsshkeys.py to SDDC Manager via SCP (Set-SCPItem), matching the upload pattern
    # used elsewhere in this module (e.g. New-UploadAndModifySDDCManagerBackup) -- the base64-pipe
    # approach used by some other functions in this module failed for this script.
    $localScript = Join-Path -Path $PSScriptRoot -ChildPath "scripts/refreshsshkeys.py"
    if (-not (Test-Path $localScript)) {
        LogMessage -type ERROR -message "[$jumpboxName] Script not found: $localScript"
        return
    }

    LogMessage -type INFO -message "[$SddcManagerFqdn] Establishing SSH connection"
    $SecurePassword = ConvertTo-SecureString -String $VcfUserPassword -AsPlainText -Force
    $mycreds = New-Object System.Management.Automation.PSCredential ('vcf', $SecurePassword)
    $inmem = New-SSHMemoryKnownHost
    New-SSHTrustedHost -KnownHostStore $inmem -HostName $SddcManagerFqdn -FingerPrint ((Get-SSHHostKey -ComputerName $SddcManagerFqdn).fingerprint) | Out-Null
    Do {
        $sshSession = New-SSHSession -ComputerName $SddcManagerFqdn -Credential $mycreds -KnownHost $inmem
    } Until ($sshSession)

    $remotePath = "/tmp/refreshsshkeys.py"
    LogMessage -type INFO -message "[$SddcManagerFqdn] Uploading refreshsshkeys.py to $remotePath"
    Try {
        Set-SCPItem -ComputerName $SddcManagerFqdn -Credential $mycreds -Path $localScript -Destination "/tmp" -KnownHost $inmem -ErrorAction Stop | Out-Null
    } Catch {
        LogMessage -type ERROR -message "[$SddcManagerFqdn] SCP upload threw an exception: $($_.Exception.Message)"
        Remove-SSHSession -SSHSession $sshSession | Out-Null
        return
    }

    # Verify from the exact same SSH session used for upload/chmod/execution -- if the vcf user's SCP
    # session lands in a different filesystem view/namespace than another login path used to check
    # manually (e.g. a separate root console), that mismatch would otherwise look like a silent failure.
    $verifyResult = Invoke-SSHCommand -SessionId $sshSession.SessionId -Command "ls -la $remotePath" -TimeOut 15
    if ($verifyResult.ExitStatus -ne 0) {
        LogMessage -type ERROR -message "[$SddcManagerFqdn] Uploaded file not found at $remotePath from this SSH session (exit $($verifyResult.ExitStatus)): $($verifyResult.Error -join ' ')"
        Remove-SSHSession -SSHSession $sshSession | Out-Null
        return
    }

    $chmodResult = Invoke-SSHCommand -SessionId $sshSession.SessionId -Command "chmod +x $remotePath" -TimeOut 15
    if ($chmodResult.ExitStatus -ne 0) {
        LogMessage -type ERROR -message "[$SddcManagerFqdn] chmod +x on uploaded script failed (exit $($chmodResult.ExitStatus)): $($chmodResult.Error -join ' ')"
        Remove-SSHSession -SSHSession $sshSession | Out-Null
        return
    }

    LogMessage -type INFO -message "[$SddcManagerFqdn] Running refreshsshkeys.py"
    # Run as the vcf user, no root elevation. vcf already owns the uploaded file (confirmed via the
    # post-upload ls -la above) and the script only needs to reach a localhost HTTP endpoint and run
    # ssh-keyscan, neither of which requires root.
    # The script prompts once per mismatched key ("Are you sure you want to update <type> key
    # (yes/no)?"), not once per run. A single piped "yes" (via `echo yes |`) only answers the first
    # such prompt; every subsequent one then hits closed stdin and fails with "EOF when reading a
    # line" -- confirmed live against a cluster where multiple hosts each needed new keys. `yes yes`
    # repeats the literal string "yes" (the prompt requires that exact word, not "y") for as long as
    # the script keeps asking.
    # Unless -all was used, pass the same match tokens used for output filtering to the script's
    # --targets flag, so it only fetches/confirms/updates keys for the enabled targets instead of
    # every known_hosts entry SDDC Manager tracks.
    if ($matchAllOutput -or $matchTokens.Count -eq 0) {
        $execCmd = "cd /tmp && yes yes | python $remotePath 2>&1"
    } else {
        $targetsArg = $matchTokens -join ','
        $execCmd = "cd /tmp && yes yes | python $remotePath --targets '$targetsArg' 2>&1"
    }
    $execResult = Invoke-SSHCommand -SessionId $sshSession.SessionId -Command $execCmd -TimeOut 300

    $rawOutputLines = @($execResult.Output) + @(($execResult.Error -join "`n") -split "`r?`n")
    $rawOutputLines = @($rawOutputLines | Where-Object { $_ -ne '' })

    if ($execResult.ExitStatus -ne 0) {
        # The filter below only makes sense to apply when the script actually ran its per-host logic
        # (in which case the noise it's meant to hide would still be present). On a non-zero exit the
        # cause could be anything -- an early failure before any host-specific line is ever printed --
        # so filtering here would silently hide the only diagnostic available. Surface everything.
        LogMessage -type ERROR -message "[$SddcManagerFqdn] refreshsshkeys.py exited with code $($execResult.ExitStatus). Full unfiltered output:"
        Foreach ($line in $rawOutputLines) {
            LogMessage -type ERROR -message "[$SddcManagerFqdn] $line"
        }
    } elseif ($matchAllOutput) {
        # No explicit target list to interpret against in -all mode -- show every line as-is.
        Foreach ($line in $rawOutputLines) {
            LogMessage -type INFO -message "[$SddcManagerFqdn] $line"
        }
    } else {
        # Interpret the script's raw output into one status per target instead of showing raw lines.
        # The script prints an explicit "does not match" line only for mismatched keys, prints
        # bracketed-list summary lines for fetch failures/declined updates/skipped-by-filter, and (since
        # matching keys are only logged to its own file, never stdout) prints nothing at all for a host
        # whose key already matches -- so "matches" is the correct default absent other evidence.
        Function VCFIRParsePythonListLine {
            Param([String[]] $Lines, [String] $Prefix)
            $items = @()
            Foreach ($line in $Lines) {
                if ($line -match "^$Prefix \[(.*)\]$") {
                    $items += @($Matches[1] -split "',\s*'" | ForEach-Object { $_.Trim("'") })
                }
            }
            return $items
        }
        $failedFqdns = VCFIRParsePythonListLine -Lines $rawOutputLines -Prefix 'Fetch SSH key was failed for'
        $notUpdatedFqdns = VCFIRParsePythonListLine -Lines $rawOutputLines -Prefix 'SSH keys will not be updated for'
        $skippedFqdns = VCFIRParsePythonListLine -Lines $rawOutputLines -Prefix 'Skipped \(outside requested target list\):'
        $mismatchLines = @($rawOutputLines | Where-Object { $_ -match 'does not match\.$' })

        Foreach ($target in $sshTargets) {
            $tokensForTarget = @($target.Tokens | Where-Object { $_ })
            $failed = $false
            $notUpdated = $false
            $skipped = $false
            $updated = $false
            Foreach ($token in $tokensForTarget) {
                if ($failedFqdns -like "*$token*") { $failed = $true }
                if ($notUpdatedFqdns -like "*$token*") { $notUpdated = $true }
                if ($skippedFqdns -like "*$token*") { $skipped = $true }
            }
            if (-not ($failed -or $notUpdated -or $skipped)) {
                Foreach ($line in $mismatchLines) {
                    Foreach ($token in $tokensForTarget) {
                        if ($line -like "*$token*") { $updated = $true; break }
                    }
                    if ($updated) { break }
                }
            }

            if ($failed) {
                LogMessage -type ERROR -message "[$($target.Label)] SSH key fetch failed"
            } elseif ($notUpdated) {
                LogMessage -type WARNING -message "[$($target.Label)] SSH key mismatch found but was not updated"
            } elseif ($skipped) {
                LogMessage -type WARNING -message "[$($target.Label)] SSH key check was skipped by refreshsshkeys.py"
            } elseif ($updated) {
                LogMessage -type INFO -message "[$($target.Label)] SSH Key updated"
            } else {
                LogMessage -type INFO -message "[$($target.Label)] SSH Key matches"
            }
        }
    }
    Remove-SSHSession -SSHSession $sshSession | Out-Null

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Invoke-SddcManagerSSHKeyRefresh

Function Get-SddcManagerToken {
    <#
    .SYNOPSIS
    Retrieves a Bearer access token from the SDDC Manager API.

    .DESCRIPTION
    The Get-SddcManagerToken cmdlet authenticates to the SDDC Manager /v1/tokens endpoint and returns the access token string for use in subsequent API calls.

    .EXAMPLE
    $token = Get-SddcManagerToken -SddcManagerFqdn "sfo-vcf01.sfo.rainpole.io" -Username "administrator@vsphere.local" -Password "VMw@re1!VMw@re1!"

    .PARAMETER SddcManagerFqdn
    FQDN of the SDDC Manager appliance.

    .PARAMETER Username
    API username (e.g. administrator@vsphere.local or admin@local).

    .PARAMETER Password
    Password for the API user.
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $SddcManagerFqdn,
        [Parameter(Mandatory = $true)][String] $Username,
        [Parameter(Mandatory = $true)][String] $Password
    )

    $jumpboxName = hostname
    LogMessage -type INFO -message "[$jumpboxName] Requesting authentication token from $SddcManagerFqdn"
    $tokenUri = "https://$SddcManagerFqdn/v1/tokens"
    $tokenBody = @{
        username = $Username
        password = $Password
    } | ConvertTo-Json

    try {
        $tokenResponse = Invoke-RestMethod -Uri $tokenUri -Method POST -ContentType "application/json" -Body $tokenBody -SkipCertificateCheck
        $accessToken = $tokenResponse.accessToken
        if (-not $accessToken) {
            LogMessage -type ERROR -message "[$SddcManagerFqdn] Token response did not contain an accessToken."
            return $null
        }
        LogMessage -type INFO -message "[$SddcManagerFqdn] Authentication token retrieved successfully"
        return $accessToken
    } catch {
        LogMessage -type ERROR -message "[$SddcManagerFqdn] Failed to retrieve authentication token: $($_.Exception.Message)"
        return $null
    }
}

Function New-ServicesRuntime {
    <#
    .SYNOPSIS
    Deploys a new VCF Management Services (VCFMS) runtime instance via the SDDC Manager API.

    .DESCRIPTION
    The New-ServicesRuntime cmdlet calls the SDDC Manager POST /v1/vsp-clusters endpoint to deploy a new VCFMS runtime. Supports two modes:

    ByFile      - Supply a pre-built JSON payload file.
    ByParameter - Supply individual values; the management domain ID is automatically retrieved from the SDDC Manager /v1/domains API.

    In both modes the function retrieves an SDDC Manager token, displays the payload for verification (with systemUserPassword redacted), prompts with Proceed with deployment? (Y/N), and only submits if you answer Y. N aborts without calling the API. After submit, the function polls the task until completion.

    .EXAMPLE
    New-ServicesRuntime -SddcManagerFqdn "sfo-vcf01.sfo.rainpole.io" -SddcManagerUser "administrator@vsphere.local" -SddcManagerPassword "VMw@re1!VMw@re1!" -Type MANAGEMENT -JsonFile ".\vcfms-runtime.json"

    .EXAMPLE
    New-ServicesRuntime -SddcManagerFqdn "sfo-vcf01.sfo.rainpole.io" -SddcManagerUser "administrator@vsphere.local" -SddcManagerPassword "VMw@re1!VMw@re1!" -Type CONSUMPTION -JsonFile ".\vcfms-consumption.json"

    .PARAMETER SddcManagerFqdn
    FQDN of the SDDC Manager appliance.

    .PARAMETER SddcManagerUser
    API username for SDDC Manager (e.g. administrator@vsphere.local).

    .PARAMETER SddcManagerPassword
    Password for the SDDC Manager API user.

    .PARAMETER Type
    Type of VCFMS runtime to deploy. Valid values are MANAGEMENT or CONSUMPTION.

    .PARAMETER JsonFile
    (ByFile) Path to a JSON file containing the full VCFMS runtime deployment payload.

    .PARAMETER PlatformFqdn
    (ByParameter) Platform FQDN for the VCFMS runtime. Must match the original.

    .PARAMETER InstanceFqdn
    (ByParameter) Instance FQDN for the VCFMS runtime. Required when -Type is MANAGEMENT.

    .PARAMETER FleetFqdn
    (ByParameter) Fleet FQDN for the VCFMS runtime. Required when -Type is MANAGEMENT.

    .PARAMETER SystemUserPassword
    (ByParameter) System user password for the VCFMS runtime.

    .PARAMETER Ipv4Addresses
    (ByParameter) Array of IPv4 addresses for the VCFMS IP pool.

    .PARAMETER Size
    (ByParameter) Deployment size (e.g. small, medium, large).

    .PARAMETER NetworkMoId
    (ByParameter) Managed Object ID of the dvportgroup (e.g. dvportgroup-28).

    .PARAMETER GatewayCidrIpv4
    (ByParameter) Gateway CIDR in IPv4 format (e.g. 10.11.99.1/24).

    .PARAMETER ClusterId
    (ByParameter) Cluster ID from the original deployment. Must match the original.

    .PARAMETER InternalClusterCidrIpv4
    (ByParameter) Internal cluster CIDR in IPv4 format (e.g. 198.18.0.0/15).

    .PARAMETER PollIntervalSeconds
    Interval in seconds to poll the task status. Default is 300 (5 minutes).
    #>

    Param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByFile")]
        [Parameter(Mandatory = $true, ParameterSetName = "ByParameter")]
        [String] $SddcManagerFqdn,

        [Parameter(Mandatory = $true, ParameterSetName = "ByFile")]
        [Parameter(Mandatory = $true, ParameterSetName = "ByParameter")]
        [String] $SddcManagerUser,

        [Parameter(Mandatory = $true, ParameterSetName = "ByFile")]
        [Parameter(Mandatory = $true, ParameterSetName = "ByParameter")]
        [String] $SddcManagerPassword,

        [Parameter(Mandatory = $true, ParameterSetName = "ByFile")]
        [Parameter(Mandatory = $true, ParameterSetName = "ByParameter")]
        [ValidateSet("MANAGEMENT", "CONSUMPTION")]
        [String] $Type,

        [Parameter(Mandatory = $true, ParameterSetName = "ByFile")]
        [String] $JsonFile,

        [Parameter(Mandatory = $true, ParameterSetName = "ByParameter")]
        [String] $PlatformFqdn,

        [Parameter(Mandatory = $false, ParameterSetName = "ByParameter")]
        [String] $InstanceFqdn,

        [Parameter(Mandatory = $false, ParameterSetName = "ByParameter")]
        [String] $FleetFqdn,

        [Parameter(Mandatory = $true, ParameterSetName = "ByParameter")]
        [String] $SystemUserPassword,

        [Parameter(Mandatory = $true, ParameterSetName = "ByParameter")]
        [String[]] $Ipv4Addresses,

        [Parameter(Mandatory = $true, ParameterSetName = "ByParameter")]
        [String] $Size,

        [Parameter(Mandatory = $true, ParameterSetName = "ByParameter")]
        [String] $NetworkMoId,

        [Parameter(Mandatory = $true, ParameterSetName = "ByParameter")]
        [String] $GatewayCidrIpv4,

        [Parameter(Mandatory = $true, ParameterSetName = "ByParameter")]
        [String] $ClusterId,

        [Parameter(Mandatory = $true, ParameterSetName = "ByParameter")]
        [String] $InternalClusterCidrIpv4,

        [Parameter(Mandatory = $false, ParameterSetName = "ByFile")]
        [Parameter(Mandatory = $false, ParameterSetName = "ByParameter")]
        [Int] $PollIntervalSeconds = 300
    )

    $jumpboxName = hostname
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    # Get authentication token
    $accessToken = Get-SddcManagerToken -SddcManagerFqdn $SddcManagerFqdn -Username $SddcManagerUser -Password $SddcManagerPassword
    if (-not $accessToken) {
        LogMessage -type ERROR -message "[$jumpboxName] Unable to obtain SDDC Manager token. Aborting."
        return
    }

    $headers = @{
        "Authorization" = "Bearer $accessToken"
        "Content-Type"  = "application/json"
        "Accept"        = "application/json"
    }

    if ($PSCmdlet.ParameterSetName -eq "ByFile") {
        # --- ByFile: read and validate the JSON payload ---
        $payloadPath = (Resolve-Path -Path $JsonFile -ErrorAction SilentlyContinue).Path
        if (-not $payloadPath) {
            LogMessage -type ERROR -message "[$jumpboxName] Payload file not found: $JsonFile"
            return
        }

        $requestBody = Get-Content $payloadPath -Raw
        try {
            $payloadObject = $requestBody | ConvertFrom-Json
        } catch {
            LogMessage -type ERROR -message "[$jumpboxName] Failed to parse JSON from $JsonFile : $($_.Exception.Message)"
            return
        }

        $requiredFields = @("domainId", "platformFqdn", "instanceFqdn", "fleetFqdn", "systemUserPassword", "type", "ipv4Pool", "size", "networkMoId", "gatewayCidrIpv4", "clusterId", "internalClusterCidrIpv4")
        $missingFields = $requiredFields | Where-Object { -not $payloadObject.$_ }
        if ($missingFields) {
            LogMessage -type ERROR -message "[$jumpboxName] Payload is missing required fields: $($missingFields -join ', ')"
            return
        }
    } else {
        # --- ByParameter: retrieve the management domain ID and build the payload ---
        if ($Type -eq 'MANAGEMENT') {
            if ([string]::IsNullOrWhiteSpace($InstanceFqdn)) {
                LogMessage -type ERROR -message "[$jumpboxName] -InstanceFqdn is required when -Type is MANAGEMENT"
                return
            }
            if ([string]::IsNullOrWhiteSpace($FleetFqdn)) {
                LogMessage -type ERROR -message "[$jumpboxName] -FleetFqdn is required when -Type is MANAGEMENT"
                return
            }
        }

        LogMessage -type INFO -message "[$SddcManagerFqdn] Retrieving management domain ID from /v1/domains"
        try {
            $domainsUri = "https://$SddcManagerFqdn/v1/domains"
            $domainsResponse = Invoke-RestMethod -Uri $domainsUri -Method GET -Headers $headers -SkipCertificateCheck
            $mgmtDomain = $domainsResponse.elements | Where-Object { $_.type -eq "MANAGEMENT" } | Select-Object -First 1
            if (-not $mgmtDomain) {
                LogMessage -type ERROR -message "[$SddcManagerFqdn] No MANAGEMENT domain found in /v1/domains response"
                return
            }
            $domainId = $mgmtDomain.id
            LogMessage -type INFO -message "[$SddcManagerFqdn] Management domain ID: $domainId"
        } catch {
            LogMessage -type ERROR -message "[$SddcManagerFqdn] Failed to retrieve domains: $($_.Exception.Message)"
            return
        }

        $payloadHash = @{
            domainId                = $domainId
            platformFqdn            = $PlatformFqdn
            systemUserPassword      = $SystemUserPassword
            type                    = $Type
            ipv4Pool                = @{ addresses = $Ipv4Addresses }
            size                    = $Size
            networkMoId             = $NetworkMoId
            gatewayCidrIpv4         = $GatewayCidrIpv4
            clusterId               = $ClusterId
            internalClusterCidrIpv4 = $InternalClusterCidrIpv4
        }
        if (-not [string]::IsNullOrWhiteSpace($InstanceFqdn)) { $payloadHash['instanceFqdn'] = $InstanceFqdn }
        if (-not [string]::IsNullOrWhiteSpace($FleetFqdn))    { $payloadHash['fleetFqdn']    = $FleetFqdn }
        $requestBody = $payloadHash | ConvertTo-Json -Depth 5
    }

    # Display the payload for verification (password redacted)
    $displayBody = $requestBody -replace '"systemUserPassword"\s*:\s*"[^"]*"', '"systemUserPassword": "***"'
    Write-Host ""
    Write-Host " VCFMS Runtime Deployment Payload:" -ForegroundColor Cyan
    Write-Host $displayBody
    Write-Host ""

    Do {
        Write-Host " Proceed with deployment? (Y/N): " -ForegroundColor Yellow -NoNewline
        $confirmation = Read-Host
    } Until ($confirmation -in @("Y", "y", "N", "n"))

    if ($confirmation -in @("N", "n")) {
        LogMessage -type INFO -message "[$SddcManagerFqdn] VCFMS runtime deployment cancelled by user."
        return
    }

    $vspClustersUri = "https://$SddcManagerFqdn/v1/vsp-clusters"
    LogMessage -type INFO -message "[$SddcManagerFqdn] Submitting VCFMS runtime deployment to POST /v1/vsp-clusters"

    try {
        $response = Invoke-RestMethod -Uri $vspClustersUri -Method POST -Headers $headers -Body $requestBody -SkipCertificateCheck
    } catch {
        LogMessage -type ERROR -message "[$SddcManagerFqdn] VCFMS deployment request failed: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            try {
                $errorStream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($errorStream)
                $errorBody = $reader.ReadToEnd()
                LogMessage -type ERROR -message "[$SddcManagerFqdn] Response body: $errorBody"
            } catch {}
        }
        return
    }

    # Check for a task ID in the response
    $taskId = $response.id
    if (-not $taskId) {
        LogMessage -type INFO -message "[$SddcManagerFqdn] API response:"
        $response | ConvertTo-Json -Depth 5 | Write-Host
        $StopWatch.Stop()
        $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
        return $response
    }

    LogMessage -type INFO -message "[$SddcManagerFqdn] VCFMS deployment task submitted: $taskId"
    LogMessage -type INFO -message "[$SddcManagerFqdn] Polling task status every $PollIntervalSeconds seconds"

    # Poll the task until completion
    $taskUri = "https://$SddcManagerFqdn/v1/tasks/$taskId"
    $taskStatus = "IN_PROGRESS"
    Do {
        Start-Sleep -Seconds $PollIntervalSeconds

        try {
            $taskResponse = Invoke-RestMethod -Uri $taskUri -Method GET -Headers $headers -SkipCertificateCheck
            $taskStatus = $taskResponse.status
            LogMessage -type INFO -message "[$SddcManagerFqdn] Status: $taskStatus"
        } catch {
            LogMessage -type WARNING -message "[$SddcManagerFqdn] Error polling task (will retry): $($_.Exception.Message)"
            $newToken = Get-SddcManagerToken -SddcManagerFqdn $SddcManagerFqdn -Username $SddcManagerUser -Password $SddcManagerPassword
            if ($newToken) {
                $headers["Authorization"] = "Bearer $newToken"
            }
        }
    } While ($taskStatus -in @("IN_PROGRESS", "IN PROGRESS", "PENDING", "RUNNING", "Pending", "Running"))

    if ($taskStatus -in @("SUCCESSFUL", "SUCCESS", "COMPLETED", "Succeeded")) {
        LogMessage -type INFO -message "[$SddcManagerFqdn] VCFMS runtime deployment completed successfully"
    } else {
        LogMessage -type ERROR -message "[$SddcManagerFqdn] VCFMS runtime deployment ended with status: $taskStatus"

        $errorDetailsFound = $false

        foreach ($err in @($taskResponse.errors)) {
            if (-not $err) { continue }
            $errMsg = if ($err.message) { $err.message } else { $err }
            LogMessage -type ERROR -message "[$SddcManagerFqdn] Error: $errMsg"
            if ($err.remediationMessage) {
                LogMessage -type ERROR -message "[$SddcManagerFqdn] Remediation: $($err.remediationMessage)"
            }
            if ($err.nestedErrors) {
                foreach ($nestedErr in @($err.nestedErrors)) {
                    LogMessage -type ERROR -message "[$SddcManagerFqdn] Nested Error: $($nestedErr.message)"
                }
            }
            $errorDetailsFound = $true
        }

        foreach ($resource in @($taskResponse.resources | Where-Object { $_.status -eq "FAILED" })) {
            LogMessage -type ERROR -message "[$SddcManagerFqdn] Resource '$($resource.name)' ($($resource.type)) failed: $($resource.message)"
            $errorDetailsFound = $true
        }

        foreach ($subTask in @($taskResponse.subTasks | Where-Object { $_.status -eq "FAILED" })) {
            $subTaskMessage = if ($subTask.errors) { (@($subTask.errors) | ForEach-Object { $_.message }) -join '; ' } else { $subTask.name }
            LogMessage -type ERROR -message "[$SddcManagerFqdn] Sub-task '$($subTask.name)' failed: $subTaskMessage"
            $errorDetailsFound = $true
        }

        if (-not $errorDetailsFound) {
            LogMessage -type ERROR -message "[$SddcManagerFqdn] No structured error details were returned by the task API. Full task response:"
            $taskResponse | ConvertTo-Json -Depth 10 | Write-Host
        }
    }

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function New-ServicesRuntime

Function Get-ServicesRuntime {
    <#
    .SYNOPSIS
    Retrieves the list of ServicesRuntime instances registered with SDDC Manager.

    .DESCRIPTION
    The Get-ServicesRuntime cmdlet calls the SDDC Manager GET /v1/vsp-clusters endpoint and returns the registered VCFMS Services Runtime instances. For each instance, a JSON file is written to the working directory using the short name of the platformFqdn as the filename. The JSON payload is in the format accepted by New-ServicesRuntime; populate systemUserPassword in the file before use.

    .EXAMPLE
    Get-ServicesRuntime -SddcManagerFqdn "sfo-vcf01.sfo.rainpole.io" -SddcManagerUser "administrator@vsphere.local" -SddcManagerPassword "VMw@re1!VMw@re1!"

    .PARAMETER SddcManagerFqdn
    FQDN of the SDDC Manager appliance.

    .PARAMETER SddcManagerUser
    API username for SDDC Manager (e.g. administrator@vsphere.local).

    .PARAMETER SddcManagerPassword
    Password for the SDDC Manager API user.
    #>

    Param(
        [Parameter(Mandatory = $true)]
        [String] $SddcManagerFqdn,

        [Parameter(Mandatory = $true)]
        [String] $SddcManagerUser,

        [Parameter(Mandatory = $true)]
        [String] $SddcManagerPassword
    )

    $jumpboxName = hostname
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    $accessToken = Get-SddcManagerToken -SddcManagerFqdn $SddcManagerFqdn -Username $SddcManagerUser -Password $SddcManagerPassword
    if (-not $accessToken) {
        LogMessage -type ERROR -message "[$jumpboxName] Unable to obtain SDDC Manager token. Aborting."
        return
    }

    $headers = @{
        "Authorization" = "Bearer $accessToken"
        "Accept"        = "application/json"
    }

    $vspClustersUri = "https://$SddcManagerFqdn/v1/vsp-clusters"
    LogMessage -type INFO -message "[$SddcManagerFqdn] Retrieving ServicesRuntime instances from GET /v1/vsp-clusters"

    try {
        $response = Invoke-RestMethod -Uri $vspClustersUri -Method GET -Headers $headers -SkipCertificateCheck
    } catch {
        LogMessage -type ERROR -message "[$SddcManagerFqdn] Request failed: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            try {
                $errorStream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($errorStream)
                $errorBody = $reader.ReadToEnd()
                LogMessage -type ERROR -message "[$SddcManagerFqdn] Response body: $errorBody"
            } catch {}
        }
        return
    }

    $clusters = if ($response.elements) { $response.elements } elseif ($response -is [Array]) { $response } else { @($response) }

    if (-not $clusters -or $clusters.Count -eq 0) {
        LogMessage -type INFO -message "[$SddcManagerFqdn] No ServicesRuntime instances found."
    } else {
        LogMessage -type INFO -message "[$SddcManagerFqdn] Found $($clusters.Count) ServicesRuntime instance(s):"
        foreach ($cluster in $clusters) {
            $payload = [ordered]@{ domainId = $cluster.domainId; platformFqdn = $cluster.platformFqdn }
            if ($cluster.type -ne 'CONSUMPTION') {
                $payload['instanceFqdn'] = $cluster.instanceFqdn
                $payload['fleetFqdn']    = $cluster.fleetFqdn
            }
            $payload['systemUserPassword'] = "<admin@vsp.local password>"
            $payload['type']               = $cluster.type
            if ($cluster.type -eq 'MANAGEMENT') {
                $startIp = $cluster.ipv4Pool.ipRange.startIpAddress
                $endIp   = $cluster.ipv4Pool.ipRange.endIpAddress
                if (-not $startIp -and $cluster.ipv4Pool.addresses) {
                    $addrs   = @($cluster.ipv4Pool.addresses)
                    $startIp = $addrs | Select-Object -First 1
                    $endIp   = $addrs | Select-Object -Last 1
                }
                $payload['ipv4Pool'] = [ordered]@{
                    ipRange = [ordered]@{
                        startIpAddress = $startIp
                        endIpAddress   = $endIp
                    }
                }
            } else {
                $addresses = @()
                if ($cluster.ipv4Pool -and $cluster.ipv4Pool.addresses) {
                    $addresses = @($cluster.ipv4Pool.addresses)
                }
                $payload['ipv4Pool'] = [ordered]@{ addresses = $addresses }
            }
            $payload['size']                    = $cluster.size
            $payload['networkMoId']             = "<vCenter Portgroup UUID>"
            $payload['gatewayCidrIpv4']         = "<Gateway CIDR for the associated network>"
            $payload['clusterId']               = $cluster.vspClusterId
            $payload['internalClusterCidrIpv4'] = $cluster.internalClusterCidrIpv4

            $shortName = ($cluster.platformFqdn -split '\.')[0]
            $outFile = Join-Path (Get-Location).Path "$shortName.json"
            $payload | ConvertTo-Json -Depth 5 | Set-Content -Path $outFile -Encoding UTF8
            LogMessage -type INFO -message "[$SddcManagerFqdn] Written: $outFile"
        }
    }

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Get-ServicesRuntime

Function Get-VcfmsServicesRuntimeToken {
    <#
    .SYNOPSIS
    Retrieves an access token from a VCFMS Services Runtime instance.

    .DESCRIPTION
    The Get-VcfmsServicesRuntimeToken cmdlet authenticates against the VCFMS Services Runtime /api/v1/identity/token endpoint using a form-urlencoded password grant and returns the access token string.

    .EXAMPLE
    $srToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -Password "VMw@re1!VMw@re1!"

    .EXAMPLE
    $srToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -Username "admin@vsp.local" -Password "VMw@re1!VMw@re1!"

    .PARAMETER ServicesRuntimeFqdn
    FQDN of the VCFMS Services Runtime instance (e.g. sfo-sr01.sfo.rainpole.io).

    .PARAMETER Username
    Username for the token request. Default is "admin@vsp.local".

    .PARAMETER Password
    Password for the services runtime user.
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $ServicesRuntimeFqdn,
        [Parameter(Mandatory = $false)][String] $Username = "admin@vsp.local",
        [Parameter(Mandatory = $true)][String] $Password
    )

    $jumpboxName = hostname
    LogMessage -type INFO -message "[$jumpboxName] Requesting VCFMS Services Runtime token from $ServicesRuntimeFqdn"

    $tokenUri = "https://$ServicesRuntimeFqdn/api/v1/identity/token"
    $tokenBody = "grant_type=password&username=$([uri]::EscapeDataString($Username))&password=$([uri]::EscapeDataString($Password))"

    try {
        $tokenResponse = Invoke-RestMethod -Uri $tokenUri -Method POST -ContentType "application/x-www-form-urlencoded" -Body $tokenBody -SkipCertificateCheck
        $accessToken = $tokenResponse.access_token
        if (-not $accessToken) {
            LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Token response did not contain an access_token."
            return $null
        }
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Services Runtime token retrieved successfully"
        return $accessToken
    } catch {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Failed to retrieve Services Runtime token: $($_.Exception.Message)"
        return $null
    }
}

Function Get-VcfOperationsToken {
    <#
    .SYNOPSIS
    Retrieves an access token from a VCF Operations instance.

    .DESCRIPTION
    The Get-VcfOperationsToken cmdlet authenticates against the VCF Operations /suite-api/api/auth/token/acquire endpoint and returns the token string for use in subsequent API calls.

    .EXAMPLE
    $opsToken = Get-VcfOperationsToken -VcfOperationsFqdn "flt-ops01a.rainpole.io" -Password "VMw@re1!VMw@re1!"

    .EXAMPLE
    $opsToken = Get-VcfOperationsToken -VcfOperationsFqdn "flt-ops01a.rainpole.io" -Username "admin" -Password "VMw@re1!VMw@re1!" -AuthSource "local"

    .PARAMETER VcfOperationsFqdn
    FQDN of the VCF Operations instance (e.g. flt-ops01a.rainpole.io).

    .PARAMETER Username
    Username for the token request. Default is "admin".

    .PARAMETER Password
    Password for the VCF Operations user.

    .PARAMETER AuthSource
    Authentication source. Default is "local".
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $VcfOperationsFqdn,
        [Parameter(Mandatory = $false)][String] $Username = "admin",
        [Parameter(Mandatory = $true)][String] $Password,
        [Parameter(Mandatory = $false)][String] $AuthSource = "local"
    )

    $jumpboxName = hostname
    LogMessage -type INFO -message "[$jumpboxName] Requesting VCF Operations token from $VcfOperationsFqdn"

    $tokenUri = "https://$VcfOperationsFqdn/suite-api/api/auth/token/acquire"
    $tokenBody = @{
        username   = $Username
        password   = $Password
        authSource = $AuthSource
    } | ConvertTo-Json

    try {
        $tokenResponse = Invoke-RestMethod -Uri $tokenUri -Method POST -ContentType "application/json" -Body $tokenBody -SkipCertificateCheck
        $accessToken = $tokenResponse.token
        if (-not $accessToken) {
            LogMessage -type ERROR -message "[$VcfOperationsFqdn] Token response did not contain a token."
            return $null
        }
        LogMessage -type INFO -message "[$VcfOperationsFqdn] VCF Operations token retrieved successfully"
        return $accessToken
    } catch {
        LogMessage -type ERROR -message "[$VcfOperationsFqdn] Failed to retrieve VCF Operations token: $($_.Exception.Message)"
        return $null
    }
}

Function Get-VcfOperationsRegisteredComponents {
    <#
    .SYNOPSIS
    Retrieves registered component IDs and related details from a VCF Operations instance.

    .DESCRIPTION
    The Get-VcfOperationsRegisteredComponents cmdlet queries the VCF Operations internal /suite-api/internal/components endpoint and returns a structured object containing:
    - components: Filtered component summaries for types FLEET_LCM, SALT_RAAS, VIDB, and LI.
    - vsp: All VSP instances registered in the endpoint, deduplicated by UUID, always returned as an array.
    - vcfa: VCFA component details if one is registered, otherwise null.

    A VCF Operations token is obtained automatically via Get-VcfOperationsToken.

    .EXAMPLE
    $result = Get-VcfOperationsRegisteredComponents -VcfOperationsFqdn "flt-ops01a.rainpole.io" -Password "VMw@re1!VMw@re1!"

    .EXAMPLE
    $result = Get-VcfOperationsRegisteredComponents -VcfOperationsFqdn "flt-ops01a.rainpole.io" -Username "admin" -Password "VMw@re1!VMw@re1!" -AuthSource "local"

    .PARAMETER VcfOperationsFqdn
    FQDN of the VCF Operations instance (e.g. flt-ops01a.rainpole.io).

    .PARAMETER Username
    Username for the VCF Operations API. Default is "admin".

    .PARAMETER Password
    Password for the VCF Operations user.

    .PARAMETER AuthSource
    Authentication source for the VCF Operations API. Default is "local".
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $VcfOperationsFqdn,
        [Parameter(Mandatory = $false)][String] $Username = "admin",
        [Parameter(Mandatory = $true)][String] $Password,
        [Parameter(Mandatory = $false)][String] $AuthSource = "local"
    )

    $jumpboxName = hostname
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    $opsToken = Get-VcfOperationsToken -VcfOperationsFqdn $VcfOperationsFqdn -Username $Username -Password $Password -AuthSource $AuthSource
    if (-not $opsToken) {
        LogMessage -type ERROR -message "[$jumpboxName] Unable to obtain VCF Operations token. Aborting."
        return $null
    }

    $headers = @{
        "Accept"                    = "application/json"
        "X-Ops-API-use-unsupported" = "true"
        "Authorization"             = "OpsToken $opsToken"
    }

    $componentsUri = "https://$VcfOperationsFqdn/suite-api/internal/components?_no_links=true"
    LogMessage -type INFO -message "[$VcfOperationsFqdn] Retrieving registered components"

    try {
        $response = Invoke-RestMethod -Uri $componentsUri -Method GET -Headers $headers -SkipCertificateCheck
    } catch {
        LogMessage -type ERROR -message "[$VcfOperationsFqdn] Failed to retrieve components: $($_.Exception.Message)"
        return $null
    }

    $allComponents = $response.components
    if (-not $allComponents -or ($allComponents | Measure-Object).Count -eq 0) {
        LogMessage -type WARNING -message "[$VcfOperationsFqdn] No components returned."
        return $null
    }

    # Filter to the component types of interest
    $targetTypes = @('FLEET_LCM', 'SALT_RAAS', 'VIDB', 'LI')
    $filtered = @($allComponents | Where-Object { $targetTypes -contains ($_.componentType).ToUpper() })

    # Collect all VSP instances, deduplicated by UUID
    $vspComponents = @(
        $allComponents |
            Where-Object { ($_.componentType).ToUpper() -eq 'VSP' } |
                ForEach-Object {
                    $ip = if ($_.properties.ip) { $_.properties.ip } else { $_.vcfInstance.ip }
                    [PSCustomObject]@{
                        id               = $_.componentUuid
                        componentVersion = $_.componentVersion
                        fqdn             = $_.properties.fqdn
                        fleetFqdn        = $_.properties.fleetFqdn
                        ip               = $ip
                        instanceName     = $_.vcfInstance.instanceName
                        vcfInstanceFqdn  = $_.vcfInstance.fqdn
                    }
                } |
                    Sort-Object -Property id -Unique
    )

    $vsp = $vspComponents

    # Extract the first VCFA component if present
    $vcfaComp = $allComponents | Where-Object { ($_.componentType).ToUpper() -eq 'VCFA' } | Select-Object -First 1
    $vcfa = if ($vcfaComp) {
        [PSCustomObject]@{
            fqdn             = $vcfaComp.properties.fqdn
            componentVersion = $vcfaComp.componentVersion
            platformFqdn     = $vcfaComp.properties.platformFqdn
            vspComponentUuid = $vcfaComp.properties.vspComponentUuid
        }
    } else {
        $null
    }

    # Build filtered component summaries
    $componentSummaries = @(
        $filtered | ForEach-Object {
            [PSCustomObject]@{
                componentType    = $_.componentType
                id               = $_.componentUuid
                componentVersion = $_.componentVersion
                fqdn             = $_.properties.fqdn
            }
        }
    )

    $result = [PSCustomObject]@{
        components = $componentSummaries
        vsp        = $vsp
        vcfa       = $vcfa
    }

    LogMessage -type INFO -message "[$VcfOperationsFqdn] Found $($filtered.Count) filtered component(s) of types: $($targetTypes -join ', '); $($vspComponents.Count) VSP instance(s)"

    $json = $result | ConvertTo-Json -Depth 10
    Write-Host ""
    Write-Host $json

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Get-VcfOperationsRegisteredComponents

Function Get-RegisteredComponentIds {
    <#
    .SYNOPSIS
    Retrieves registered component IDs and related details from a VCF Operations instance.

    .DESCRIPTION
    The Get-RegisteredComponentIds cmdlet queries the VCF Operations internal /suite-api/internal/components endpoint and returns a structured object containing:
    - components: Filtered component summaries for types FLEET_LCM, SALT_RAAS, VIDB, and LI.
    - vsp: All VSP instances registered in the endpoint, deduplicated by UUID, always returned as an array.
    - vcfa: VCFA component details if one is registered, otherwise null.

    A VCF Operations token is obtained automatically via Get-VcfOperationsToken.

    .EXAMPLE
    $result = Get-RegisteredComponentIds -VcfOperationsFqdn "flt-ops01a.rainpole.io" -Password "VMw@re1!VMw@re1!"

    .EXAMPLE
    $result = Get-RegisteredComponentIds -VcfOperationsFqdn "flt-ops01a.rainpole.io" -Username "admin" -Password "VMw@re1!VMw@re1!" -AuthSource "local"

    .PARAMETER VcfOperationsFqdn
    FQDN of the VCF Operations instance (e.g. flt-ops01a.rainpole.io).

    .PARAMETER Username
    Username for the VCF Operations API. Default is "admin".

    .PARAMETER Password
    Password for the VCF Operations user.

    .PARAMETER AuthSource
    Authentication source for the VCF Operations API. Default is "local".
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $VcfOperationsFqdn,
        [Parameter(Mandatory = $false)][String] $Username = "admin",
        [Parameter(Mandatory = $true)][String] $Password,
        [Parameter(Mandatory = $false)][String] $AuthSource = "local"
    )

    $jumpboxName = hostname
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    $opsToken = Get-VcfOperationsToken -VcfOperationsFqdn $VcfOperationsFqdn -Username $Username -Password $Password -AuthSource $AuthSource
    if (-not $opsToken) {
        LogMessage -type ERROR -message "[$jumpboxName] Unable to obtain VCF Operations token. Aborting."
        return $null
    }

    $headers = @{
        "Accept"                    = "application/json"
        "X-Ops-API-use-unsupported" = "true"
        "Authorization"             = "OpsToken $opsToken"
    }

    $componentsUri = "https://$VcfOperationsFqdn/suite-api/internal/components?_no_links=true"
    LogMessage -type INFO -message "[$VcfOperationsFqdn] Retrieving registered components"

    try {
        $response = Invoke-RestMethod -Uri $componentsUri -Method GET -Headers $headers -SkipCertificateCheck
    } catch {
        LogMessage -type ERROR -message "[$VcfOperationsFqdn] Failed to retrieve components: $($_.Exception.Message)"
        return $null
    }

    $allComponents = $response.components
    if (-not $allComponents -or ($allComponents | Measure-Object).Count -eq 0) {
        LogMessage -type WARNING -message "[$VcfOperationsFqdn] No components returned."
        return $null
    }

    # Filter to the component types of interest
    $targetTypes = @('FLEET_LCM', 'SALT_RAAS', 'VIDB', 'LI')
    $filtered = @($allComponents | Where-Object { $targetTypes -contains ($_.componentType).ToUpper() })

    # Collect all VSP instances, deduplicated by UUID
    $vspComponents = @(
        $allComponents |
            Where-Object { ($_.componentType).ToUpper() -eq 'VSP' } |
            ForEach-Object {
                $ip = if ($_.properties.ip) { $_.properties.ip } else { $_.vcfInstance.ip }
                [PSCustomObject]@{
                    id              = $_.componentUuid
                    fqdn            = $_.properties.fqdn
                    fleetFqdn       = $_.properties.fleetFqdn
                    ip              = $ip
                    instanceName    = $_.vcfInstance.instanceName
                    vcfInstanceFqdn = $_.vcfInstance.fqdn
                }
            } |
            Sort-Object -Property id -Unique
    )

    $vsp = $vspComponents

    # Extract the first VCFA component if present
    $vcfaComp = $allComponents | Where-Object { ($_.componentType).ToUpper() -eq 'VCFA' } | Select-Object -First 1
    $vcfa = if ($vcfaComp) {
        [PSCustomObject]@{
            fqdn             = $vcfaComp.properties.fqdn
            platformFqdn     = $vcfaComp.properties.platformFqdn
            vspComponentUuid = $vcfaComp.properties.vspComponentUuid
        }
    } else {
        $null
    }

    # Build filtered component summaries
    $componentSummaries = @(
        $filtered | ForEach-Object {
            [PSCustomObject]@{
                componentType = $_.componentType
                id            = $_.componentUuid
                fqdn          = $_.properties.fqdn
            }
        }
    )

    $result = [PSCustomObject]@{
        components = $componentSummaries
        vsp        = $vsp
        vcfa       = $vcfa
    }

    LogMessage -type INFO -message "[$VcfOperationsFqdn] Found $($filtered.Count) filtered component(s) of types: $($targetTypes -join ', '); $($vspComponents.Count) VSP instance(s)"

    $json = $result | ConvertTo-Json -Depth 10
    Write-Host ""
    Write-Host $json

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Get-RegisteredComponentIds

Function Add-VcfmsTrustedCertificate {
    <#
    .SYNOPSIS
    Retrieves the TLS certificate from a remote host and trusts it on a VCFMS Services Runtime instance.

    .DESCRIPTION
    The Add-VcfmsTrustedCertificate cmdlet connects to the specified remote host to retrieve its TLS certificate in PEM format, then adds it as a trusted certificate on the VCFMS Services Runtime via POST /api/v1/system/trusted-certificates?action=add. A Services Runtime token is obtained automatically using Get-VcfmsServicesRuntimeToken.

    .EXAMPLE
    Add-VcfmsTrustedCertificate -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!" -RemoteHostFqdn "sfo-ins01.sfo.rainpole.io"

    .EXAMPLE
    Add-VcfmsTrustedCertificate -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!" -RemoteHostFqdn "sfo-ins01.sfo.rainpole.io" -RemoteHostPort 443

    .PARAMETER ServicesRuntimeFqdn
    FQDN of the VCFMS Services Runtime instance to add the trusted certificate to.

    .PARAMETER ServicesRuntimePassword
    Password for the Services Runtime admin user (used to obtain a token).

    .PARAMETER ServicesRuntimeUsername
    Username for the Services Runtime token. Default is "admin@vsp.local".

    .PARAMETER RemoteHostFqdn
    FQDN of the remote host whose TLS certificate should be retrieved and trusted (e.g. the VCF Installer).

    .PARAMETER RemoteHostPort
    Port to connect to on the remote host. Default is 443.

    .PARAMETER PollIntervalSeconds
    Interval in seconds to poll the task status. Default is 10.
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $ServicesRuntimeFqdn,
        [Parameter(Mandatory = $true)][String] $ServicesRuntimePassword,
        [Parameter(Mandatory = $false)][String] $ServicesRuntimeUsername = "admin@vsp.local",
        [Parameter(Mandatory = $true)][String] $RemoteHostFqdn,
        [Parameter(Mandatory = $false)][Int] $RemoteHostPort = 443,
        [Parameter(Mandatory = $false)][Int] $PollIntervalSeconds = 10
    )

    $jumpboxName = hostname
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    # Retrieve the remote host's TLS certificate
    LogMessage -type INFO -message "[$jumpboxName] Retrieving TLS certificate from ${RemoteHostFqdn}:${RemoteHostPort}"
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient($RemoteHostFqdn, $RemoteHostPort)
        $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, { $true })
        $sslStream.AuthenticateAsClient($RemoteHostFqdn)
        $remoteCert = $sslStream.RemoteCertificate
        $sslStream.Close()
        $tcpClient.Close()
    } catch {
        LogMessage -type ERROR -message "[$jumpboxName] Failed to retrieve certificate from ${RemoteHostFqdn}:${RemoteHostPort}: $($_.Exception.Message)"
        return
    }

    if (-not $remoteCert) {
        LogMessage -type ERROR -message "[$jumpboxName] No certificate returned from ${RemoteHostFqdn}:${RemoteHostPort}"
        return
    }

    # Convert to PEM format
    $certBytes = $remoteCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $certBase64 = [Convert]::ToBase64String($certBytes, [Base64FormattingOptions]::InsertLineBreaks)
    $certPem = "-----BEGIN CERTIFICATE-----`n$certBase64`n-----END CERTIFICATE-----"

    LogMessage -type INFO -message "[$jumpboxName] Certificate retrieved: Subject=$($remoteCert.Subject)"

    # Get Services Runtime token
    $srToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn $ServicesRuntimeFqdn -Username $ServicesRuntimeUsername -Password $ServicesRuntimePassword
    if (-not $srToken) {
        LogMessage -type ERROR -message "[$jumpboxName] Unable to obtain Services Runtime token. Aborting."
        return
    }
    $tokenFetchedAt = [DateTime]::UtcNow

    $headers = @{
        "Authorization" = "Bearer $srToken"
        "Content-Type"  = "application/json"
    }

    # Build the request body
    $requestBody = @{ cert = $certPem } | ConvertTo-Json

    $trustUri = "https://$ServicesRuntimeFqdn/api/v1/system/trusted-certificates?action=add"
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Adding trusted certificate for $RemoteHostFqdn"

    try {
        $response = Invoke-RestMethod -Uri $trustUri -Method POST -Headers $headers -Body $requestBody -SkipCertificateCheck
    } catch {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Failed to add trusted certificate: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            try {
                $errorStream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($errorStream)
                $errorBody = $reader.ReadToEnd()
                LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Response body: $errorBody"
            } catch {}
        }
        return
    }

    # Check for a task ID in the response
    $taskId = $response.id
    if (-not $taskId) {
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Certificate for $RemoteHostFqdn trusted successfully (no task returned)"
        $StopWatch.Stop()
        $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
        return $response
    }

    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Trust certificate task submitted: $taskId"
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Polling task status every $PollIntervalSeconds seconds"

    $taskUri = "https://$ServicesRuntimeFqdn/api/v1/tasks/$taskId"
    $taskStatus = "IN_PROGRESS"
    Do {
        Start-Sleep -Seconds $PollIntervalSeconds

        try {
            if (([DateTime]::UtcNow - $tokenFetchedAt).TotalMinutes -ge 60) {
                LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Token age >= 60 minutes; refreshing"
                $newToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn $ServicesRuntimeFqdn -Username $ServicesRuntimeUsername -Password $ServicesRuntimePassword
                if ($newToken) {
                    $srToken = $newToken
                    $headers["Authorization"] = "Bearer $srToken"
                    $tokenFetchedAt = [DateTime]::UtcNow
                } else {
                    LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Token refresh failed; continuing with existing token"
                }
            }
            $taskResponse = Invoke-RestMethod -Uri $taskUri -Method GET -Headers $headers -SkipCertificateCheck
            $taskStatus = $taskResponse.status
            LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Status: $taskStatus"
        } catch {
            LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Error polling task (will retry): $($_.Exception.Message)"
        }
    } While ($taskStatus -in @("IN_PROGRESS", "IN PROGRESS", "PENDING", "RUNNING"))

    if ($taskStatus -in @("SUCCESSFUL", "SUCCESS", "COMPLETED", "Succeeded")) {
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Certificate for $RemoteHostFqdn trusted successfully"
    } else {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Trust certificate task ended with status: $taskStatus"
        if ($taskResponse.errors) {
            foreach ($err in $taskResponse.errors) {
                LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Error: $($err.message)"
            }
        }
    }

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Add-VcfmsTrustedCertificate

Function Set-ServicesRuntimeSftpBackupSettings {
    <#
    .SYNOPSIS
    Configures SFTP backup settings on a VCFMS Services Runtime instance.

    .DESCRIPTION
    The Set-ServicesRuntimeSftpBackupSettings cmdlet retrieves the SFTP server's SSH host key fingerprint, then applies SFTP backup configuration to the specified VCFMS component via POST /api/v1/components/{componentId}?action=apply.

    .EXAMPLE
    Set-ServicesRuntimeSftpBackupSettings -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!" -ComponentId "1f5c79fe-e3aa-41b1-a5cf-774a6497fa3d" -SftpHost "10.167.173.126" -SftpUsername "svc-vcf-bck" -SftpPassword "VMw@re1!" -SftpDirectory "/media/backups/" -EncryptionPassphrase "VMw@re1!VMw@re1!"

    .PARAMETER ServicesRuntimeFqdn
    FQDN of the VCFMS Services Runtime instance.

    .PARAMETER ServicesRuntimePassword
    Password for the Services Runtime admin user (used to obtain a token).

    .PARAMETER ServicesRuntimeUsername
    Username for the Services Runtime token. Default is "admin@vsp.local".

    .PARAMETER ComponentId
    Component ID (cluster ID) to apply the SFTP settings to.

    .PARAMETER SftpHost
    IP address or FQDN of the SFTP server.

    .PARAMETER SftpPort
    SSH port on the SFTP server. Default is 22.

    .PARAMETER SftpUsername
    Username for SFTP authentication.

    .PARAMETER SftpPassword
    Password for SFTP authentication.

    .PARAMETER SftpDirectory
    Remote directory path for backups on the SFTP server.

    .PARAMETER EncryptionPassphrase
    Passphrase used to encrypt the backups.

    .PARAMETER SftpFingerprint
    SSH host key fingerprint of the SFTP server. If not provided, it is retrieved automatically via ssh-keyscan.

    .PARAMETER PollIntervalSeconds
    Interval in seconds to poll the task status. Default is 60 (one minute).
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $ServicesRuntimeFqdn,
        [Parameter(Mandatory = $true)][String] $ServicesRuntimePassword,
        [Parameter(Mandatory = $false)][String] $ServicesRuntimeUsername = "admin@vsp.local",
        [Parameter(Mandatory = $true)][String] $ComponentId,
        [Parameter(Mandatory = $true)][String] $SftpHost,
        [Parameter(Mandatory = $false)][String] $SftpPort = "22",
        [Parameter(Mandatory = $true)][String] $SftpUsername,
        [Parameter(Mandatory = $true)][String] $SftpPassword,
        [Parameter(Mandatory = $true)][String] $SftpDirectory,
        [Parameter(Mandatory = $true)][String] $EncryptionPassphrase,
        [Parameter(Mandatory = $false)][String] $SftpFingerprint,
        [Parameter(Mandatory = $false)][Int] $PollIntervalSeconds = 60
    )

    $jumpboxName = hostname
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    # Retrieve the SFTP fingerprint if not provided
    if (-not $SftpFingerprint) {
        LogMessage -type INFO -message "[$jumpboxName] Retrieving SSH host key fingerprint from ${SftpHost}:${SftpPort}"
        try {
            $keyScanOutput = & ssh-keyscan -p $SftpPort $SftpHost 2>$null
            if (-not $keyScanOutput) {
                LogMessage -type ERROR -message "[$jumpboxName] ssh-keyscan returned no output for ${SftpHost}:${SftpPort}. Verify the host is reachable."
                return
            }
            $fingerprintOutput = $keyScanOutput | & ssh-keygen -lf - 2>$null
            if (-not $fingerprintOutput) {
                LogMessage -type ERROR -message "[$jumpboxName] ssh-keygen could not compute fingerprint from keyscan output."
                return
            }
            # Parse the fingerprint (e.g. "256 SHA256:xxxx host (ECDSA)" -> take the SHA256 part)
            $fingerprintLines = $fingerprintOutput -split "`n" | Where-Object { $_ -match "SHA256:" }
            if ($fingerprintLines) {
                $SftpFingerprint = ($fingerprintLines[0].Trim() -split "\s+")[1]
            } else {
                $SftpFingerprint = ($fingerprintOutput -split "`n")[0].Trim()
            }
            LogMessage -type INFO -message "[$jumpboxName] SFTP fingerprint: $SftpFingerprint"
        } catch {
            LogMessage -type ERROR -message "[$jumpboxName] Failed to retrieve SFTP fingerprint: $($_.Exception.Message)"
            return
        }
    } else {
        LogMessage -type INFO -message "[$jumpboxName] Using provided SFTP fingerprint: $SftpFingerprint"
    }

    # Get Services Runtime token
    $srToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn $ServicesRuntimeFqdn -Username $ServicesRuntimeUsername -Password $ServicesRuntimePassword
    if (-not $srToken) {
        LogMessage -type ERROR -message "[$jumpboxName] Unable to obtain Services Runtime token. Aborting."
        return
    }
    $tokenFetchedAt = [DateTime]::UtcNow

    $headers = @{
        "Authorization" = "Bearer $srToken"
    }

    # Build the request body
    $requestBody = @{
        spec    = @{
            configuration = @{
                backups = @{
                    destination          = "sftp"
                    encryptionPassphrase = $EncryptionPassphrase
                    storage              = @{
                        sftp = @{
                            directory   = $SftpDirectory
                            host        = $SftpHost
                            port        = $SftpPort
                            username    = $SftpUsername
                            password    = $SftpPassword
                            fingerprint = $SftpFingerprint
                        }
                    }
                }
            }
        }
        options = @{}
    } | ConvertTo-Json -Depth 10

    # Display the payload (password redacted)
    $displayBody = $requestBody -replace '"password"\s*:\s*"[^"]*"', '"password": "***"' -replace '"encryptionPassphrase"\s*:\s*"[^"]*"', '"encryptionPassphrase": "***"'
    Write-Host ""
    Write-Host " SFTP Backup Settings Payload:" -ForegroundColor Cyan
    Write-Host $displayBody
    Write-Host ""

    $applyUri = "https://$ServicesRuntimeFqdn/api/v1/components/${ComponentId}?action=apply"
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Applying SFTP backup settings to component $ComponentId"

    try {
        $response = Invoke-RestMethod -Uri $applyUri -Method POST -Headers $headers -Body $requestBody -SkipCertificateCheck
    } catch {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Failed to apply SFTP backup settings: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            try {
                $errorStream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($errorStream)
                $errorBody = $reader.ReadToEnd()
                LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Response body: $errorBody"
            } catch {}
        }
        return
    }

    # Check for a task ID in the response
    $taskId = $response.id
    if (-not $taskId) {
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] SFTP backup settings applied successfully (no task returned)"
        $StopWatch.Stop()
        $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
        return $response
    }

    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] SFTP settings task submitted: $taskId"
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Polling task status every $PollIntervalSeconds seconds"

    $taskUri = "https://$ServicesRuntimeFqdn/api/v1/tasks/$taskId"
    $taskStatus = "IN_PROGRESS"
    Do {
        Start-Sleep -Seconds $PollIntervalSeconds

        try {
            if (([DateTime]::UtcNow - $tokenFetchedAt).TotalMinutes -ge 60) {
                LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Token age >= 60 minutes; refreshing"
                $newToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn $ServicesRuntimeFqdn -Username $ServicesRuntimeUsername -Password $ServicesRuntimePassword
                if ($newToken) {
                    $srToken = $newToken
                    $headers["Authorization"] = "Bearer $srToken"
                    $tokenFetchedAt = [DateTime]::UtcNow
                } else {
                    LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Token refresh failed; continuing with existing token"
                }
            }
            $taskResponse = Invoke-RestMethod -Uri $taskUri -Method GET -Headers $headers -SkipCertificateCheck
            $taskStatus = $taskResponse.status
            LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Status: $taskStatus"
        } catch {
            LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Error polling task (will retry): $($_.Exception.Message)"
        }
    } While ($taskStatus -in @("IN_PROGRESS", "IN PROGRESS", "PENDING", "RUNNING"))

    if ($taskStatus -in @("SUCCESSFUL", "SUCCESS", "COMPLETED", "Succeeded")) {
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] SFTP backup settings applied successfully"
    } else {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] SFTP settings task ended with status: $taskStatus"
        if ($taskResponse.errors) {
            foreach ($err in $taskResponse.errors) {
                LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Error: $($err.message)"
            }
        }
    }

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Set-ServicesRuntimeSftpBackupSettings

Function Set-ServicesRuntimeBackupSchedule {
    <#
    .SYNOPSIS
    Configures the full and incremental backup schedule on a VCFMS Services Runtime instance.

    .DESCRIPTION
    The Set-ServicesRuntimeBackupSchedule cmdlet applies a scheduled backup configuration to the specified VCFMS component via POST /api/v1/components/{componentId}?action=apply. Full and incremental backups are each independently enabled/disabled and given a cron schedule.

    .EXAMPLE
    Set-ServicesRuntimeBackupSchedule -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!" -ComponentId "1f5c79fe-e3aa-41b1-a5cf-774a6497fa3d" -FullBackupEnabled $true -FullBackupSchedule "0 2 * * 0" -IncrementalBackupEnabled $true -IncrementalBackupSchedule "0 2 * * 1-6"

    .EXAMPLE
    Set-ServicesRuntimeBackupSchedule -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!" -ComponentId "1f5c79fe-e3aa-41b1-a5cf-774a6497fa3d" -FullBackupEnabled $false -IncrementalBackupEnabled $false

    .PARAMETER ServicesRuntimeFqdn
    FQDN of the VCFMS Services Runtime instance.

    .PARAMETER ServicesRuntimePassword
    Password for the Services Runtime admin user (used to obtain a token).

    .PARAMETER ServicesRuntimeUsername
    Username for the Services Runtime token. Default is "admin@vsp.local".

    .PARAMETER ComponentId
    Component ID (cluster ID) to apply the backup schedule to. If omitted, the component of type "vsp" is resolved automatically.

    .PARAMETER FullBackupEnabled
    Whether scheduled full backups are enabled.

    .PARAMETER FullBackupSchedule
    Cron schedule for full backups. Required when -FullBackupEnabled is $true.

    .PARAMETER IncrementalBackupEnabled
    Whether scheduled incremental backups are enabled.

    .PARAMETER IncrementalBackupSchedule
    Cron schedule for incremental backups. Required when -IncrementalBackupEnabled is $true.

    .PARAMETER PollIntervalSeconds
    Interval in seconds to poll the task status. Default is 60 (one minute).
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $ServicesRuntimeFqdn,
        [Parameter(Mandatory = $true)][String] $ServicesRuntimePassword,
        [Parameter(Mandatory = $false)][String] $ServicesRuntimeUsername = "admin@vsp.local",
        [Parameter(Mandatory = $false)][String] $ComponentId,
        [Parameter(Mandatory = $true)][Bool] $FullBackupEnabled,
        [Parameter(Mandatory = $false)][String] $FullBackupSchedule,
        [Parameter(Mandatory = $true)][Bool] $IncrementalBackupEnabled,
        [Parameter(Mandatory = $false)][String] $IncrementalBackupSchedule,
        [Parameter(Mandatory = $false)][Int] $PollIntervalSeconds = 60
    )

    $jumpboxName = hostname
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    if ($FullBackupEnabled -and [string]::IsNullOrWhiteSpace($FullBackupSchedule)) {
        LogMessage -type ERROR -message "[$jumpboxName] -FullBackupSchedule is required when -FullBackupEnabled is `$true"
        return
    }
    if ($IncrementalBackupEnabled -and [string]::IsNullOrWhiteSpace($IncrementalBackupSchedule)) {
        LogMessage -type ERROR -message "[$jumpboxName] -IncrementalBackupSchedule is required when -IncrementalBackupEnabled is `$true"
        return
    }

    # Get Services Runtime token
    $srToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn $ServicesRuntimeFqdn -Username $ServicesRuntimeUsername -Password $ServicesRuntimePassword
    if (-not $srToken) {
        LogMessage -type ERROR -message "[$jumpboxName] Unable to obtain Services Runtime token. Aborting."
        return
    }
    $tokenFetchedAt = [DateTime]::UtcNow

    $headers = @{
        "Authorization" = "Bearer $srToken"
        "Accept"        = "application/json"
    }

    # Resolve component ID
    if ($ComponentId) {
        $componentId = $ComponentId.Trim()
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Using supplied component ID: $componentId"
    } else {
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Resolving VSP component ID"
        try {
            $componentsResponse = Invoke-RestMethod -Uri "https://$ServicesRuntimeFqdn/api/v1/components" -Method GET -Headers $headers -SkipCertificateCheck
        } catch {
            LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Failed to retrieve components: $($_.Exception.Message)"
            return
        }
        $vspComponent = @($componentsResponse.components | Where-Object { $_.type -eq "vsp" }) | Select-Object -First 1
        if (-not $vspComponent) {
            LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] No component of type 'vsp' found. Pass -ComponentId to specify manually."
            return
        }
        $componentId = $vspComponent.id
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Resolved VSP component ID: $componentId"
    }

    # Build the request body
    $requestBody = @{
        spec    = @{
            configuration = @{
                backups = @{
                    full        = @{
                        enable   = $FullBackupEnabled
                        schedule = $FullBackupSchedule
                    }
                    incremental = @{
                        enable   = $IncrementalBackupEnabled
                        schedule = $IncrementalBackupSchedule
                    }
                }
            }
        }
        options = @{}
    } | ConvertTo-Json -Depth 10

    Write-Host ""
    Write-Host " Backup Schedule Payload:" -ForegroundColor Cyan
    Write-Host $requestBody
    Write-Host ""

    $applyUri = "https://$ServicesRuntimeFqdn/api/v1/components/${componentId}?action=apply"
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Applying backup schedule to component $componentId"

    try {
        $response = Invoke-RestMethod -Uri $applyUri -Method POST -Headers $headers -Body $requestBody -SkipCertificateCheck
    } catch {
        $statusCode = $null
        if ($_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }

        $errorMessage = $_.Exception.Message
        $rawErrorDetails = $_.ErrorDetails.Message
        if ($rawErrorDetails) {
            try {
                $errorBody = $rawErrorDetails | ConvertFrom-Json
                if ($errorBody.message) { $errorMessage = $errorBody.message }
                elseif ($errorBody.messages) { $errorMessage = ($errorBody.messages | ForEach-Object { if ($_.default) { $_.default } else { $_ } }) -join '; ' }
                elseif ($errorBody.error) { $errorMessage = $errorBody.error }
                else { $errorMessage = $rawErrorDetails }
            } catch {
                $errorMessage = $rawErrorDetails
            }
        }

        if ($statusCode -eq 404) {
            LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Component $componentId not found (HTTP 404). Verify the component ID with GET /api/v1/components or Get-ServicesRuntimeBackupSchedule."
        } else {
            LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Failed to apply backup schedule: $errorMessage"
        }
        return
    }

    # Check for a task ID in the response
    $taskId = $response.id
    if (-not $taskId) {
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Backup schedule applied successfully (no task returned)"
        $StopWatch.Stop()
        $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
        return
    }

    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Backup schedule task submitted: $taskId"
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Polling task status every $PollIntervalSeconds seconds"

    $taskUri = "https://$ServicesRuntimeFqdn/api/v1/tasks/$taskId"
    $taskStatus = "IN_PROGRESS"
    Do {
        Start-Sleep -Seconds $PollIntervalSeconds

        try {
            if (([DateTime]::UtcNow - $tokenFetchedAt).TotalMinutes -ge 60) {
                LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Token age >= 60 minutes; refreshing"
                $newToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn $ServicesRuntimeFqdn -Username $ServicesRuntimeUsername -Password $ServicesRuntimePassword
                if ($newToken) {
                    $srToken = $newToken
                    $headers["Authorization"] = "Bearer $srToken"
                    $tokenFetchedAt = [DateTime]::UtcNow
                } else {
                    LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Token refresh failed; continuing with existing token"
                }
            }
            $taskResponse = Invoke-RestMethod -Uri $taskUri -Method GET -Headers $headers -SkipCertificateCheck
            $taskStatus = $taskResponse.status
            LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Status: $taskStatus"
        } catch {
            LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Error polling task (will retry): $($_.Exception.Message)"
        }
    } While ($taskStatus -in @("IN_PROGRESS", "IN PROGRESS", "PENDING", "RUNNING"))

    if ($taskStatus -in @("SUCCESSFUL", "SUCCESS", "COMPLETED", "Succeeded")) {
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Backup schedule applied successfully"
    } else {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Backup schedule task ended with status: $taskStatus"
        if ($taskResponse.errors) {
            foreach ($err in $taskResponse.errors) {
                LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Error: $($err.message)"
            }
        }
    }

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Set-ServicesRuntimeBackupSchedule

Function Get-ServicesRuntimeBackupSchedule {
    <#
    .SYNOPSIS
    Retrieves the existing full and incremental backup schedule from a VCFMS Services Runtime instance.

    .DESCRIPTION
    The Get-ServicesRuntimeBackupSchedule cmdlet retrieves the specified component's detail via GET /api/v1/components/{ComponentId} and returns the backup schedule found at spec.configuration.backups (full and incremental enable/schedule values). If -ComponentId is not supplied, the component of type "vsp" is resolved automatically from GET /api/v1/components.

    .EXAMPLE
    Get-ServicesRuntimeBackupSchedule -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!"

    .EXAMPLE
    Get-ServicesRuntimeBackupSchedule -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!" -ComponentId "1f5c79fe-e3aa-41b1-a5cf-774a6497fa3d"

    .PARAMETER ServicesRuntimeFqdn
    FQDN of the VCFMS Services Runtime instance.

    .PARAMETER ServicesRuntimePassword
    Password for the Services Runtime admin user (used to obtain a token).

    .PARAMETER ServicesRuntimeUsername
    Username for the Services Runtime token. Default is "admin@vsp.local".

    .PARAMETER ComponentId
    Component ID (cluster ID) to retrieve the backup schedule from. If omitted, the component of type "vsp" is resolved automatically.
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $ServicesRuntimeFqdn,
        [Parameter(Mandatory = $true)][String] $ServicesRuntimePassword,
        [Parameter(Mandatory = $false)][String] $ServicesRuntimeUsername = "admin@vsp.local",
        [Parameter(Mandatory = $false)][String] $ComponentId
    )

    $jumpboxName = hostname
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    # Get Services Runtime token
    $srToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn $ServicesRuntimeFqdn -Username $ServicesRuntimeUsername -Password $ServicesRuntimePassword
    if (-not $srToken) {
        LogMessage -type ERROR -message "[$jumpboxName] Unable to obtain Services Runtime token. Aborting."
        return
    }

    $headers = @{
        "Authorization" = "Bearer $srToken"
        "Accept"        = "application/json"
    }

    # Resolve component ID
    if ($ComponentId) {
        $componentId = $ComponentId.Trim()
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Using supplied component ID: $componentId"
    } else {
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Resolving VSP component ID"
        try {
            $componentsResponse = Invoke-RestMethod -Uri "https://$ServicesRuntimeFqdn/api/v1/components" -Method GET -Headers $headers -SkipCertificateCheck
        } catch {
            LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Failed to retrieve components: $($_.Exception.Message)"
            return
        }
        $vspComponent = @($componentsResponse.components | Where-Object { $_.type -eq "vsp" }) | Select-Object -First 1
        if (-not $vspComponent) {
            LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] No component of type 'vsp' found. Pass -ComponentId to specify manually."
            return
        }
        $componentId = $vspComponent.id
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Resolved VSP component ID: $componentId"
    }

    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Retrieving backup schedule for component $componentId"

    try {
        $componentDetail = Invoke-RestMethod -Uri "https://$ServicesRuntimeFqdn/api/v1/components/$componentId" -Method GET -Headers $headers -SkipCertificateCheck
    } catch {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] GET /api/v1/components/$componentId failed: $($_.Exception.Message)"
        return
    }

    $backups = $componentDetail.spec.configuration.backups
    if (-not $backups -or (-not $backups.full -and -not $backups.incremental)) {
        LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] No backup schedule configuration found for component $componentId"
        $StopWatch.Stop()
        $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
        return
    }

    $result = [PSCustomObject]@{
        FullBackupEnabled         = $backups.full.enable
        FullBackupSchedule        = $backups.full.schedule
        IncrementalBackupEnabled  = $backups.incremental.enable
        IncrementalBackupSchedule = $backups.incremental.schedule
    }

    Write-Host ""
    Write-Host " Backup Schedule - Component $componentId" -ForegroundColor Cyan
    Write-Host " ────────────────────────────────────────────────────────────────────" -ForegroundColor Cyan
    $result | Format-List | Out-String | Write-Host
    Write-Host " ────────────────────────────────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host ""

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"

    return $result
}
Export-ModuleMember -Function Get-ServicesRuntimeBackupSchedule

Function Get-ServicesRuntimeComponentBackups {
    <#
    .SYNOPSIS
    Retrieves and displays ServicesRuntimeComponent backup information for one or more component types.

    .DESCRIPTION
    The Get-ServicesRuntimeComponentBackups cmdlet queries the  Services Runtime GET /api/v1/system/backups endpoint and returns backup details for the specified component types, sorted by component type and age. Output includes component type, version, backup name, age, and path.

    When -Components does not include "vsp" or "vcfa", the "Available Backup Groups" table includes an additional "Associated VSP Backup (UTC)" column showing the vsp backup whose timestamp is closest to each group, for reference when the vsp component itself is not part of the selection.

    .EXAMPLE
    Get-ServicesRuntimeComponentBackups -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!"

    .EXAMPLE
    Get-ServicesRuntimeComponentBackups -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!" -Components "vsp","salt"

    .EXAMPLE
    Get-ServicesRuntimeComponentBackups -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!" -VspId "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

    .PARAMETER ServicesRuntimeFqdn
    FQDN of the Services Runtime instance.

    .PARAMETER ServicesRuntimePassword
    Password for the Services Runtime admin user (used to obtain a token).

    .PARAMETER ServicesRuntimeUsername
    Username for the Services Runtime token. Default is "admin@vsp.local".

    .PARAMETER Components
    One or more component types to display. Valid values: vsp, vcf-fleet-lcm, vcf-fleet-depot, vcf-sddc-lcm, salt, salt-raas, vidb, ops-logs, vcfa. Default is all of them. When you opt in to generated restore JSON without passing -Components, ops-logs and vcfa are omitted from that JSON (you can still include them by passing -Components explicitly).

    .PARAMETER VspId
    When specified, only backups whose path contains /vcf/backups/<VspId>/ are returned. Use this to scope results to a specific VSP instance when multiple are present in the backup store.
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $ServicesRuntimeFqdn,
        [Parameter(Mandatory = $true)][String] $ServicesRuntimePassword,
        [Parameter(Mandatory = $false)][String] $ServicesRuntimeUsername = "admin@vsp.local",
        [Parameter(Mandatory = $false)][ValidateSet("vsp", "vcf-fleet-lcm", "vcf-fleet-depot", "vcf-sddc-lcm", "salt", "salt-raas", "vidb", "ops-logs", "vcfa")][String[]] $Components = @("vsp", "vcf-fleet-lcm", "vcf-fleet-depot", "vcf-sddc-lcm", "salt", "salt-raas", "vidb", "ops-logs", "vcfa"),
        [Parameter(Mandatory = $false)][String] $VspId
    )

    $jumpboxName = hostname
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    # Get Services Runtime token
    $srToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn $ServicesRuntimeFqdn -Username $ServicesRuntimeUsername -Password $ServicesRuntimePassword
    if (-not $srToken) {
        LogMessage -type ERROR -message "[$jumpboxName] Unable to obtain Services Runtime token. Aborting."
        return
    }

    $headers = @{
        "Authorization" = "Bearer $srToken"
        "Accept"        = "application/json"
    }

    $backupsUri = "https://$ServicesRuntimeFqdn/api/v1/system/backups"
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Retrieving backup list"

    try {
        $response = Invoke-RestMethod -Uri $backupsUri -Method GET -Headers $headers -SkipCertificateCheck
    } catch {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Failed to retrieve backups: $($_.Exception.Message)"
        return
    }

    $allBackups = $response.backups
    if (-not $allBackups -or ($allBackups | Measure-Object).Count -eq 0) {
        LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] No backups found."
        return
    }

    if ($PSBoundParameters.ContainsKey('VspId')) {
        $allBackups = @($allBackups | Where-Object { $_.path -match ('/vcf/backups/' + [regex]::Escape($VspId) + '(/|$)') })
        if ($allBackups.Count -eq 0) {
            LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] No backups found with VspId '$VspId' in path."
            return
        }
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Filtered to $($allBackups.Count) backup(s) matching VspId '$VspId'"
    }

    # Parse all backups for the requested component types, normalising the timestamp
    $parsedBackups = @()
    $now = Get-Date

    foreach ($backup in $allBackups) {
        if ($backup.component.type -notin $Components) { continue }
        $backupName     = $backup.name
        $normalizedName = $backupName -replace 'T(\d{2})-(\d{2})-(\d{2})Z', 'T$1:$2:$3Z'
        $backupDate     = $null
        $daysOld        = $null
        try {
            $backupDate = [datetime]::Parse($normalizedName, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal)
            $daysOld    = [math]::Floor(($now - $backupDate).TotalDays)
        } catch {}

        $parsedBackups += [PSCustomObject]@{
            ComponentType  = $backup.component.type
            Version        = $backup.component.version
            Name           = $backupName
            NormalizedName = $normalizedName
            BackupDate     = $backupDate
            DaysOld        = $daysOld
            Path           = $backup.path
        }
    }

    if ($parsedBackups.Count -eq 0) {
        LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] No backups found for components: $($Components -join ', ')"
        return
    }

    # Build rank-based backup groups: rank 1 = most recent backup of each component,
    # rank 2 = second most recent, and so on. Components backed up at different times
    # within the same scheduled window are still placed in the same rank group.
    $byComponent = @{}
    foreach ($b in $parsedBackups) {
        if (-not $byComponent.ContainsKey($b.ComponentType)) {
            $byComponent[$b.ComponentType] = [System.Collections.Generic.List[PSCustomObject]]::new()
        }
        $byComponent[$b.ComponentType].Add($b)
    }
    foreach ($key in @($byComponent.Keys)) {
        $byComponent[$key] = @($byComponent[$key] | Sort-Object BackupDate -Descending)
    }

    $maxRank   = ($byComponent.Values | ForEach-Object { $_.Count } | Measure-Object -Maximum).Maximum
    $groupList = [System.Collections.Generic.List[PSCustomObject]]::new()

    for ($rank = 0; $rank -lt $maxRank; $rank++) {
        $entries = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($componentType in ($byComponent.Keys | Sort-Object)) {
            if ($rank -lt $byComponent[$componentType].Count) {
                $entries.Add($byComponent[$componentType][$rank])
            }
        }
        if ($entries.Count -gt 0) {
            $groupList.Add([PSCustomObject]@{ Index = ($rank + 1); Entries = $entries })
        }
    }

    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Found $($parsedBackups.Count) backup(s) across $($groupList.Count) backup group(s)"

    # Display numbered list of backup groups
    $isSingleComponent = ($Components.Count -eq 1)

    # When the selection doesn't include vsp (or vcfa) directly, surface the nearest vsp backup
    # alongside each group for reference -- vsp is the platform's own backup and its timing is
    # useful context even when it wasn't explicitly requested. $allBackups is unfiltered by
    # -Components (only by -VspId), so vsp entries are available here regardless of $Components.
    $showVspColumn = ($Components -notcontains "vsp") -and ($Components -notcontains "vcfa")
    $vspBackups = @()
    if ($showVspColumn) {
        foreach ($backup in $allBackups) {
            if ($backup.component.type -ne "vsp") { continue }
            $vspNormalizedName = $backup.name -replace 'T(\d{2})-(\d{2})-(\d{2})Z', 'T$1:$2:$3Z'
            $vspBackupDate = $null
            try {
                $vspBackupDate = [datetime]::Parse($vspNormalizedName, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal)
            } catch {}
            if ($vspBackupDate) {
                $vspBackups += [PSCustomObject]@{ Name = $backup.name; BackupDate = $vspBackupDate }
            }
        }
        if ($vspBackups.Count -eq 0) {
            LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] No vsp backups found to correlate with the requested component(s). Associated VSP Backup column will be omitted."
            $showVspColumn = $false
        }
    }

    # Build every row up front so the separator can be sized to the widest row --
    # the Components column's length varies with how many component types share a group.
    $headerLine = if ($isSingleComponent) {
        if ($showVspColumn) {
            "  {0,3}  {1,-20}  {2,-10}  {3,-26}  {4}" -f "ID", "Backup Points", "Age", "Associated VSP Backup", "Components"
        } else {
            "  {0,3}  {1,-20}  {2,-10}  {3}" -f "ID", "Backup Points", "Age", "Components"
        }
    } else {
        if ($showVspColumn) {
            "  {0,3}  {1,-18}  {2,-16}  {3,-10}  {4,-26}  {5}" -f "ID", "Backup Start", "Backup End", "Age", "Associated VSP Backup", "Components"
        } else {
            "  {0,3}  {1,-18}  {2,-16}  {3,-10}  {4}" -f "ID", "Backup Start", "Backup End", "Age", "Components"
        }
    }

    $rowLines = [System.Collections.Generic.List[String]]::new()
    if (-not $isSingleComponent) {
        if ($showVspColumn) {
            $rowLines.Add(("  {0,3}  {1,-18}  {2,-16}  {3,-10}  {4,-26}  {5}" -f 0, "Custom", "-", "-", "-", "Choose a backup point per component"))
        } else {
            $rowLines.Add(("  {0,3}  {1,-18}  {2,-16}  {3,-10}  {4}" -f 0, "Custom", "-", "-", "Choose a backup point per component"))
        }
    }

    foreach ($group in $groupList) {
        $sortedEntries = $group.Entries | Sort-Object BackupDate -Descending
        $newest        = $sortedEntries | Select-Object -First 1
        $oldest        = $sortedEntries | Select-Object -Last 1
        $ageStr        = if ($newest.BackupDate) {
            $ageSpan = $now - $newest.BackupDate
            if ($ageSpan.TotalDays -ge 1) { "$([math]::Floor($ageSpan.TotalDays)) Days" } else { "$([math]::Floor($ageSpan.TotalHours)) Hours" }
        } else { "unknown" }
        $uniqueTypes   = @($group.Entries | Select-Object -ExpandProperty ComponentType | Sort-Object -Unique)
        $newestStr     = if ($newest.BackupDate) { $newest.BackupDate.ToString("yyyy-MM-dd HH:mm") } else { "unknown" }

        $vspStr = "-"
        if ($showVspColumn -and $newest.BackupDate) {
            $nearestVsp = $vspBackups | Sort-Object { [math]::Abs(($_.BackupDate - $newest.BackupDate).Ticks) } | Select-Object -First 1
            if ($nearestVsp) { $vspStr = $nearestVsp.BackupDate.ToString("yyyy-MM-dd HH:mm") }
        }

        if ($isSingleComponent) {
            if ($showVspColumn) {
                $rowLines.Add(("  {0,3}  {1,-20}  {2,-10}  {3,-26}  {4} ({5})" -f $group.Index, $newestStr, $ageStr, $vspStr, ($uniqueTypes -join ', '), $uniqueTypes.Count))
            } else {
                $rowLines.Add(("  {0,3}  {1,-20}  {2,-10}  {3} ({4})" -f $group.Index, $newestStr, $ageStr, ($uniqueTypes -join ', '), $uniqueTypes.Count))
            }
        } else {
            $oldestStr = if ($oldest.BackupDate) { $oldest.BackupDate.ToString("yyyy-MM-dd HH:mm") } else { "unknown" }
            if ($showVspColumn) {
                $rowLines.Add(("  {0,3}  {1,-18}  {2,-16}  {3,-10}  {4,-26}  {5} ({6})" -f $group.Index, $oldestStr, $newestStr, $ageStr, $vspStr, ($uniqueTypes -join ', '), $uniqueTypes.Count))
            } else {
                $rowLines.Add(("  {0,3}  {1,-18}  {2,-16}  {3,-10}  {4} ({5})" -f $group.Index, $oldestStr, $newestStr, $ageStr, ($uniqueTypes -join ', '), $uniqueTypes.Count))
            }
        }
    }

    $tableWidth = (@($rowLines) + $headerLine | Measure-Object -Property Length -Maximum).Maximum
    $separator  = " " + ("─" * $tableWidth)

    Write-Host ""
    Write-Host " Available Backup Groups (All times in UTC)" -ForegroundColor Cyan
    Write-Host $separator -ForegroundColor Cyan
    Write-Host $headerLine -ForegroundColor Gray
    Write-Host ""

    $rowLines | ForEach-Object { Write-Host $_ -ForegroundColor White }

    Write-Host $separator -ForegroundColor Cyan
    Write-Host ""

    # User selects a backup group
    $selectedGroup = $null
    $customMode    = $false
    Do {
        Write-Host " Enter the ID of the backup group to use, or C to Cancel: " -ForegroundColor Yellow -NoNewline
        $selection = Read-Host
        if ($selection -in @("C", "c")) {
            LogMessage -type INFO -message "[$jumpboxName] Cancelled by user."
            $StopWatch.Stop()
            $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
            LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
            return
        }
        $selNum = -1
        if ([int]::TryParse($selection, [ref]$selNum) -and (-not $isSingleComponent) -and $selNum -eq 0) {
            $customMode    = $true
            $selectedGroup = [PSCustomObject]@{ Index = 0; Entries = @() }
        } elseif ([int]::TryParse($selection, [ref]$selNum) -and $selNum -ge 1 -and $selNum -le $groupList.Count) {
            $selectedGroup = $groupList | Where-Object { $_.Index -eq $selNum }
        } else {
            Write-Host " Invalid selection. Enter a number between 1 and $($groupList.Count), or C to Cancel." -ForegroundColor Yellow
        }
    } Until ($null -ne $selectedGroup)

    # Build the final list of chosen entries: either the picked rank group, or a per-component custom selection
    $finalEntries = @()
    if ($customMode) {
        LogMessage -type INFO -message "[$jumpboxName] Building custom backup selection"
        foreach ($componentType in ($byComponent.Keys | Sort-Object)) {
            $options = $byComponent[$componentType]

            Write-Host ""
            Write-Host " Backup points for '$componentType'" -ForegroundColor Cyan
            Write-Host " ────────────────────────────────────────────────────────────────────" -ForegroundColor Cyan
            Write-Host ("  {0,3}  {1,-20}  {2,-10}  {3}" -f "ID", "Backup Time (UTC)", "Age", "Version") -ForegroundColor Gray
            for ($i = 0; $i -lt $options.Count; $i++) {
                $opt    = $options[$i]
                $optStr = if ($opt.BackupDate) { $opt.BackupDate.ToString("yyyy-MM-dd HH:mm") } else { "unknown" }
                $optAge = if ($opt.BackupDate) {
                    $optAgeSpan = $now - $opt.BackupDate
                    if ($optAgeSpan.TotalDays -ge 1) { "$([math]::Floor($optAgeSpan.TotalDays)) Days" } else { "$([math]::Floor($optAgeSpan.TotalHours)) Hours" }
                } else { "unknown" }
                Write-Host ("  {0,3}  {1,-20}  {2,-10}  {3}" -f ($i + 1), $optStr, $optAge, $opt.Version) -ForegroundColor White
            }
            Write-Host " ────────────────────────────────────────────────────────────────────" -ForegroundColor Cyan

            $chosenEntry = $null
            Do {
                Write-Host " Enter the ID of the backup point to use for '$componentType', or C to Cancel: " -ForegroundColor Yellow -NoNewline
                $optSelection = Read-Host
                if ($optSelection -in @("C", "c")) {
                    LogMessage -type INFO -message "[$jumpboxName] Cancelled by user."
                    $StopWatch.Stop()
                    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
                    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
                    return
                }
                $optNum = 0
                if ([int]::TryParse($optSelection, [ref]$optNum) -and $optNum -ge 1 -and $optNum -le $options.Count) {
                    $chosenEntry = $options[$optNum - 1]
                } else {
                    Write-Host " Invalid selection. Enter a number between 1 and $($options.Count), or C to Cancel." -ForegroundColor Yellow
                }
            } Until ($null -ne $chosenEntry)

            $finalEntries += $chosenEntry
        }
        $groupLabel = "Custom"
        LogMessage -type INFO -message "[$jumpboxName] Selected custom backup group ($($finalEntries.Count) component(s))"
    } else {
        $finalEntries      = @($selectedGroup.Entries)
        $sortedFinalEntries = $finalEntries | Sort-Object BackupDate -Descending
        $newestFinal       = $sortedFinalEntries | Select-Object -First 1
        $oldestFinal       = $sortedFinalEntries | Select-Object -Last 1
        $newestFinalStr    = if ($newestFinal.BackupDate) { $newestFinal.BackupDate.ToString("yyyy-MM-dd HH:mm") } else { "unknown" }
        $oldestFinalStr    = if ($oldestFinal.BackupDate) { $oldestFinal.BackupDate.ToString("yyyy-MM-dd HH:mm") } else { "unknown" }
        $groupLabel        = if ($oldestFinalStr -eq $newestFinalStr) { "$newestFinalStr UTC" } else { "$oldestFinalStr -> $newestFinalStr UTC" }
    }

    # Show what is available in the selected backup group
    $groupTitle = if ($customMode) { "Components in custom backup group" } else { "Components in backup group $($selectedGroup.Index) ($groupLabel)" }
    Write-Host ""
    Write-Host " $groupTitle" -ForegroundColor Cyan
    Write-Host " ────────────────────────────────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host ("  {0,-16}  {1,-18}  {2}" -f "Component", "Version", "Backup Time") -ForegroundColor Gray
    $finalEntries | Sort-Object BackupDate -Descending | ForEach-Object {
        $entryTimeStr = if ($_.BackupDate) { $_.BackupDate.ToString("yyyy-MM-dd HH:mm") } else { "unknown" }
        Write-Host ("  {0,-16}  {1,-18}  {2}" -f $_.ComponentType, $_.Version, $entryTimeStr) -ForegroundColor White
    }
    Write-Host " ────────────────────────────────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host ""

    # Offer to construct a restore JSON for the selected backup group
    Do {
        Write-Host " Would you like to construct a restore JSON for this backup group? (Y/N): " -ForegroundColor Yellow -NoNewline
        $buildJson = Read-Host
    } Until ($buildJson -in @("Y", "y", "N", "n"))

    if ($buildJson -in @("Y", "y")) {
        $explicitlyPassed      = $PSBoundParameters.ContainsKey("Components")
        $restoreComponentTypes = if ($explicitlyPassed) { $Components } else { $Components | Where-Object { $_ -notin @("ops-logs", "vcfa") } }

        $restoreComponents = @(
            foreach ($componentType in $restoreComponentTypes) {
                $entry = $finalEntries | Where-Object { $_.ComponentType -eq $componentType } | Select-Object -First 1
                if ($entry) { @{ path = $entry.Path; point = $entry.Name } }
            }
        )

        $restorePayload = @{ components = $restoreComponents } | ConvertTo-Json -Depth 5
        $outputFile     = ".\restore-payload.json"
        $restorePayload | Out-File -FilePath $outputFile -Encoding utf8
        LogMessage -type INFO -message "[$jumpboxName] Restore JSON saved to $outputFile ($($restoreComponents.Count) component(s))"
        Write-Host ""
        Write-Host " Restore JSON contents:" -ForegroundColor Cyan
        Write-Host $restorePayload
        Write-Host ""
    }

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Get-ServicesRuntimeComponentBackups

Function Restore-ServicesRuntimeComponentBackup {
    <#
    .SYNOPSIS
    Restores Service Runtime component backups from a user-provided JSON payload file.

    .DESCRIPTION
    The Restore-ServicesRuntimeComponentBackup cmdlet submits a restore request to the Services Runtime POST /api/v1/system/backups?action=restore endpoint.

    The restore payload is a JSON file containing the "components" array, where each entry specifies the SFTP path and restore point for one component. Use Get-ServicesRuntimeComponentBackups to list available backups and their paths, then construct the JSON file with the desired restore points.

    The function displays the payload for confirmation before submitting, then polls the restore status until completion.

    .EXAMPLE
    # Step 1: List available backups to find paths and restore points
    Get-ServicesRuntimeComponentBackups -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!"

    # Step 2: Create a JSON file (restore-payload.json) with the desired components:
    # {
    #   "components": [
    #     { "path": "sftp://svc-vcf-bck@10.167.173.126:22/media/backups/vcf/backups/.../vsp/.../2026-03-23T16-45-31Z", "point": "2026-03-23T16-45-31Z" },
    #     { "path": "sftp://svc-vcf-bck@10.167.173.126:22/media/backups/vcf/backups/.../salt/.../2026-03-23T17-13-37Z", "point": "2026-03-23T17-13-37Z" }
    #   ]
    # }

    # Step 3: Run the restore
    Restore-ServicesRuntimeComponentBackup -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!" -RestoreJsonFile ".\restore-payload.json"

    .PARAMETER ServicesRuntimeFqdn
    FQDN of the Services Runtime instance.

    .PARAMETER ServicesRuntimePassword
    Password for the Services Runtime admin user (used to obtain a token).

    .PARAMETER ServicesRuntimeUsername
    Username for the Services Runtime token. Default is "admin@vsp.local".

    .PARAMETER RestoreJsonFile
    Path to a JSON file containing the restore payload. The file must contain a "components" array with "path" and "point" for each component to restore.

    #>

    Param(
        [Parameter(Mandatory = $true)][String] $ServicesRuntimeFqdn,
        [Parameter(Mandatory = $true)][String] $ServicesRuntimePassword,
        [Parameter(Mandatory = $false)][String] $ServicesRuntimeUsername = "admin@vsp.local",
        [Parameter(Mandatory = $true)][String] $RestoreJsonFile
    )

    $jumpboxName = hostname
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    # Read and validate the payload file
    $payloadPath = (Resolve-Path -Path $RestoreJsonFile -ErrorAction SilentlyContinue).Path
    if (-not $payloadPath) {
        LogMessage -type ERROR -message "[$jumpboxName] Restore payload file not found: $RestoreJsonFile"
        return
    }

    $payloadContent = Get-Content $payloadPath -Raw
    try {
        $payloadObject = $payloadContent | ConvertFrom-Json
    } catch {
        LogMessage -type ERROR -message "[$jumpboxName] Failed to parse JSON from $RestoreJsonFile : $($_.Exception.Message)"
        return
    }

    if (-not $payloadObject.components -or ($payloadObject.components | Measure-Object).Count -eq 0) {
        LogMessage -type ERROR -message "[$jumpboxName] Payload file must contain a 'components' array with at least one entry."
        return
    }

    # Display the payload for confirmation
    Write-Host ""
    Write-Host " Restore Payload ($($payloadObject.components.Count) component(s)):" -ForegroundColor Cyan
    Write-Host " ----------------------------------------------------------------" -ForegroundColor Cyan
    foreach ($comp in $payloadObject.components) {
        $componentName = ($comp.path -split '/') | Where-Object { $_ -in @("vsp", "vcf-fleet-lcm", "vcf-fleet-depot", "vcf-sddc-lcm", "salt", "salt-raas", "vidb", "ops-logs", "vcfa") } | Select-Object -First 1
        if (-not $componentName) { $componentName = "unknown" }
        Write-Host "   $componentName" -ForegroundColor Yellow -NoNewline
        Write-Host " -> point: $($comp.point)" -ForegroundColor White
        Write-Host "     path: $($comp.path)" -ForegroundColor Gray
    }
    Write-Host ""

    Do {
        Write-Host " Proceed with restore? (Y/N): " -ForegroundColor Yellow -NoNewline
        $confirmation = Read-Host
    } Until ($confirmation -in @("Y", "y", "N", "n"))

    if ($confirmation -in @("N", "n")) {
        LogMessage -type INFO -message "[$jumpboxName] Restore cancelled by user."
        return
    }

    # Get Services Runtime token
    $srToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn $ServicesRuntimeFqdn -Username $ServicesRuntimeUsername -Password $ServicesRuntimePassword
    if (-not $srToken) {
        LogMessage -type ERROR -message "[$jumpboxName] Unable to obtain Services Runtime token. Aborting."
        return
    }
    $tokenFetchedAt = [DateTime]::UtcNow

    $headers = @{
        "Authorization" = "Bearer $srToken"
        "Content-Type"  = "application/json"
        "Accept"        = "application/json"
    }

    # Build a componentId -> type name lookup for friendlier status reporting
    $componentNameById = @{}
    try {
        $componentsResp = Invoke-RestMethod -Uri "https://$ServicesRuntimeFqdn/api/v1/components" -Method GET -Headers $headers -SkipCertificateCheck
        foreach ($c in $componentsResp.components) {
            if ($c.id -and $c.type) { $componentNameById[$c.id] = $c.type }
        }
    } catch {
        LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Could not pre-fetch component names; UUIDs will be used in status output"
    }

    $restoreUri = "https://$ServicesRuntimeFqdn/api/v1/system/backups?action=restore"
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Submitting restore request"

    try {
        $response = Invoke-RestMethod -Uri $restoreUri -Method POST -Headers $headers -Body $payloadContent -SkipCertificateCheck
    } catch {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Restore request failed: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            try {
                $errorStream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($errorStream)
                $errorBody = $reader.ReadToEnd()
                LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Response body: $errorBody"
            } catch {}
        }
        return
    }

    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Restore request accepted"

    # Check for a task ID in the POST response
    $taskId = $response.id
    if (-not $taskId) {
        # POST /backups?action=restore does not return a task ID directly;
        # find the restore task by querying GET /api/v1/tasks
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Searching for restore task via /api/v1/tasks"
        Start-Sleep -Seconds 5
        try {
            $tasksResponse = Invoke-RestMethod -Uri "https://$ServicesRuntimeFqdn/api/v1/tasks" -Method GET -Headers $headers -SkipCertificateCheck
            $restoreTask = $tasksResponse.tasks |
                Where-Object { $_.type -eq "com.vmware.vcfms.task.RestoreMultipleComponents" -and $_.status -notin @("Succeeded", "Failed", "Cancelled") } |
                    Sort-Object createTime -Descending |
                        Select-Object -First 1
            if ($restoreTask) {
                $taskId = $restoreTask.id
            }
        } catch {
            LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Could not query tasks endpoint: $($_.Exception.Message)"
        }
    }

    if (-not $taskId) {
        LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Could not find restore task. Use Watch-VcfmsTask -FindRunning to check progress."
        $StopWatch.Stop()
        $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
        return
    }

    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Restore task ID: $taskId"

    $taskUri = "https://$ServicesRuntimeFqdn/api/v1/tasks/$taskId"
    $taskStatus = "Running"
    $reportedComponentStatuses = @{}
    $componentFirstSeenAt = @{}
    $lastStatusLoggedAt = [DateTime]::MinValue
    $lastLoggedStatus = ""
    Do {
        Start-Sleep -Seconds 60

        try {
            if (([DateTime]::UtcNow - $tokenFetchedAt).TotalMinutes -ge 60) {
                LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Token age >= 60 minutes; refreshing"
                $newToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn $ServicesRuntimeFqdn -Username $ServicesRuntimeUsername -Password $ServicesRuntimePassword
                if ($newToken) {
                    $srToken = $newToken
                    $headers["Authorization"] = "Bearer $srToken"
                    $tokenFetchedAt = [DateTime]::UtcNow
                } else {
                    LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Token refresh failed; continuing with existing token"
                }
            }
            $taskResponse = Invoke-RestMethod -Uri $taskUri -Method GET -Headers $headers -SkipCertificateCheck
            $taskStatus = $taskResponse.status
            $statusChanged = $taskStatus -ne $lastLoggedStatus
            $quietIntervalElapsed = ([DateTime]::UtcNow - $lastStatusLoggedAt).TotalSeconds -ge 300
            if ($statusChanged -or $quietIntervalElapsed) {
                LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Status: $taskStatus"
                $lastStatusLoggedAt = [DateTime]::UtcNow
                $lastLoggedStatus = $taskStatus
            }

            # Report any new or changed restoreResults entries
            if ($taskResponse.result -and $taskResponse.result.restoreResults) {
                $terminalComponentStates = @("Succeeded","Failed","Cancelled","COMPLETED","FAILED","CANCELLED","SUCCESS","SUCCESSFUL","ERROR")
                foreach ($entry in $taskResponse.result.restoreResults) {
                    $cid = $entry.componentId
                    $cStatus = $entry.status
                    if ($cid -and $cStatus) {
                        if (-not $componentFirstSeenAt.ContainsKey($cid)) {
                            $componentFirstSeenAt[$cid] = [DateTime]::UtcNow
                        }
                        $prev = $reportedComponentStatuses[$cid]
                        if ($prev -ne $cStatus) {
                            $cName = if ($componentNameById.ContainsKey($cid)) { $componentNameById[$cid] } else { $cid }
                            $elapsedMsg = ""
                            if ($cStatus -in $terminalComponentStates) {
                                $span = $null
                                if ($entry.startTime -and $entry.endTime) {
                                    $cStart = ConvertFrom-VcfmsTaskTimestampToUtc -Timestamp $entry.startTime
                                    $cEnd   = ConvertFrom-VcfmsTaskTimestampToUtc -Timestamp $entry.endTime
                                    if ($cStart -and $cEnd) { $span = $cEnd - $cStart }
                                }
                                if (-not $span) {
                                    $span = [DateTime]::UtcNow - $componentFirstSeenAt[$cid]
                                }
                                $totalMinutes = ($span.Hours * 60) + $span.Minutes
                                $elapsedMsg = " in $totalMinutes minutes and $($span.Seconds) seconds"
                            }
                            LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Component $cName status: $cStatus$elapsedMsg"
                            $reportedComponentStatuses[$cid] = $cStatus
                        }
                    }
                }
            }
        } catch {
            LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Error polling task (will retry): $($_.Exception.Message)"
        }
    } While ($taskStatus -in @("IN_PROGRESS", "IN PROGRESS", "PENDING", "RUNNING", "RESTORING", "Running", "Pending", "Queued"))

    if ($taskStatus -in @("SUCCESSFUL", "SUCCESS", "COMPLETED", "Succeeded")) {
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Restore completed successfully"
    } else {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Restore ended with status: $taskStatus"

        # messages array (populated for some failure types)
        if ($taskResponse.messages -and ($taskResponse.messages | Measure-Object).Count -gt 0) {
            foreach ($msg in $taskResponse.messages) {
                LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] $msg"
            }
        }

        # Failed precheck groups take priority — when present, stage errors are just symptoms
        $failedGroups = @($taskResponse.precheckGroups | Where-Object { $_.status -eq "FAILED" })
        if ($failedGroups.Count -gt 0) {
            foreach ($group in $failedGroups) {
                foreach ($check in @($group.prechecks | Where-Object { $_.status -eq "FAILED" })) {
                    $issueMsg = if ($check.issue.message.default) { $check.issue.message.default } else { $check.name.default }
                    $issueMsg = $issueMsg -replace '\s*\[[\w.]+\]\s*$', ''
                    LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] $issueMsg"
                }
            }
        } else {
            # No precheck failures — surface stage errors as the next diagnostic signal
            $failedStages = @($taskResponse.stages | Where-Object { $_.status -eq "Failed" })
            if ($failedStages.Count -gt 0) {
                Write-Host ""
                Write-Host " Stage Errors" -ForegroundColor Cyan
                Write-Host " ────────────────────────────────────────────────────────────────────" -ForegroundColor Cyan
                foreach ($stage in $failedStages) {
                    Write-Host "  Stage : $($stage.name) ($($stage.stageType))" -ForegroundColor Yellow
                    $meaningfulErrors = @($stage.errors | Where-Object { $_ -notmatch 'retryStrategy\.expression' })
                    foreach ($err in $meaningfulErrors) {
                        Write-Host "    $err" -ForegroundColor Gray
                    }
                }
                Write-Host " ────────────────────────────────────────────────────────────────────" -ForegroundColor Cyan
                Write-Host ""
            }
        }
    }

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Restore-ServicesRuntimeComponentBackup

Function Get-VcfmsFleetLCMToken {
    <#
    .SYNOPSIS
    Retrieves an access token from a VCFMS Fleet LCM instance.

    .DESCRIPTION
    The Get-VcfmsFleetLCMToken cmdlet authenticates against the VCFMS Fleet LCM /api/v1/identity/token endpoint using a form-urlencoded password grant and returns the access token string.

    .EXAMPLE
    $fcToken = Get-VcfmsFleetLCMToken -FleetLCMFqdn "flt-fc01.rainpole.io" -Password "VMw@re1!VMw@re1!"

    .PARAMETER FleetLCMFqdn
    FQDN of the VCFMS Fleet LCM instance.

    .PARAMETER Username
    Username for the token request. Default is "admin@vsp.local".

    .PARAMETER Password
    Password for the Fleet LCM user.
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $FleetLCMFqdn,
        [Parameter(Mandatory = $false)][String] $Username = "admin@vsp.local",
        [Parameter(Mandatory = $true)][String] $Password
    )

    $jumpboxName = hostname
    LogMessage -type INFO -message "[$jumpboxName] Requesting VCFMS Fleet LCM token from $FleetLCMFqdn"

    $tokenUri = "https://$FleetLCMFqdn/api/v1/identity/token"
    $tokenBody = "grant_type=password&username=$([uri]::EscapeDataString($Username))&password=$([uri]::EscapeDataString($Password))"

    try {
        $tokenResponse = Invoke-RestMethod -Uri $tokenUri -Method POST -ContentType "application/x-www-form-urlencoded" -Body $tokenBody -SkipCertificateCheck
        $accessToken = $tokenResponse.access_token
        if (-not $accessToken) {
            LogMessage -type ERROR -message "[$FleetLCMFqdn] Token response did not contain an access_token."
            return $null
        }
        LogMessage -type INFO -message "[$FleetLCMFqdn] Fleet LCM token retrieved successfully"
        return $accessToken
    } catch {
        LogMessage -type ERROR -message "[$FleetLCMFqdn] Failed to retrieve Fleet LCM token: $($_.Exception.Message)"
        return $null
    }
}

Function Get-VcfmsComponents {
    <#
    .SYNOPSIS
    Retrieves VCFMS component IDs from the Fleet LCM. Optionally filters by component type description.

    .DESCRIPTION
    The Get-VcfmsComponents cmdlet queries the VCFMS Fleet LCM GET /fleet-lcm/v1/components endpoint and returns component details. If no ComponentTypes are specified, all components are returned. If one or more types are specified, only matching components are returned. For "VCF services runtime" components, the FQDN is also included in the output.

    .EXAMPLE
    Get-VcfmsComponents -FleetLCMFqdn "flt-fc01.rainpole.io" -FleetLCMPassword "VMw@re1!VMw@re1!"

    .EXAMPLE
    Get-VcfmsComponents -FleetLCMFqdn "flt-fc01.rainpole.io" -FleetLCMPassword "VMw@re1!VMw@re1!" -ComponentTypes "Log management","Salt master"

    .EXAMPLE
    Get-VcfmsComponents -FleetLCMFqdn "flt-fc01.rainpole.io" -FleetLCMPassword "VMw@re1!VMw@re1!" -ComponentTypes "VCF services runtime"

    .PARAMETER FleetLCMFqdn
    FQDN of the VCFMS Fleet LCM instance.

    .PARAMETER FleetLCMPassword
    Password for the Fleet LCM admin user (used to obtain a token).

    .PARAMETER FleetLCMUsername
    Username for the Fleet LCM token. Default is "admin@vsp.local".

    .PARAMETER ComponentTypes
    One or more component type descriptions to filter by (e.g. "VCF Operations", "Salt master", "VCF services runtime"). If not specified, all components are returned.
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $FleetLCMFqdn,
        [Parameter(Mandatory = $true)][String] $FleetLCMPassword,
        [Parameter(Mandatory = $false)][String] $FleetLCMUsername = "admin@vsp.local",
        [Parameter(Mandatory = $false)][String[]] $ComponentTypes
    )

    $jumpboxName = hostname
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    # Get Fleet LCM token
    $fcToken = Get-VcfmsFleetLCMToken -FleetLCMFqdn $FleetLCMFqdn -Username $FleetLCMUsername -Password $FleetLCMPassword
    if (-not $fcToken) {
        LogMessage -type ERROR -message "[$jumpboxName] Unable to obtain Fleet LCM token. Aborting."
        return
    }

    $headers = @{
        "Authorization" = "Bearer $fcToken"
        "Accept"        = "application/json"
    }

    $componentsUri = "https://$FleetLCMFqdn/fleet-lcm/v1/components?includeConsumptionVsp=true&includeVcdMigrator=true"
    LogMessage -type INFO -message "[$FleetLCMFqdn] Retrieving VCFMS components"

    try {
        $response = Invoke-RestMethod -Uri $componentsUri -Method GET -Headers $headers -SkipCertificateCheck
    } catch {
        LogMessage -type ERROR -message "[$FleetLCMFqdn] Failed to retrieve components: $($_.Exception.Message)"
        return
    }

    $allComponents = $response.components
    if (-not $allComponents -or ($allComponents | Measure-Object).Count -eq 0) {
        LogMessage -type WARNING -message "[$FleetLCMFqdn] No components found."
        return
    }

    # Filter by component types if specified
    if ($ComponentTypes -and $ComponentTypes.Count -gt 0) {
        $filteredComponents = $allComponents | Where-Object { $_.componentTypeDescription -in $ComponentTypes }
    } else {
        $filteredComponents = $allComponents
    }

    if (-not $filteredComponents -or ($filteredComponents | Measure-Object).Count -eq 0) {
        LogMessage -type WARNING -message "[$FleetLCMFqdn] No components found matching: $($ComponentTypes -join ', ')"
        return
    }

    # Build result objects
    $results = @()
    foreach ($comp in $filteredComponents) {
        # Include Fqdn on every row ($null when N/A) so Format-Table shows the column; otherwise the first
        # objects without Fqdn determine columns and runtime FQDNs are hidden.
        $fqdn = if ($comp.componentTypeDescription -eq 'VCF services runtime') { $comp.fqdn } else { $null }
        $results += [PSCustomObject]@{
            'Id'   = $comp.id
            'Type' = $comp.componentTypeDescription
            'Fqdn' = $fqdn
        }
    }

    $filterMsg = if ($ComponentTypes) { "matching: $($ComponentTypes -join ', ')" } else { "(all)" }
    LogMessage -type INFO -message "[$FleetLCMFqdn] Found $($results.Count) component(s) $filterMsg"
    Write-Host ""
    $results | Format-Table -AutoSize -Property Id, Type, Fqdn | Out-String | Write-Host

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Get-VcfmsComponents

Function Watch-VcfmsTask {
    <#
    .SYNOPSIS
    Monitors a VCFMS Services Runtime task until completion, or finds currently running tasks.

    .DESCRIPTION
    The Watch-VcfmsTask cmdlet supports two modes:

    Monitor  - Polls a specific task by ID via GET /api/v1/tasks/{taskId} until it reaches a terminal state (Succeeded, Failed, Cancelled). Returns the final task response.
    FindRunning - Queries GET /api/v1/tasks to find all currently running (non-terminal) tasks and displays them in a table.

    .EXAMPLE
    $task = Watch-VcfmsTask -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!" -TaskId "un56awijhfbudjma4mjin3cjwi"

    .EXAMPLE
    Watch-VcfmsTask -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!" -FindRunning

    .PARAMETER ServicesRuntimeFqdn
    FQDN of the VCFMS Services Runtime instance.

    .PARAMETER ServicesRuntimePassword
    Password for the Services Runtime admin user.

    .PARAMETER ServicesRuntimeUsername
    Username for the Services Runtime token. Default is "admin@vsp.local".

    .PARAMETER TaskId
    (Monitor mode) The task ID to monitor.

    .PARAMETER FindRunning
    (FindRunning mode) Switch to query and display all currently running tasks.

    .PARAMETER PollIntervalSeconds
    Interval in seconds between status polls. Default is 30. Only used in Monitor mode.
    #>

    Param(
        [Parameter(Mandatory = $true, ParameterSetName = "Monitor")]
        [Parameter(Mandatory = $true, ParameterSetName = "FindRunning")]
        [String] $ServicesRuntimeFqdn,

        [Parameter(Mandatory = $true, ParameterSetName = "Monitor")]
        [Parameter(Mandatory = $true, ParameterSetName = "FindRunning")]
        [String] $ServicesRuntimePassword,

        [Parameter(Mandatory = $false, ParameterSetName = "Monitor")]
        [Parameter(Mandatory = $false, ParameterSetName = "FindRunning")]
        [String] $ServicesRuntimeUsername = "admin@vsp.local",

        [Parameter(Mandatory = $true, ParameterSetName = "Monitor")]
        [String] $TaskId,

        [Parameter(Mandatory = $true, ParameterSetName = "FindRunning")]
        [Switch] $FindRunning,

        [Parameter(Mandatory = $false, ParameterSetName = "Monitor")]
        [Int] $PollIntervalSeconds = 30
    )

    $jumpboxName = hostname
    $terminalStates = @("COMPLETED", "FAILED", "CANCELLED", "ERROR", "SUCCESS", "SUCCESSFUL", "Succeeded", "Failed")

    $srToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn $ServicesRuntimeFqdn -Username $ServicesRuntimeUsername -Password $ServicesRuntimePassword
    if (-not $srToken) {
        LogMessage -type ERROR -message "[$jumpboxName] Unable to obtain Services Runtime token. Aborting."
        return
    }
    $tokenFetchedAt = [DateTime]::UtcNow

    $headers = @{
        "Authorization" = "Bearer $srToken"
        "Accept"        = "application/json"
    }

    # --- FindRunning mode: list all non-terminal tasks ---
    if ($PSCmdlet.ParameterSetName -eq "FindRunning") {
        $tasksUri = "https://$ServicesRuntimeFqdn/api/v1/tasks"
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Querying all tasks"

        try {
            $response = Invoke-RestMethod -Uri $tasksUri -Method GET -Headers $headers -SkipCertificateCheck
        } catch {
            LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Failed to retrieve tasks: $($_.Exception.Message)"
            return
        }

        $allTasks = $response.tasks
        if (-not $allTasks -or ($allTasks | Measure-Object).Count -eq 0) {
            LogMessage -type INFO -message "[$ServicesRuntimeFqdn] No tasks found"
            return
        }

        $runningTasks = $allTasks | Where-Object { $_.status -notin $terminalStates }

        if (-not $runningTasks -or ($runningTasks | Measure-Object).Count -eq 0) {
            LogMessage -type INFO -message "[$ServicesRuntimeFqdn] No running tasks found"
            return
        }

        $now = [datetime]::UtcNow
        $results = @()
        foreach ($task in $runningTasks) {
            $running = ""
            if ($task.startTime) {
                $start = ConvertFrom-VcfmsTaskTimestampToUtc -Timestamp $task.startTime
                if ($start) {
                    $running = Format-TimeSpanElapsedColons -Span ($now - $start)
                }
            }
            $shortType = $task.type -replace '^com\.vmware\.vcfms\.task\.', ''
            $results += [PSCustomObject]@{
                'Id'      = $task.id
                'Type'    = $shortType
                'Status'  = $task.status
                'Phase'   = $task.phase
                'Running' = $running
                'Created' = $task.createTime
            }
        }

        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Found $($results.Count) running task(s)"
        Write-Host ""
        $results | Format-Table -AutoSize | Out-String | Write-Host
        return
    }

    # --- Monitor mode: poll a specific task ---
    $taskUri = "https://$ServicesRuntimeFqdn/api/v1/tasks/$TaskId"

    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Monitoring task $TaskId (polling every ${PollIntervalSeconds}s)"

    Do {
        Start-Sleep -Seconds $PollIntervalSeconds
        try {
            if (([DateTime]::UtcNow - $tokenFetchedAt).TotalMinutes -ge 60) {
                LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Token age >= 60 minutes; refreshing"
                $newToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn $ServicesRuntimeFqdn -Username $ServicesRuntimeUsername -Password $ServicesRuntimePassword
                if ($newToken) {
                    $srToken = $newToken
                    $headers["Authorization"] = "Bearer $srToken"
                    $tokenFetchedAt = [DateTime]::UtcNow
                } else {
                    LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Token refresh failed; continuing with existing token"
                }
            }
            $taskResponse = Invoke-RestMethod -Uri $taskUri -Method GET -Headers $headers -SkipCertificateCheck
            $taskStatus = $taskResponse.status
            $elapsed = ""
            if ($taskResponse.startTime -and $taskResponse.endTime) {
                $start = ConvertFrom-VcfmsTaskTimestampToUtc -Timestamp $taskResponse.startTime
                $end = ConvertFrom-VcfmsTaskTimestampToUtc -Timestamp $taskResponse.endTime
                if ($start -and $end) {
                    $elapsed = " (elapsed: $(Format-TimeSpanElapsedColons -Span ($end - $start)))"
                }
            } elseif ($taskResponse.startTime) {
                $start = ConvertFrom-VcfmsTaskTimestampToUtc -Timestamp $taskResponse.startTime
                if ($start) {
                    $elapsed = " (running: $(Format-TimeSpanElapsedColons -Span ([datetime]::UtcNow - $start)))"
                }
            }
            LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Status: $taskStatus$elapsed"
        } catch {
            LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Error polling task (will retry): $($_.Exception.Message)"
            $taskStatus = "POLLING_ERROR"
        }
    } While ($taskStatus -notin $terminalStates)

    if ($taskStatus -in @("COMPLETED", "SUCCESS", "SUCCESSFUL", "Succeeded")) {
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Task $TaskId completed successfully"
    } else {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Task $TaskId ended with status: $taskStatus"
        if ($taskResponse.messages) {
            foreach ($msg in $taskResponse.messages) {
                LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] $msg"
            }
        }
    }

    return $taskResponse
}

Function Stop-VcfmsTask {
    <#
    .SYNOPSIS
    Cancels a VCFMS Services Runtime task by ID.

    .DESCRIPTION
    The Stop-VcfmsTask cmdlet sends a cancel request to a Services Runtime task via POST /api/v1/tasks/{taskId}?action=cancel.

    .EXAMPLE
    Stop-VcfmsTask -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!" -TaskId "2gvic5inrfauxgcnb6askblveu"

    .PARAMETER ServicesRuntimeFqdn
    FQDN of the VCFMS Services Runtime instance.

    .PARAMETER ServicesRuntimePassword
    Password for the Services Runtime admin user.

    .PARAMETER ServicesRuntimeUsername
    Username for the Services Runtime token. Default is "admin@vsp.local".

    .PARAMETER TaskId
    The task ID to cancel.

    .PARAMETER PollIntervalSeconds
    Interval in seconds to poll the task status after cancellation. Default is 10.
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $ServicesRuntimeFqdn,
        [Parameter(Mandatory = $true)][String] $ServicesRuntimePassword,
        [Parameter(Mandatory = $false)][String] $ServicesRuntimeUsername = "admin@vsp.local",
        [Parameter(Mandatory = $true)][String] $TaskId,
        [Parameter(Mandatory = $false)][Int] $PollIntervalSeconds = 10
    )

    $jumpboxName = hostname
    $terminalStates = @("COMPLETED", "FAILED", "CANCELLED", "ERROR", "SUCCESS", "SUCCESSFUL", "Succeeded", "Failed", "Cancelled")

    $srToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn $ServicesRuntimeFqdn -Username $ServicesRuntimeUsername -Password $ServicesRuntimePassword
    if (-not $srToken) {
        LogMessage -type ERROR -message "[$jumpboxName] Unable to obtain Services Runtime token. Aborting."
        return
    }
    $tokenFetchedAt = [DateTime]::UtcNow

    $headers = @{
        "Authorization" = "Bearer $srToken"
        "Accept"        = "application/json"
    }

    $cancelUri = "https://$ServicesRuntimeFqdn/api/v1/tasks/${TaskId}?action=cancel"
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Cancelling task $TaskId"

    try {
        $response = Invoke-RestMethod -Uri $cancelUri -Method POST -Headers $headers -SkipCertificateCheck
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Task $TaskId cancel request submitted"
    } catch {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Failed to cancel task $TaskId : $($_.Exception.Message)"
        if ($_.Exception.Response) {
            try {
                $errorStream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($errorStream)
                $errorBody = $reader.ReadToEnd()
                LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Response body: $errorBody"
            } catch {}
        }
        return
    }

    # Poll until the task reaches a terminal state
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Polling task status every $PollIntervalSeconds seconds"
    $taskUri = "https://$ServicesRuntimeFqdn/api/v1/tasks/$TaskId"
    $taskStatus = "Cancelling"
    Do {
        Start-Sleep -Seconds $PollIntervalSeconds
        try {
            if (([DateTime]::UtcNow - $tokenFetchedAt).TotalMinutes -ge 60) {
                LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Token age >= 60 minutes; refreshing"
                $newToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn $ServicesRuntimeFqdn -Username $ServicesRuntimeUsername -Password $ServicesRuntimePassword
                if ($newToken) {
                    $srToken = $newToken
                    $headers["Authorization"] = "Bearer $srToken"
                    $tokenFetchedAt = [DateTime]::UtcNow
                } else {
                    LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Token refresh failed; continuing with existing token"
                }
            }
            $taskResponse = Invoke-RestMethod -Uri $taskUri -Method GET -Headers $headers -SkipCertificateCheck
            $taskStatus = $taskResponse.status
            LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Status: $taskStatus"
        } catch {
            LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Error polling task (will retry): $($_.Exception.Message)"
        }
    } While ($taskStatus -notin $terminalStates)

    if ($taskStatus -in @("CANCELLED", "Cancelled")) {
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Task $TaskId cancelled successfully"
    } else {
        LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Task $TaskId ended with status: $taskStatus"
    }

    return $taskResponse
}
Export-ModuleMember -Function Stop-VcfmsTask

Function Start-ServicesRuntimeComponentBackup {
    <#
    .SYNOPSIS
    Takes an on-demand backup of one or more VCFMS components.

    .DESCRIPTION
    The Start-ServicesRuntimeComponentBackup cmdlet retrieves the list of registered VCFMS components from the Fleet LCM, groups and sorts them by the VCF instance they are associated with, and prompts you to pick a single VCF instance before selecting one, several, or all of that instance's components to back up. It then submits a backup task to the target Services Runtime instance via POST /api/v1/system/backups?action=backup and polls the task until it reaches a terminal state.

    Pass -ComponentIds to skip the interactive selection and back up a known set of components directly. All specified component IDs must belong to the same VCF instance.

    .EXAMPLE
    Start-ServicesRuntimeComponentBackup -FleetLCMFqdn "flt-fc01.rainpole.io" -FleetLCMPassword "VMw@re1!VMw@re1!" -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!"

    .EXAMPLE
    Start-ServicesRuntimeComponentBackup -FleetLCMFqdn "flt-fc01.rainpole.io" -FleetLCMPassword "VMw@re1!VMw@re1!" -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!" -ComponentIds "4e38afb4-ac83-481b-876f-922497eaada7","a669bd76-e75c-4c88-8e9e-a0e6526f4d28"

    .PARAMETER FleetLCMFqdn
    FQDN of the VCFMS Fleet LCM instance used to enumerate components.

    .PARAMETER FleetLCMPassword
    Password for the Fleet LCM admin user (used to obtain a token).

    .PARAMETER FleetLCMUsername
    Username for the Fleet LCM token. Default is "admin@vsp.local".

    .PARAMETER ServicesRuntimeFqdn
    FQDN of the VCFMS Services Runtime instance that will run the backup task.

    .PARAMETER ServicesRuntimePassword
    Password for the Services Runtime admin user.

    .PARAMETER ServicesRuntimeUsername
    Username for the Services Runtime token. Default is "admin@vsp.local".

    .PARAMETER ComponentIds
    One or more component IDs to back up. If not specified, the cmdlet displays a numbered list of components and prompts for a selection.

    .PARAMETER PollIntervalSeconds
    Interval in seconds to poll the backup task status. Default is 30.
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $FleetLCMFqdn,
        [Parameter(Mandatory = $true)][String] $FleetLCMPassword,
        [Parameter(Mandatory = $false)][String] $FleetLCMUsername = "admin@vsp.local",

        [Parameter(Mandatory = $true)][String] $ServicesRuntimeFqdn,
        [Parameter(Mandatory = $true)][String] $ServicesRuntimePassword,
        [Parameter(Mandatory = $false)][String] $ServicesRuntimeUsername = "admin@vsp.local",

        [Parameter(Mandatory = $false)][String[]] $ComponentIds,
        [Parameter(Mandatory = $false)][Int] $PollIntervalSeconds = 30
    )

    $jumpboxName = hostname
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    # Get Fleet LCM token and enumerate components
    $fcToken = Get-VcfmsFleetLCMToken -FleetLCMFqdn $FleetLCMFqdn -Username $FleetLCMUsername -Password $FleetLCMPassword
    if (-not $fcToken) {
        LogMessage -type ERROR -message "[$jumpboxName] Unable to obtain Fleet LCM token. Aborting."
        return
    }

    $fcHeaders = @{
        "Authorization" = "Bearer $fcToken"
        "Accept"        = "application/json"
    }

    $componentsUri = "https://$FleetLCMFqdn/fleet-lcm/v1/components?includeConsumptionVsp=true&includeVcdMigrator=true"
    LogMessage -type INFO -message "[$FleetLCMFqdn] Retrieving VCFMS components"

    try {
        $componentsResponse = Invoke-RestMethod -Uri $componentsUri -Method GET -Headers $fcHeaders -SkipCertificateCheck
    } catch {
        LogMessage -type ERROR -message "[$FleetLCMFqdn] Failed to retrieve components: $($_.Exception.Message)"
        return
    }

    $unsupportedComponentTypes = @("VCF Operations", "VCF Operations for networks", "Telemetry", "Real-time metrics store", "Real-time metrics", "Migration service engine")
    $allComponents = @($componentsResponse.components | Where-Object { $_.componentTypeDescription -notin $unsupportedComponentTypes })
    if (-not $allComponents -or $allComponents.Count -eq 0) {
        LogMessage -type WARNING -message "[$FleetLCMFqdn] No components found."
        return
    }

    $allComponentsList = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($comp in $allComponents) {
        $fqdn            = if ($comp.componentTypeDescription -eq 'VCF services runtime') { $comp.fqdn } else { $null }
        $vcfInstanceName = if ($comp.vspCluster.fqdn) { $comp.vspCluster.fqdn } else { "Fleet-wide" }
        $allComponentsList.Add([PSCustomObject]@{
            Id           = $comp.id
            Type         = $comp.componentTypeDescription
            Fqdn         = $fqdn
            VcfInstance  = $vcfInstanceName
        })
    }

    $selectedComponents = @()

    if ($PSBoundParameters.ContainsKey("ComponentIds")) {
        $selectedComponents = $allComponentsList | Where-Object { $_.Id -in $ComponentIds }
        $missingIds = $ComponentIds | Where-Object { $_ -notin $allComponentsList.Id }
        if ($missingIds) {
            LogMessage -type ERROR -message "[$FleetLCMFqdn] Component ID(s) not found: $($missingIds -join ', ')"
            return
        }
        $distinctInstances = @($selectedComponents.VcfInstance | Sort-Object -Unique)
        if ($distinctInstances.Count -gt 1) {
            LogMessage -type ERROR -message "[$FleetLCMFqdn] Component IDs span multiple VCF instances ($($distinctInstances -join ', ')). Select components from a single VCF instance."
            return
        }
    } else {
        # Group components by VCF instance and present a numbered list of instances
        $instanceGroups = [System.Collections.Generic.List[PSCustomObject]]::new()
        $instanceIndex = 1
        foreach ($vcfInstance in ($allComponentsList.VcfInstance | Sort-Object -Unique)) {
            $instanceGroups.Add([PSCustomObject]@{
                Index      = $instanceIndex
                VcfInstance = $vcfInstance
                Components  = @($allComponentsList | Where-Object { $_.VcfInstance -eq $vcfInstance } | Sort-Object Type)
            })
            $instanceIndex++
        }

        Write-Host ""
        Write-Host " Available VCF Instances" -ForegroundColor Cyan
        Write-Host " ────────────────────────────────────────────────────────────────────" -ForegroundColor Cyan
        Write-Host ("  {0,3}  {1,-40}  {2}" -f "ID", "VCF Instance", "Components") -ForegroundColor Gray
        Write-Host ""
        foreach ($group in $instanceGroups) {
            Write-Host ("  {0,3}  {1,-40}  {2}" -f $group.Index, $group.VcfInstance, $group.Components.Count) -ForegroundColor White
        }
        Write-Host " ────────────────────────────────────────────────────────────────────" -ForegroundColor Cyan
        Write-Host ""

        $selectedGroup = $null
        Do {
            Write-Host " Enter the ID of the VCF instance to back up, or C to Cancel: " -ForegroundColor Yellow -NoNewline
            $instanceSelection = Read-Host
            if ($instanceSelection -in @("C", "c")) {
                LogMessage -type INFO -message "[$jumpboxName] Cancelled by user."
                $StopWatch.Stop()
                $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
                LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
                return
            }
            $instanceNum = 0
            if ([int]::TryParse($instanceSelection, [ref]$instanceNum) -and $instanceNum -ge 1 -and $instanceNum -le $instanceGroups.Count) {
                $selectedGroup = $instanceGroups | Where-Object { $_.Index -eq $instanceNum }
            } else {
                Write-Host " Invalid selection. Enter a number between 1 and $($instanceGroups.Count), or C to Cancel." -ForegroundColor Yellow
            }
        } Until ($null -ne $selectedGroup)

        $componentList = [System.Collections.Generic.List[PSCustomObject]]::new()
        $index = 1
        foreach ($comp in $selectedGroup.Components) {
            $componentList.Add([PSCustomObject]@{
                Index = $index
                Id    = $comp.Id
                Type  = $comp.Type
                Fqdn  = $comp.Fqdn
            })
            $index++
        }

        # Display numbered list of components within the selected VCF instance
        Write-Host ""
        Write-Host " Available Components - $($selectedGroup.VcfInstance)" -ForegroundColor Cyan
        Write-Host " ────────────────────────────────────────────────────────────────────" -ForegroundColor Cyan
        Write-Host ("  {0,3}  {1,-28}  {2}" -f "ID", "Type", "Fqdn") -ForegroundColor Gray
        Write-Host ""
        foreach ($comp in $componentList) {
            Write-Host ("  {0,3}  {1,-28}  {2}" -f $comp.Index, $comp.Type, $comp.Fqdn) -ForegroundColor White
        }
        Write-Host " ────────────────────────────────────────────────────────────────────" -ForegroundColor Cyan
        Write-Host ""

        Do {
            Write-Host " Enter component ID(s) to back up (comma-separated), 'ALL', or C to Cancel: " -ForegroundColor Yellow -NoNewline
            $selection = Read-Host
            if ($selection -in @("C", "c")) {
                LogMessage -type INFO -message "[$jumpboxName] Cancelled by user."
                $StopWatch.Stop()
                $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
                LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
                return
            }
            if ($selection -in @("ALL", "all")) {
                $selectedComponents = $componentList
            } else {
                $selectedIndexes = $selection -split ',' | ForEach-Object { $_.Trim() }
                $selectedComponents = @()
                $invalidEntries = @()
                foreach ($entry in $selectedIndexes) {
                    $num = 0
                    if ([int]::TryParse($entry, [ref]$num) -and $num -ge 1 -and $num -le $componentList.Count) {
                        $selectedComponents += ($componentList | Where-Object { $_.Index -eq $num })
                    } else {
                        $invalidEntries += $entry
                    }
                }
                if ($invalidEntries.Count -gt 0) {
                    Write-Host " Invalid selection(s): $($invalidEntries -join ', '). Enter numbers between 1 and $($componentList.Count), 'ALL', or C to Cancel." -ForegroundColor Yellow
                    $selectedComponents = @()
                }
            }
        } Until ($selectedComponents.Count -gt 0)
    }

    Write-Host ""
    Write-Host " Components selected for backup:" -ForegroundColor Cyan
    foreach ($comp in $selectedComponents) {
        Write-Host ("  {0}  ({1})" -f $comp.Type, $comp.Id) -ForegroundColor White
    }
    Write-Host ""

    Do {
        Write-Host " Proceed with backup? (Y/N): " -ForegroundColor Yellow -NoNewline
        $confirmation = Read-Host
    } Until ($confirmation -in @("Y", "y", "N", "n"))

    if ($confirmation -in @("N", "n")) {
        LogMessage -type INFO -message "[$jumpboxName] Backup cancelled by user."
        $StopWatch.Stop()
        $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
        return
    }

    # Get Services Runtime token and submit the backup task
    $srToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn $ServicesRuntimeFqdn -Username $ServicesRuntimeUsername -Password $ServicesRuntimePassword
    if (-not $srToken) {
        LogMessage -type ERROR -message "[$jumpboxName] Unable to obtain Services Runtime token. Aborting."
        return
    }

    $srHeaders = @{
        "Authorization" = "Bearer $srToken"
        "Content-Type"  = "application/json"
        "Accept"        = "application/json"
    }

    $backupBody = @{ components = @($selectedComponents.Id) } | ConvertTo-Json -Depth 5
    $backupUri  = "https://$ServicesRuntimeFqdn/api/v1/system/backups?action=backup"
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Submitting backup for $($selectedComponents.Count) component(s)"

    try {
        $backupResponse = Invoke-RestMethod -Uri $backupUri -Method POST -Headers $srHeaders -Body $backupBody -SkipCertificateCheck
    } catch {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Backup request failed: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            try {
                $errorStream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($errorStream)
                $errorBody = $reader.ReadToEnd()
                LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Response body: $errorBody"
            } catch {}
        }
        return
    }

    $taskId = $backupResponse.id
    if (-not $taskId) {
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] API response:"
        $backupResponse | ConvertTo-Json -Depth 5 | Write-Host
        $StopWatch.Stop()
        $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
        return
    }

    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Backup task submitted: $taskId"

    $null = Watch-VcfmsTask -ServicesRuntimeFqdn $ServicesRuntimeFqdn -ServicesRuntimePassword $ServicesRuntimePassword -ServicesRuntimeUsername $ServicesRuntimeUsername -TaskId $taskId -PollIntervalSeconds $PollIntervalSeconds

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Start-ServicesRuntimeComponentBackup

Function Remove-VcfmsComponent {
    <#
    .SYNOPSIS
    Deletes one or more VCFMS components via the Fleet LCM API, processing them serially and waiting for each task to complete before proceeding.

    .DESCRIPTION
    The Remove-VcfmsComponent cmdlet calls DELETE /fleet-lcm/v1/components/{componentId} for each component ID provided. Components are deleted one at a time in the order given, and the function monitors each deletion task via the Fleet LCM /fleet-lcm/v1/tasks endpoint until it reaches a terminal state before starting the next. If a deletion fails, processing stops. Use Get-VcfmsComponents to discover component IDs.

    .EXAMPLE
    Remove-VcfmsComponent -FleetLCMFqdn "flt-fc01.rainpole.io" -FleetLCMPassword "VMw@re1!VMw@re1!" -ComponentIds "4e38afb4-ac83-481b-876f-922497eaada7"

    .EXAMPLE
    Remove-VcfmsComponent -FleetLCMFqdn "flt-fc01.rainpole.io" -FleetLCMPassword "VMw@re1!VMw@re1!" -ComponentIds "4e38afb4-ac83-481b-876f-922497eaada7","a669bd76-e75c-4c88-8e9e-a0e6526f4d28","3544191a-dc7a-409f-8c7a-4cd6cf5d93ca"

    .PARAMETER FleetLCMFqdn
    FQDN of the VCFMS Fleet LCM instance.

    .PARAMETER FleetLCMPassword
    Password for the Fleet LCM admin user.

    .PARAMETER FleetLCMUsername
    Username for the Fleet LCM token. Default is "admin@vsp.local".

    .PARAMETER ComponentIds
    One or more component IDs to delete. Processed serially in the order provided.

    .PARAMETER PollIntervalSeconds
    Interval in seconds to poll each deletion task. Default is 30.
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $FleetLCMFqdn,
        [Parameter(Mandatory = $true)][String] $FleetLCMPassword,
        [Parameter(Mandatory = $false)][String] $FleetLCMUsername = "admin@vsp.local",
        [Parameter(Mandatory = $true)][String[]] $ComponentIds,
        [Parameter(Mandatory = $false)][Int] $PollIntervalSeconds = 30
    )

    $jumpboxName = hostname
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    $terminalStates = @("COMPLETED", "FAILED", "CANCELLED", "ERROR", "SUCCESS", "SUCCESSFUL", "Succeeded", "Failed")
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] $($ComponentIds.Count) component(s) to delete (serial processing)"

    Write-Host ""
    Write-Host " Components to delete (in order):" -ForegroundColor Cyan
    $index = 1
    foreach ($compId in $ComponentIds) {
        Write-Host "   $index. $compId" -ForegroundColor Yellow
        $index++
    }
    Write-Host ""
    Do {
        Write-Host " Proceed with deletion? (Y/N): " -ForegroundColor Yellow -NoNewline
        $confirmation = Read-Host
    } Until ($confirmation -in @("Y", "y", "N", "n"))

    if ($confirmation -in @("N", "n")) {
        LogMessage -type INFO -message "[$jumpboxName] Operation cancelled by user."
        return
    }

    $results = @()
    $current = 1

    foreach ($componentId in $ComponentIds) {
        LogMessage -type INFO -message "[$FleetLCMFqdn] Deleting component $current of $($ComponentIds.Count): $componentId"

        $fcToken = Get-VcfmsFleetLCMToken -FleetLCMFqdn $FleetLCMFqdn -Username $FleetLCMUsername -Password $FleetLCMPassword
        if (-not $fcToken) {
            LogMessage -type ERROR -message "[$FleetLCMFqdn] Unable to obtain Fleet LCM token. Stopping."
            break
        }

        $headers = @{
            "Authorization" = "Bearer $fcToken"
            "Accept"        = "application/json"
        }

        $deleteUri = "https://$FleetLCMFqdn/fleet-lcm/v1/components/$componentId"

        try {
            $response = Invoke-RestMethod -Uri $deleteUri -Method DELETE -Headers $headers -SkipCertificateCheck
        } catch {
            LogMessage -type ERROR -message "[$FleetLCMFqdn] DELETE failed for component $componentId : $($_.Exception.Message)"
            if ($_.Exception.Response) {
                try {
                    $errorStream = $_.Exception.Response.GetResponseStream()
                    $reader = New-Object System.IO.StreamReader($errorStream)
                    $errorBody = $reader.ReadToEnd()
                    LogMessage -type ERROR -message "[$FleetLCMFqdn] Response body: $errorBody"
                } catch {}
            }
            $results += [PSCustomObject]@{ ComponentId = $componentId; TaskId = $null; Status = "DELETE_FAILED" }
            $current++
            continue
        }

        $taskId = $response.id
        $taskDesc = $response.description.localizedMessage
        if ($taskDesc) {
            LogMessage -type INFO -message "[$FleetLCMFqdn] $taskDesc"
        }

        if ($taskId) {
            LogMessage -type INFO -message "[$FleetLCMFqdn] Deletion task: $taskId"
            $taskUri = "https://$FleetLCMFqdn/fleet-lcm/v1/tasks/$taskId"
            $taskStatus = "IN_PROGRESS"

            Do {
                Start-Sleep -Seconds $PollIntervalSeconds
                try {
                    $taskResponse = Invoke-RestMethod -Uri $taskUri -Method GET -Headers $headers -SkipCertificateCheck
                    $taskStatus = $taskResponse.status
                    LogMessage -type INFO -message "[$FleetLCMFqdn] Status: $taskStatus"
                } catch {
                    LogMessage -type WARNING -message "[$FleetLCMFqdn] Error polling task (will retry): $($_.Exception.Message)"
                    $newToken = Get-VcfmsFleetLCMToken -FleetLCMFqdn $FleetLCMFqdn -Username $FleetLCMUsername -Password $FleetLCMPassword
                    if ($newToken) {
                        $headers["Authorization"] = "Bearer $newToken"
                    }
                }
            } While ($taskStatus -notin $terminalStates)

            $finalStatus = $taskStatus
            $results += [PSCustomObject]@{ ComponentId = $componentId; TaskId = $taskId; Status = $finalStatus }

            if ($finalStatus -in @("COMPLETED", "SUCCESS", "SUCCESSFUL", "Succeeded")) {
                LogMessage -type INFO -message "[$FleetLCMFqdn] Component $componentId deleted successfully"
            } else {
                LogMessage -type ERROR -message "[$FleetLCMFqdn] Component $componentId deletion ended with status: $finalStatus. Stopping."
                if ($taskResponse.description.localizedMessage) {
                    LogMessage -type ERROR -message "[$FleetLCMFqdn] $($taskResponse.description.localizedMessage)"
                }
                break
            }
        } else {
            LogMessage -type INFO -message "[$FleetLCMFqdn] Component $componentId deleted (no async task returned)"
            $results += [PSCustomObject]@{ ComponentId = $componentId; TaskId = $null; Status = "COMPLETED" }
        }

        $current++
    }

    Write-Host ""
    Write-Host " Deletion Summary:" -ForegroundColor Cyan
    $results | Format-Table -AutoSize -Property ComponentId, TaskId, Status | Out-String | Write-Host

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Remove-VcfmsComponent

Function Set-ServicesRuntimeComponentVips {
    <#
    .SYNOPSIS
    Updates the ingress VIPs for a component via the Services Runtime apply API.

    .DESCRIPTION
    The Set-ServicesRuntimeComponentVips cmdlet locates the installed component of the specified type via
    GET /api/v1/components (unless -ComponentId is supplied), then GET /api/v1/components/{id} to
    resolve the JSON property name under spec.configuration.ingress (it must match the platform — for
    some stacks this differs from the component type string, e.g. ops_logs vs ops-logs).

    It builds an apply payload with spec.configuration.ingress.<resolvedKey>.vips.ipv4 and
    POST /api/v1/components/{componentId}?action=apply including an empty options object (same shape
    as other apply operations in this module).

    Supported component types: vcfa, vidb, ops-logs.

    The function:
      1. Validates parameters and retrieves a Services Runtime token.
      2. Resolves the component ID (by type or -ComponentId).
      3. GETs component detail and resolves the ingress JSON property name.
      4. Displays the payload for review.
      5. Prompts "Proceed? (Y/N)" before calling the API (skipped when -Force is set).
      6. Submits the apply request and polls the task; after success, GETs the component again to verify VIPs.

    Use -DryRun to display the payload and exit without calling the API.

    .EXAMPLE
    Set-ServicesRuntimeComponentVips -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!" -ComponentType "vcfa" -Vips "10.0.0.5"

    .EXAMPLE
    Set-ServicesRuntimeComponentVips -ServicesRuntimeFqdn "lax-sr01.lax.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!" -ComponentType "vidb" -Vips "10.21.99.23" -DryRun

    .EXAMPLE
    Set-ServicesRuntimeComponentVips -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!" -ComponentType "ops-logs" -Vips "10.0.0.8"" -Force

    .PARAMETER ServicesRuntimeFqdn
    FQDN of the Services Runtime instance.

    .PARAMETER ServicesRuntimePassword
    Password for the Services Runtime admin user.

    .PARAMETER ServicesRuntimeUsername
    Username for the Services Runtime token. Default is "admin@vsp.local".

    .PARAMETER ComponentType
    The component type to update. Valid values: vcfa, vidb, ops-logs.

    .PARAMETER Vips
    Array of 1-3 IPv4 addresses to set as the new ingress VIPs.

    .PARAMETER PollIntervalSeconds
    Interval in seconds to poll the apply task. Default is 30.

    .PARAMETER DryRun
    Display the payload and exit without calling the API.

    .PARAMETER Force
    Skip the interactive confirmation prompt and proceed immediately.

    .PARAMETER ComponentId
    If set, applies to this component UUID directly instead of resolving by type from GET /api/v1/components.
    Use when more than one component shares the same type or you already know the correct ID.

    .PARAMETER IngressKey
    Explicit JSON property name under spec.configuration.ingress (e.g. ops_logs vs ops-logs).
    If omitted, the name is taken from GET /api/v1/components/{id} so it matches what the platform stores.
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $ServicesRuntimeFqdn,
        [Parameter(Mandatory = $true)][String] $ServicesRuntimePassword,
        [Parameter(Mandatory = $false)][String] $ServicesRuntimeUsername = "admin@vsp.local",
        [Parameter(Mandatory = $true)][ValidateSet("vcfa", "vidb", "ops-logs")][String] $ComponentType,
        [Parameter(Mandatory = $true)][ValidateCount(1,3)][String[]] $Vips,
        [Parameter(Mandatory = $false)][String] $ComponentId,
        [Parameter(Mandatory = $false)][String] $IngressKey,
        [Parameter(Mandatory = $false)][Int] $PollIntervalSeconds = 30,
        [Parameter(Mandatory = $false)][Switch] $DryRun,
        [Parameter(Mandatory = $false)][Switch] $Force
    )

    $jumpboxName = hostname
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    $terminalStates = @(
        "COMPLETED", "Completed", "COMPLETE", "FAILED", "CANCELLED", "ERROR", "SUCCESS", "SUCCESSFUL",
        "Succeeded", "Failed"
    )
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] Component type : $ComponentType"
    LogMessage -type INFO -message "[$jumpboxName] New VIPs       : $($Vips -join ', ')"

    # Step 1: Token
    $srToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn $ServicesRuntimeFqdn -Username $ServicesRuntimeUsername -Password $ServicesRuntimePassword
    if (-not $srToken) {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Unable to obtain Services Runtime token. Aborting."
        return
    }
    $headers = @{
        "Authorization" = "Bearer $srToken"
        "Accept"        = "application/json"
        "Content-Type"  = "application/json"
    }

    # Step 2: Resolve component ID
    if ($ComponentId) {
        $componentId = $ComponentId.Trim()
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Using supplied component ID: $componentId"
    } else {
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Looking up component with type '$ComponentType'"
        try {
            $componentsResponse = Invoke-RestMethod -Uri "https://$ServicesRuntimeFqdn/api/v1/components" -Method GET -Headers $headers -SkipCertificateCheck
        } catch {
            LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Failed to retrieve components: $($_.Exception.Message)"
            return
        }

        $matching = @($componentsResponse.components | Where-Object { $_.type -eq $ComponentType })
        if ($matching.Count -eq 0) {
            LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] No installed component found with type '$ComponentType'"
            return
        }
        if ($matching.Count -gt 1) {
            LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Multiple components with type '$ComponentType' ($($matching.Count)); using the first. Pass -ComponentId to select a specific instance."
        }
        $component = $matching[0]
        $componentId = $component.id
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Found component: $componentId (type=$ComponentType)"
    }

    # Step 3: GET component detail — discover the real ingress property name (may differ from .type, e.g. ops_logs)
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Retrieving component detail for ingress key resolution"
    try {
        $compDetail = Invoke-RestMethod -Uri "https://$ServicesRuntimeFqdn/api/v1/components/$componentId" -Method GET -Headers $headers -SkipCertificateCheck
    } catch {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] GET /api/v1/components/$componentId failed: $($_.Exception.Message)"
        return
    }

    $ingressParent = $compDetail.spec.configuration.ingress
    $resolvedIngressKey = $null
    if ($IngressKey) {
        $resolvedIngressKey = $IngressKey.Trim()
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Using -IngressKey '$resolvedIngressKey'"
    } elseif (-not $ingressParent) {
        $resolvedIngressKey = $ComponentType
        LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] No spec.configuration.ingress in component detail; using type string '$resolvedIngressKey' as JSON key"
    } else {
        $propNames = @($ingressParent.PSObject.Properties.Name)
        if ($propNames -contains $ComponentType) {
            $resolvedIngressKey = $ComponentType
        } else {
            $under = $ComponentType -replace '-', '_'
            if ($propNames -contains $under) {
                $resolvedIngressKey = $under
                LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Ingress key in API is '$resolvedIngressKey' (underscore form); apply will use this key."
            } elseif ($propNames.Count -eq 1) {
                $resolvedIngressKey = $propNames[0]
                LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Ingress uses a single key '$resolvedIngressKey' (component type filter was '$ComponentType')."
            } else {
                LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Could not map type '$ComponentType' to an ingress key. Available keys: $($propNames -join ', '). Re-run with -IngressKey."
                return
            }
        }
    }

    # Force the VIPs into a typed string array so ConvertTo-Json always emits a JSON array.
    [string[]]$vipsArray = @($Vips | ForEach-Object { $_.Trim() })

    $ingressEntry = [ordered]@{
        vips = [ordered]@{
            ipv4 = $vipsArray
        }
    }
    $ingressObject = [ordered]@{}
    $ingressObject[$resolvedIngressKey] = $ingressEntry

    # Include options like other apply operations (Set-ServicesRuntimeSftpBackupSettings); some stacks ignore partial applies without it.
    $payload = [ordered]@{
        spec    = [ordered]@{
            configuration = [ordered]@{
                ingress = $ingressObject
            }
        }
        options = [ordered]@{}
    }
    $payloadJson = $payload | ConvertTo-Json -Depth 10 -Compress:$false

    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Current ingress ($resolvedIngressKey) before apply — fetching VIP list from detail"
    try {
        if ($ingressParent -and $resolvedIngressKey) {
            $currentBlock = $ingressParent.$resolvedIngressKey
            if ($currentBlock -and $currentBlock.vips.ipv4) {
                LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Existing ipv4: $($currentBlock.vips.ipv4 -join ', ')"
            }
        }
    } catch {
        LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Could not read existing VIPs from detail object."
    }

    Write-Host ""
    Write-Host " Apply payload:" -ForegroundColor Cyan
    Write-Host $payloadJson
    Write-Host ""

    if ($DryRun) {
        LogMessage -type ADVISORY -message "[$jumpboxName] Dry run — exiting without calling the API."
        $StopWatch.Stop()
        $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
        return
    }

    # Step 4: Confirmation
    if (-not $Force) {
        Do {
            Write-Host " Proceed with VIP update for component $componentId ? (Y/N): " -ForegroundColor Yellow -NoNewline
            $confirmation = Read-Host
        } Until ($confirmation -in @("Y", "y", "N", "n"))

        if ($confirmation -in @("N", "n")) {
            LogMessage -type INFO -message "[$jumpboxName] Operation cancelled by user."
            return
        }
    }

    # Step 5: Refresh token and submit apply
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Submitting apply for component $componentId"
    $srToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn $ServicesRuntimeFqdn -Username $ServicesRuntimeUsername -Password $ServicesRuntimePassword
    if (-not $srToken) {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Unable to refresh Services Runtime token. Aborting."
        return
    }
    $tokenFetchedAt = [DateTime]::UtcNow
    $headers["Authorization"] = "Bearer $srToken"

    $applyUri = "https://$ServicesRuntimeFqdn/api/v1/components/$componentId`?action=apply"
    try {
        $applyResponse = Invoke-RestMethod -Uri $applyUri -Method POST -Headers $headers -Body $payloadJson -SkipCertificateCheck
    } catch {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Apply request failed: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            try {
                $errBody = (New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())).ReadToEnd()
                LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Response body: $errBody"
            } catch {}
        }
        return
    }

    $taskId = $applyResponse.id
    if (-not $taskId) {
        LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Apply accepted but no task ID returned; response:"
        $applyResponse | ConvertTo-Json -Depth 5 | Write-Host
        $StopWatch.Stop()
        $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
        return
    }
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Apply task created: $taskId"

    # Step 6: Poll task (status falls back to phase — matches shell jq '.status // .phase')
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Polling task $taskId every ${PollIntervalSeconds}s"
    $elapsed = 0
    $taskStatus = "UNKNOWN"
    $taskResponse = $null
    Do {
        Start-Sleep -Seconds $PollIntervalSeconds
        $elapsed += $PollIntervalSeconds
        try {
            if (([DateTime]::UtcNow - $tokenFetchedAt).TotalMinutes -ge 60) {
                LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Token age >= 60 minutes; refreshing"
                $newToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn $ServicesRuntimeFqdn -Username $ServicesRuntimeUsername -Password $ServicesRuntimePassword
                if ($newToken) {
                    $srToken = $newToken
                    $headers["Authorization"] = "Bearer $srToken"
                    $tokenFetchedAt = [DateTime]::UtcNow
                } else {
                    LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Token refresh failed; continuing with existing token"
                }
            }
            $taskResponse = Invoke-RestMethod -Uri "https://$ServicesRuntimeFqdn/api/v1/tasks/$taskId" -Method GET -Headers $headers -SkipCertificateCheck
            $rawSt = $taskResponse.status
            $rawPh = $taskResponse.phase
            if (-not [string]::IsNullOrWhiteSpace([string]$rawSt)) {
                $taskStatus = [string]$rawSt
            } elseif (-not [string]::IsNullOrWhiteSpace([string]$rawPh)) {
                $taskStatus = [string]$rawPh
            } else {
                $taskStatus = "UNKNOWN"
            }
        } catch {
            LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Poll error (will retry): $($_.Exception.Message)"
            $taskStatus = "UNKNOWN"
        }
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Task $taskId status=$taskStatus (${elapsed}s elapsed)"
    } While ($taskStatus -notin $terminalStates)

    Write-Host ""
    $successStates = @("COMPLETED", "Completed", "COMPLETE", "SUCCESS", "SUCCESSFUL", "Succeeded")
    if ($taskStatus -in $successStates) {
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Apply task reported success (status/phase=$taskStatus)"
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Component : $componentId"
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Requested VIPs : $($Vips -join ', ')"

        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Verifying desired VIPs in GET /api/v1/components/$componentId"
        try {
            if (([DateTime]::UtcNow - $tokenFetchedAt).TotalMinutes -ge 60) {
                LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Token age >= 60 minutes; refreshing"
                $newToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn $ServicesRuntimeFqdn -Username $ServicesRuntimeUsername -Password $ServicesRuntimePassword
                if ($newToken) {
                    $srToken = $newToken
                    $headers["Authorization"] = "Bearer $srToken"
                    $tokenFetchedAt = [DateTime]::UtcNow
                } else {
                    LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Token refresh failed; continuing with existing token"
                }
            }
            $afterDetail = Invoke-RestMethod -Uri "https://$ServicesRuntimeFqdn/api/v1/components/$componentId" -Method GET -Headers $headers -SkipCertificateCheck
            $ig = $afterDetail.spec.configuration.ingress
            $afterBlock = $ig.$resolvedIngressKey
            if ($afterBlock -and $afterBlock.vips.ipv4) {
                $actual = @($afterBlock.vips.ipv4 | ForEach-Object { "$_" })
                $want = @($vipsArray | ForEach-Object { "$_" })
                $diff = Compare-Object -ReferenceObject ($want | Sort-Object) -DifferenceObject ($actual | Sort-Object)
                $match = ($null -eq $diff)
                LogMessage -type INFO -message "[$ServicesRuntimeFqdn] API reports ingress.$resolvedIngressKey.vips.ipv4 = $($actual -join ', ')"
                if (-not $match) {
                    LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] VIPs in API still do not match requested values. The apply task succeeded but configuration was not updated (check ingress key, platform logs, or merge a full spec)."
                }
            } else {
                LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Could not read spec.configuration.ingress.$resolvedIngressKey.vips.ipv4 after apply; verify manually in the UI or API."
            }
        } catch {
            LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Post-apply verification GET failed: $($_.Exception.Message)"
        }
    } else {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] VIP update ended with status: $taskStatus"
        if ($taskResponse -and $taskResponse.description.localizedMessage) {
            LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] $($taskResponse.description.localizedMessage)"
        }
    }

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Set-ServicesRuntimeComponentVips

Function Open-VcfmsSshSession {
    # Opens a Posh-SSH session with an auto-trusted host key.
    # Unexported — used by Get-VcfmsServicesRuntimeKubeconfig.
    param([String]$Fqdn, [System.Management.Automation.PSCredential]$Creds)
    $inmem = New-SSHMemoryKnownHost
    New-SSHTrustedHost -KnownHostStore $inmem -HostName $Fqdn `
        -FingerPrint ((Get-SSHHostKey -ComputerName $Fqdn).fingerprint) | Out-Null
    $session = $null
    Do { $session = New-SSHSession -ComputerName $Fqdn -Credential $Creds -KnownHost $inmem }
    Until ($session)
    return $session
}

Function Get-VcfmsRemoteFileContent {
    # Fetches a remote file via sudo -S base64 and returns decoded UTF-8 text, or $null on failure.
    # Unexported — used by Get-VcfmsServicesRuntimeKubeconfig.
    param([int]$SessionId, [String]$RemotePath, [String]$Pwd)
    $cmd    = "echo '$Pwd' | sudo -S base64 -w 0 $RemotePath"
    $result = Invoke-SSHCommand -SessionId $SessionId -Command $cmd -TimeOut 30
    if ($result.ExitStatus -ne 0) { return $null }
    $b64 = ($result.Output -join "") -replace '[^A-Za-z0-9+/=]', ''
    if ([string]::IsNullOrWhiteSpace($b64)) { return $null }
    return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64))
}

Function Get-VcfmsServicesRuntimeKubeconfig {
    <#
    Connects to a Services Runtime cluster node via SSH as vmware-system-user, elevates to root
    using the same password, and retrieves /etc/kubernetes/admin.conf.

    The FQDN of the Services Runtime cluster is accepted as ServicesRuntimeFqdn. The short name
    (host label before the first dot) is derived automatically and used as the kubeconfig filename
    stem unless ClusterName is explicitly provided.

    If the initial node is a worker (admin.conf absent), the function reads
    /etc/kubernetes/node-agent.conf, extracts the control plane server address from the
    clusters[].cluster.server field, connects to that address, and retrieves admin.conf from
    there instead.

    The kubeconfig is written locally as <ClusterName>.kubeconfig in OutputDir.

    Returns the full path to the written file, or $null on failure.

    This is an unexported helper — use it from other functions in this module; it is not
    surfaced via Export-ModuleMember.
    #>
    Param(
        [Parameter(Mandatory = $true)][String] $ServicesRuntimeFqdn,
        [Parameter(Mandatory = $true)][String] $Password,
        [Parameter(Mandatory = $false)][String] $ClusterName,
        [Parameter(Mandatory = $false)][String] $OutputDir = "."
    )

    # Derive short name from FQDN when ClusterName is not explicitly supplied
    if (-not $ClusterName) {
        $ClusterName = $ServicesRuntimeFqdn.Split('.')[0]
    }

    $jumpboxName = hostname
    LogMessage -type INFO -message "[$jumpboxName] Retrieving kubeconfig from $ServicesRuntimeFqdn (cluster: $ClusterName)"

    $SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
    $creds = New-Object System.Management.Automation.PSCredential ('vmware-system-user', $SecurePassword)

    $session          = $null
    $controlPlaneHost = $ServicesRuntimeFqdn
    try {
        $session = Open-VcfmsSshSession -Fqdn $ServicesRuntimeFqdn -Creds $creds

        # Try admin.conf first (present on control plane nodes)
        $kubeconfigContent = Get-VcfmsRemoteFileContent -SessionId $session.SessionId `
            -RemotePath '/etc/kubernetes/admin.conf' -Pwd $Password

        if (-not $kubeconfigContent) {
            # Likely a worker node — read node-agent.conf to discover the control plane address
            LogMessage -type INFO -message "[$ServicesRuntimeFqdn] admin.conf not found; reading node-agent.conf to locate control plane"
            $nodeAgentContent = Get-VcfmsRemoteFileContent -SessionId $session.SessionId `
                -RemotePath '/etc/kubernetes/node-agent.conf' -Pwd $Password

            if (-not $nodeAgentContent) {
                LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Neither admin.conf nor node-agent.conf could be read"
                return $null
            }

            # node-agent.conf is a kubeconfig; extract server from clusters[0].cluster.server
            # Format: "    server: https://<host>:<port>"
            $serverLine = ($nodeAgentContent -split "`n" | Where-Object { $_ -match '^\s*server:\s*https?://' } | Select-Object -First 1)
            if (-not $serverLine) {
                LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Could not find server field in node-agent.conf"
                return $null
            }
            $controlPlaneUri  = ($serverLine -replace '^\s*server:\s*', '').Trim()
            $controlPlaneHost = ([uri]$controlPlaneUri).Host
            LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Control plane address from node-agent.conf: $controlPlaneHost"

            # Close the worker session and open a new one to the control plane
            Remove-SSHSession -SSHSession $session | Out-Null
            $session = $null
            $session = Open-VcfmsSshSession -Fqdn $controlPlaneHost -Creds $creds

            $kubeconfigContent = Get-VcfmsRemoteFileContent -SessionId $session.SessionId `
                -RemotePath '/etc/kubernetes/admin.conf' -Pwd $Password

            if (-not $kubeconfigContent) {
                LogMessage -type ERROR -message "[$controlPlaneHost] Could not read admin.conf from control plane node"
                return $null
            }
            LogMessage -type INFO -message "[$controlPlaneHost] admin.conf retrieved from control plane"
        } else {
            LogMessage -type INFO -message "[$ServicesRuntimeFqdn] admin.conf retrieved (node is a control plane)"
        }

        # Write locally — resolve OutputDir to an absolute path so .NET WriteAllText lands in $PWD
        $resolvedOutputDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDir)
        if (-not (Test-Path $resolvedOutputDir)) {
            New-Item -ItemType Directory -Path $resolvedOutputDir -Force | Out-Null
        }
        $outputPath = Join-Path -Path $resolvedOutputDir -ChildPath "$ClusterName.kubeconfig"
        [System.IO.File]::WriteAllText($outputPath, $kubeconfigContent, (New-Object System.Text.UTF8Encoding $false))
        LogMessage -type INFO -message "[$jumpboxName] Kubeconfig written to $outputPath"
        LogMessage -type INFO -message "[$jumpboxName] Control plane node  : $controlPlaneHost"

        return [PSCustomObject]@{
            KubeconfigPath   = $outputPath
            ControlPlaneHost = $controlPlaneHost
        }

    } catch {
        LogMessage -type ERROR -message "[$jumpboxName] Failed to retrieve kubeconfig: $($_.Exception.Message)"
        return $null
    } finally {
        if ($session) { Remove-SSHSession -SSHSession $session | Out-Null }
    }
}

Function ConvertTo-VcfmsYaml {
    # Block-style YAML serialiser. Matches PyYAML safe_dump(default_flow_style=False).
    # Unexported — used by New-ExtractVcfmsBackup.
    param($obj, [int]$indent = 0)
    $pad = ' ' * $indent
    if ($null -eq $obj) { return 'null' }
    if ($obj -is [bool])   { if ($obj) { return 'true' } else { return 'false' } }
    if ($obj -is [int] -or $obj -is [long] -or $obj -is [double]) { return "$obj" }
    if ($obj -is [string]) {
        if ($obj -eq '' -or
            $obj -match '^[\s]|[\s]$|^[>|!&*{}[\],#`@%]|: |^-\s|^[\d]' -or
            $obj -match '[\r\n]' -or
            $obj -in @('true','false','null','yes','no','on','off')) {
            $escaped = $obj -replace "'", "''"
            return "'$escaped'"
        }
        return $obj
    }
    if ($obj -is [System.Collections.IDictionary]) {
        if ($obj.Count -eq 0) { return '{}' }
        $lines = @()
        foreach ($k in $obj.Keys) {
            $v  = $obj[$k]
            $ks = ConvertTo-VcfmsYaml $k 0
            if ($null -eq $v -or $v -is [bool] -or $v -is [int] -or $v -is [long] -or $v -is [double] -or $v -is [string]) {
                $lines += "$pad${ks}: $(ConvertTo-VcfmsYaml $v 0)"
            } elseif ($v -is [System.Collections.IList]) {
                if ($v.Count -eq 0) {
                    $lines += "$pad${ks}: []"
                } else {
                    $lines += "$pad${ks}:"
                    $lines += ConvertTo-VcfmsYaml $v $indent
                }
            } else {
                $lines += "$pad${ks}:"
                $lines += ConvertTo-VcfmsYaml $v ($indent + 2)
            }
        }
        return $lines -join "`n"
    }
    if ($obj -is [System.Collections.IList]) {
        if ($obj.Count -eq 0) { return '[]' }
        $lines = @()
        foreach ($item in $obj) {
            if ($null -eq $item -or $item -is [bool] -or $item -is [int] -or $item -is [long] -or $item -is [double] -or $item -is [string]) {
                $lines += "$pad- $(ConvertTo-VcfmsYaml $item 0)"
            } elseif ($item -is [System.Collections.IList]) {
                $lines += "$pad-"
                $lines += ConvertTo-VcfmsYaml $item ($indent + 2)
            } else {
                $inner     = ConvertTo-VcfmsYaml $item ($indent + 2)
                $firstLine = $inner.TrimStart()
                $rest      = ($inner -split "`n" | Select-Object -Skip 1) -join "`n"
                $lines += "$pad- $firstLine"
                if ($rest) { $lines += $rest }
            }
        }
        return $lines -join "`n"
    }
    return "$obj"
}

Function ConvertTo-VcfmsOrderedHashtable {
    # Converts a PSCustomObject graph to ordered hashtables for deterministic YAML key order.
    # Unexported — used by New-ExtractVcfmsBackup.
    param($obj)
    if ($obj -is [System.Management.Automation.PSCustomObject]) {
        $ht = [ordered]@{}
        foreach ($prop in $obj.PSObject.Properties) {
            $ht[$prop.Name] = ConvertTo-VcfmsOrderedHashtable $prop.Value
        }
        return $ht
    }
    if ($obj -is [System.Collections.IList] -and $obj -isnot [string]) {
        return @($obj | ForEach-Object { ConvertTo-VcfmsOrderedHashtable $_ })
    }
    return $obj
}

Function Remove-VcfmsTransientMeta {
    # Strips transient metadata fields before writing YAML.
    # Unexported — used by New-ExtractVcfmsBackup.
    param($obj)
    if ($obj -is [System.Collections.IDictionary] -and $obj.Contains('metadata')) {
        foreach ($k in @('managedFields','resourceVersion','uid','creationTimestamp')) {
            $obj['metadata'].Remove($k) | Out-Null
        }
    }
    return $obj
}

Function Invoke-VcfmsOpensslDecrypt {
    # Replicates: openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:<passphrase>
    # Unexported — used by New-ExtractVcfmsBackup.
    param([string]$InPath, [string]$OutPath, [string]$Passphrase)

    $cipherBytes = [System.IO.File]::ReadAllBytes($InPath)
    $magic = [System.Text.Encoding]::ASCII.GetString($cipherBytes[0..7])
    if ($magic -ne 'Salted__') {
        throw "Unexpected OpenSSL header: '$magic' — expected 'Salted__'"
    }
    $salt       = $cipherBytes[8..15]
    $ciphertext = $cipherBytes[16..($cipherBytes.Length - 1)]

    $passBytes = [System.Text.Encoding]::UTF8.GetBytes($Passphrase)
    $pbkdf2    = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
                     $passBytes, [byte[]]$salt, 10000,
                     [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $key = $pbkdf2.GetBytes(32)
    $iv  = $pbkdf2.GetBytes(16)

    $aes          = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode     = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding  = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key      = $key
    $aes.IV       = $iv
    $decryptor    = $aes.CreateDecryptor()
    $inStream     = [System.IO.MemoryStream]::new($ciphertext)
    $cryptoStream = New-Object System.Security.Cryptography.CryptoStream(
                        $inStream, $decryptor,
                        [System.Security.Cryptography.CryptoStreamMode]::Read)
    $outStream    = [System.IO.File]::OpenWrite($OutPath)
    try { $cryptoStream.CopyTo($outStream) }
    finally { $cryptoStream.Close(); $outStream.Close(); $aes.Dispose() }
}

Function Expand-VcfmsTarGz {
    # Pure-.NET gzip + tar extractor.
    # Unexported — used by New-ExtractVcfmsBackup.
    param([string]$ArchivePath, [string]$DestDir)

    [System.IO.Directory]::CreateDirectory($DestDir) | Out-Null
    $fs  = [System.IO.File]::OpenRead($ArchivePath)
    $gz  = New-Object System.IO.Compression.GZipStream($fs, [System.IO.Compression.CompressionMode]::Decompress)
    $buf = New-Object byte[] 512

    try {
        while ($true) {
            $read = 0
            while ($read -lt 512) {
                $n = $gz.Read($buf, $read, 512 - $read)
                if ($n -eq 0) { return }
                $read += $n
            }
            $allZero = $true
            foreach ($b in $buf) { if ($b -ne 0) { $allZero = $false; break } }
            if ($allZero) { return }

            $nameRaw   = [System.Text.Encoding]::ASCII.GetString($buf, 0,   100).TrimEnd([char]0)
            $sizeOctal = [System.Text.Encoding]::ASCII.GetString($buf, 124,  12).Trim().TrimEnd([char]0)
            $typeFlag  = [char]$buf[156]
            $prefixRaw = [System.Text.Encoding]::ASCII.GetString($buf, 345, 155).TrimEnd([char]0)
            $entryName = if ($prefixRaw) { "$prefixRaw/$nameRaw" } else { $nameRaw }
            $entrySize = if ($sizeOctal) { [Convert]::ToInt64($sizeOctal.Trim(), 8) } else { 0 }

            $blocks    = [int][Math]::Ceiling($entrySize / 512)
            $dataBytes = New-Object byte[] ($blocks * 512)
            $dataRead  = 0
            while ($dataRead -lt $dataBytes.Length) {
                $n = $gz.Read($dataBytes, $dataRead, $dataBytes.Length - $dataRead)
                if ($n -eq 0) { break }
                $dataRead += $n
            }

            if ($typeFlag -eq '0' -or $typeFlag -eq [char]0) {
                $destPath   = Join-Path $DestDir ($entryName -replace '/', [System.IO.Path]::DirectorySeparatorChar)
                $destParent = [System.IO.Path]::GetDirectoryName($destPath)
                [System.IO.Directory]::CreateDirectory($destParent) | Out-Null
                [System.IO.File]::WriteAllBytes($destPath, $dataBytes[0..([int]$entrySize - 1)])
            }
        }
    } finally {
        $gz.Close(); $fs.Close()
    }
}

Function Resolve-VcfmsVeleroJson {
    # Finds a Velero resource JSON under either the direct or v1-preferredversion layout.
    # Unexported — used by New-ExtractVcfmsBackup.
    param([string]$VeleroBase, [string]$ResourceKind, [string]$Namespace, [string]$Stem)
    foreach ($layout in @(
        (Join-Path $VeleroBase "resources\$ResourceKind\namespaces\$Namespace\$Stem.json"),
        (Join-Path $VeleroBase "resources\$ResourceKind\v1-preferredversion\namespaces\$Namespace\$Stem.json")
    )) {
        if (Test-Path $layout) { return $layout }
    }
    return $null
}

Function New-VcfmsTlsSecretFromNdc {
    # Synthesizes a kubernetes.io/tls Secret from an NDC Opaque secret JSON.
    # Unexported — used by New-ExtractVcfmsBackup.
    param([string]$NdcJsonPath, [string]$PlainStem)
    $ndc     = Get-Content $NdcJsonPath -Raw | ConvertFrom-Json
    $data    = $ndc.data
    $certB64 = if ($data.cert) { $data.cert } elseif ($data.'tls.crt') { $data.'tls.crt' } else { $null }
    $keyB64  = if ($data.key)  { $data.key }  elseif ($data.'tls.key') { $data.'tls.key' } else { $null }
    if (-not $certB64 -or -not $keyB64) {
        throw "NDC secret $NdcJsonPath has no cert/key in .data; cannot synthesize $PlainStem"
    }
    $ns = if ($ndc.metadata.namespace) { $ndc.metadata.namespace } else { 'vmsp-platform' }
    $md = [ordered]@{
        name      = $PlainStem
        namespace = $ns
        annotations = [ordered]@{
            'vmsp.vmware.com/generated-from-backup' = ([System.IO.Path]::GetFileNameWithoutExtension($NdcJsonPath))
        }
    }
    $ndcLabels = @{}
    if ($ndc.metadata.labels) {
        $ndc.metadata.labels.PSObject.Properties | ForEach-Object {
            if ($_.Name -ne 'backup.vmsp.vmware.com/skip-restore') { $ndcLabels[$_.Name] = $_.Value }
        }
    }
    if ($ndcLabels.Count -gt 0) { $md['labels'] = $ndcLabels }
    return [ordered]@{
        apiVersion = 'v1'
        kind       = 'Secret'
        metadata   = $md
        type       = 'kubernetes.io/tls'
        data       = [ordered]@{ 'tls.crt' = $certB64; 'tls.key' = $keyB64 }
    }
}

Function New-ExtractVcfmsBackup {
    <#
    .SYNOPSIS
    Extracts Kubernetes resource YAML from a locally downloaded VMSP component backup archive.

    .DESCRIPTION
    The New-ExtractVcfmsBackup cmdlet decrypts a local *.base.tgz VMSP backup archive, extracts
    the inner Velero archive, and writes the following Kubernetes resources as YAML files
    directly under OutputDir when present in the archive:
      vmsp-platform.yaml              PackageDeployment
      ingress-fleet-tls-ndc.yaml      NDC mirror secret
      ingress-fleet-tls.yaml          Standard TLS secret (from backup or synthesized from NDC)
      ingress-instance-tls-ndc.yaml   NDC mirror secret
      ingress-instance-tls.yaml       Standard TLS secret (from backup or synthesized from NDC)
      ingress-platform-tls-ndc.yaml   NDC mirror secret
      ingress-platform-tls.yaml       Standard TLS secret (from backup or synthesized from NDC)

    The archive is decrypted using AES-256-CBC with PBKDF2 key derivation, matching the OpenSSL
    enc -aes-256-cbc -pbkdf2 format produced by the VMSP backup service.

    Transient metadata fields (managedFields, resourceVersion, uid, creationTimestamp) are
    stripped from every resource before writing.

    When ServicesRuntimeNodeFqdn, ServicesRuntimePassword, and ClusterName are supplied the
    kubeconfig is retrieved automatically from the Services Runtime node via
    Get-VcfmsServicesRuntimeKubeconfig before extraction runs.

    .EXAMPLE
    New-ExtractVcfmsBackup `
        -LocalArchivePath "C:\backups\2026-03-23T16-45-31Z.base.tgz" `
        -EncryptionPassphrase "MyPassphrase!" `
        -OutputDir "C:\backup-yaml" `
        -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" `
        -ServicesRuntimePassword "VMw@re1!VMw@re1!"

    .EXAMPLE
    New-ExtractVcfmsBackup `
        -LocalArchivePath "C:\backups\2026-03-23T16-45-31Z.base.tgz" `
        -EncryptionPassphrase "MyPassphrase!" `
        -OutputDir "C:\backup-yaml" `
        -KubeconfigPath "C:\kubeconfigs\sfo-sr01.kubeconfig"

    .PARAMETER LocalArchivePath
    Path to the *.base.tgz backup archive on the local Windows host.

    .PARAMETER EncryptionPassphrase
    Passphrase used to decrypt the backup archive (AES-256-CBC / PBKDF2).

    .PARAMETER OutputDir
    Directory where extracted YAML files are written. Created if it does not exist.
    Defaults to a timestamped subfolder in the current directory.

    .PARAMETER ServicesRuntimeFqdn
    FQDN of the Services Runtime cluster. When provided together with ServicesRuntimePassword
    the kubeconfig is fetched automatically. The short name (host label before the first dot)
    is used as the kubeconfig filename stem unless KubeconfigPath is supplied instead.

    .PARAMETER ServicesRuntimePassword
    Password for vmware-system-user on the Services Runtime node (also used for sudo elevation).

    .PARAMETER KubeconfigPath
    Path to an already-downloaded kubeconfig file. Takes precedence over automatic retrieval.
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $LocalArchivePath,
        [Parameter(Mandatory = $true)][String] $EncryptionPassphrase,
        [Parameter(Mandatory = $false)][String] $OutputDir,
        [Parameter(Mandatory = $false)][String] $ServicesRuntimeFqdn,
        [Parameter(Mandatory = $false)][String] $ServicesRuntimePassword,
        [Parameter(Mandatory = $false)][String] $KubeconfigPath
    )

    $jumpboxName = hostname
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    # Validate inputs
    $resolvedArchive = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LocalArchivePath)
    if (-not (Test-Path $resolvedArchive)) {
        LogMessage -type ERROR -message "[$jumpboxName] Local archive not found: $resolvedArchive"
        $StopWatch.Stop(); return
    }

    # Resolve output directory
    if ($OutputDir) {
        $resolvedOutputDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDir)
    } else {
        $resolvedOutputDir = Join-Path $PWD "backup-yaml-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    }
    [System.IO.Directory]::CreateDirectory($resolvedOutputDir) | Out-Null

    # Optionally retrieve the kubeconfig (not needed for extraction itself, written alongside YAML
    # for the caller's convenience)
    $resolvedKubeconfig = $KubeconfigPath
    if (-not $resolvedKubeconfig) {
        if ($ServicesRuntimeFqdn -and $ServicesRuntimePassword) {
            LogMessage -type INFO -message "[$jumpboxName] Retrieving kubeconfig from $ServicesRuntimeFqdn"
            $kubeconfigResult = Get-VcfmsServicesRuntimeKubeconfig `
                -ServicesRuntimeFqdn $ServicesRuntimeFqdn `
                -Password            $ServicesRuntimePassword `
                -OutputDir           $resolvedOutputDir
            if (-not $kubeconfigResult) {
                LogMessage -type ERROR -message "[$jumpboxName] Failed to retrieve kubeconfig. Aborting."
                $StopWatch.Stop(); return
            }
            $resolvedKubeconfig = $kubeconfigResult.KubeconfigPath
        }
    }

    LogMessage -type INFO -message "[$jumpboxName] Local archive  : $resolvedArchive"
    LogMessage -type INFO -message "[$jumpboxName] Output dir     : $resolvedOutputDir"
    if ($resolvedKubeconfig) {
        LogMessage -type INFO -message "[$jumpboxName] Kubeconfig     : $resolvedKubeconfig"
    }

    # Step 1: Decrypt the outer blob (OpenSSL AES-256-CBC / PBKDF2)
    $workDir   = Join-Path ([System.IO.Path]::GetTempPath()) "vcfms-extract-$(Get-Random)"
    [System.IO.Directory]::CreateDirectory($workDir) | Out-Null
    try {
        $outerTgz  = Join-Path $workDir "decoded.tgz"
        LogMessage -type INFO -message "[$jumpboxName] Decrypting archive"
        try {
            Invoke-VcfmsOpensslDecrypt -InPath $resolvedArchive -OutPath $outerTgz -Passphrase $EncryptionPassphrase
        } catch {
            LogMessage -type ERROR -message "[$jumpboxName] Decryption failed: $($_.Exception.Message)"
            $StopWatch.Stop(); return
        }

        # Step 2: Extract the outer tar.gz — look for the inner *-vsp-*.tar.gz
        $outerRoot = Join-Path $workDir "outer"
        LogMessage -type INFO -message "[$jumpboxName] Extracting outer archive"
        try {
            Expand-VcfmsTarGz -ArchivePath $outerTgz -DestDir $outerRoot
        } catch {
            LogMessage -type ERROR -message "[$jumpboxName] Outer archive extraction failed: $($_.Exception.Message)"
            $StopWatch.Stop(); return
        }

        $innerTgz = Get-ChildItem -Path $outerRoot -Recurse -Filter '*-vsp-*.tar.gz' |
                        Select-Object -First 1 -ExpandProperty FullName
        if (-not $innerTgz) {
            LogMessage -type ERROR -message "[$jumpboxName] Could not find inner *-vsp-*.tar.gz under extracted archive"
            $StopWatch.Stop(); return
        }

        # Step 3: Extract the inner Velero tar.gz
        $veleroRoot = Join-Path $workDir "velero"
        LogMessage -type INFO -message "[$jumpboxName] Extracting inner Velero archive"
        try {
            Expand-VcfmsTarGz -ArchivePath $innerTgz -DestDir $veleroRoot
        } catch {
            LogMessage -type ERROR -message "[$jumpboxName] Inner archive extraction failed: $($_.Exception.Message)"
            $StopWatch.Stop(); return
        }

        # Step 4: Walk the Velero tree and write YAML files
        $secretKind   = 'secrets'
        $pdKind       = 'packagedeployments.releases.vmsp.vmware.com'
        $ns           = 'vmsp-platform'
        $writtenFiles = @()

        # vmsp-platform.yaml (PackageDeployment)
        $pdStem = 'vmsp-platform'
        $pdJson = Resolve-VcfmsVeleroJson -VeleroBase $veleroRoot -ResourceKind $pdKind -Namespace $ns -Stem $pdStem
        if ($pdJson) {
            $obj  = ConvertTo-VcfmsOrderedHashtable (Get-Content $pdJson -Raw | ConvertFrom-Json)
            $obj  = Remove-VcfmsTransientMeta $obj
            $yaml = ConvertTo-VcfmsYaml $obj
            $dest = Join-Path $resolvedOutputDir "$pdStem.yaml"
            [System.IO.File]::WriteAllText($dest, $yaml + "`n", (New-Object System.Text.UTF8Encoding $false))
            LogMessage -type INFO -message "[$jumpboxName] Written: $dest"
            $writtenFiles += $dest
        } else {
            LogMessage -type WARNING -message "[$jumpboxName] $pdStem (PackageDeployment) not found in archive"
        }

        # ingress-<family>-tls-ndc.yaml / ingress-<family>-tls.yaml for each ingress family
        foreach ($family in @('fleet', 'instance', 'platform')) {
            $ndcStem  = "ingress-$family-tls-ndc"
            $ndcJson  = Resolve-VcfmsVeleroJson -VeleroBase $veleroRoot -ResourceKind $secretKind -Namespace $ns -Stem $ndcStem
            if ($ndcJson) {
                $obj  = ConvertTo-VcfmsOrderedHashtable (Get-Content $ndcJson -Raw | ConvertFrom-Json)
                $obj  = Remove-VcfmsTransientMeta $obj
                $yaml = ConvertTo-VcfmsYaml $obj
                $dest = Join-Path $resolvedOutputDir "$ndcStem.yaml"
                [System.IO.File]::WriteAllText($dest, $yaml + "`n", (New-Object System.Text.UTF8Encoding $false))
                LogMessage -type INFO -message "[$jumpboxName] Written: $dest"
                $writtenFiles += $dest
            } else {
                LogMessage -type WARNING -message "[$jumpboxName] $ndcStem not found in archive"
            }

            # ingress-<family>-tls.yaml — from backup directly, or synthesized from NDC
            $plainStem = "ingress-$family-tls"
            $dest      = Join-Path $resolvedOutputDir "$plainStem.yaml"
            $plainJson = Resolve-VcfmsVeleroJson -VeleroBase $veleroRoot -ResourceKind $secretKind -Namespace $ns -Stem $plainStem
            if ($plainJson) {
                $obj  = ConvertTo-VcfmsOrderedHashtable (Get-Content $plainJson -Raw | ConvertFrom-Json)
                $obj  = Remove-VcfmsTransientMeta $obj
                $yaml = ConvertTo-VcfmsYaml $obj
                [System.IO.File]::WriteAllText($dest, $yaml + "`n", (New-Object System.Text.UTF8Encoding $false))
                LogMessage -type INFO -message "[$jumpboxName] Written: $dest"
                $writtenFiles += $dest
            } elseif ($ndcJson) {
                try {
                    $obj  = New-VcfmsTlsSecretFromNdc -NdcJsonPath $ndcJson -PlainStem $plainStem
                    $obj  = Remove-VcfmsTransientMeta $obj
                    $yaml = ConvertTo-VcfmsYaml $obj
                    [System.IO.File]::WriteAllText($dest, $yaml + "`n", (New-Object System.Text.UTF8Encoding $false))
                    LogMessage -type INFO -message "[$jumpboxName] Written (synthesized from NDC): $dest"
                    $writtenFiles += $dest
                } catch {
                    LogMessage -type WARNING -message "[$jumpboxName] Could not synthesize $plainStem : $($_.Exception.Message)"
                }
            } else {
                LogMessage -type WARNING -message "[$jumpboxName] $plainStem not found in archive and no NDC source to synthesize from"
            }
        }

        Write-Host ""
        Write-Host " YAML written to: $resolvedOutputDir" -ForegroundColor Cyan
        foreach ($f in $writtenFiles) {
            Write-Host "   $(Split-Path $f -Leaf)" -ForegroundColor White
        }
        Write-Host ""

    } finally {
        # Always clean up the temp work directory
        if (Test-Path $workDir) { Remove-Item -Recurse -Force $workDir -ErrorAction SilentlyContinue }
    }

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function New-ExtractVcfmsBackup

Function Invoke-VcfmsBackupSftpToYaml {
    <#
    .SYNOPSIS
    Copies and executes the vmsp-backup-sftp-to-yaml.sh script on the Services Runtime
    control plane node to pull a VMSP component backup from SFTP and export it as YAML.

    .DESCRIPTION
    The Invoke-VcfmsBackupSftpToYaml cmdlet performs the following steps:

      1. Resolves the Services Runtime control plane node (handles worker-node redirect
         via node-agent.conf automatically).
      2. Base64-encodes the bundled vmsp-backup-sftp-to-yaml.sh script and uploads it to
         /tmp on the control plane node via the existing SSH session — no SCP binary
         required.
      3. Executes the script under sudo with KUBECONFIG=/etc/kubernetes/admin.conf (so the
         script can read the encryption passphrase secret from the cluster) and
         VMSP_SFTP_PASSWORD set from -SftpPassword, as:

           bash ./vmsp-backup-sftp-to-yaml.sh \
             --sftp-host "<SftpHost>" \
             --sftp-user "<SftpUser>" \
             --sftp-dir "<SftpDir>" \
             --remote-archive "<RemoteArchive>" \
             --output-dir ./backup-yaml

      4. Streams script output to the console in real time.
      5. Removes the temporary script from the remote node on completion.

    .EXAMPLE
    Invoke-VcfmsBackupSftpToYaml `
        -ServicesRuntimeFqdn     "sfo-sr01.sfo.rainpole.io" `
        -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
        -SftpHost                "10.167.173.130" `
        -SftpUser                "svc-vcf-bck" `
        -SftpPassword            "VMw@re1!VMw@re1!" `
        -SftpDir                 "/media/backups" `
        -RemoteArchive           "/media/backups/vcf/backups/e6b2ad0a-b76f-4080-b9db-aa338bacdc64/9.1.1.0.25662438/vsp/e6b2ad0a-b76f-4080-b9db-aa338bacdc64/9.1.1.0.25662438/2026-08-20T10-13-53Z/2026-08-20T10-13-53Z.base.tgz"

    .PARAMETER ServicesRuntimeFqdn
    FQDN or IP of any Services Runtime cluster node. If a worker node is supplied the
    function automatically resolves and connects to the control plane.

    .PARAMETER ServicesRuntimePassword
    Password for vmware-system-user (SSH login and sudo elevation).

    .PARAMETER SftpHost
    SFTP server host or IP. Passed as --sftp-host.

    .PARAMETER SftpUser
    SFTP username. Passed as --sftp-user.

    .PARAMETER SftpPassword
    SFTP password. Passed to the remote script as the VMSP_SFTP_PASSWORD environment
    variable rather than a command-line flag.

    .PARAMETER SftpDir
    Remote SFTP root directory for backups. Passed as --sftp-dir.

    .PARAMETER RemoteArchive
    Full SFTP path to the *.base.tgz backup archive. Passed as --remote-archive.

    .PARAMETER RemoteScriptTimeout
    Seconds to wait for the remote script to complete. Default is 600 (10 minutes).
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $ServicesRuntimeFqdn,
        [Parameter(Mandatory = $true)][String] $ServicesRuntimePassword,
        [Parameter(Mandatory = $true)][String] $SftpHost,
        [Parameter(Mandatory = $true)][String] $SftpUser,
        [Parameter(Mandatory = $true)][String] $SftpPassword,
        [Parameter(Mandatory = $true)][String] $SftpDir,
        [Parameter(Mandatory = $true)][String] $RemoteArchive,
        [Parameter(Mandatory = $false)][Int] $RemoteScriptTimeout = 600
    )

    $jumpboxName = hostname
    $StopWatch   = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    # -------------------------------------------------------------------------
    # Validate the local script exists
    # -------------------------------------------------------------------------
    $localScript = Join-Path -Path $PSScriptRoot -ChildPath "scripts/vmsp-backup-sftp-to-yaml.sh"
    if (-not (Test-Path $localScript)) {
        LogMessage -type ERROR -message "[$jumpboxName] Script not found: $localScript"
        $StopWatch.Stop(); return
    }

    # -------------------------------------------------------------------------
    # Resolve the control plane node
    # Reuse Get-VcfmsServicesRuntimeKubeconfig which handles worker → CP redirect.
    # -------------------------------------------------------------------------
    LogMessage -type INFO -message "[$jumpboxName] Resolving control plane node from $ServicesRuntimeFqdn"
    $kubeconfigResult = Get-VcfmsServicesRuntimeKubeconfig `
        -ServicesRuntimeFqdn $ServicesRuntimeFqdn `
        -Password            $ServicesRuntimePassword `
        -OutputDir           "."
    if (-not $kubeconfigResult) {
        LogMessage -type ERROR -message "[$jumpboxName] Could not resolve control plane node. Aborting."
        $StopWatch.Stop(); return
    }
    $controlPlaneHost = $kubeconfigResult.ControlPlaneHost
    LogMessage -type INFO -message "[$jumpboxName] Control plane node  : $controlPlaneHost"

    # -------------------------------------------------------------------------
    # Open SSH session to the control plane node
    # -------------------------------------------------------------------------
    $SecurePassword    = ConvertTo-SecureString -String $ServicesRuntimePassword -AsPlainText -Force
    $creds             = New-Object System.Management.Automation.PSCredential ('vmware-system-user', $SecurePassword)
    $session           = $null
    $remoteScriptName  = "vmsp-backup-sftp-to-yaml.sh"
    $remotePath        = "/tmp/$remoteScriptName"

    try {
        $session = Open-VcfmsSshSession -Fqdn $controlPlaneHost -Creds $creds

        # -------------------------------------------------------------------------
        # Upload the script via base64 pipe — avoids any SCP binary dependency
        # -------------------------------------------------------------------------
        LogMessage -type INFO -message "[$controlPlaneHost] Uploading script to $remotePath"
        $scriptBytes = [System.IO.File]::ReadAllBytes($localScript)
        # Strip CR bytes so the file always has Unix line endings on the remote node,
        # regardless of how git checked it out on the local machine (Windows autocrlf etc.)
        $scriptBytes = [byte[]]($scriptBytes | Where-Object { $_ -ne 0x0D })
        $b64         = [System.Convert]::ToBase64String($scriptBytes)

        # printf is used instead of echo to avoid an appended newline corrupting the decode
        $uploadCmd    = "printf '%s' '$b64' | base64 -d > $remotePath && chmod +x $remotePath"
        $uploadResult = Invoke-SSHCommand -SessionId $session.SessionId -Command $uploadCmd -TimeOut 60
        if ($uploadResult.ExitStatus -ne 0) {
            LogMessage -type ERROR -message "[$controlPlaneHost] Script upload failed (exit $($uploadResult.ExitStatus)): $($uploadResult.Error -join ' ')"
            return
        }
        LogMessage -type INFO -message "[$controlPlaneHost] Script uploaded successfully"

        # -------------------------------------------------------------------------
        # Build and execute the remote command
        # sudo -S reads the password from stdin; env preserves KUBECONFIG (so the script
        # can read the encryption passphrase secret from the cluster) and VMSP_SFTP_PASSWORD
        # across the sudo boundary.
        # -------------------------------------------------------------------------
        $scriptArgs = "--sftp-host '$SftpHost' --sftp-user '$SftpUser' --sftp-dir '$SftpDir' --remote-archive '$RemoteArchive' --output-dir ./backup-yaml"

        $execCmd = "cd /tmp && echo '$ServicesRuntimePassword' | sudo -S env KUBECONFIG=/etc/kubernetes/admin.conf VMSP_SFTP_PASSWORD='$SftpPassword' bash ./$remoteScriptName $scriptArgs 2>&1"

        LogMessage -type INFO -message "[$controlPlaneHost] Executing script (timeout: ${RemoteScriptTimeout}s)"
        Write-Host ""
        Write-Host " ── vmsp-backup-sftp-to-yaml output ──────────────────────" -ForegroundColor Cyan

        $execResult = Invoke-SSHCommand -SessionId $session.SessionId -Command $execCmd -TimeOut $RemoteScriptTimeout

        # Print all output (stdout + stderr merged via 2>&1); filter sudo prompt noise
        $execResult.Output |
            Where-Object { $_ -notmatch '^\[sudo\]' } |
            ForEach-Object { Write-Host "  $_" }

        # Belt-and-suspenders: if Posh-SSH still delivers anything on the Error channel
        # split on newlines first so a single multi-line string is handled correctly
        if ($execResult.Error) {
            (($execResult.Error -join "`n") -split "`r?`n") |
                Where-Object { $_ -notmatch '^\[sudo\]' -and $_ -ne '' } |
                ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
        }

        Write-Host " ────────────────────────────────────────────────────────────────────" -ForegroundColor Cyan
        Write-Host ""

        if ($execResult.ExitStatus -eq 0) {
            LogMessage -type INFO -message "[$controlPlaneHost] Script completed successfully"
        } else {
            LogMessage -type ERROR -message "[$controlPlaneHost] Script exited with code $($execResult.ExitStatus)"
        }

    } catch {
        LogMessage -type ERROR -message "[$jumpboxName] $($_.Exception.Message)"
    } finally {
        # Always remove the temporary script from the remote node
        if ($session) {
            Invoke-SSHCommand -SessionId $session.SessionId `
                -Command "rm -f $remotePath" -TimeOut 15 | Out-Null
            Remove-SSHSession -SSHSession $session | Out-Null
            LogMessage -type INFO -message "[$controlPlaneHost] Temporary script removed"
        }
    }

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Invoke-VcfmsBackupSftpToYaml

Function Disable-VcfmsClusterLogging {
    <#
    .SYNOPSIS
    Disables logging on a VCFMS Services Runtime cluster by applying a logs.type=none configuration.

    .DESCRIPTION
    The Disable-VcfmsClusterLogging cmdlet posts a component apply task to the VCFMS Services
    Runtime API that sets spec.configuration.logs.type to "none", then polls the task until it
    reaches a terminal state.

    The VSP component ID can be supplied directly via ComponentId, or resolved automatically from
    the Services Runtime components API by matching the first component of type "vsp".

    .EXAMPLE
    # Disable logging and auto-retrieve kubeconfig for post-apply validation
    Disable-VcfmsClusterLogging -ServicesRuntimeFqdn "lax-sr01.lax.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!"

    .EXAMPLE
    # Supply an existing kubeconfig so the validation step does not need to SSH
    Disable-VcfmsClusterLogging `
        -ServicesRuntimeFqdn     "lax-sr01.lax.rainpole.io" `
        -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
        -ComponentId             "e319236e-867e-4779-9270-4921bddf4f1f" `
        -KubeconfigPath          "C:\kubeconfigs\lax-sr01.kubeconfig"

    .PARAMETER ServicesRuntimeFqdn
    FQDN of the VCFMS Services Runtime instance.

    .PARAMETER ServicesRuntimePassword
    Password for the Services Runtime admin user.

    .PARAMETER ServicesRuntimeUsername
    Username for the Services Runtime token. Default is "admin@vsp.local".

    .PARAMETER ComponentId
    VSP component ID to apply the logging change to. When omitted the cmdlet resolves the first
    component of type "vsp" from GET /api/v1/components.

    .PARAMETER PollIntervalSeconds
    Interval in seconds between task status polls. Default is 30.

    .PARAMETER KubeconfigPath
    Path to an existing kubeconfig for the Services Runtime cluster, used for post-apply
    validation of the fluentd operator. When omitted the kubeconfig is retrieved automatically
    from the Services Runtime node using ServicesRuntimeFqdn and ServicesRuntimePassword.

    .PARAMETER KubeconfigOutputDir
    Directory where the auto-retrieved kubeconfig is written. Defaults to the current directory.
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $ServicesRuntimeFqdn,
        [Parameter(Mandatory = $true)][String] $ServicesRuntimePassword,
        [Parameter(Mandatory = $false)][String] $ServicesRuntimeUsername = "admin@vsp.local",
        [Parameter(Mandatory = $false)][String] $ComponentId,
        [Parameter(Mandatory = $false)][Int] $PollIntervalSeconds = 30,
        [Parameter(Mandatory = $false)][String] $KubeconfigPath,
        [Parameter(Mandatory = $false)][String] $KubeconfigOutputDir = "."
    )

    $jumpboxName = hostname
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    $terminalStates = @("COMPLETED","Completed","COMPLETE","FAILED","CANCELLED","ERROR","SUCCESS","SUCCESSFUL","Succeeded","Failed")
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    # Pre-requisite: kubectl must be available on the local machine
    if (-not (Get-Command kubectl -ErrorAction SilentlyContinue)) {
        LogMessage -type WARNING -message "[$jumpboxName] kubectl not found on PATH. Please install kubectl and ensure it is available before running this cmdlet."
        $StopWatch.Stop(); return
    }
    LogMessage -type INFO -message "[$jumpboxName] kubectl found: $((Get-Command kubectl).Source)"

    # Pre-requisite: if a kubeconfig path was supplied, verify it exists before starting the apply task
    if ($KubeconfigPath -and -not (Test-Path $KubeconfigPath)) {
        LogMessage -type WARNING -message "[$jumpboxName] KubeconfigPath not found: $KubeconfigPath — verify the path and re-run."
        $StopWatch.Stop(); return
    }

    # Step 1: Token
    $srToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn $ServicesRuntimeFqdn -Username $ServicesRuntimeUsername -Password $ServicesRuntimePassword
    if (-not $srToken) {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Unable to obtain Services Runtime token. Aborting."
        $StopWatch.Stop(); return
    }
    $tokenFetchedAt = [DateTime]::UtcNow
    $headers = @{
        "Authorization" = "Bearer $srToken"
        "Accept"        = "application/json"
        "Content-Type"  = "application/json"
    }

    # Step 2: Resolve VSP component ID
    if ($ComponentId) {
        $componentId = $ComponentId.Trim()
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Using supplied component ID: $componentId"
    } else {
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Resolving VSP component ID"
        try {
            $componentsResponse = Invoke-RestMethod -Uri "https://$ServicesRuntimeFqdn/api/v1/components" -Method GET -Headers $headers -SkipCertificateCheck
        } catch {
            LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Failed to retrieve components: $($_.Exception.Message)"
            $StopWatch.Stop(); return
        }
        $vspComponent = @($componentsResponse.components | Where-Object { $_.type -eq "vsp" }) | Select-Object -First 1
        if (-not $vspComponent) {
            LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] No component of type 'vsp' found. Pass -ComponentId to specify manually."
            $StopWatch.Stop(); return
        }
        $componentId = $vspComponent.id
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Resolved VSP component ID: $componentId"
    }

    # Step 3: Submit apply task with logs.type = none
    $body = @{
        spec    = @{
            configuration = @{
                logs = @{ type = "none" }
            }
        }
        options = @{
            precheckOnly = $false
            precheck     = $true
            timeout      = "1h"
        }
    } | ConvertTo-Json -Depth 6

    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Submitting apply task to disable logging on component $componentId"
    try {
        $applyResponse = Invoke-RestMethod -Uri "https://$ServicesRuntimeFqdn/api/v1/components/$componentId`?action=apply" -Method POST -Headers $headers -Body $body -SkipCertificateCheck
    } catch {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Apply request failed: $($_.Exception.Message)"
        $StopWatch.Stop(); return
    }

    $taskId = $applyResponse.id
    if (-not $taskId) {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] No task ID returned from apply response"
        $StopWatch.Stop(); return
    }
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Apply task created: $taskId"

    # Step 4: Poll task to completion
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Polling task $taskId every ${PollIntervalSeconds}s"
    $elapsed = 0
    $taskStatus = "UNKNOWN"
    $taskResponse = $null
    Do {
        Start-Sleep -Seconds $PollIntervalSeconds
        $elapsed += $PollIntervalSeconds
        try {
            if (([DateTime]::UtcNow - $tokenFetchedAt).TotalMinutes -ge 60) {
                LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Token age >= 60 minutes; refreshing"
                $newToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn $ServicesRuntimeFqdn -Username $ServicesRuntimeUsername -Password $ServicesRuntimePassword
                if ($newToken) {
                    $srToken = $newToken
                    $headers["Authorization"] = "Bearer $srToken"
                    $tokenFetchedAt = [DateTime]::UtcNow
                } else {
                    LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Token refresh failed; continuing with existing token"
                }
            }
            $taskResponse = Invoke-RestMethod -Uri "https://$ServicesRuntimeFqdn/api/v1/tasks/$taskId" -Method GET -Headers $headers -SkipCertificateCheck
            $rawSt = $taskResponse.status
            $rawPh = $taskResponse.phase
            if (-not [string]::IsNullOrWhiteSpace([string]$rawSt)) {
                $taskStatus = [string]$rawSt
            } elseif (-not [string]::IsNullOrWhiteSpace([string]$rawPh)) {
                $taskStatus = [string]$rawPh
            } else {
                $taskStatus = "UNKNOWN"
            }
        } catch {
            LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Poll error (will retry): $($_.Exception.Message)"
            $taskStatus = "UNKNOWN"
        }
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Task $taskId status=$taskStatus (${elapsed}s elapsed)"
    } While ($taskStatus -notin $terminalStates)

    Write-Host ""
    $successStates = @("COMPLETED","Completed","COMPLETE","SUCCESS","SUCCESSFUL","Succeeded")
    if ($taskStatus -in $successStates) {
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Logging disabled successfully on component $componentId"

        # Post-apply validation — pass the kubeconfig directly if supplied, otherwise let the
        # validation function retrieve it from the same Services Runtime node
        if ($KubeconfigPath) {
            Confirm-VcfmsFluentdOperatorState -KubeconfigPath $KubeconfigPath
        } else {
            Confirm-VcfmsFluentdOperatorState `
                -ServicesRuntimeFqdn     $ServicesRuntimeFqdn `
                -ServicesRuntimePassword $ServicesRuntimePassword `
                -KubeconfigOutputDir     $KubeconfigOutputDir
        }
    } else {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Apply task ended with status: $taskStatus"
        if ($taskResponse -and $taskResponse.description.localizedMessage) {
            LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] $($taskResponse.description.localizedMessage)"
        }
    }

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Disable-VcfmsClusterLogging

Function Enable-VcfmsClusterLogging {
    <#
    .SYNOPSIS
    Enables logging on a VCFMS Services Runtime cluster by configuring a VCF Operations
    (Aria Log Insight) log management target.

    .DESCRIPTION
    The Enable-VcfmsClusterLogging cmdlet enables logging on the VCFMS Services Runtime
    cluster on the recovery site after a successful log management restore.

    The cmdlet:
      1. Acquires an access token from the Services Runtime API.
      2. Resolves the VSP component ID from GET /api/v1/components (unless -ComponentId is supplied).
      3. Posts a component apply task to POST /api/v1/components/{id}?action=apply with:
           spec.configuration.logs.type = "ops"
           spec.configuration.logs.ops.host   = LogManagementVip
           spec.configuration.logs.ops.scheme = "https"
           spec.configuration.logs.ops.port   = LogManagementPort
      4. Polls GET /api/v1/tasks/{taskId} until the task reaches a terminal state.
      5. Validates the logging-operator-fluentd StatefulSet health in the vmsp-platform
         namespace via kubectl (using Confirm-VcfmsFluentdOperatorState).

    .EXAMPLE
    # Enable logging — component ID and kubeconfig resolved automatically
    Enable-VcfmsClusterLogging `
        -ServicesRuntimeFqdn     "lax-sr01.lax.rainpole.io" `
        -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
        -LogManagementVip        "flt-logs01.rainpole.io"

    .EXAMPLE
    # Supply a specific VSP component ID and an existing kubeconfig
    Enable-VcfmsClusterLogging `
        -ServicesRuntimeFqdn     "lax-sr01.lax.rainpole.io" `
        -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
        -LogManagementVip        "flt-logs01.rainpole.io" `
        -ComponentId             "e319236e-867e-4779-9270-4921bddf4f1f" `
        -KubeconfigPath          "C:\kubeconfigs\lax-sr01.kubeconfig"

    .PARAMETER ServicesRuntimeFqdn
    FQDN of the VCFMS Services Runtime instance on the recovery site,
    e.g. "lax-sr01.lax.rainpole.io".

    .PARAMETER ServicesRuntimePassword
    Password for the Services Runtime admin user. Used to obtain the API token and,
    when -KubeconfigPath is not supplied, to retrieve the kubeconfig for post-apply
    validation.

    .PARAMETER ServicesRuntimeUsername
    Username for the Services Runtime token request. Default is "admin@vsp.local".

    .PARAMETER LogManagementVip
    FQDN or IP of the Log Management VIP that the Services Runtime should forward
    logs to, e.g. "flt-logs01.rainpole.io".

    .PARAMETER LogManagementPort
    Port used for the log management endpoint. Default is "9543".

    .PARAMETER ComponentId
    Optional. VSP component ID to target. When omitted the cmdlet resolves the first
    component of type "vsp" from GET /api/v1/components.

    .PARAMETER PollIntervalSeconds
    Interval in seconds between task status polls. Default is 30.

    .PARAMETER KubeconfigPath
    Optional. Path to an existing kubeconfig for the Services Runtime cluster, used for
    post-apply validation of the fluentd operator. When omitted the kubeconfig is retrieved
    automatically from the Services Runtime node.

    .PARAMETER KubeconfigOutputDir
    Directory where the auto-retrieved kubeconfig is written. Defaults to the current directory.
    #>

    Param(
        [Parameter(Mandatory = $true)][String]  $ServicesRuntimeFqdn,
        [Parameter(Mandatory = $true)][String]  $ServicesRuntimePassword,
        [Parameter(Mandatory = $false)][String] $ServicesRuntimeUsername = "admin@vsp.local",
        [Parameter(Mandatory = $true)][String]  $LogManagementVip,
        [Parameter(Mandatory = $false)][String] $LogManagementPort = "9543",
        [Parameter(Mandatory = $false)][String] $ComponentId,
        [Parameter(Mandatory = $false)][Int]    $PollIntervalSeconds = 30,
        [Parameter(Mandatory = $false)][String] $KubeconfigPath,
        [Parameter(Mandatory = $false)][String] $KubeconfigOutputDir = "."
    )

    $jumpboxName    = hostname
    $StopWatch      = New-Object -TypeName System.Diagnostics.Stopwatch
    $terminalStates = @("COMPLETED","Completed","COMPLETE","FAILED","CANCELLED","ERROR","SUCCESS","SUCCESSFUL","Succeeded","Failed")
    $StopWatch.Start()
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] Services Runtime : $ServicesRuntimeFqdn"
    LogMessage -type INFO -message "[$jumpboxName] Log Management   : $LogManagementVip port $LogManagementPort"

    # -------------------------------------------------------------------------
    # Step 1: Acquire Services Runtime token
    # -------------------------------------------------------------------------
    $srToken = Get-VcfmsServicesRuntimeToken `
        -ServicesRuntimeFqdn $ServicesRuntimeFqdn `
        -Username            $ServicesRuntimeUsername `
        -Password            $ServicesRuntimePassword
    if (-not $srToken) {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Unable to obtain Services Runtime token. Aborting."
        $StopWatch.Stop(); return
    }
    $tokenFetchedAt = [DateTime]::UtcNow
    $headers = @{
        "Authorization" = "Bearer $srToken"
        "Accept"        = "application/json"
        "Content-Type"  = "application/json"
    }

    # -------------------------------------------------------------------------
    # Step 2: Resolve VSP component ID
    # -------------------------------------------------------------------------
    if ($ComponentId) {
        $componentId = $ComponentId.Trim()
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Using supplied component ID: $componentId"
    } else {
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Resolving VSP component ID from GET /api/v1/components"
        try {
            $componentsResponse = Invoke-RestMethod -Uri "https://$ServicesRuntimeFqdn/api/v1/components" `
                -Method GET -Headers $headers -SkipCertificateCheck
        } catch {
            LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Failed to retrieve components: $($_.Exception.Message)"
            $StopWatch.Stop(); return
        }
        $vspComponent = @($componentsResponse.components | Where-Object { $_.type -eq "vsp" }) | Select-Object -First 1
        if (-not $vspComponent) {
            LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] No component of type 'vsp' found. Pass -ComponentId to specify manually."
            $StopWatch.Stop(); return
        }
        $componentId = $vspComponent.id
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Resolved VSP component ID : $componentId  (status: $($vspComponent.status))"
    }

    # -------------------------------------------------------------------------
    # Step 3: Submit apply task to enable logging
    # -------------------------------------------------------------------------
    $body = @{
        spec    = @{
            configuration = @{
                logs = @{
                    type = "ops"
                    ops  = @{
                        host   = $LogManagementVip
                        scheme = "https"
                        port   = $LogManagementPort
                    }
                }
            }
        }
        options = @{
            precheckOnly = $false
            precheck     = $true
            timeout      = "1h"
        }
    } | ConvertTo-Json -Depth 8

    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Submitting apply task to enable logging on component $componentId"
    try {
        $applyResponse = Invoke-RestMethod `
            -Uri    "https://$ServicesRuntimeFqdn/api/v1/components/$componentId`?action=apply" `
            -Method POST -Headers $headers -Body $body -SkipCertificateCheck
    } catch {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Apply request failed: $($_.Exception.Message)"
        $StopWatch.Stop(); return
    }

    $taskId = $applyResponse.id
    if (-not $taskId) {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] No task ID returned from apply response."
        $StopWatch.Stop(); return
    }
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Apply task created: $taskId"

    # -------------------------------------------------------------------------
    # Step 4: Poll task to completion
    # -------------------------------------------------------------------------
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Polling task $taskId every ${PollIntervalSeconds}s"
    $elapsed      = 0
    $taskStatus   = "UNKNOWN"
    $taskResponse = $null
    Do {
        Start-Sleep -Seconds $PollIntervalSeconds
        $elapsed += $PollIntervalSeconds
        try {
            if (([DateTime]::UtcNow - $tokenFetchedAt).TotalMinutes -ge 60) {
                LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Token age >= 60 minutes; refreshing"
                $newToken = Get-VcfmsServicesRuntimeToken `
                    -ServicesRuntimeFqdn $ServicesRuntimeFqdn `
                    -Username            $ServicesRuntimeUsername `
                    -Password            $ServicesRuntimePassword
                if ($newToken) {
                    $srToken                  = $newToken
                    $headers["Authorization"] = "Bearer $srToken"
                    $tokenFetchedAt           = [DateTime]::UtcNow
                } else {
                    LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Token refresh failed; continuing with existing token"
                }
            }
            $taskResponse = Invoke-RestMethod `
                -Uri    "https://$ServicesRuntimeFqdn/api/v1/tasks/$taskId" `
                -Method GET -Headers $headers -SkipCertificateCheck
            $rawSt = $taskResponse.status
            $rawPh = $taskResponse.phase
            if (-not [string]::IsNullOrWhiteSpace([string]$rawSt)) {
                $taskStatus = [string]$rawSt
            } elseif (-not [string]::IsNullOrWhiteSpace([string]$rawPh)) {
                $taskStatus = [string]$rawPh
            } else {
                $taskStatus = "UNKNOWN"
            }
        } catch {
            LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Poll error (will retry): $($_.Exception.Message)"
            $taskStatus = "UNKNOWN"
        }
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Task $taskId status=$taskStatus (${elapsed}s elapsed)"
    } While ($taskStatus -notin $terminalStates)

    Write-Host ""
    $successStates = @("COMPLETED","Completed","COMPLETE","SUCCESS","SUCCESSFUL","Succeeded")
    if ($taskStatus -notin $successStates) {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Apply task ended with status: $taskStatus"
        if ($taskResponse -and $taskResponse.description.localizedMessage) {
            LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] $($taskResponse.description.localizedMessage)"
        }
        $StopWatch.Stop(); return
    }

    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Logging enabled successfully on component $componentId"

    # -------------------------------------------------------------------------
    # Step 5: Post-apply validation — verify logging-operator-fluentd is healthy
    # -------------------------------------------------------------------------
    if ($KubeconfigPath) {
        Confirm-VcfmsFluentdOperatorState -KubeconfigPath $KubeconfigPath
    } else {
        Confirm-VcfmsFluentdOperatorState `
            -ServicesRuntimeFqdn     $ServicesRuntimeFqdn `
            -ServicesRuntimePassword $ServicesRuntimePassword `
            -KubeconfigOutputDir     $KubeconfigOutputDir
    }

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Enable-VcfmsClusterLogging

Function Confirm-VcfmsFluentdOperatorState {
    <#
    .SYNOPSIS
    Validates the health of the fluentd logging operator on a VCFMS Services Runtime cluster.

    .DESCRIPTION
    The Confirm-VcfmsFluentdOperatorState cmdlet checks the rollout and readiness status of the
    logging-operator-fluentd StatefulSet in the vmsp-platform namespace by running:

      kubectl -n vmsp-platform rollout status sts/logging-operator-fluentd
      kubectl -n vmsp-platform get sts logging-operator-fluentd

    A healthy response shows "partitioned roll out complete" and READY = 1/1.

    If the StatefulSet is not healthy the cmdlet automatically:
      1. Flushes the Fluentd buffer:
           kubectl exec logging-operator-fluentd-0 -n vmsp-platform -- find /buffers -name "*.buffer" -type f -delete
      2. Scales down to 0 replicas then back to 1:
           kubectl scale sts logging-operator-fluentd -n vmsp-platform --replicas=0
           kubectl scale sts logging-operator-fluentd -n vmsp-platform --replicas=1

    The kubeconfig used is resolved in this order:
      1. -KubeconfigPath if supplied
      2. Auto-retrieved from the Services Runtime node via Get-VcfmsServicesRuntimeKubeconfig
         when -ServicesRuntimeFqdn and -ServicesRuntimePassword are supplied

    .EXAMPLE
    # Use an existing kubeconfig
    Confirm-VcfmsFluentdOperatorState -KubeconfigPath "C:\kubeconfigs\sfo-sr01.kubeconfig"

    .EXAMPLE
    # Retrieve kubeconfig automatically
    Confirm-VcfmsFluentdOperatorState `
        -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" `
        -ServicesRuntimePassword "VMw@re1!VMw@re1!"

    .PARAMETER KubeconfigPath
    Path to an existing kubeconfig file for the Services Runtime cluster.

    .PARAMETER ServicesRuntimeFqdn
    FQDN of the Services Runtime cluster. Used to retrieve the kubeconfig automatically when
    KubeconfigPath is not supplied.

    .PARAMETER ServicesRuntimePassword
    Password for vmware-system-user on the Services Runtime node (also used for sudo elevation).

    .PARAMETER KubeconfigOutputDir
    Directory where the retrieved kubeconfig is written. Defaults to the current directory.
    Only used when the kubeconfig is retrieved automatically.
    #>

    Param(
        [Parameter(Mandatory = $false)][String] $KubeconfigPath,
        [Parameter(Mandatory = $false)][String] $ServicesRuntimeFqdn,
        [Parameter(Mandatory = $false)][String] $ServicesRuntimePassword,
        [Parameter(Mandatory = $false)][String] $KubeconfigOutputDir = "."
    )

    $jumpboxName = hostname
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    # Resolve kubeconfig
    $resolvedKubeconfig = $KubeconfigPath
    if (-not $resolvedKubeconfig) {
        if ($ServicesRuntimeFqdn -and $ServicesRuntimePassword) {
            LogMessage -type INFO -message "[$jumpboxName] Retrieving kubeconfig from $ServicesRuntimeFqdn"
            $kubeconfigResult = Get-VcfmsServicesRuntimeKubeconfig `
                -ServicesRuntimeFqdn $ServicesRuntimeFqdn `
                -Password            $ServicesRuntimePassword `
                -OutputDir           $KubeconfigOutputDir
            if (-not $kubeconfigResult) {
                LogMessage -type ERROR -message "[$jumpboxName] Failed to retrieve kubeconfig. Aborting."
                $StopWatch.Stop(); return
            }
            $resolvedKubeconfig = $kubeconfigResult.KubeconfigPath
        } else {
            LogMessage -type ERROR -message "[$jumpboxName] Provide -KubeconfigPath or both -ServicesRuntimeFqdn and -ServicesRuntimePassword."
            $StopWatch.Stop(); return
        }
    }

    if (-not (Test-Path $resolvedKubeconfig)) {
        LogMessage -type ERROR -message "[$jumpboxName] Kubeconfig not found: $resolvedKubeconfig"
        $StopWatch.Stop(); return
    }

    LogMessage -type INFO -message "[$jumpboxName] Kubeconfig     : $resolvedKubeconfig"

    $ns  = "vmsp-platform"
    $sts = "logging-operator-fluentd"
    $pod = "logging-operator-fluentd-0"

    # -------------------------------------------------------------------------
    # Step 1: rollout status
    # -------------------------------------------------------------------------
    LogMessage -type INFO -message "[$jumpboxName] Checking rollout status of sts/$sts"
    $rolloutOutput = & kubectl --kubeconfig $resolvedKubeconfig -n $ns rollout status "sts/$sts" 2>&1
    Write-Host ""
    Write-Host " rollout status sts/$sts" -ForegroundColor Cyan
    $rolloutOutput | ForEach-Object { Write-Host "   $_" }

    $rolloutHealthy = ($rolloutOutput -join " ") -match "partitioned roll out complete|successfully rolled out"

    # -------------------------------------------------------------------------
    # Step 2: get sts
    # -------------------------------------------------------------------------
    LogMessage -type INFO -message "[$jumpboxName] Checking StatefulSet readiness"
    $getOutput = & kubectl --kubeconfig $resolvedKubeconfig -n $ns get sts $sts 2>&1
    Write-Host ""
    Write-Host " get sts $sts" -ForegroundColor Cyan
    $getOutput | ForEach-Object { Write-Host "   $_" }

    # Parse READY column — healthy when reported as "1/1" (or N/N where both numbers match)
    $readyHealthy = $false
    $dataLine = $getOutput | Select-Object -Skip 1 | Select-Object -First 1
    if ($dataLine -match '\s(\d+)/(\d+)\s') {
        $readyHealthy = ($Matches[1] -eq $Matches[2]) -and ([int]$Matches[1] -gt 0)
    }

    Write-Host ""
    if ($rolloutHealthy -and $readyHealthy) {
        LogMessage -type INFO -message "[$jumpboxName] StatefulSet $sts is healthy (rollout complete, READY=$($Matches[1])/$($Matches[2]))"
        $StopWatch.Stop()
        $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
        return
    }

    LogMessage -type WARNING -message "[$jumpboxName] StatefulSet $sts is NOT healthy — rolloutOK=$rolloutHealthy, readyOK=$readyHealthy"

    # -------------------------------------------------------------------------
    # Step 3: flush the Fluentd buffer
    # -------------------------------------------------------------------------
    LogMessage -type INFO -message "[$jumpboxName] Flushing Fluentd buffer on $pod"
    $flushOutput = & kubectl --kubeconfig $resolvedKubeconfig exec $pod -n $ns `
        -- find /buffers -name "*.buffer" -type f -delete 2>&1
    if ($flushOutput) {
        $flushOutput | ForEach-Object { Write-Host "   $_" }
    } else {
        LogMessage -type INFO -message "[$jumpboxName] Buffer flush completed (no output — directory may have been empty)"
    }

    # -------------------------------------------------------------------------
    # Step 4: scale down to 0
    # -------------------------------------------------------------------------
    LogMessage -type INFO -message "[$jumpboxName] Scaling $sts down to 0 replicas"
    $scaleDownOutput = & kubectl --kubeconfig $resolvedKubeconfig scale sts $sts -n $ns --replicas=0 2>&1
    $scaleDownOutput | ForEach-Object { Write-Host "   $_" }

    LogMessage -type INFO -message "[$jumpboxName] Waiting 15 seconds before scaling back up"
    Start-Sleep -Seconds 15

    # -------------------------------------------------------------------------
    # Step 5: scale back up to 1
    # -------------------------------------------------------------------------
    LogMessage -type INFO -message "[$jumpboxName] Scaling $sts up to 1 replica"
    $scaleUpOutput = & kubectl --kubeconfig $resolvedKubeconfig scale sts $sts -n $ns --replicas=1 2>&1
    $scaleUpOutput | ForEach-Object { Write-Host "   $_" }

    # -------------------------------------------------------------------------
    # Step 6: re-check rollout status after remediation
    # -------------------------------------------------------------------------
    LogMessage -type INFO -message "[$jumpboxName] Waiting 30 seconds for pod to initialise"
    Start-Sleep -Seconds 30

    LogMessage -type INFO -message "[$jumpboxName] Re-checking rollout status after remediation"
    $rolloutOutput2 = & kubectl --kubeconfig $resolvedKubeconfig -n $ns rollout status "sts/$sts" 2>&1
    Write-Host ""
    Write-Host " rollout status sts/$sts (post-remediation)" -ForegroundColor Cyan
    $rolloutOutput2 | ForEach-Object { Write-Host "   $_" }

    $getOutput2 = & kubectl --kubeconfig $resolvedKubeconfig -n $ns get sts $sts 2>&1
    Write-Host ""
    Write-Host " get sts $sts (post-remediation)" -ForegroundColor Cyan
    $getOutput2 | ForEach-Object { Write-Host "   $_" }

    $rolloutHealthy2 = ($rolloutOutput2 -join " ") -match "partitioned roll out complete|successfully rolled out"
    $readyHealthy2   = $false
    $dataLine2 = $getOutput2 | Select-Object -Skip 1 | Select-Object -First 1
    if ($dataLine2 -match '\s(\d+)/(\d+)\s') {
        $readyHealthy2 = ($Matches[1] -eq $Matches[2]) -and ([int]$Matches[1] -gt 0)
    }

    Write-Host ""
    if ($rolloutHealthy2 -and $readyHealthy2) {
        LogMessage -type INFO -message "[$jumpboxName] StatefulSet $sts is healthy after remediation"
    } else {
        LogMessage -type ERROR -message "[$jumpboxName] StatefulSet $sts is still NOT healthy after remediation — manual investigation required"
    }

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Confirm-VcfmsFluentdOperatorState

Function Set-VcfmsFleetIdentity {
    <#
    .SYNOPSIS
    Applies fleet identity TLS secrets and configures fleet ingress on the recovery VCFMS cluster.

    .DESCRIPTION
    The Set-VcfmsFleetIdentity cmdlet performs two steps:

    Step 1 — Apply fleet TLS secrets from a backup extraction:
      kubectl apply -f ingress-fleet-tls.yaml
      kubectl apply -f ingress-fleet-tls-ndc.yaml

    Step 2 — Configure fleet ingress via the Services Runtime API:
      Reads the VSP component ID from the vmsp-platform namespace label:
        component.vmsp.vmware.com/id
      Then posts an apply task to PATCH spec.configuration.ingress.fleet with the
      provided FleetFqdn and FleetVip, and polls until the task reaches a terminal state.

    Both files must exist in BackupYamlDir. The kubeconfig is resolved in this order:
      1. -KubeconfigPath if supplied
      2. Auto-retrieved from the Services Runtime node via Get-VcfmsServicesRuntimeKubeconfig
         when -ServicesRuntimeFqdn and -ServicesRuntimePassword are supplied

    .EXAMPLE
    Set-VcfmsFleetIdentity `
        -BackupYamlDir           "C:\backup-yaml" `
        -ServicesRuntimeFqdn     "sfo-sr01.sfo.rainpole.io" `
        -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
        -FleetFqdn               "flt-fc01.sfo.rainpole.io" `
        -FleetVip                "10.50.0.10"

    .EXAMPLE
    Set-VcfmsFleetIdentity `
        -BackupYamlDir           "C:\backup-yaml" `
        -KubeconfigPath          "C:\kubeconfigs\sfo-sr01.kubeconfig" `
        -ServicesRuntimeFqdn     "sfo-sr01.sfo.rainpole.io" `
        -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
        -FleetFqdn               "flt-fc01.sfo.rainpole.io" `
        -FleetVip                "10.50.0.10"

    .PARAMETER BackupYamlDir
    Directory containing the YAML files produced by New-ExtractVcfmsBackup. Must contain
    both ingress-fleet-tls.yaml and ingress-fleet-tls-ndc.yaml.

    .PARAMETER FleetFqdn
    FQDN of the Fleet LCM instance to configure in the ingress spec.

    .PARAMETER FleetVip
    IPv4 VIP address for the Fleet LCM ingress to configure in the ingress spec.

    .PARAMETER ServicesRuntimeFqdn
    FQDN of the Services Runtime cluster. Required for the API apply call and for automatic
    kubeconfig retrieval when KubeconfigPath is not supplied.

    .PARAMETER ServicesRuntimePassword
    Password for the Services Runtime admin user and vmware-system-user SSH access.

    .PARAMETER ServicesRuntimeUsername
    Username for the Services Runtime API token. Default is "admin@vsp.local".

    .PARAMETER KubeconfigPath
    Path to an existing kubeconfig for the recovery Services Runtime cluster. Takes precedence
    over automatic retrieval.

    .PARAMETER KubeconfigOutputDir
    Directory where the auto-retrieved kubeconfig is written. Defaults to the current directory.

    .PARAMETER PollIntervalSeconds
    Interval in seconds between task status polls. Default is 30.
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $BackupYamlDir,
        [Parameter(Mandatory = $true)][String] $FleetFqdn,
        [Parameter(Mandatory = $true)][String] $FleetVip,
        [Parameter(Mandatory = $true)][String] $ServicesRuntimeFqdn,
        [Parameter(Mandatory = $true)][String] $ServicesRuntimePassword,
        [Parameter(Mandatory = $false)][String] $ServicesRuntimeUsername = "admin@vsp.local",
        [Parameter(Mandatory = $false)][String] $KubeconfigPath,
        [Parameter(Mandatory = $false)][String] $KubeconfigOutputDir = ".",
        [Parameter(Mandatory = $false)][Int]    $PollIntervalSeconds = 30
    )

    $jumpboxName   = hostname
    $StopWatch     = New-Object -TypeName System.Diagnostics.Stopwatch
    $terminalStates = @("COMPLETED","Completed","COMPLETE","FAILED","CANCELLED","ERROR","SUCCESS","SUCCESSFUL","Succeeded","Failed")
    $StopWatch.Start()
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    # -------------------------------------------------------------------------
    # Pre-flight: validate YAML files
    # -------------------------------------------------------------------------
    $resolvedYamlDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($BackupYamlDir)
    if (-not (Test-Path $resolvedYamlDir)) {
        LogMessage -type ERROR -message "[$jumpboxName] BackupYamlDir not found: $resolvedYamlDir"
        $StopWatch.Stop(); return
    }

    $tlsYaml      = Join-Path $resolvedYamlDir "ingress-fleet-tls.yaml"
    $ndcYaml      = Join-Path $resolvedYamlDir "ingress-fleet-tls-ndc.yaml"
    $missingFiles = @()
    if (-not (Test-Path $tlsYaml)) { $missingFiles += $tlsYaml }
    if (-not (Test-Path $ndcYaml)) { $missingFiles += $ndcYaml }
    if ($missingFiles.Count -gt 0) {
        foreach ($f in $missingFiles) {
            LogMessage -type ERROR -message "[$jumpboxName] Required YAML file not found: $f"
        }
        $StopWatch.Stop(); return
    }

    # -------------------------------------------------------------------------
    # Resolve kubeconfig
    # -------------------------------------------------------------------------
    $resolvedKubeconfig = $KubeconfigPath
    if (-not $resolvedKubeconfig) {
        LogMessage -type INFO -message "[$jumpboxName] Retrieving kubeconfig from $ServicesRuntimeFqdn"
        $kubeconfigResult = Get-VcfmsServicesRuntimeKubeconfig `
            -ServicesRuntimeFqdn $ServicesRuntimeFqdn `
            -Password            $ServicesRuntimePassword `
            -OutputDir           $KubeconfigOutputDir
        if (-not $kubeconfigResult) {
            LogMessage -type ERROR -message "[$jumpboxName] Failed to retrieve kubeconfig. Aborting."
            $StopWatch.Stop(); return
        }
        $resolvedKubeconfig = $kubeconfigResult.KubeconfigPath
    }

    if (-not (Test-Path $resolvedKubeconfig)) {
        LogMessage -type ERROR -message "[$jumpboxName] Kubeconfig not found: $resolvedKubeconfig"
        $StopWatch.Stop(); return
    }

    LogMessage -type INFO -message "[$jumpboxName] YAML directory  : $resolvedYamlDir"
    LogMessage -type INFO -message "[$jumpboxName] Kubeconfig      : $resolvedKubeconfig"
    LogMessage -type INFO -message "[$jumpboxName] Fleet FQDN      : $FleetFqdn"
    LogMessage -type INFO -message "[$jumpboxName] Fleet VIP       : $FleetVip"

    # =========================================================================
    # Step 1: Apply fleet TLS secrets
    # =========================================================================
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Step 1: Applying fleet identity secrets"
    $allSucceeded = $true
    foreach ($yamlFile in @($tlsYaml, $ndcYaml)) {
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Applying $(Split-Path $yamlFile -Leaf)"
        $output   = & kubectl --kubeconfig $resolvedKubeconfig apply -f $yamlFile 2>&1
        $exitCode = $LASTEXITCODE
        $output | ForEach-Object { Write-Host "   $_" }
        if ($exitCode -eq 0) {
            LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Applied: $(Split-Path $yamlFile -Leaf)"
        } else {
            LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] kubectl apply failed (exit $exitCode): $(Split-Path $yamlFile -Leaf)"
            $allSucceeded = $false
        }
    }

    if (-not $allSucceeded) {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] One or more YAML files failed to apply — aborting ingress configuration"
        $StopWatch.Stop(); return
    }
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Fleet identity secrets applied successfully"

    # =========================================================================
    # Step 2: Configure fleet ingress via Services Runtime API
    # =========================================================================
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Step 2: Configuring fleet ingress via API"

    # Step 2a: Read VSP component ID from the vmsp-platform namespace label
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Reading VSP component ID from vmsp-platform namespace"
    $nsLabelOutput = & kubectl --kubeconfig $resolvedKubeconfig get ns vmsp-platform `
        -o "jsonpath={.metadata.labels.component\.vmsp\.vmware\.com/id}" 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0 -or [string]::IsNullOrWhiteSpace($nsLabelOutput)) {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Failed to read VSP component ID from namespace label (exit $exitCode): $nsLabelOutput"
        $StopWatch.Stop(); return
    }
    $componentId = $nsLabelOutput.Trim()
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] VSP component ID: $componentId"

    # Step 2b: Get Services Runtime token
    $srToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn $ServicesRuntimeFqdn -Username $ServicesRuntimeUsername -Password $ServicesRuntimePassword
    if (-not $srToken) {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Unable to obtain Services Runtime token. Aborting."
        $StopWatch.Stop(); return
    }
    $tokenFetchedAt = [DateTime]::UtcNow
    $headers = @{
        "Authorization" = "Bearer $srToken"
        "Accept"        = "application/json"
        "Content-Type"  = "application/json"
    }

    # Step 2c: Submit apply task with fleet ingress spec
    $body = @{
        spec    = @{
            configuration = @{
                ingress = @{
                    fleet = @{
                        fqdn = $FleetFqdn
                        vips = @{ ipv4 = @($FleetVip) }
                    }
                }
            }
        }
        options = @{ timeout = "30m" }
    } | ConvertTo-Json -Depth 8

    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Submitting fleet ingress apply for component $componentId"
    try {
        $applyResponse = Invoke-RestMethod `
            -Uri "https://$ServicesRuntimeFqdn/api/v1/components/$componentId`?action=apply" `
            -Method POST -Headers $headers -Body $body -SkipCertificateCheck
    } catch {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Apply request failed: $($_.Exception.Message)"
        $StopWatch.Stop(); return
    }

    $taskId = $applyResponse.id
    if (-not $taskId) {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] No task ID returned from apply response"
        $StopWatch.Stop(); return
    }
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Apply task created: $taskId"

    # Step 2d: Poll task to completion
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Polling task $taskId every ${PollIntervalSeconds}s"
    $elapsed     = 0
    $taskStatus  = "UNKNOWN"
    $taskResponse = $null
    Do {
        Start-Sleep -Seconds $PollIntervalSeconds
        $elapsed += $PollIntervalSeconds
        try {
            if (([DateTime]::UtcNow - $tokenFetchedAt).TotalMinutes -ge 60) {
                LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Token age >= 60 minutes; refreshing"
                $newToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn $ServicesRuntimeFqdn -Username $ServicesRuntimeUsername -Password $ServicesRuntimePassword
                if ($newToken) {
                    $srToken = $newToken
                    $headers["Authorization"] = "Bearer $srToken"
                    $tokenFetchedAt = [DateTime]::UtcNow
                } else {
                    LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Token refresh failed; continuing with existing token"
                }
            }
            $taskResponse = Invoke-RestMethod -Uri "https://$ServicesRuntimeFqdn/api/v1/tasks/$taskId" -Method GET -Headers $headers -SkipCertificateCheck
            $rawSt = $taskResponse.status
            $rawPh = $taskResponse.phase
            if (-not [string]::IsNullOrWhiteSpace([string]$rawSt)) {
                $taskStatus = [string]$rawSt
            } elseif (-not [string]::IsNullOrWhiteSpace([string]$rawPh)) {
                $taskStatus = [string]$rawPh
            } else {
                $taskStatus = "UNKNOWN"
            }
        } catch {
            LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Poll error (will retry): $($_.Exception.Message)"
            $taskStatus = "UNKNOWN"
        }
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Task $taskId status=$taskStatus (${elapsed}s elapsed)"
    } While ($taskStatus -notin $terminalStates)

    Write-Host ""
    $successStates = @("COMPLETED","Completed","COMPLETE","SUCCESS","SUCCESSFUL","Succeeded")
    if ($taskStatus -in $successStates) {
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Fleet ingress configured successfully"
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Fleet FQDN : $FleetFqdn"
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Fleet VIP  : $FleetVip"
    } else {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Apply task ended with status: $taskStatus"
        if ($taskResponse -and $taskResponse.description.localizedMessage) {
            LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] $($taskResponse.description.localizedMessage)"
        }
    }

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Set-VcfmsFleetIdentity

Function Clear-VcfmsFleetIdentity {
    <#
    .SYNOPSIS
    Removes the fleet ingress VIP configuration from a VCFMS Services Runtime cluster.

    .DESCRIPTION
    The Clear-VcfmsFleetIdentity cmdlet clears the fleet ingress configuration that was
    previously applied by Set-VcfmsFleetIdentity. It submits the same apply payload shape
    to POST /api/v1/components/{id}?action=apply but with blank values for the fleet FQDN
    and an empty VIP array, effectively removing the fleet VIP from the ingress spec:

      spec.configuration.ingress.fleet.fqdn = ""
      spec.configuration.ingress.fleet.vips = { ipv4: [] }

    The VSP component ID is read from the vmsp-platform namespace label
    (component.vmsp.vmware.com/id) using the resolved kubeconfig, and the resulting
    task is polled to completion.

    The kubeconfig is resolved in this order:
      1. -KubeconfigPath if supplied
      2. Auto-retrieved from the Services Runtime node via Get-VcfmsServicesRuntimeKubeconfig
         when -ServicesRuntimeFqdn and -ServicesRuntimePassword are supplied

    .EXAMPLE
    # Auto-retrieve kubeconfig
    Clear-VcfmsFleetIdentity `
        -ServicesRuntimeFqdn     "sfo-sr01.sfo.rainpole.io" `
        -ServicesRuntimePassword "VMw@re1!VMw@re1!"

    .EXAMPLE
    # Use an existing kubeconfig
    Clear-VcfmsFleetIdentity `
        -ServicesRuntimeFqdn     "sfo-sr01.sfo.rainpole.io" `
        -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
        -KubeconfigPath          "C:\kubeconfigs\sfo-sr01.kubeconfig"

    .PARAMETER ServicesRuntimeFqdn
    FQDN of the Services Runtime cluster. Required for the API apply call and for automatic
    kubeconfig retrieval when KubeconfigPath is not supplied.

    .PARAMETER ServicesRuntimePassword
    Password for the Services Runtime admin user and vmware-system-user SSH access.

    .PARAMETER ServicesRuntimeUsername
    Username for the Services Runtime API token. Default is "admin@vsp.local".

    .PARAMETER KubeconfigPath
    Path to an existing kubeconfig for the Services Runtime cluster. Takes precedence
    over automatic retrieval.

    .PARAMETER KubeconfigOutputDir
    Directory where the auto-retrieved kubeconfig is written. Defaults to the current directory.

    .PARAMETER PollIntervalSeconds
    Interval in seconds between task status polls. Default is 60.
    #>

    Param(
        [Parameter(Mandatory = $true)][String]  $ServicesRuntimeFqdn,
        [Parameter(Mandatory = $true)][String]  $ServicesRuntimePassword,
        [Parameter(Mandatory = $false)][String] $ServicesRuntimeUsername = "admin@vsp.local",
        [Parameter(Mandatory = $false)][String] $KubeconfigPath,
        [Parameter(Mandatory = $false)][String] $KubeconfigOutputDir = ".",
        [Parameter(Mandatory = $false)][Int]    $PollIntervalSeconds = 60
    )

    $jumpboxName    = hostname
    $StopWatch      = New-Object -TypeName System.Diagnostics.Stopwatch
    $terminalStates = @("COMPLETED","Completed","COMPLETE","FAILED","CANCELLED","ERROR","SUCCESS","SUCCESSFUL","Succeeded","Failed")
    $StopWatch.Start()
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] Services Runtime : $ServicesRuntimeFqdn"

    # -------------------------------------------------------------------------
    # Resolve kubeconfig
    # -------------------------------------------------------------------------
    $resolvedKubeconfig = $KubeconfigPath
    if (-not $resolvedKubeconfig) {
        LogMessage -type INFO -message "[$jumpboxName] Retrieving kubeconfig from $ServicesRuntimeFqdn"
        $kubeconfigResult = Get-VcfmsServicesRuntimeKubeconfig `
            -ServicesRuntimeFqdn $ServicesRuntimeFqdn `
            -Password            $ServicesRuntimePassword `
            -OutputDir           $KubeconfigOutputDir
        if (-not $kubeconfigResult) {
            LogMessage -type ERROR -message "[$jumpboxName] Failed to retrieve kubeconfig. Aborting."
            $StopWatch.Stop(); return
        }
        $resolvedKubeconfig = $kubeconfigResult.KubeconfigPath
    }

    if (-not (Test-Path $resolvedKubeconfig)) {
        LogMessage -type ERROR -message "[$jumpboxName] Kubeconfig not found: $resolvedKubeconfig"
        $StopWatch.Stop(); return
    }
    LogMessage -type INFO -message "[$jumpboxName] Kubeconfig : $resolvedKubeconfig"

    # -------------------------------------------------------------------------
    # Step 1: Read VSP component ID from the vmsp-platform namespace label
    # -------------------------------------------------------------------------
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Reading VSP component ID from vmsp-platform namespace"
    $nsLabelOutput = & kubectl --kubeconfig $resolvedKubeconfig get ns vmsp-platform `
        -o "jsonpath={.metadata.labels.component\.vmsp\.vmware\.com/id}" 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0 -or [string]::IsNullOrWhiteSpace($nsLabelOutput)) {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Failed to read VSP component ID from namespace label (exit $exitCode): $nsLabelOutput"
        $StopWatch.Stop(); return
    }
    $componentId = $nsLabelOutput.Trim()
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] VSP component ID : $componentId"

    # -------------------------------------------------------------------------
    # Step 2: Acquire Services Runtime token
    # -------------------------------------------------------------------------
    $srToken = Get-VcfmsServicesRuntimeToken `
        -ServicesRuntimeFqdn $ServicesRuntimeFqdn `
        -Username            $ServicesRuntimeUsername `
        -Password            $ServicesRuntimePassword
    if (-not $srToken) {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Unable to obtain Services Runtime token. Aborting."
        $StopWatch.Stop(); return
    }
    $tokenFetchedAt = [DateTime]::UtcNow
    $headers = @{
        "Authorization" = "Bearer $srToken"
        "Accept"        = "application/json"
        "Content-Type"  = "application/json"
    }

    # -------------------------------------------------------------------------
    # Step 3: Submit apply task with blank fleet ingress values
    # Same payload shape as Set-VcfmsFleetIdentity — fqdn cleared to empty
    # string and vips.ipv4 set to an empty array.
    # -------------------------------------------------------------------------
    $body = @{
        spec    = @{
            configuration = @{
                ingress = @{
                    fleet = @{
                        fqdn = ""
                        vips = @{ ipv4 = @() }
                    }
                }
            }
        }
        options = @{ timeout = "30m" }
    } | ConvertTo-Json -Depth 8

    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Submitting apply task to clear fleet ingress on component $componentId"
    try {
        $applyResponse = Invoke-RestMethod `
            -Uri    "https://$ServicesRuntimeFqdn/api/v1/components/$componentId`?action=apply" `
            -Method POST -Headers $headers -Body $body -SkipCertificateCheck
    } catch {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Apply request failed: $($_.Exception.Message)"
        $StopWatch.Stop(); return
    }

    $taskId = $applyResponse.id
    if (-not $taskId) {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] No task ID returned from apply response."
        $StopWatch.Stop(); return
    }
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Apply task created: $taskId"

    # -------------------------------------------------------------------------
    # Step 4: Poll task to completion
    # -------------------------------------------------------------------------
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Polling task $taskId every ${PollIntervalSeconds}s"
    $elapsed      = 0
    $taskStatus   = "UNKNOWN"
    $taskResponse = $null
    Do {
        Start-Sleep -Seconds $PollIntervalSeconds
        $elapsed += $PollIntervalSeconds
        try {
            if (([DateTime]::UtcNow - $tokenFetchedAt).TotalMinutes -ge 60) {
                LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Token age >= 60 minutes; refreshing"
                $newToken = Get-VcfmsServicesRuntimeToken `
                    -ServicesRuntimeFqdn $ServicesRuntimeFqdn `
                    -Username            $ServicesRuntimeUsername `
                    -Password            $ServicesRuntimePassword
                if ($newToken) {
                    $srToken                  = $newToken
                    $headers["Authorization"] = "Bearer $srToken"
                    $tokenFetchedAt           = [DateTime]::UtcNow
                } else {
                    LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Token refresh failed; continuing with existing token"
                }
            }
            $taskResponse = Invoke-RestMethod `
                -Uri    "https://$ServicesRuntimeFqdn/api/v1/tasks/$taskId" `
                -Method GET -Headers $headers -SkipCertificateCheck
            $rawSt = $taskResponse.status
            $rawPh = $taskResponse.phase
            if (-not [string]::IsNullOrWhiteSpace([string]$rawSt)) {
                $taskStatus = [string]$rawSt
            } elseif (-not [string]::IsNullOrWhiteSpace([string]$rawPh)) {
                $taskStatus = [string]$rawPh
            } else {
                $taskStatus = "UNKNOWN"
            }
        } catch {
            LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Poll error (will retry): $($_.Exception.Message)"
            $taskStatus = "UNKNOWN"
        }
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Task $taskId status=$taskStatus (${elapsed}s elapsed)"
    } While ($taskStatus -notin $terminalStates)

    Write-Host ""
    $successStates = @("COMPLETED","Completed","COMPLETE","SUCCESS","SUCCESSFUL","Succeeded")
    if ($taskStatus -in $successStates) {
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Fleet ingress VIP cleared successfully on component $componentId"
    } else {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Apply task ended with status: $taskStatus"
        if ($taskResponse -and $taskResponse.description.localizedMessage) {
            LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] $($taskResponse.description.localizedMessage)"
        }
    }

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Clear-VcfmsFleetIdentity

Function Invoke-VcfmsFleetComponentRegistration {
    <#
    .SYNOPSIS
    Copies and executes the fleet component registration script on the Services Runtime
    control plane node.

    .DESCRIPTION
    The Invoke-VcfmsFleetComponentRegistration cmdlet performs the following steps:

      1. Resolves the Services Runtime control plane node (handles worker-node redirect
         via node-agent.conf automatically).
      2. Base64-encodes the bundled update_fleet_component_registration.sh script and
         uploads it to /tmp on the control plane node via the existing SSH session —
         no SCP binary required.
      3. Executes the script under sudo with KUBECONFIG=/etc/kubernetes/admin.conf so
         that all kubectl calls use the local cluster admin credentials.
      4. Streams script output to the console in real time.
      5. Removes the temporary script from the remote node on completion.

    The script targets the Fleet LCM component registrations using one of three modes:
    --target-vcf (short VCF name), --target-fqdn (FQDN substring), or --target-sddc-id
    (exact UUID). Exactly one of -TargetVcfInstance, -TargetFqdn, or -TargetSddcId must
    be supplied.

    .EXAMPLE
    # Target by short VCF instance name
    Invoke-VcfmsFleetComponentRegistration `
        -ServicesRuntimeFqdn     "sfo-sr01.sfo.rainpole.io" `
        -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
        -TargetVcfInstance       "vcf02"

    .EXAMPLE
    # Target by FQDN substring — useful when friendly names like "Los Angeles" are used
    Invoke-VcfmsFleetComponentRegistration `
        -ServicesRuntimeFqdn     "lax-sr01.lax.rainpole.io" `
        -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
        -TargetFqdn              "lax"

    .EXAMPLE
    # Target by exact SDDC LCM UUID
    Invoke-VcfmsFleetComponentRegistration `
        -ServicesRuntimeFqdn     "lax-sr01.lax.rainpole.io" `
        -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
        -TargetSddcId            "7a07f2c3-be5b-420a-8ce3-64b20f4ec52a"

    .EXAMPLE
    # Dry run — show what would be changed without writing anything
    Invoke-VcfmsFleetComponentRegistration `
        -ServicesRuntimeFqdn     "lax-sr01.lax.rainpole.io" `
        -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
        -TargetFqdn              "lax" `
        -DryRun

    .PARAMETER ServicesRuntimeFqdn
    FQDN or IP of any Services Runtime cluster node. If a worker node is supplied the
    function automatically resolves and connects to the control plane.

    .PARAMETER ServicesRuntimePassword
    Password for vmware-system-user (SSH login and sudo elevation).

    .PARAMETER TargetVcfInstance
    VCF instance FQDN or substring to match against the sddc_lcm.fqdn column, e.g.
    "lax-ic01.lax.rainpole.io". Passed as --target-fqdn to the script.
    Mutually exclusive with -TargetFqdn and -TargetSddcId.

    .PARAMETER TargetFqdn
    FQDN substring pattern to match against the sddc_lcm.fqdn column, e.g. "lax" to match
    "lax-ic01.lax.rainpole.io". Passed as --target-fqdn to the script.
    Mutually exclusive with -TargetVcfInstance and -TargetSddcId.

    .PARAMETER TargetSddcId
    FQDN substring pattern to match against the sddc_lcm.fqdn column. Passed as
    --target-fqdn to the script. Note: UUID-based lookup is not currently supported by
    the script; use -TargetFqdn for a reliable substring match.
    Mutually exclusive with -TargetVcfInstance and -TargetFqdn.

    .PARAMETER DryRun
    When specified, passes --dry-run to the script. No database changes are made;
    the script shows what would be updated.

    .PARAMETER RemoteScriptTimeout
    Seconds to wait for the remote script to complete. Default is 300 (5 minutes).
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $ServicesRuntimeFqdn,
        [Parameter(Mandatory = $true)][String] $ServicesRuntimePassword,
        [Parameter(Mandatory = $true,  ParameterSetName = "ByVcfInstance")][String] $TargetVcfInstance,
        [Parameter(Mandatory = $true,  ParameterSetName = "ByFqdn")][String]        $TargetFqdn,
        [Parameter(Mandatory = $true,  ParameterSetName = "BySddcId")][String]      $TargetSddcId,
        [Parameter(Mandatory = $false)][Switch] $DryRun,
        [Parameter(Mandatory = $false)][Int] $RemoteScriptTimeout = 300
    )

    $jumpboxName  = hostname
    $StopWatch    = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    # -------------------------------------------------------------------------
    # Validate the local script exists
    # -------------------------------------------------------------------------
    $localScript = Join-Path -Path $PSScriptRoot -ChildPath "scripts/9.1.0/update_fleet_component_registration.sh"
    if (-not (Test-Path $localScript)) {
        LogMessage -type ERROR -message "[$jumpboxName] Script not found: $localScript"
        $StopWatch.Stop(); return
    }

    # -------------------------------------------------------------------------
    # Resolve the control plane node
    # Reuse Get-VcfmsServicesRuntimeKubeconfig which handles worker → CP redirect.
    # The kubeconfig is written as a useful side effect; we primarily need ControlPlaneHost.
    # -------------------------------------------------------------------------
    LogMessage -type INFO -message "[$jumpboxName] Resolving control plane node from $ServicesRuntimeFqdn"
    $kubeconfigResult = Get-VcfmsServicesRuntimeKubeconfig `
        -ServicesRuntimeFqdn $ServicesRuntimeFqdn `
        -Password            $ServicesRuntimePassword `
        -OutputDir           "."
    if (-not $kubeconfigResult) {
        LogMessage -type ERROR -message "[$jumpboxName] Could not resolve control plane node. Aborting."
        $StopWatch.Stop(); return
    }
    $controlPlaneHost = $kubeconfigResult.ControlPlaneHost
    LogMessage -type INFO -message "[$jumpboxName] Control plane node  : $controlPlaneHost"
    switch ($PSCmdlet.ParameterSetName) {
        "ByVcfInstance" { LogMessage -type INFO -message "[$jumpboxName] Target VCF instance : $TargetVcfInstance" }
        "ByFqdn"        { LogMessage -type INFO -message "[$jumpboxName] Target FQDN pattern : $TargetFqdn" }
        "BySddcId"      { LogMessage -type INFO -message "[$jumpboxName] Target SDDC LCM ID  : $TargetSddcId" }
    }
    if ($DryRun) {
        LogMessage -type INFO -message "[$jumpboxName] Mode               : DRY RUN (no changes will be written)"
    }

    # -------------------------------------------------------------------------
    # Open SSH session to the control plane node
    # -------------------------------------------------------------------------
    $SecurePassword = ConvertTo-SecureString -String $ServicesRuntimePassword -AsPlainText -Force
    $creds          = New-Object System.Management.Automation.PSCredential ('vmware-system-user', $SecurePassword)
    $session        = $null
    $remotePath     = "/tmp/update_fleet_component_registration.sh"

    try {
        $session = Open-VcfmsSshSession -Fqdn $controlPlaneHost -Creds $creds

        # -------------------------------------------------------------------------
        # Upload the script via base64 pipe — avoids any SCP binary dependency
        # -------------------------------------------------------------------------
        LogMessage -type INFO -message "[$controlPlaneHost] Uploading script to $remotePath"
        $scriptBytes = [System.IO.File]::ReadAllBytes($localScript)
        # Strip CR bytes so the file always has Unix line endings on the remote node,
        # regardless of how git checked it out on the local machine (Windows autocrlf etc.)
        $scriptBytes = [byte[]]($scriptBytes | Where-Object { $_ -ne 0x0D })
        $b64         = [System.Convert]::ToBase64String($scriptBytes)

        # printf is used instead of echo to avoid an appended newline corrupting the decode
        $uploadCmd    = "printf '%s' '$b64' | base64 -d > $remotePath && chmod +x $remotePath"
        $uploadResult = Invoke-SSHCommand -SessionId $session.SessionId -Command $uploadCmd -TimeOut 60
        if ($uploadResult.ExitStatus -ne 0) {
            LogMessage -type ERROR -message "[$controlPlaneHost] Script upload failed (exit $($uploadResult.ExitStatus)): $($uploadResult.Error -join ' ')"
            return
        }
        LogMessage -type INFO -message "[$controlPlaneHost] Script uploaded successfully"

        # -------------------------------------------------------------------------
        # Build and execute the remote command
        # sudo -S reads the password from stdin; env preserves KUBECONFIG across the
        # sudo boundary so every kubectl call inside the script uses admin.conf
        # -------------------------------------------------------------------------
        $scriptArgs = switch ($PSCmdlet.ParameterSetName) {
            "ByVcfInstance" { "--target-fqdn '$TargetVcfInstance'" }
            "ByFqdn"        { "--target-fqdn '$TargetFqdn'" }
            "BySddcId"      { "--target-fqdn '$TargetSddcId'" }
        }
        if ($DryRun) { $scriptArgs += " --dry-run" }

        $execCmd = "echo '$ServicesRuntimePassword' | sudo -S env KUBECONFIG=/etc/kubernetes/admin.conf bash $remotePath $scriptArgs 2>&1"

        LogMessage -type INFO -message "[$controlPlaneHost] Executing script (timeout: ${RemoteScriptTimeout}s)"
        Write-Host ""
        Write-Host " ── update_fleet_component_registration output ──────────────────────" -ForegroundColor Cyan

        $execResult = Invoke-SSHCommand -SessionId $session.SessionId -Command $execCmd -TimeOut $RemoteScriptTimeout

        # Print all output (stdout + stderr merged via 2>&1); filter sudo prompt noise
        $execResult.Output |
            Where-Object { $_ -notmatch '^\[sudo\]' } |
            ForEach-Object { Write-Host "  $_" }

        # Belt-and-suspenders: if Posh-SSH still delivers anything on the Error channel
        # split on newlines first so a single multi-line string is handled correctly
        if ($execResult.Error) {
            (($execResult.Error -join "`n") -split "`r?`n") |
                Where-Object { $_ -notmatch '^\[sudo\]' -and $_ -ne '' } |
                ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
        }

        Write-Host " ────────────────────────────────────────────────────────────────────" -ForegroundColor Cyan
        Write-Host ""

        if ($execResult.ExitStatus -eq 0) {
            LogMessage -type INFO -message "[$controlPlaneHost] Script completed successfully"
        } else {
            LogMessage -type ERROR -message "[$controlPlaneHost] Script exited with code $($execResult.ExitStatus)"
        }

    } catch {
        LogMessage -type ERROR -message "[$jumpboxName] $($_.Exception.Message)"
    } finally {
        # Always remove the temporary script from the remote node
        if ($session) {
            Invoke-SSHCommand -SessionId $session.SessionId `
                -Command "rm -f $remotePath" -TimeOut 15 | Out-Null
            Remove-SSHSession -SSHSession $session | Out-Null
            LogMessage -type INFO -message "[$controlPlaneHost] Temporary script removed"
        }
    }

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Invoke-VcfmsFleetComponentRegistration

Function Update-ServicesRuntimePackageDeployment {
    <#
    .SYNOPSIS
    Updates the vSphere placement configuration in the vmsp-platform PackageDeployment on a Services Runtime cluster.

    .DESCRIPTION
    The Update-VcfmsPlatformPackageDeploymentVsphere cmdlet performs the following steps:

      1. Connects to vCenter via PowerCLI and resolves Managed Object Reference IDs and
         inventory paths for the target datacenter, cluster, datastore, distributed port
         group, VM folder, resource pool, and VM template.
      2. Retrieves the Services Runtime cluster KUBECONFIG using the existing
         Get-VcfmsServicesRuntimeKubeconfig helper (worker-node redirect handled
         automatically).
      3. Patches the vmsp-platform PackageDeployment (pd/vmsp-platform in namespace
         vmsp-platform) with the resolved vSphere placement values via kubectl patch
         --type=merge.

    Use -DryRun to display the computed patch JSON without applying it.

    .EXAMPLE
    Update-VcfmsPlatformPackageDeploymentVsphere `
        -ServicesRuntimeFqdn     "sfo-sr01.sfo.rainpole.io" `
        -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
        -vCenterFqdn             "sfo-m01-vc01.sfo.rainpole.io" `
        -vCenterUsername         "administrator@vsphere.local" `
        -vCenterPassword         "VMw@re1!VMw@re1!" `
        -TargetDatacenter        "sfo-m01-dc01" `
        -TargetCluster           "sfo-m01-cl02" `
        -TargetDatastore         "sfo-m01-cl02-vsan01" `
        -TargetDpG               "sfo-m01-cl02-vds01-pg-vcf-mgmt" `
        -TargetFolder            "vcf-management-services" `
        -TargetRP                "Resources" `
        -TargetTemplate          "vcf-services-runtime-template-9.1.0.0.25370367"

    .EXAMPLE
    Update-VcfmsPlatformPackageDeploymentVsphere `
        -ServicesRuntimeFqdn     "sfo-sr01.sfo.rainpole.io" `
        -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
        -vCenterFqdn             "sfo-m01-vc01.sfo.rainpole.io" `
        -vCenterUsername         "administrator@vsphere.local" `
        -vCenterPassword         "VMw@re1!VMw@re1!" `
        -TargetDatacenter        "sfo-m01-dc01" `
        -TargetCluster           "sfo-m01-cl02" `
        -TargetDatastore         "sfo-m01-cl02-vsan01" `
        -TargetDpG               "sfo-m01-cl02-vds01-pg-vcf-mgmt" `
        -TargetFolder            "vcf-management-services" `
        -TargetRP                "Resources" `
        -TargetTemplate          "vcf-services-runtime-template-9.1.0.0.25370367" `
        -DryRun

    .PARAMETER ServicesRuntimeFqdn
    FQDN or IP of any Services Runtime cluster node. Worker nodes are automatically
    redirected to the control plane.

    .PARAMETER ServicesRuntimePassword
    Password for vmware-system-user (SSH login).

    .PARAMETER vCenterFqdn
    FQDN of the vCenter Server that manages the target vSphere inventory.

    .PARAMETER vCenterUsername
    Username for vCenter authentication. Defaults to administrator@vsphere.local.

    .PARAMETER vCenterPassword
    Password for the vCenter user.

    .PARAMETER TargetDatacenter
    Name of the target vSphere datacenter.

    .PARAMETER TargetCluster
    Name of the target vSphere cluster.

    .PARAMETER TargetDatastore
    Name of the target datastore.

    .PARAMETER TargetDpG
    Name of the target distributed port group.

    .PARAMETER TargetFolder
    Name of the target VM folder (type VM).

    .PARAMETER TargetRP
    Name of the target resource pool. Defaults to "Resources" (the cluster root pool).

    .PARAMETER TargetTemplate
    Name of the target VM template.

    .PARAMETER OutputDir
    Directory where the retrieved kubeconfig file is written. Defaults to the current
    directory.

    .PARAMETER DryRun
    When specified, displays the computed patch JSON without applying it to the cluster.
    #>

    Param(
        [Parameter(Mandatory = $true)][String]  $ServicesRuntimeFqdn,
        [Parameter(Mandatory = $true)][String]  $ServicesRuntimePassword,
        [Parameter(Mandatory = $true)][String]  $vCenterFqdn,
        [Parameter(Mandatory = $false)][String] $vCenterUsername = "administrator@vsphere.local",
        [Parameter(Mandatory = $true)][String]  $vCenterPassword,
        [Parameter(Mandatory = $true)][String]  $TargetDatacenter,
        [Parameter(Mandatory = $true)][String]  $TargetCluster,
        [Parameter(Mandatory = $true)][String]  $TargetDatastore,
        [Parameter(Mandatory = $true)][String]  $TargetDpG,
        [Parameter(Mandatory = $true)][String]  $TargetFolder,
        [Parameter(Mandatory = $false)][String] $TargetRP = "Resources",
        [Parameter(Mandatory = $true)][String]  $TargetTemplate,
        [Parameter(Mandatory = $false)][String] $OutputDir = ".",
        [Parameter(Mandatory = $false)][Switch] $DryRun
    )

    $jumpboxName = hostname
    $StopWatch   = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    # -------------------------------------------------------------------------
    # Pre-requisite: kubectl must be on PATH
    # -------------------------------------------------------------------------
    if (-not (Get-Command kubectl -ErrorAction SilentlyContinue)) {
        LogMessage -type WARNING -message "[$jumpboxName] kubectl not found on PATH. Install kubectl and re-run."
        $StopWatch.Stop(); return
    }

    # =========================================================================
    # Step 1: Connect to vCenter and resolve vSphere inventory MoRef IDs
    # =========================================================================
    LogMessage -type INFO -message "[$jumpboxName] Step 1: Connecting to vCenter $vCenterFqdn"
    $vcConnection  = $null
    $vsphereValues = $null

    try {
        $vcConnection = Connect-VIServer -Server $vCenterFqdn -User $vCenterUsername -Password $vCenterPassword -ErrorAction Stop
        LogMessage -type INFO -message "[$vCenterFqdn] Connected to vCenter"

        LogMessage -type INFO -message "[$vCenterFqdn] Resolving vSphere inventory objects"
        $dc       = Get-Datacenter -Name $TargetDatacenter -ErrorAction Stop
        $cluster  = Get-Cluster    -Name $TargetCluster    -Location $dc      -ErrorAction Stop
        $hosts    = Get-VMHost     -Location $cluster       -ErrorAction Stop
        $ds       = Get-Datastore  -Name $TargetDatastore  -VMHost $hosts     -ErrorAction Stop
        $dvs      = Get-VDSwitch   -VMHost $hosts          -ErrorAction Stop | Select-Object -Unique
        $dpg      = Get-VDPortgroup -Name $TargetDpG       -VDSwitch $dvs     -ErrorAction Stop | Select-Object -First 1
        $folder   = Get-Folder     -Name $TargetFolder     -Type VM -Location $dc -ErrorAction Stop
        $rp       = Get-ResourcePool -Name $TargetRP       -Location $cluster  -ErrorAction Stop
        $template = Get-Template   -Name $TargetTemplate   -Location $folder   -ErrorAction Stop

        LogMessage -type INFO -message "[$vCenterFqdn] All inventory objects resolved"

        # MoRef IDs (Type:Value format expected by the PD)
        $dcId      = "$($dc.ExtensionData.MoRef.Type):$($dc.ExtensionData.MoRef.Value)"
        $clusterId = "$($cluster.ExtensionData.MoRef.Type):$($cluster.ExtensionData.MoRef.Value)"
        $dsId      = "$($ds.ExtensionData.MoRef.Type):$($ds.ExtensionData.MoRef.Value)"
        $dpgId     = "$($dpg.ExtensionData.MoRef.Type):$($dpg.ExtensionData.MoRef.Value)"
        $folderId  = "$($folder.ExtensionData.MoRef.Type):$($folder.ExtensionData.MoRef.Value)"
        $rpId      = "$($rp.ExtensionData.MoRef.Type):$($rp.ExtensionData.MoRef.Value)"
        $tmplId    = "$($template.ExtensionData.MoRef.Type):$($template.ExtensionData.MoRef.Value)"

        # Inventory paths
        $dcPath      = "/$($dc.Name)"
        $clusterPath = "/$($dc.Name)/host/$($cluster.Name)"
        $dsPath      = "/$($dc.Name)/datastore/$($ds.Name)"
        $networkPath = "/$($dc.Name)/network/$($dpg.Name)"
        $folderPath  = "/$($dc.Name)/vm/$($folder.Name)"
        $rpPath      = "$clusterPath/Resources/$($rp.Name)".Replace("/Resources/Resources", "/Resources")

        LogMessage -type INFO -message "[$vCenterFqdn] Datacenter   : $dcPath ($dcId)"
        LogMessage -type INFO -message "[$vCenterFqdn] Cluster      : $clusterPath ($clusterId)"
        LogMessage -type INFO -message "[$vCenterFqdn] Datastore    : $dsPath ($dsId)"
        LogMessage -type INFO -message "[$vCenterFqdn] Network      : $networkPath ($dpgId)"
        LogMessage -type INFO -message "[$vCenterFqdn] Folder       : $folderPath ($folderId)"
        LogMessage -type INFO -message "[$vCenterFqdn] ResourcePool : $rpPath ($rpId)"
        LogMessage -type INFO -message "[$vCenterFqdn] Template     : $TargetTemplate ($tmplId)"

        $vsphereValues = [ordered]@{
            cluster          = $clusterPath
            clusterId        = $clusterId
            datacenter       = $dcPath
            datacenterId     = $dcId
            datastore        = $dsPath
            datastoreId      = $dsId
            datastoreURL     = $ds.ExtensionData.Info.Url
            enriched         = "true"
            folder           = $folderPath
            folderId         = $folderId
            host             = $vCenterFqdn
            insecureTLS      = $false
            network          = $networkPath
            networkId        = $dpgId
            port             = "443"
            resourcePool     = $rpPath
            resourcePoolId   = $rpId
            server           = $vCenterFqdn
            templateFolder   = $folderPath
            templateFolderId = $folderId
            templateId       = $tmplId
        }

    } catch {
        LogMessage -type ERROR -message "[$vCenterFqdn] Failed to resolve vSphere inventory: $_"
        $StopWatch.Stop(); return
    } finally {
        if ($null -ne $vcConnection -and $vcConnection.IsConnected) {
            Disconnect-VIServer -Server $vcConnection -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
            LogMessage -type INFO -message "[$vCenterFqdn] Disconnected from vCenter"
        }
    }

    # =========================================================================
    # Step 2: Retrieve KUBECONFIG from the Services Runtime cluster
    # =========================================================================
    LogMessage -type INFO -message "[$jumpboxName] Step 2: Retrieving kubeconfig from $ServicesRuntimeFqdn"
    $kubeconfigResult = Get-VcfmsServicesRuntimeKubeconfig `
        -ServicesRuntimeFqdn $ServicesRuntimeFqdn `
        -Password            $ServicesRuntimePassword `
        -OutputDir           $OutputDir
    if (-not $kubeconfigResult) {
        LogMessage -type ERROR -message "[$jumpboxName] Could not retrieve kubeconfig. Aborting."
        $StopWatch.Stop(); return
    }
    $resolvedKubeconfig = $kubeconfigResult.KubeconfigPath
    LogMessage -type INFO -message "[$jumpboxName] Kubeconfig written to $resolvedKubeconfig"

    # =========================================================================
    # Step 3: Build merge patch JSON
    # =========================================================================
    $patch = @{ spec = @{ vsphere = $vsphereValues } } | ConvertTo-Json -Depth 5 -Compress

    if ($DryRun) {
        LogMessage -type INFO -message "[$jumpboxName] DRY RUN — patch that would be applied to pd/vmsp-platform:"
        Write-Host ""
        Write-Host ($patch | ConvertFrom-Json | ConvertTo-Json -Depth 5)
        Write-Host ""
        $StopWatch.Stop()
        $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
        return
    }

    # =========================================================================
    # Step 4: Patch pd/vmsp-platform in namespace vmsp-platform
    # =========================================================================
    LogMessage -type INFO -message "[$jumpboxName] Step 3: Patching pd/vmsp-platform in namespace vmsp-platform"
    $patchOutput = & kubectl --kubeconfig $resolvedKubeconfig `
        patch pd vmsp-platform -n vmsp-platform `
        --type=merge -p $patch 2>&1
    $exitCode = $LASTEXITCODE
    $patchOutput | ForEach-Object { Write-Host "  $_" }
    if ($exitCode -eq 0) {
        LogMessage -type INFO -message "[$jumpboxName] pd/vmsp-platform patched successfully"
    } else {
        LogMessage -type ERROR -message "[$jumpboxName] kubectl patch failed (exit $exitCode)"
        $StopWatch.Stop(); return
    }

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Update-ServicesRuntimePackageDeployment

Function Get-VcfmsFleetComponentRegistration {
    <#
    .SYNOPSIS
    Displays the current Fleet LCM routing for all fleet-scoped components.

    .DESCRIPTION
    The Get-VcfmsFleetComponentRegistration cmdlet resolves the Services Runtime control
    plane node, uploads a small inline query script, and executes it under sudo with
    KUBECONFIG=/etc/kubernetes/admin.conf so that kubectl can reach the Fleet LCM DB pods.
    It displays two psql-formatted tables:
      1. Registered SDDC LCM instances
      2. Fleet-scoped component registrations (VIDB, SALT_RAAS, VCF_FLEET_LCM,
         VCF_FLEET_DEPOT, OPS_LOGS) with their current SDDC LCM routing

    Use this to verify the result of Invoke-VcfmsFleetComponentRegistration.

    .EXAMPLE
    Get-VcfmsFleetComponentRegistration -ServicesRuntimeFqdn "lax-sr01.lax.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!"

    .PARAMETER ServicesRuntimeFqdn
    FQDN or IP of any Services Runtime cluster node. The function resolves the control
    plane automatically.

    .PARAMETER ServicesRuntimePassword
    Password for vmware-system-user (SSH login and sudo elevation).
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $ServicesRuntimeFqdn,
        [Parameter(Mandatory = $true)][String] $ServicesRuntimePassword
    )

    $jumpboxName = hostname
    $StopWatch   = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    # Resolve control plane node
    LogMessage -type INFO -message "[$jumpboxName] Resolving control plane node from $ServicesRuntimeFqdn"
    $kubeconfigResult = Get-VcfmsServicesRuntimeKubeconfig `
        -ServicesRuntimeFqdn $ServicesRuntimeFqdn `
        -Password            $ServicesRuntimePassword `
        -OutputDir           "."
    if (-not $kubeconfigResult) {
        LogMessage -type ERROR -message "[$jumpboxName] Could not resolve control plane node. Aborting."
        $StopWatch.Stop(); return
    }
    $controlPlaneHost = $kubeconfigResult.ControlPlaneHost
    LogMessage -type INFO -message "[$jumpboxName] Control plane node: $controlPlaneHost"

    $SecurePassword = ConvertTo-SecureString -String $ServicesRuntimePassword -AsPlainText -Force
    $creds          = New-Object System.Management.Automation.PSCredential ('vmware-system-user', $SecurePassword)
    $session        = $null
    $remotePath     = "/tmp/get_fleet_component_registration.sh"

    # Build the query script using a single-quoted here-string so that bash variables
    # ($pod, $FLEET_DB_POD) and SQL single-quotes are preserved literally.
    # Newlines will be CRLF on Windows; the \r bytes are stripped before encoding below.
    $scriptContent = @'
#!/bin/bash
set -euo pipefail

FLEET_DB_POD=""
for pod in vcf-fleet-lcm-db-0 vcf-fleet-lcm-db-1 vcf-fleet-lcm-db-2; do
  if kubectl exec -n vcf-fleet-lcm "$pod" -c postgres -- \
      psql -U postgres -t -c "SELECT pg_is_in_recovery();" 2>/dev/null | grep -q f; then
    FLEET_DB_POD="$pod"
    break
  fi
done

if [[ -z "$FLEET_DB_POD" ]]; then
  echo "ERROR: No primary Fleet LCM DB pod found" >&2
  exit 1
fi
echo "Fleet LCM primary DB pod: $FLEET_DB_POD"

echo ""
echo "Registered SDDC LCM Instances:"
kubectl exec -n vcf-fleet-lcm "$FLEET_DB_POD" -c postgres -- \
  psql -U postgres -d vcffleetlcmdb -c \
  "SELECT id, fqdn, is_primary, status FROM sddc_lcm ORDER BY is_primary DESC, fqdn;"

echo ""
echo "Fleet-Scoped Component Registrations:"
kubectl exec -n vcf-fleet-lcm "$FLEET_DB_POD" -c postgres -- \
  psql -U postgres -d vcffleetlcmdb -c \
  "SELECT c.component_type AS type, c.fqdn AS component_fqdn, c.version, COALESCE(s.fqdn,'(none)') AS sddc_lcm_fqdn FROM component c LEFT JOIN sddc_lcm s ON c.sddc_lcm_id = s.id WHERE c.component_type IN ('VIDB','SALT_RAAS','VCF_FLEET_LCM','VCF_FLEET_DEPOT','OPS_LOGS') ORDER BY c.component_type;"
'@

    try {
        $session = Open-VcfmsSshSession -Fqdn $controlPlaneHost -Creds $creds

        # Upload — strip \r so Windows CRLF does not break bash (same fix as Invoke-VcfmsFleetComponentRegistration)
        LogMessage -type INFO -message "[$controlPlaneHost] Uploading query script"
        $scriptBytes = [System.Text.Encoding]::UTF8.GetBytes($scriptContent)
        $scriptBytes = [byte[]]($scriptBytes | Where-Object { $_ -ne 0x0D })
        $b64         = [System.Convert]::ToBase64String($scriptBytes)
        $uploadCmd   = "printf '%s' '$b64' | base64 -d > $remotePath && chmod +x $remotePath"
        $uploadResult = Invoke-SSHCommand -SessionId $session.SessionId -Command $uploadCmd -TimeOut 60
        if ($uploadResult.ExitStatus -ne 0) {
            LogMessage -type ERROR -message "[$controlPlaneHost] Script upload failed (exit $($uploadResult.ExitStatus))"
            return
        }

        # Execute under sudo with KUBECONFIG; merge stderr so nothing is silently lost
        $execCmd    = "echo '$ServicesRuntimePassword' | sudo -S env KUBECONFIG=/etc/kubernetes/admin.conf bash $remotePath 2>&1"
        $execResult = Invoke-SSHCommand -SessionId $session.SessionId -Command $execCmd -TimeOut 60

        Write-Host ""
        Write-Host " Fleet Component Registration Status" -ForegroundColor Cyan
        Write-Host " ────────────────────────────────────────────────────────────────────" -ForegroundColor Cyan
        $execResult.Output |
            Where-Object { $_ -notmatch '^\[sudo\]' } |
            ForEach-Object { Write-Host "  $_" }
        Write-Host " ────────────────────────────────────────────────────────────────────" -ForegroundColor Cyan
        Write-Host ""

        if ($execResult.ExitStatus -ne 0) {
            LogMessage -type ERROR -message "[$controlPlaneHost] Query script exited with code $($execResult.ExitStatus)"
        }

    } catch {
        LogMessage -type ERROR -message "[$jumpboxName] $($_.Exception.Message)"
    } finally {
        if ($session) {
            Invoke-SSHCommand -SessionId $session.SessionId -Command "rm -f $remotePath" -TimeOut 15 | Out-Null
            Remove-SSHSession -SSHSession $session | Out-Null
        }
    }

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Get-VcfmsFleetComponentRegistration

Function Invoke-VcfOpsVidbVcfInstanceUpdate {
    <#
    .SYNOPSIS
    Re-associates an external Identity Broker (VIDB) with a new VCF instance in VCF Operations after a disaster recovery failover.

    .DESCRIPTION
    The Invoke-VcfOpsVidbVcfInstanceUpdate cmdlet re-associates an external Identity Broker
    (VIDB) with a new VCF instance in VCF Operations after a disaster recovery failover.

    The function performs two interactive discovery steps before executing the remediation script:

      Step 3 — VCF Instance selection:
        Queries the VCF Operations API (/suite-api/internal/vidb/vidbs) to retrieve all
        registered VCF adapter instances. The results are presented as a numbered list and
        the operator selects which VCF instance the Identity Broker should be re-associated
        with. If -VcfInstanceId is supplied the selection step is skipped.

      Step 4 — SSO Domain selection:
        Queries the kv_vidb_sso_domain table in the VCF Operations postgres database to
        retrieve stale SSO domain entries. The results are presented as a numbered list and
        the operator selects which domain key to remove, or chooses to skip the cleanup.
        If -SsoDomainId is supplied the selection step is skipped.

    The function then uploads the bundled update-vidb-vcf-instance.sh script to the VCF
    Operations primary node via SSH and executes it as root. The script performs:

      1. Acquires an auth token from VCF Operations.
      2. Resolves the management VC GUID for the target VCF instance ID.
      3. Finds the external VIDB record by VIDB hostname.
      4. Fetches and decrypts the VIDB tenant client secret from the local postgres database.
      5. Issues a PUT to update the external VIDB with the new vcGUID and vcfInstanceId.
      6. Updates the adapter collector for the external VIDB adapter.
      7. Polls the eligible VIDB API until the VIDB becomes eligible (20-minute timeout).
      8. Optionally removes the selected stale SSO domain config row from kv_vidb_sso_domain.

    Prerequisites:
      - SSH must be enabled on the VCF Operations primary node.
      - The caller must supply the root password for SSH access.
      - curl, python3, and jq (auto-installed if absent) must be available on the appliance.

    .EXAMPLE
    # Interactive — VCF instance and SSO domain are selected from discovered lists
    Invoke-VcfOpsVidbVcfInstanceUpdate `
        -VcfOpsFqdn          "flt-ops01a.rainpole.io" `
        -VcfOpsRootPassword  "VMw@re1!VMw@re1!" `
        -VcfOpsAdminPassword "VMw@re1!VMw@re1!" `
        -VidbFqdn            "flt-idb01.rainpole.io"

    .EXAMPLE
    # Non-interactive — VCF instance and SSO domain ID supplied directly
    Invoke-VcfOpsVidbVcfInstanceUpdate `
        -VcfOpsFqdn          "flt-ops01a.rainpole.io" `
        -VcfOpsRootPassword  "VMw@re1!VMw@re1!" `
        -VcfOpsAdminPassword "VMw@re1!VMw@re1!" `
        -VidbFqdn            "flt-idb01.rainpole.io" `
        -VcfInstanceId       "e1855511-d704-49ea-8caa-a45895dd0137" `
        -SsoDomainId         "8aa85146-c6ef-4758-9346-4957e4a67dc4"

    .PARAMETER VcfOpsFqdn
    FQDN of the VCF Operations primary node. SSH is opened to this host as root.

    .PARAMETER VcfOpsRootPassword
    Root password for SSH access to the VCF Operations primary node.

    .PARAMETER VcfOpsAdminPassword
    Password for the VCF Operations admin user. Used to acquire an API token for discovery
    queries and passed to the remote script.

    .PARAMETER VcfOpsAdminUsername
    Username for the VCF Operations API. Default is "admin".

    .PARAMETER VidbFqdn
    FQDN of the external Identity Broker (VIDB), e.g. "flt-idb01.rainpole.io".

    .PARAMETER VcfInstanceId
    Optional. UUID of the new VCF instance to associate with the Identity Broker. When
    omitted the function queries the VCF Operations API and presents a numbered list for
    interactive selection.

    .PARAMETER SsoDomainId
    Optional. UUID key to remove from the kv_vidb_sso_domain table. When omitted the
    function queries the postgres database and presents a numbered list for interactive
    selection. Choose "S" at the prompt to skip the SSO domain cleanup entirely.

    .PARAMETER RemoteScriptTimeout
    Seconds to wait for the remote script to complete. Default is 1500 (25 minutes) to
    accommodate the built-in 20-minute VIDB eligibility poll.
    #>

    Param(
        [Parameter(Mandatory = $true)][String]  $VcfOpsFqdn,
        [Parameter(Mandatory = $true)][String]  $VcfOpsRootPassword,
        [Parameter(Mandatory = $true)][String]  $VcfOpsAdminPassword,
        [Parameter(Mandatory = $false)][String] $VcfOpsAdminUsername = "admin",
        [Parameter(Mandatory = $true)][String]  $VidbFqdn,
        [Parameter(Mandatory = $false)][String] $VcfInstanceId,
        [Parameter(Mandatory = $false)][String] $SsoDomainId,
        [Parameter(Mandatory = $false)][Int]    $RemoteScriptTimeout = 1500
    )

    $jumpboxName = hostname
    $StopWatch   = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] VCF Ops Host   : $VcfOpsFqdn"
    LogMessage -type INFO -message "[$jumpboxName] VIDB Host      : $VidbFqdn"

    # -------------------------------------------------------------------------
    # Validate the local script exists
    # -------------------------------------------------------------------------
    $localScript = Join-Path -Path $PSScriptRoot -ChildPath "scripts/9.1.0/update-vidb-vcf-instance.sh"
    if (-not (Test-Path $localScript)) {
        LogMessage -type ERROR -message "[$jumpboxName] Script not found: $localScript"
        $StopWatch.Stop(); return
    }

    # -------------------------------------------------------------------------
    # Verify SSH (TCP/22) is reachable on the VCF Operations node before
    # attempting to open a session — gives an actionable error message when
    # SSH has not been enabled on the appliance.
    # -------------------------------------------------------------------------
    LogMessage -type INFO -message "[$jumpboxName] Checking SSH reachability on $VcfOpsFqdn port 22"
    $sshCheck = Test-NetConnection -ComputerName $VcfOpsFqdn -Port 22 -WarningAction SilentlyContinue
    if (-not $sshCheck.TcpTestSucceeded) {
        LogMessage -type ERROR -message "[$jumpboxName] SSH (TCP/22) is not reachable on $VcfOpsFqdn"
        LogMessage -type ERROR -message "[$jumpboxName] Enable SSH on the VCF Operations appliance before retrying:"
        LogMessage -type ERROR -message "[$jumpboxName]   1. Log in to the VCF Operations management UI at https://$VcfOpsFqdn"
        LogMessage -type ERROR -message "[$jumpboxName]   2. Navigate to Administration > Support > SSH Service"
        LogMessage -type ERROR -message "[$jumpboxName]   3. Enable the SSH service, then re-run this function"
        $StopWatch.Stop(); return
    }
    LogMessage -type INFO -message "[$jumpboxName] SSH is reachable on $VcfOpsFqdn"

    # -------------------------------------------------------------------------
    # Open SSH session to the VCF Operations primary node as root
    # -------------------------------------------------------------------------
    $SecurePassword = ConvertTo-SecureString -String $VcfOpsRootPassword -AsPlainText -Force
    $creds          = New-Object System.Management.Automation.PSCredential ('root', $SecurePassword)
    $remotePath     = "/tmp/update-vidb-vcf-instance.sh"
    $session        = $null

    try {
        $session = Open-VcfmsSshSession -Fqdn $VcfOpsFqdn -Creds $creds

        # =====================================================================
        # Step 3 — Interactive VCF Instance selection
        #   Query GET /suite-api/internal/vidb/vidbs for all registered VCF
        #   adapter instances and present a numbered list. The operator selects
        #   the VCF instance the Identity Broker should be re-associated with.
        #   Skipped when -VcfInstanceId is supplied directly.
        # =====================================================================
        if (-not $VcfInstanceId) {
            LogMessage -type INFO -message "[$VcfOpsFqdn] Step 3: Querying VCF adapter instances from VCF Operations API"

            # Acquire a short-lived token for the discovery query
            $tokenUri  = "https://$VcfOpsFqdn/suite-api/api/auth/token/acquire"
            $tokenBody = @{ username = $VcfOpsAdminUsername; password = $VcfOpsAdminPassword } | ConvertTo-Json -Compress
            try {
                $tokenResp = Invoke-RestMethod -Uri $tokenUri -Method POST -Body $tokenBody `
                    -ContentType "application/json" -SkipCertificateCheck
            } catch {
                LogMessage -type ERROR -message "[$VcfOpsFqdn] Failed to acquire VCF Operations API token: $($_.Exception.Message)"
                $StopWatch.Stop(); return
            }
            $apiToken = $tokenResp.token
            if (-not $apiToken) {
                LogMessage -type ERROR -message "[$VcfOpsFqdn] VCF Operations API token was empty. Check credentials."
                $StopWatch.Stop(); return
            }

            $vidbsUri  = "https://$VcfOpsFqdn/suite-api/internal/vidb/vidbs"
            $apiHeaders = @{
                "Authorization"                  = "vRealizeOpsToken $apiToken"
                "x-vrealizeops-api-use-unsupported" = "true"
                "Accept"                         = "application/json"
            }
            try {
                $vidbsResp = Invoke-RestMethod -Uri $vidbsUri -Method GET -Headers $apiHeaders -SkipCertificateCheck
            } catch {
                LogMessage -type ERROR -message "[$VcfOpsFqdn] Failed to query VCF adapter instances: $($_.Exception.Message)"
                $StopWatch.Stop(); return
            }

            $vcfInstances = @($vidbsResp | Where-Object { $_.vcfInstanceId -and $_.fqdn })
            if ($vcfInstances.Count -eq 0) {
                LogMessage -type ERROR -message "[$VcfOpsFqdn] No VCF adapter instances were returned by the API."
                $StopWatch.Stop(); return
            }

            # Build and display numbered selection table
            $vcfInstanceTable = @()
            $vcfInstanceTable += [pscustomobject]@{ ID = "ID"; VCFInstanceId = "VCF Instance ID"; FQDN = "FQDN"; Type = "Type"; ResourceName = "Resource Name" }
            $vcfInstanceTable += [pscustomobject]@{ ID = "--"; VCFInstanceId = "------------------------------------"; FQDN = "----"; Type = "--------"; ResourceName = "-------------" }
            $idx = 1
            foreach ($inst in $vcfInstances) {
                $vcfInstanceTable += [pscustomobject]@{
                    ID           = $idx
                    VCFInstanceId = $inst.vcfInstanceId
                    FQDN         = $inst.fqdn
                    Type         = $inst.deploymentType
                    ResourceName = $inst.vcfResourceName
                }
                $idx++
            }

            Write-Host ""
            Write-Host " Step 3: Select the VCF instance to associate with the Identity Broker" -ForegroundColor Cyan
            Write-Host ""
            $vcfInstanceTable | Format-Table -Property @{Expression = " "}, ID, VCFInstanceId, FQDN, Type, ResourceName -AutoSize -HideTableHeaders |
                Out-String | ForEach-Object { $_.Trim("`r", "`n") }

            $validIds = 1..($vcfInstances.Count) | ForEach-Object { "$_" }
            Do {
                Write-Host ""
                Write-Host " Enter the ID of the VCF instance to use, or C to Cancel: " -ForegroundColor Yellow -NoNewline
                $vcfInstanceSelection = Read-Host
            } Until (($vcfInstanceSelection -in $validIds) -or ($vcfInstanceSelection -ieq "C"))

            if ($vcfInstanceSelection -ieq "C") {
                LogMessage -type INFO -message "[$jumpboxName] Operation cancelled by user at VCF instance selection."
                $StopWatch.Stop(); return
            }

            $VcfInstanceId = $vcfInstances[$vcfInstanceSelection - 1].vcfInstanceId
            LogMessage -type INFO -message "[$VcfOpsFqdn] Selected VCF Instance ID : $VcfInstanceId"
        } else {
            LogMessage -type INFO -message "[$VcfOpsFqdn] Step 3: Using supplied VCF Instance ID : $VcfInstanceId"
        }

        # =====================================================================
        # Step 4 — Interactive SSO Domain selection
        #   Query kv_vidb_sso_domain in the VCF Operations postgres database via
        #   SSH and present a numbered list. The operator selects the stale SSO
        #   domain key to remove, or enters S to skip the cleanup entirely.
        #   Skipped when -SsoDomainId is supplied directly.
        # =====================================================================
        if (-not $SsoDomainId) {
            LogMessage -type INFO -message "[$VcfOpsFqdn] Step 4: Querying kv_vidb_sso_domain table in VCF Operations database"

            $psql    = '/opt/vmware/vpostgres/current/bin/psql -p 5433 -d vcopsdb -t -A'
            $ssoSql  = "SELECT key, name, vidb_resource_id, vcf_instance_id FROM kv_vidb_sso_domain;"
            $ssoCmd  = "su - postgres -c `"$psql -c '$ssoSql'`""
            $ssoResult = Invoke-SSHCommand -SessionId $session.SessionId -Command $ssoCmd -TimeOut 30

            $ssoDomainRows = @()
            if ($ssoResult.ExitStatus -eq 0 -and $ssoResult.Output) {
                foreach ($line in ($ssoResult.Output | Where-Object { $_ -match '\S' })) {
                    $parts = $line -split '\|'
                    if ($parts.Count -ge 4) {
                        $ssoDomainRows += [pscustomobject]@{
                            Key            = $parts[0].Trim()
                            Name           = $parts[1].Trim()
                            VidbResourceId = $parts[2].Trim()
                            VcfInstanceId  = $parts[3].Trim()
                        }
                    }
                }
            }

            if ($ssoDomainRows.Count -eq 0) {
                LogMessage -type INFO -message "[$VcfOpsFqdn] No rows found in kv_vidb_sso_domain — SSO domain cleanup will be skipped."
            } else {
                # Build and display numbered selection table
                $ssoTable = @()
                $ssoTable += [pscustomobject]@{ ID = "ID"; Key = "Key (SSO Domain ID)"; Name = "Name"; VidbResourceId = "VIDB Resource ID"; VcfInstanceId = "VCF Instance ID" }
                $ssoTable += [pscustomobject]@{ ID = "--"; Key = "------------------------------------"; Name = "----"; VidbResourceId = "------------------------------------"; VcfInstanceId = "------------------------------------" }
                $idx = 1
                foreach ($row in $ssoDomainRows) {
                    $ssoTable += [pscustomobject]@{
                        ID            = $idx
                        Key           = $row.Key
                        Name          = $row.Name
                        VidbResourceId = $row.VidbResourceId
                        VcfInstanceId  = $row.VcfInstanceId
                    }
                    $idx++
                }

                Write-Host ""
                Write-Host " Step 4: Select the stale SSO domain entry to remove from kv_vidb_sso_domain" -ForegroundColor Cyan
                Write-Host ""
                $ssoTable | Format-Table -Property @{Expression = " "}, ID, Key, Name, VidbResourceId, VcfInstanceId -AutoSize -HideTableHeaders |
                    Out-String | ForEach-Object { $_.Trim("`r", "`n") }

                $validSsoIds = 1..($ssoDomainRows.Count) | ForEach-Object { "$_" }
                Do {
                    Write-Host ""
                    Write-Host " Enter the ID of the SSO domain entry to remove, S to Skip, or C to Cancel: " -ForegroundColor Yellow -NoNewline
                    $ssoSelection = Read-Host
                } Until (($ssoSelection -in $validSsoIds) -or ($ssoSelection -ieq "S") -or ($ssoSelection -ieq "C"))

                if ($ssoSelection -ieq "C") {
                    LogMessage -type INFO -message "[$jumpboxName] Operation cancelled by user at SSO domain selection."
                    $StopWatch.Stop(); return
                }

                if ($ssoSelection -ieq "S") {
                    LogMessage -type INFO -message "[$VcfOpsFqdn] SSO domain cleanup skipped by user."
                } else {
                    $SsoDomainId = $ssoDomainRows[$ssoSelection - 1].Key
                    LogMessage -type INFO -message "[$VcfOpsFqdn] Selected SSO Domain ID : $SsoDomainId"
                }
            }
        } else {
            LogMessage -type INFO -message "[$VcfOpsFqdn] Step 4: Using supplied SSO Domain ID : $SsoDomainId"
        }

        # -------------------------------------------------------------------------
        # Upload the script via base64 pipe — avoids any SCP binary dependency
        # -------------------------------------------------------------------------
        LogMessage -type INFO -message "[$VcfOpsFqdn] Uploading script to $remotePath"
        $scriptBytes = [System.IO.File]::ReadAllBytes($localScript)
        # Strip CR bytes so the file always has Unix line endings on the remote node
        $scriptBytes = [byte[]]($scriptBytes | Where-Object { $_ -ne 0x0D })
        $b64         = [System.Convert]::ToBase64String($scriptBytes)

        $uploadCmd    = "printf '%s' '$b64' | base64 -d > $remotePath && chmod +x $remotePath"
        $uploadResult = Invoke-SSHCommand -SessionId $session.SessionId -Command $uploadCmd -TimeOut 60
        if ($uploadResult.ExitStatus -ne 0) {
            LogMessage -type ERROR -message "[$VcfOpsFqdn] Script upload failed (exit $($uploadResult.ExitStatus)): $($uploadResult.Error -join ' ')"
            return
        }
        LogMessage -type INFO -message "[$VcfOpsFqdn] Script uploaded successfully"

        # -------------------------------------------------------------------------
        # Build and execute the remote command
        # The script must run as root (already the SSH user); passwords with special
        # characters are passed as environment variables to avoid shell quoting issues.
        # -------------------------------------------------------------------------
        $scriptArgs = "--ops-host '$VcfOpsFqdn' --username '$VcfOpsAdminUsername' --password `$VCF_OPS_ADMIN_PASSWORD --vcf-id '$VcfInstanceId' --vidb-host '$VidbFqdn'"
        if ($SsoDomainId) {
            $scriptArgs += " --sso-domain-id '$SsoDomainId'"
        }

        $execCmd = "export VCF_OPS_ADMIN_PASSWORD='$VcfOpsAdminPassword'; bash $remotePath $scriptArgs 2>&1"

        LogMessage -type INFO -message "[$VcfOpsFqdn] Executing update-vidb-vcf-instance.sh (timeout: ${RemoteScriptTimeout}s)"
        Write-Host ""
        Write-Host " ── update-vidb-vcf-instance.sh output ──────────────────────────────" -ForegroundColor Cyan

        $execResult = Invoke-SSHCommand -SessionId $session.SessionId -Command $execCmd -TimeOut $RemoteScriptTimeout

        $execResult.Output | ForEach-Object { Write-Host "  $_" }

        if ($execResult.Error) {
            (($execResult.Error -join "`n") -split "`r?`n") |
                Where-Object { $_ -ne '' } |
                ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
        }

        Write-Host " ────────────────────────────────────────────────────────────────────" -ForegroundColor Cyan
        Write-Host ""

        if ($execResult.ExitStatus -eq 0) {
            LogMessage -type INFO -message "[$VcfOpsFqdn] Script completed successfully"
        } else {
            LogMessage -type ERROR -message "[$VcfOpsFqdn] Script exited with code $($execResult.ExitStatus)"
        }

    } catch {
        LogMessage -type ERROR -message "[$jumpboxName] $($_.Exception.Message)"
    } finally {
        if ($session) {
            Invoke-SSHCommand -SessionId $session.SessionId `
                -Command "rm -f $remotePath" -TimeOut 15 | Out-Null
            Remove-SSHSession -SSHSession $session | Out-Null
            LogMessage -type INFO -message "[$VcfOpsFqdn] Temporary script removed"
        }
    }

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Invoke-VcfOpsVidbVcfInstanceUpdate

Function Install-VcfaMigrationServiceEngine {
    <#
    .SYNOPSIS
    Stages and installs the Migration Service Engine component on a VCF Automation Services Runtime cluster.

    .DESCRIPTION
    The Install-VcfaMigrationServiceEngine cmdlet stages and installs the Migration Service Engine
    on a VCF Automation Services Runtime cluster. The Migration Service Engine is not captured in
    VCF Automation backups and must be reinstalled after a restore. The cmdlet performs three steps:

      1. Acquires an access token from the VCF Automation Services Runtime API.
      2. Stages the migration-service binary via POST /api/v1/components?action=stage, then
         polls GET /api/v1/tasks/{taskId} until the stage task reaches a terminal state.
      3. Installs the migration-service component via POST /api/v1/components?action=install,
         then polls GET /api/v1/tasks/{taskId} until the install task reaches a terminal state.

    .EXAMPLE
    # Stage and install using default version
    Install-VcfaMigrationServiceEngine `
        -VcfaServiceRuntimeFqdn     "flt-vcfa-sr01.rainpole.io" `
        -VcfaServiceRuntimePassword "VMw@re1!VMw@re1!" `
        -RepositoryUrl              "https://depot.rainpole.io/package-pool/depot-manifest-migration-service-9.1.0.0.25370929.yaml"

    .EXAMPLE
    # Supply a specific version and offline depot manifest URL
    Install-VcfaMigrationServiceEngine `
        -VcfaServiceRuntimeFqdn     "flt-vcfa-sr01.rainpole.io" `
        -VcfaServiceRuntimePassword "VMw@re1!VMw@re1!" `
        -Version                    "9.1.0.0.25370929" `
        -RepositoryUrl              "https://depot.rainpole.io/package-pool/depot-manifest-migration-service-9.1.0.0.25370929.yaml"

    .PARAMETER VcfaServiceRuntimeFqdn
    FQDN of the VCF Automation Services Runtime cluster, e.g. "flt-vcfa-sr01.rainpole.io".

    .PARAMETER VcfaServiceRuntimePassword
    Password for the VCF Automation Services Runtime admin user.

    .PARAMETER VcfaServiceRuntimeUsername
    Username for the token request. Default is "admin@vsp.local".

    .PARAMETER Version
    Version string for the migration-service component to stage and install.
    Default is "9.1.0.0.25370929".

    .PARAMETER RepositoryUrl
    URL to the depot manifest YAML for the migration-service version being staged. This must
    point to an accessible depot — either an offline/air-gapped depot mirror or an
    internal update repository. No default is provided; this parameter is required.

    .PARAMETER InstallSize
    Deployment size for the Migration Service Engine. Default is "small".

    .PARAMETER StagePollIntervalSeconds
    Interval in seconds between task status polls during the stage operation. Default is 30.

    .PARAMETER InstallPollIntervalSeconds
    Interval in seconds between task status polls during the install operation. Default is 30.
    #>

    Param(
        [Parameter(Mandatory = $true)][String]  $VcfaServiceRuntimeFqdn,
        [Parameter(Mandatory = $true)][String]  $VcfaServiceRuntimePassword,
        [Parameter(Mandatory = $false)][String] $VcfaServiceRuntimeUsername = "admin@vsp.local",
        [Parameter(Mandatory = $false)][String] $Version = "9.1.0.0.25370929",
        [Parameter(Mandatory = $true)][String]  $RepositoryUrl,
        [Parameter(Mandatory = $false)][String] $InstallSize = "small",
        [Parameter(Mandatory = $false)][Int]    $StagePollIntervalSeconds = 30,
        [Parameter(Mandatory = $false)][Int]    $InstallPollIntervalSeconds = 30
    )

    $jumpboxName    = hostname
    $StopWatch      = New-Object -TypeName System.Diagnostics.Stopwatch
    $terminalStates = @("COMPLETED","Completed","COMPLETE","FAILED","CANCELLED","ERROR","SUCCESS","SUCCESSFUL","Succeeded","Failed")
    $StopWatch.Start()
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] VCFA Services Runtime    : $VcfaServiceRuntimeFqdn"
    LogMessage -type INFO -message "[$jumpboxName] Migration Service version : $Version"
    LogMessage -type INFO -message "[$jumpboxName] Install size              : $InstallSize"

    # -------------------------------------------------------------------------
    # Step 1: Acquire VCFA Services Runtime token
    # The VCFA SR uses the same /api/v1/identity/token endpoint as VCFMS SR.
    # -------------------------------------------------------------------------
    $srToken = Get-VcfmsServicesRuntimeToken `
        -ServicesRuntimeFqdn $VcfaServiceRuntimeFqdn `
        -Username            $VcfaServiceRuntimeUsername `
        -Password            $VcfaServiceRuntimePassword
    if (-not $srToken) {
        LogMessage -type ERROR -message "[$VcfaServiceRuntimeFqdn] Unable to obtain VCFA Services Runtime token. Aborting."
        $StopWatch.Stop(); return
    }
    $tokenFetchedAt = [DateTime]::UtcNow
    $headers = @{
        "Authorization" = "Bearer $srToken"
        "Accept"        = "application/json"
        "Content-Type"  = "application/json"
    }

    # -------------------------------------------------------------------------
    # Helper: refresh token if approaching the 60-minute expiry
    # -------------------------------------------------------------------------
    $refreshToken = {
        if (([DateTime]::UtcNow - $tokenFetchedAt).TotalMinutes -ge 60) {
            LogMessage -type INFO -message "[$VcfaServiceRuntimeFqdn] Token age >= 60 minutes; refreshing"
            $newToken = Get-VcfmsServicesRuntimeToken `
                -ServicesRuntimeFqdn $VcfaServiceRuntimeFqdn `
                -Username            $VcfaServiceRuntimeUsername `
                -Password            $VcfaServiceRuntimePassword
            if ($newToken) {
                $script:srToken                  = $newToken
                $script:headers["Authorization"] = "Bearer $newToken"
                $script:tokenFetchedAt           = [DateTime]::UtcNow
            } else {
                LogMessage -type WARNING -message "[$VcfaServiceRuntimeFqdn] Token refresh failed; continuing with existing token"
            }
        }
    }

    # -------------------------------------------------------------------------
    # Step 2: Stage the migration-service binary
    # -------------------------------------------------------------------------
    LogMessage -type INFO -message "[$VcfaServiceRuntimeFqdn] Staging migration-service $Version"

    $stageBody = @{
        type       = "migration-service"
        version    = $Version
        repository = @{
            url = $RepositoryUrl
        }
        options    = @{
            timeout = "30m"
        }
    } | ConvertTo-Json -Depth 5

    try {
        $stageResponse = Invoke-RestMethod `
            -Uri    "https://$VcfaServiceRuntimeFqdn/api/v1/components?action=stage" `
            -Method POST -Headers $headers -Body $stageBody -SkipCertificateCheck
    } catch {
        LogMessage -type ERROR -message "[$VcfaServiceRuntimeFqdn] Stage request failed: $($_.Exception.Message)"
        $StopWatch.Stop(); return
    }

    $stageTaskId = $stageResponse.id
    if (-not $stageTaskId) {
        LogMessage -type ERROR -message "[$VcfaServiceRuntimeFqdn] No task ID returned from stage response."
        $StopWatch.Stop(); return
    }
    LogMessage -type INFO -message "[$VcfaServiceRuntimeFqdn] Stage task created: $stageTaskId"

    # Poll stage task
    LogMessage -type INFO -message "[$VcfaServiceRuntimeFqdn] Polling stage task $stageTaskId every ${StagePollIntervalSeconds}s"
    $elapsed      = 0
    $taskStatus   = "UNKNOWN"
    $taskResponse = $null
    Do {
        Start-Sleep -Seconds $StagePollIntervalSeconds
        $elapsed += $StagePollIntervalSeconds
        & $refreshToken
        try {
            $taskResponse = Invoke-RestMethod `
                -Uri    "https://$VcfaServiceRuntimeFqdn/api/v1/tasks/$stageTaskId" `
                -Method GET -Headers $headers -SkipCertificateCheck
            $rawSt = $taskResponse.status
            $rawPh = $taskResponse.phase
            if (-not [string]::IsNullOrWhiteSpace([string]$rawSt)) {
                $taskStatus = [string]$rawSt
            } elseif (-not [string]::IsNullOrWhiteSpace([string]$rawPh)) {
                $taskStatus = [string]$rawPh
            } else {
                $taskStatus = "UNKNOWN"
            }
        } catch {
            LogMessage -type WARNING -message "[$VcfaServiceRuntimeFqdn] Poll error (will retry): $($_.Exception.Message)"
            $taskStatus = "UNKNOWN"
        }
        LogMessage -type INFO -message "[$VcfaServiceRuntimeFqdn] Stage task $stageTaskId status=$taskStatus (${elapsed}s elapsed)"
    } While ($taskStatus -notin $terminalStates)

    $successStates = @("COMPLETED","Completed","COMPLETE","SUCCESS","SUCCESSFUL","Succeeded")
    if ($taskStatus -notin $successStates) {
        LogMessage -type ERROR -message "[$VcfaServiceRuntimeFqdn] Stage task ended with status: $taskStatus"
        if ($taskResponse -and $taskResponse.description.localizedMessage) {
            LogMessage -type ERROR -message "[$VcfaServiceRuntimeFqdn] $($taskResponse.description.localizedMessage)"
        }
        $StopWatch.Stop(); return
    }
    LogMessage -type INFO -message "[$VcfaServiceRuntimeFqdn] Migration Service Engine staged successfully"

    # -------------------------------------------------------------------------
    # Step 3: Install the migration-service component
    # -------------------------------------------------------------------------
    LogMessage -type INFO -message "[$VcfaServiceRuntimeFqdn] Installing migration-service $Version (size: $InstallSize)"

    $installBody = @{
        type    = "vcd-migrator"
        version = $Version
        spec    = @{
            configuration = @{
                size = $InstallSize
            }
        }
        options = @{
            timeout       = "60m"
            prechecksOnly = $false
        }
    } | ConvertTo-Json -Depth 5

    try {
        $installResponse = Invoke-RestMethod `
            -Uri    "https://$VcfaServiceRuntimeFqdn/api/v1/components?action=install" `
            -Method POST -Headers $headers -Body $installBody -SkipCertificateCheck
    } catch {
        LogMessage -type ERROR -message "[$VcfaServiceRuntimeFqdn] Install request failed: $($_.Exception.Message)"
        $StopWatch.Stop(); return
    }

    $installTaskId = $installResponse.id
    if (-not $installTaskId) {
        LogMessage -type ERROR -message "[$VcfaServiceRuntimeFqdn] No task ID returned from install response."
        $StopWatch.Stop(); return
    }
    LogMessage -type INFO -message "[$VcfaServiceRuntimeFqdn] Install task created: $installTaskId"

    # Poll install task
    LogMessage -type INFO -message "[$VcfaServiceRuntimeFqdn] Polling install task $installTaskId every ${InstallPollIntervalSeconds}s"
    $elapsed      = 0
    $taskStatus   = "UNKNOWN"
    $taskResponse = $null
    Do {
        Start-Sleep -Seconds $InstallPollIntervalSeconds
        $elapsed += $InstallPollIntervalSeconds
        & $refreshToken
        try {
            $taskResponse = Invoke-RestMethod `
                -Uri    "https://$VcfaServiceRuntimeFqdn/api/v1/tasks/$installTaskId" `
                -Method GET -Headers $headers -SkipCertificateCheck
            $rawSt = $taskResponse.status
            $rawPh = $taskResponse.phase
            if (-not [string]::IsNullOrWhiteSpace([string]$rawSt)) {
                $taskStatus = [string]$rawSt
            } elseif (-not [string]::IsNullOrWhiteSpace([string]$rawPh)) {
                $taskStatus = [string]$rawPh
            } else {
                $taskStatus = "UNKNOWN"
            }
        } catch {
            LogMessage -type WARNING -message "[$VcfaServiceRuntimeFqdn] Poll error (will retry): $($_.Exception.Message)"
            $taskStatus = "UNKNOWN"
        }
        LogMessage -type INFO -message "[$VcfaServiceRuntimeFqdn] Install task $installTaskId status=$taskStatus (${elapsed}s elapsed)"
    } While ($taskStatus -notin $terminalStates)

    if ($taskStatus -notin $successStates) {
        LogMessage -type ERROR -message "[$VcfaServiceRuntimeFqdn] Install task ended with status: $taskStatus"
        if ($taskResponse -and $taskResponse.description.localizedMessage) {
            LogMessage -type ERROR -message "[$VcfaServiceRuntimeFqdn] $($taskResponse.description.localizedMessage)"
        }
        $StopWatch.Stop(); return
    }
    LogMessage -type INFO -message "[$VcfaServiceRuntimeFqdn] Migration Service Engine installed successfully"

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Install-VcfaMigrationServiceEngine

Function Remove-VcfmsRecoveredComponents {
    <#
    .SYNOPSIS
    Cleans up recovered fleet components from a VCF Management Services instance on the recovery site.

    .DESCRIPTION
    The Remove-VcfmsRecoveredComponents cmdlet performs the cleanup of recovered fleet components
    from a VCFMS Services Runtime cluster as part of the failback preparation process. It connects
    to the control plane node via SSH and runs two cleanup operations:

      Step 1a — Delete component resources from Kubernetes:
        kubectl delete component ops-logs salt-raas vidb vcf-fleet-depot vcf-fleet-lcm

      Step 1b — Remove matching rows from the vcf-sddc-lcm postgres database:
        kubectl exec vcf-sddc-lcm-db-0 ... psql DELETE FROM component WHERE component_type IN (...)
        kubectl exec vcf-sddc-lcm-db-1 ... psql DELETE FROM component WHERE component_type IN (...)

        Only one of the two database pods (db-0, db-1) is active at any given time — the command
        against the standby pod will fail. Both are attempted and the failure of either is treated
        as expected; the cmdlet reports which succeeded and which failed without aborting.

    The kubeconfig is resolved in this order:
      1. -KubeconfigPath if supplied
      2. Auto-retrieved from the Services Runtime node via Get-VcfmsServicesRuntimeKubeconfig
         when -ServicesRuntimeFqdn and -ServicesRuntimePassword are supplied

    .EXAMPLE
    # Auto-retrieve kubeconfig
    Remove-VcfmsRecoveredComponents `
        -ServicesRuntimeFqdn     "lax-sr01.lax.rainpole.io" `
        -ServicesRuntimePassword "VMw@re1!VMw@re1!"

    .EXAMPLE
    # Use an existing kubeconfig
    Remove-VcfmsRecoveredComponents `
        -ServicesRuntimeFqdn     "lax-sr01.lax.rainpole.io" `
        -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
        -KubeconfigPath          "C:\kubeconfigs\lax-sr01.kubeconfig"

    .PARAMETER ServicesRuntimeFqdn
    FQDN or IP of any Services Runtime cluster node. If a worker node is supplied the function
    automatically resolves and connects to the control plane.

    .PARAMETER ServicesRuntimePassword
    Password for vmware-system-user (SSH login and sudo elevation).

    .PARAMETER KubeconfigPath
    Optional. Path to an existing kubeconfig for the Services Runtime cluster. Takes precedence
    over automatic retrieval.

    .PARAMETER KubeconfigOutputDir
    Directory where the auto-retrieved kubeconfig is written. Defaults to the current directory.
    #>

    Param(
        [Parameter(Mandatory = $true)][String]  $ServicesRuntimeFqdn,
        [Parameter(Mandatory = $true)][String]  $ServicesRuntimePassword,
        [Parameter(Mandatory = $false)][String] $KubeconfigPath,
        [Parameter(Mandatory = $false)][String] $KubeconfigOutputDir = "."
    )

    $jumpboxName = hostname
    $StopWatch   = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    LogMessage -type INFO -message "[$jumpboxName] Services Runtime : $ServicesRuntimeFqdn"

    # -------------------------------------------------------------------------
    # Resolve kubeconfig
    # -------------------------------------------------------------------------
    $resolvedKubeconfig = $KubeconfigPath
    if (-not $resolvedKubeconfig) {
        LogMessage -type INFO -message "[$jumpboxName] Retrieving kubeconfig from $ServicesRuntimeFqdn"
        $kubeconfigResult = Get-VcfmsServicesRuntimeKubeconfig `
            -ServicesRuntimeFqdn $ServicesRuntimeFqdn `
            -Password            $ServicesRuntimePassword `
            -OutputDir           $KubeconfigOutputDir
        if (-not $kubeconfigResult) {
            LogMessage -type ERROR -message "[$jumpboxName] Could not retrieve kubeconfig. Aborting."
            $StopWatch.Stop(); return
        }
        $resolvedKubeconfig = $kubeconfigResult.KubeconfigPath
        $controlPlaneHost   = $kubeconfigResult.ControlPlaneHost
    } else {
        LogMessage -type INFO -message "[$jumpboxName] Using supplied kubeconfig: $resolvedKubeconfig"
        $controlPlaneHost = $ServicesRuntimeFqdn
    }
    LogMessage -type INFO -message "[$jumpboxName] Control plane node : $controlPlaneHost"
    LogMessage -type INFO -message "[$jumpboxName] Kubeconfig         : $resolvedKubeconfig"

    # -------------------------------------------------------------------------
    # Step 1a: Delete the recovered component resources from Kubernetes
    # -------------------------------------------------------------------------
    $components = "ops-logs", "salt-raas", "vidb", "vcf-fleet-depot", "vcf-fleet-lcm"
    $componentList = $components -join " "
    LogMessage -type INFO -message "[$controlPlaneHost] Step 1a: Deleting component resources: $componentList"

    $deleteOutput = & kubectl --kubeconfig $resolvedKubeconfig delete component @components 2>&1
    $deleteExit   = $LASTEXITCODE

    $deleteOutput | ForEach-Object { Write-Host "   $_" }

    if ($deleteExit -eq 0) {
        LogMessage -type INFO -message "[$controlPlaneHost] Component resources deleted successfully"
    } else {
        LogMessage -type WARNING -message "[$controlPlaneHost] kubectl delete exited with code $deleteExit — resources may have already been removed"
    }

    # -------------------------------------------------------------------------
    # Step 1b: Remove rows from the vcf-sddc-lcm postgres database
    # Both db-0 and db-1 are attempted. Only one pod will be active; the
    # command against the standby is expected to fail and is handled gracefully.
    # -------------------------------------------------------------------------
    $deleteTypes = "DELETE FROM component WHERE component_type IN ('VIDB', 'OPS_LOGS', 'SALT_RAAS', 'VCF_FLEET_LCM', 'VCF_FLEET_DEPOT');"
    $dbPods      = @("vcf-sddc-lcm-db-0", "vcf-sddc-lcm-db-1")

    foreach ($dbPod in $dbPods) {
        LogMessage -type INFO -message "[$controlPlaneHost] Step 1b: Running DELETE on $dbPod"
        try {
            # -i (no -t): non-interactive stdin; -- separates kubectl args from container command
            $dbOutput = & kubectl --kubeconfig $resolvedKubeconfig exec $dbPod `
                -n vcf-sddc-lcm -i -- psql -U postgres -d vcfsddclcmdb -c $deleteTypes 2>&1
            $dbExit = $LASTEXITCODE

            if ($dbOutput) { $dbOutput | ForEach-Object { Write-Host "   $_" } }

            if ($dbExit -eq 0) {
                LogMessage -type INFO -message "[$controlPlaneHost] DELETE succeeded on $dbPod (active pod)"
            } else {
                LogMessage -type WARNING -message "[$controlPlaneHost] DELETE on $dbPod exited with code $dbExit — this pod is likely the standby (expected)"
            }
        } catch {
            LogMessage -type WARNING -message "[$controlPlaneHost] DELETE on $dbPod failed (likely standby pod): $($_.Exception.Message)"
        }
    }

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Remove-VcfmsRecoveredComponents

#EndRegion Services Runtime

#Region Supervisor
Function Confirm-ContentLibraryDatastoreFolder
{
    <#
    .SYNOPSIS
    Checks for the presence of a content library folder on the target datastore and creates it if absent.

    .DESCRIPTION
    The Confirm-ContentLibraryDatastoreFolder cmdlet connects to the specified vCenter, resolves the named
    content library to its GUID, locates the named datastore, and verifies that a folder in the format
    'contentlib-<libraryId>' exists at the root of that datastore. If the folder is not found it is created.

    For vSAN datastores (both OSA and ESA), the function uses the PowerCLI VimDatastore PSDrive provider,
    which wraps vSphere's Datastore Browser API (MakeDirectory). vCenter exposes this API uniformly for all
    datastore types it manages, so the same code path also handles VMFS and NFS datastores that are
    registered as named datastores in vCenter.

    Note: this function is not applicable to content libraries backed by a raw NFS mount point (storage
    backing type 'OTHER'). In that case the folder is managed by the NFS server itself and no vSphere
    datastore object exists to operate against.

    .EXAMPLE
    Confirm-ContentLibraryDatastoreFolder -vCenterFQDN "sfo-m01-vc01.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMware1!" -datastoreName "sfo-m01-cl01-ds-vsan01" -contentLibraryName "sfo-m01-cl01"

    .PARAMETER vCenterFQDN
    FQDN of the vCenter instance that owns the target datastore.

    .PARAMETER vCenterAdmin
    Admin user for the vCenter instance.

    .PARAMETER vCenterAdminPassword
    Admin password for the vCenter instance.

    .PARAMETER datastoreName
    Name of the datastore on which to confirm the content library folder.

    .PARAMETER contentLibraryName
    Name of the content library. Its GUID is resolved via Get-ContentLibrary and the folder name is
    constructed as 'contentlib-<libraryId>'.
    #>

    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $datastoreName,
        [Parameter (Mandatory = $true)][String] $contentLibraryName
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()

    $driveName  = "clDSCheck_$(Get-Random)"

    Try {
        LogMessage -type INFO -message "[$vCenterFQDN] Connecting to vCenter"
        $viConnection = Connect-VIServer -Server $vCenterFQDN -User $vCenterAdmin -Password $vCenterAdminPassword -ErrorAction Stop

        # Resolve the content library's GUID from its name
        LogMessage -type INFO -message "[$vCenterFQDN] Resolving Content Library '$contentLibraryName'"
        $library = Get-ContentLibrary -Name $contentLibraryName -ErrorAction Stop | Select-Object -First 1
        if (-not $library) {
            LogMessage -type ERROR -message "[$vCenterFQDN] Content Library '$contentLibraryName' not found"
            Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
            return
        }
        $libraryId  = $library.Id
        $folderName = "contentlib-$libraryId"
        LogMessage -type INFO -message "[$vCenterFQDN] Content Library '$contentLibraryName' resolved (Id: $libraryId)"

        # Resolve the datastore object — works for vSAN, VMFS, and NFS
        LogMessage -type INFO -message "[$vCenterFQDN] Resolving datastore '$datastoreName'"
        $datastore = Get-Datastore -Name $datastoreName -ErrorAction Stop | Select-Object -First 1
        if (-not $datastore) {
            LogMessage -type ERROR -message "[$vCenterFQDN] Datastore '$datastoreName' not found"
            Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
            return
        }
        LogMessage -type INFO -message "[$vCenterFQDN] Datastore '$datastoreName' resolved (Type: $($datastore.Type))"

        # Mount the datastore as a PSDrive using the VimDatastore provider.
        # This approach is uniform across vSAN, VMFS, and NFS datastores.
        LogMessage -type INFO -message "[$vCenterFQDN] Mounting datastore '$datastoreName' as PSDrive '$driveName'"
        New-PSDrive -Location $datastore -Name $driveName -PSProvider VimDatastore -Root "\" -ErrorAction Stop | Out-Null

        $folderPath = "${driveName}:\$folderName"

        if (Test-Path -Path $folderPath) {
            LogMessage -type INFO -message "[$vCenterFQDN] Folder '$folderName' already exists on datastore '$datastoreName' — no action required"
        } else {
            LogMessage -type INFO -message "[$vCenterFQDN] Folder '$folderName' not found on datastore '$datastoreName' — creating"
            New-Item -ItemType Directory -Path $folderPath -ErrorAction Stop | Out-Null
            LogMessage -type INFO -message "[$vCenterFQDN] Folder '$folderName' created successfully on datastore '$datastoreName'"
        }
    } Catch {
        LogMessage -type ERROR -message "[$vCenterFQDN] $($_.Exception.Message)"
    } Finally {
        # Always remove the PSDrive and disconnect, even on error
        if (Get-PSDrive -Name $driveName -ErrorAction SilentlyContinue) {
            Remove-PSDrive -Name $driveName -ErrorAction SilentlyContinue | Out-Null
        }
        Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
    }

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Confirm-ContentLibraryDatastoreFolder

Function Set-ContentLibraryDatastoreMapping
{
    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterRootPassword,
        [Parameter (Mandatory = $true)][String] $contentLibraryName,
        [Parameter (Mandatory = $true)][String] $datastoreName
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()

    # Establish SSH connection to vCenter as root
    $SecurePassword = ConvertTo-SecureString -String $vCenterRootPassword -AsPlainText -Force
    $rootCreds = New-Object System.Management.Automation.PSCredential ("root", $SecurePassword)
    Get-SSHTrustedHost | Remove-SSHTrustedHost | Out-Null
    $inmem = New-SSHMemoryKnownHost
    New-SSHTrustedHost -KnownHostStore $inmem -HostName $vCenterFQDN -FingerPrint ((Get-SSHHostKey -ComputerName $vCenterFQDN).fingerprint) | Out-Null
    Do {
        $sshSession = New-SSHSession -ComputerName $vCenterFQDN -Credential $rootCreds -KnownHost $inmem
    } Until ($sshSession)

    # Open shell stream with wide terminal to avoid line-wrapping corruption
    $stream = New-SSHShellStream -SSHSession $sshSession -TerminalName "xterm" -Columns 250
    Start-Sleep 1
    $stream.Read() | Out-Null

    # Escape the VMware appliance shell to bash
    LogMessage -type INFO -message "[$vCenterFQDN] Escaping appliance shell to bash"
    $stream.WriteLine("shell")
    Start-Sleep 2
    $stream.Read() | Out-Null

    # Filter to strip shell prompts and echo'd commands from SSH stream output
    $cleanSshOutput = {
        param([String]$raw)
        ($raw -split "`n" | Where-Object {
            $_ -notmatch 'root@' -and
            $_ -notmatch 'vcf@' -and
            $_ -notmatch 'echo\s+"' -and
            $_ -notmatch '^\s*$'
        }) -join "`n"
    }
    $guidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    $psql = '/opt/vmware/vpostgres/current/bin/psql -d VCDB -U postgres -t -A'

    # Query cl_library for the content library's UUID and current serverguid (bytea decoded to readable UUID)
    LogMessage -type INFO -message "[$vCenterFQDN] Querying VCDB for Content Library '$contentLibraryName'"
    $stream.WriteLine("echo `"SELECT id, encode(serverguid,'escape') FROM vc.cl_library WHERE name='$contentLibraryName';`" | $psql")
    Start-Sleep 3
    $clLibraryOutput = & $cleanSshOutput $stream.Read()
    $libraryMatches = ($clLibraryOutput | Select-String -Pattern $guidPattern -AllMatches).Matches
    $libraryId       = $libraryMatches | Select-Object -First 1 -ExpandProperty Value
    $existinvCenterId = $libraryMatches | Select-Object -Last 1 -ExpandProperty Value
    if (-not $libraryId) {
        LogMessage -type ERROR -message "[$vCenterFQDN] Could not find Content Library '$contentLibraryName' in VCDB"
        Remove-SSHSession -SSHSession $sshSession | Out-Null
        return
    }
    LogMessage -type INFO -message "[$vCenterFQDN] Library GUID: $libraryId"
    LogMessage -type INFO -message "[$vCenterFQDN] vCenter ID: $existinvCenterId"

    # Query cl_library_storage for the storage backing UUID (bytea decoded to readable UUID)
    LogMessage -type INFO -message "[$vCenterFQDN] Querying VCDB for Content Library storage_id of '$libraryId'"
    $stream.WriteLine("echo `"select storage_id from cl_library_storage where library_id='$libraryId';`" | $psql")
    Start-Sleep 3
    $storageId = (& $cleanSshOutput $stream.Read() | Select-String -Pattern $guidPattern -AllMatches).Matches | Select-Object -First 1 -ExpandProperty Value
    if (-not $storageId) {
        LogMessage -type ERROR -message "[$vCenterFQDN] Could not find Content Library storage_id for '$libraryId' in VCDB"
        Remove-SSHSession -SSHSession $sshSession | Out-Null
        return
    }
    LogMessage -type INFO -message "[$vCenterFQDN] Content Library Storage ID: $storageId"

    # Query vc.vpx_datastore for the target datastore's MoRef
    LogMessage -type INFO -message "[$vCenterFQDN] Querying VCDB for MoRef of datastore '$datastoreName'"
    $stream.WriteLine("echo `"SELECT 'datastore-' || id FROM vc.vpx_datastore WHERE name='$datastoreName';`" | $psql")
    Start-Sleep 3
    $newDatastoreMoRef = (& $cleanSshOutput $stream.Read() | Select-String -Pattern 'datastore-\d+' -AllMatches).Matches | Select-Object -First 1 -ExpandProperty Value
    if (-not $newDatastoreMoRef) {
        LogMessage -type ERROR -message "[$vCenterFQDN] Could not find datastore '$datastoreName' in VCDB"
        Remove-SSHSession -SSHSession $sshSession | Out-Null
        return
    }
    LogMessage -type INFO -message "[$vCenterFQDN] Datastore MoRef: $newDatastoreMoRef"

    # Build the new storageuri in the format Datastore:<datastoreMoRef>:<serverGuid>
    $newStorageUri = "Datastore:$newDatastoreMoRef`:$existinvCenterId"
    LogMessage -type INFO -message "[$vCenterFQDN] New storageuri: $newStorageUri"

    # Update cl_storage storageuri for the storage backing
    LogMessage -type INFO -message "[$vCenterFQDN] Updating cl_storage storageuri for storage_id '$storageId'"
    $stream.WriteLine("echo `"UPDATE cl_storage SET storageuri='$newStorageUri' WHERE id='$storageId';`" | $psql")
    Start-Sleep 3
    $stream.Read() | Out-Null

    # Verify the update by reading back the new storageuri
    # COLUMNS=500 prevents psql/terminal from wrapping the URI across multiple lines
    $stream.WriteLine("COLUMNS=500 echo `"SELECT storageuri FROM cl_storage WHERE id='$storageId';`" | $psql")
    Start-Sleep 3
    $verifyRaw = $stream.Read()
    $verifyOutput = & $cleanSshOutput $verifyRaw
    # Use a direct regex match against the full output to avoid line-split/wrap sensitivity
    $uriPattern = 'Datastore:[^\s\r\n]+'
    $verifiedUri = ([regex]::Match($verifyOutput, $uriPattern)).Value.Trim().Replace("`r", "")
    if ($verifiedUri -eq $newStorageUri) {
        LogMessage -type INFO -message "[$vCenterFQDN] cl_storage UPDATE verified: $verifiedUri"
    } else {
        LogMessage -type WARNING -message "[$vCenterFQDN] cl_storage UPDATE could not be verified. Expected: $newStorageUri | Got: $verifiedUri"
    }

    $stream.WriteLine("service-control --restart vmware-content-library")
    LogMessage -type INFO -message "[$vCenterFQDN] Restarted Content Library Service"
    Remove-SSHSession -SSHSession $sshSession | Out-Null

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Set-ContentLibraryDatastoreMapping

Function Invoke-SupervisorRestore
{
    Param(
        [Parameter (Mandatory = $true)][String] $vCenterFQDN,
        [Parameter (Mandatory = $true)][String] $vCenterAdmin,
        [Parameter (Mandatory = $true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory = $true)][String] $vCenterRootPassword,
        [Parameter (Mandatory = $true)][String] $supervisorName,
        [Parameter (Mandatory = $true)][String] $backupFilePath
    )
    $jumpboxName = hostname
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()

    $backupFileName = (Get-Item -Path $backupFilePath).Name
    $remoteBackupPath = "/storage/supervisorbackup/$backupFileName"

    # Upload backup file to vCenter appliance via SCP
    LogMessage -type INFO -message "[$vCenterFQDN] Uploading backup file '$backupFileName' to vCenter appliance"
    $SecurePassword = ConvertTo-SecureString -String $vCenterRootPassword -AsPlainText -Force
    $rootCreds = New-Object System.Management.Automation.PSCredential ("root", $SecurePassword)
    Get-SSHTrustedHost | Remove-SSHTrustedHost | Out-Null
    $inmem = New-SSHMemoryKnownHost
    New-SSHTrustedHost -KnownHostStore $inmem -HostName $vCenterFQDN -FingerPrint ((Get-SSHHostKey -ComputerName $vCenterFQDN).fingerprint) | Out-Null
    Set-SCPItem -ComputerName $vCenterFQDN -Credential $rootCreds -Path $backupFilePath -Destination "/storage/supervisorbackup" -KnownHost $inmem
    LogMessage -type INFO -message "[$vCenterFQDN] Backup file uploaded to '$remoteBackupPath'"

    # Obtain a vCenter REST API session token
    LogMessage -type INFO -message "[$vCenterFQDN] Obtaining vCenter REST API session token"
    $base64Creds = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${vCenterAdmin}:${vCenterAdminPassword}"))
    $sessionToken = (Invoke-WebRequest -Method POST -Uri "https://$vCenterFQDN/api/session" -Headers @{ Authorization = "Basic $base64Creds" } -SkipCertificateCheck).Content | ConvertFrom-Json
    $headers = @{ 'vmware-api-session-id' = $sessionToken }

    # Resolve the supervisor name to its ID
    LogMessage -type INFO -message "[$vCenterFQDN] Resolving supervisor '$supervisorName' to ID"
    $supervisors = (Invoke-WebRequest -Method GET -Uri "https://$vCenterFQDN/api/vcenter/namespace-management/supervisors/summaries" -Headers $headers -SkipCertificateCheck).Content | ConvertFrom-Json
    $supervisorId = ($supervisors.items | Where-Object { $_.supervisor_summary.display_name -eq $supervisorName } | Select-Object -First 1).supervisor
    if (-not $supervisorId) {
        LogMessage -type ERROR -message "[$vCenterFQDN] Could not find supervisor '$supervisorName'"
        return
    }
    LogMessage -type INFO -message "[$vCenterFQDN] Supervisor ID: $supervisorId"

    # List backup archives and match the uploaded file by location
    LogMessage -type INFO -message "[$vCenterFQDN] Locating backup archive matching '$backupFileName'"
    $archives = (Invoke-WebRequest -Method GET -Uri "https://$vCenterFQDN/api/vcenter/namespace-management/supervisors/$supervisorId/recovery/backup/archives" -Headers $headers -SkipCertificateCheck).Content | ConvertFrom-Json
    $archiveId = ($archives | Where-Object { $_.location -like "*$backupFileName*" } | Select-Object -First 1).archive
    if (-not $archiveId) {
        LogMessage -type ERROR -message "[$vCenterFQDN] Could not find backup archive matching '$backupFileName'"
        return
    }
    LogMessage -type INFO -message "[$vCenterFQDN] Archive ID: $archiveId"

    # Initiate the restore job
    LogMessage -type INFO -message "[$vCenterFQDN] Initiating restore of supervisor '$supervisorName' from archive '$archiveId'"
    $taskId = (Invoke-WebRequest -Method POST -Uri "https://$vCenterFQDN/api/vcenter/namespace-management/supervisors/$supervisorId/recovery/restore/jobs/$archiveId" -Headers $headers -SkipCertificateCheck).Content | ConvertFrom-Json
    LogMessage -type INFO -message "[$vCenterFQDN] Restore task ID: $taskId"

    # Monitor the restore task to completion
    LogMessage -type INFO -message "[$vCenterFQDN] Monitoring restore task '$taskId'"
    Do {
        Start-Sleep 30
        $taskStatus = (Invoke-WebRequest -Method GET -Uri "https://$vCenterFQDN/api/cis/tasks/$taskId" -Headers $headers -SkipCertificateCheck).Content | ConvertFrom-Json
        LogMessage -type INFO -message "[$vCenterFQDN] Restore task status: $($taskStatus.status)"
    } While ($taskStatus.status -in @('RUNNING', 'PENDING'))

    if ($taskStatus.status -eq 'SUCCEEDED') {
        LogMessage -type INFO -message "[$vCenterFQDN] Restore of supervisor '$supervisorName' completed successfully"
    } else {
        LogMessage -type ERROR -message "[$vCenterFQDN] Restore task ended with status '$($taskStatus.status)'"
    }

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}
Export-ModuleMember -Function Invoke-SupervisorRestore

#EndRegion Supervisor

#Region UI Orchestrator

Function Start-InstanceRecoveryUI {
    <#
    .SYNOPSIS
    Launches the VCF Instance Recovery orchestrator UI

    .DESCRIPTION
    The Start-InstanceRecoveryUI cmdlet opens a WPF window -- loaded in-process from
    xaml\InstanceRecoveryOrchestratorUI.xaml via XamlReader, no separate .exe or build step -- that
    lets you pick an extracted-sddc-data.json file, lists the workload domains it contains, and runs
    the recovery steps for the selected domain in an embedded, fully interactive PowerShell console
    (via EasyWindowsTerminalControl, vendored under lib\EasyWindowsTerminalControl).

    The window runs on its own dedicated STA runspace so this cmdlet returns control to your console
    immediately rather than blocking until the window is closed.

    .EXAMPLE
    Start-InstanceRecoveryUI
    #>

    Param()

    $moduleRoot = $PSScriptRoot
    $xamlPath = Join-Path $moduleRoot 'xaml\InstanceRecoveryOrchestratorUI.xaml'
    $libPath = Join-Path $moduleRoot 'lib\EasyWindowsTerminalControl'

    if (-not (Test-Path $xamlPath)) {
        LogMessage -type ERROR -message "Cannot find UI resource '$xamlPath'."
        return
    }
    if (-not (Test-Path $libPath)) {
        LogMessage -type ERROR -message "Cannot find vendored EasyWindowsTerminalControl assemblies at '$libPath'."
        return
    }

    # Self-contained: runs in its own isolated runspace/session state, so it has no dependency on
    # this module's functions (e.g. LogMessage) -- only .NET/WPF and the vendored terminal control.
    $uiScript = @'
param(
    [string]$XamlPath,
    [string]$LibPath
)

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml

# Prepend the vendored folder to the native search path -- EasyWindowsTerminalControl wraps native
# C++/DirectX rendering components that need to resolve alongside its managed assembly.
$env:PATH = "$LibPath;$env:PATH"
Get-ChildItem -Path $LibPath -Filter '*.dll' | ForEach-Object {
    try {
        Add-Type -Path $_.FullName -ErrorAction Stop
    } catch {
        Write-Warning "Failed to load $($_.FullName): $($_.Exception.Message)"
    }
}

# EasyWindowsTerminalControl's native rendering/ConPTY session appears to need
# Application.Current to already exist by the time the control is constructed -- a normal
# compiled WPF app's generated Main() always does "new Application(); app.Run();" before its
# StartupUri window (and therefore any control inside it) is ever built. XamlReader.Load()
# below constructs the Term control immediately, so the Application must be created first.
$app = New-Object System.Windows.Application

[xml]$xamlDocument = Get-Content -Path $XamlPath -Raw
$xamlReader = New-Object System.Xml.XmlNodeReader $xamlDocument
$window = [System.Windows.Markup.XamlReader]::Load($xamlReader)

$extractRadio = $window.FindName('ExtractBackupRadio')
$browseButton = $window.FindName('BrowseButton')
$filePathTextBox = $window.FindName('FilePathTextBox')
$statusTextBlock = $window.FindName('StatusTextBlock')
$dataSourceDomainsTabControl = $window.FindName('DataSourceDomainsTabControl')
$domainsListBox = $window.FindName('WorkloadDomainsListBox')
$stepsGroupBox = $window.FindName('StepsGroupBox')
$managementDomainRestoresStepsListBox = $window.FindName('ManagementDomainRestoresStepsListBox')
$recoverDefaultClusterStepsListBox = $window.FindName('RecoverDefaultClusterStepsListBox')
$runAllManagementDomainRestoresButton = $window.FindName('RunAllManagementDomainRestoresButton')
$runAllRecoverDefaultClusterButton = $window.FindName('RunAllRecoverDefaultClusterButton')
$variablesGroupBox = $window.FindName('VariablesGroupBox')
$loadVariablesButton = $window.FindName('LoadVariablesButton')
$loadedVariablesTextBlock = $window.FindName('LoadedVariablesTextBlock')
$variablesItemsPanel = $window.FindName('VariablesItemsPanel')
$term = $window.FindName('Term')

function Protect-SingleQuotes([string]$Value) {
    return $Value.Replace("'", "''")
}

function Send-ToConsole([string]$CommandLine) {
    if ($null -eq $term.ConPTYTerm) {
        $statusTextBlock.Text = "Console isn't ready yet (ConPTYTerm is null) -- try again in a moment."
        return
    }
    try {
        $term.ConPTYTerm.WriteToTerm("$CommandLine`r")
    } catch {
        $statusTextBlock.Text = "WriteToTerm failed: $($_.Exception.Message)"
    }
}

function Invoke-Step($Dot, [string]$CommandLine) {
    $Dot.Fill = [System.Windows.Media.Brushes]::DodgerBlue
    Send-ToConsole $CommandLine
}

# Returns [PSCustomObject]@{ Panel; Dot; CommandLine }, not just the row's visual Panel -- Dot and
# CommandLine are needed separately so a tab's "Run All" button can replay every row's Run action
# (dot included) without re-parsing the rendered list.
function New-StepRow([string]$CommandLine) {
    $panel = New-Object System.Windows.Controls.DockPanel
    $panel.Margin = '4,0,4,0'

    $dot = New-Object System.Windows.Shapes.Ellipse
    $dot.Width = 10
    $dot.Height = 10
    $dot.Fill = [System.Windows.Media.Brushes]::LightGray
    $dot.Margin = '0,0,8,0'
    $dot.VerticalAlignment = 'Center'

    # Only the cmdlet name is shown; the full command line (with its parameters) stays in the
    # module and is only ever sent to the console, never rendered in the Steps list. Variable
    # values referenced in it (e.g. $targetFqdn) come from whatever was loaded via "Load
    # Variables..." -- they're already set in the console session by the time Run is clicked.
    $cmdletName = ($CommandLine -split '\s+', 2)[0]

    $runButton = New-Object System.Windows.Controls.Button
    $runButton.Content = 'Run'
    $runButton.Width = 60
    $runButton.Margin = '8,0,0,0'
    [System.Windows.Controls.DockPanel]::SetDock($runButton, [System.Windows.Controls.Dock]::Right)
    $runButton.Add_Click({
        try {
            Invoke-Step $dot $CommandLine
        } catch {
            $statusTextBlock.Text = "Run button failed: $($_.Exception.Message)"
        }
    }.GetNewClosure())

    $label = New-Object System.Windows.Controls.TextBlock
    $label.Text = $cmdletName
    $label.FontFamily = New-Object System.Windows.Media.FontFamily('Consolas')
    $label.VerticalAlignment = 'Center'

    [void]$panel.Children.Add($dot)
    [void]$panel.Children.Add($runButton)
    [void]$panel.Children.Add($label)
    return [PSCustomObject]@{ Panel = $panel; Dot = $dot; CommandLine = $CommandLine }
}

# Variable names referenced across $CommandLines (e.g. "$targetFqdn"), in order of first
# appearance, deduplicated. Used to order the Variables panel by when each value is actually
# needed as you work down the Steps list, rather than alphabetically or by answer-file order.
function Get-ReferencedVariableNames([string[]]$CommandLines) {
    $names = [System.Collections.Generic.List[string]]::new()
    $seen = @{}
    foreach ($commandLine in $CommandLines) {
        foreach ($match in [regex]::Matches($commandLine, '\$([A-Za-z_][A-Za-z0-9_]*)')) {
            $name = $match.Groups[1].Value
            if (-not $seen.ContainsKey($name)) {
                $seen[$name] = $true
                [void]$names.Add($name)
            }
        }
    }
    return $names
}

function New-VariableRow([string]$Name, [string]$Value) {
    $panel = New-Object System.Windows.Controls.DockPanel
    $panel.Margin = '0,0,0,6'

    $label = New-Object System.Windows.Controls.TextBlock
    $label.Text = $Name
    $label.FontFamily = New-Object System.Windows.Media.FontFamily('Consolas')
    $label.VerticalAlignment = 'Center'
    $label.Width = 160
    $label.Margin = '0,0,8,0'
    $label.TextTrimming = 'CharacterEllipsis'
    [System.Windows.Controls.DockPanel]::SetDock($label, [System.Windows.Controls.Dock]::Left)

    $valueBox = New-Object System.Windows.Controls.TextBox
    $valueBox.Text = $Value

    # Edits only take effect on LostFocus (not per-keystroke) -- re-sends the updated value to the
    # console so a value changed after loading still reaches the running session.
    $valueBox.Add_LostFocus({
        Send-ToConsole "`$$Name = '$(Protect-SingleQuotes $valueBox.Text)'"
    }.GetNewClosure())

    [void]$panel.Children.Add($label)
    [void]$panel.Children.Add($valueBox)
    return $panel
}

function Start-TerminalReadyWatcher {
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(200)
    $script:terminalReadyAttempts = 0
    $timer.Add_Tick({
        # $this, not $timer -- by the time this fires, Start-TerminalReadyWatcher has already
        # returned, so its local $timer variable is out of scope and resolves to $null here.
        # $this is bound to the DispatcherTimer instance automatically by Add_Tick.
        #
        # No command is sent to the console once it's ready: the module is installed on
        # $env:PSModulePath, so PowerShell auto-loads it the first time a Step's cmdlet actually
        # runs -- an explicit Import-Module here would just be a redundant, race-prone extra step.
        $script:terminalReadyAttempts++
        if ($null -ne $term.ConPTYTerm) {
            $this.Stop()
        } elseif ($script:terminalReadyAttempts -gt 50) {
            $this.Stop()
            $statusTextBlock.Text = 'Embedded console did not start in time.'
        }
    })
    $timer.Start()
}

$browseButton.Add_Click({
    $extracting = $extractRadio.IsChecked -eq $true
    $dialog = New-Object Microsoft.Win32.OpenFileDialog
    if ($extracting) {
        $dialog.Filter = 'All files (*.*)|*.*'
        $dialog.Title = 'Select backup file'
    } else {
        $dialog.Filter = 'JSON files (*.json)|*.json|All files (*.*)|*.*'
        $dialog.Title = 'Select extracted-sddc-data.json'
    }

    if ($dialog.ShowDialog() -ne $true) {
        return
    }

    $filePathTextBox.Text = $dialog.FileName

    if ($extracting) {
        # Extracting a backup file is not implemented yet -- selecting a file here does nothing further.
        return
    }

    $domainsListBox.Items.Clear()
    $managementDomainRestoresStepsListBox.Items.Clear()
    $recoverDefaultClusterStepsListBox.Items.Clear()
    $variablesItemsPanel.Children.Clear()
    $loadedVariablesTextBlock.Text = 'No variables loaded yet.'
    $stepsGroupBox.Visibility = [System.Windows.Visibility]::Collapsed
    $variablesGroupBox.Visibility = [System.Windows.Visibility]::Collapsed
    $global:allStepCommandLines = @()
    $statusTextBlock.Text = ''

    try {
        $extractedSddcData = Get-Content -Path $dialog.FileName -Raw | ConvertFrom-Json
    } catch {
        $statusTextBlock.Text = "Failed to load extracted SDDC data: $($_.Exception.Message)"
        return
    }

    if (-not $extractedSddcData.workloadDomains) {
        $statusTextBlock.Text = "No 'workloadDomains' property found in the selected file."
        return
    }

    foreach ($domain in $extractedSddcData.workloadDomains) {
        $item = New-Object System.Windows.Controls.ListBoxItem
        $item.Content = "$($domain.domainName) ($($domain.domainType))"
        $item.Tag = $domain
        [void]$domainsListBox.Items.Add($item)
    }

    # Switch focus to the Workload Domains tab now that there's something to pick from -- saves a
    # manual click back and forth between the two tabs every time a data file is loaded.
    $dataSourceDomainsTabControl.SelectedIndex = 1

    $escapedPath = Protect-SingleQuotes $dialog.FileName
    Send-ToConsole "`$extractedSDDCDataFile = '$escapedPath'"
}.GetNewClosure())

# Answer file is a flat JSON object, e.g. { "targetFqdn": "sfo-m01-vc02...", "targetAdminPassword": "..." }.
# Each entry is sent to the console once, immediately, as "$name = 'value'" -- from then on every
# step's Run button can reference $targetFqdn etc. directly, the same way $extractedSDDCDataFile
# already works. Rows are ordered by first use across the selected domain's steps (Management
# Domain Restores, then Recover Default Cluster) so they read top-to-bottom in the order you'll
# need them; any answer-file entries not referenced by any step are appended afterward, in file
# order, so nothing loaded is ever silently dropped from view.
$loadVariablesButton.Add_Click({
    try {
        $dialog = New-Object Microsoft.Win32.OpenFileDialog
        $dialog.Filter = 'JSON files (*.json)|*.json|All files (*.*)|*.*'
        $dialog.Title = 'Select variable answers file'
        if ($dialog.ShowDialog() -ne $true) {
            return
        }

        $answers = Get-Content -Path $dialog.FileName -Raw | ConvertFrom-Json
        $answerMap = [ordered]@{}
        foreach ($property in $answers.PSObject.Properties) {
            $answerMap[$property.Name] = [string]$property.Value
        }

        $variablesItemsPanel.Children.Clear()

        if ($answerMap.Count -eq 0) {
            $loadedVariablesTextBlock.Text = "No variables found in '$($dialog.FileName)'."
            return
        }

        $orderedNames = @(Get-ReferencedVariableNames $global:allStepCommandLines | Where-Object { $answerMap.Contains($_) })
        $orderedNames += @($answerMap.Keys | Where-Object { $orderedNames -notcontains $_ })

        foreach ($name in $orderedNames) {
            $value = $answerMap[$name]
            Send-ToConsole "`$$name = '$(Protect-SingleQuotes $value)'"
            [void]$variablesItemsPanel.Children.Add((New-VariableRow $name $value))
        }

        $loadedVariablesTextBlock.Text = "Loaded $($orderedNames.Count) variable(s) from $($dialog.FileName)."
    } catch {
        $statusTextBlock.Text = "Load Variables failed: $($_.Exception.Message)"
    }
}.GetNewClosure())

$domainsListBox.Add_SelectionChanged({
  try {
    $managementDomainRestoresStepsListBox.Items.Clear()
    $recoverDefaultClusterStepsListBox.Items.Clear()
    $variablesItemsPanel.Children.Clear()
    $loadedVariablesTextBlock.Text = 'No variables loaded yet.'
    $managementDomainRestoresCommandLines = @()
    $recoverDefaultClusterCommandLines = @()

    $selected = $domainsListBox.SelectedItem
    if ($null -eq $selected) {
        $stepsGroupBox.Visibility = [System.Windows.Visibility]::Collapsed
        $variablesGroupBox.Visibility = [System.Windows.Visibility]::Collapsed
        $global:allStepCommandLines = @()
        return
    }
    $stepsGroupBox.Visibility = [System.Windows.Visibility]::Visible
    $variablesGroupBox.Visibility = [System.Windows.Visibility]::Visible

    if ($selected.Tag.domainType -eq 'MANAGEMENT') {
        $managementDomainRestoresCommandLines = @(
            'New-ExtractDataFromSDDCBackup -vcfBackupFilePath $vcfBackupFilePath -encryptionPassword $encryptionPassword -credentialsFilePath $credentialsFilePath',
            'New-PrepareManagementHostNetworking -extractedSDDCDataFile $extractedSDDCDataFile -mtu 8900',
            'Add-VMKernelsToManagementHosts -extractedSDDCDataFile $extractedSDDCDataFile',
            'New-SingleHostVsanDatastore -extractedSDDCDataFile $extractedSDDCDataFile',
            'New-vCenterOvaDeployment -targetType $targetType -targetFqdn $targetFqdn -targetAdmin $targetAdmin -targetAdminPassword $targetAdminPassword -extractedSDDCDataFile $extractedSDDCDataFile -workloadDomain $workloadDomain -restoredvCenterDeploymentSize $restoredvCenterDeploymentSize -vCenterOvaFile $vCenterOvaFile',
            'New-NSXManagerOvaDeployment -targetType $targetType -targetFqdn $targetFqdn -targetAdmin $targetAdmin -targetAdminPassword $targetAdminPassword -extractedSDDCDataFile $extractedSDDCDataFile -workloadDomain $workloadDomain -restoredNsxManagerDeploymentSize $restoredNsxManagerDeploymentSize -nsxManagerOvaFile $nsxManagerOvaFile',
            'New-SDDCManagerOvaDeployment -targetType $targetType -targetFqdn $targetFqdn -targetAdmin $targetAdmin -targetAdminPassword $targetAdminPassword -extractedSDDCDataFile $extractedSDDCDataFile -sddcManagerOvaFile $sddcManagerOvaFile -rootUserPassword $rootUserPassword -vcfUserPassword $vcfUserPassword -localUserPassword $localUserPassword -basicAuthUserPassword $basicAuthUserPassword',
            'Invoke-vCenterRestore -extractedSDDCDataFile $extractedSDDCDataFile -workloadDomain $workloadDomain -vCenterBackupPath $vCenterBackupPath -locationtype $locationtype -locationUser $locationUser -locationPassword $locationPassword',
            'Invoke-NSXManagerRestore -extractedSDDCDataFile $extractedSDDCDataFile -workloadDomain $workloadDomain -sftpServer $sftpServer -sftpUser $sftpUser -sftpPassword $sftpPassword -sftpServerBackupPath $sftpServerBackupPath -backupPassphrase $nsxBackupPassphrase',
            'New-UploadAndModifySDDCManagerBackup -targetType $targetType -targetFqdn $targetFqdn -targetAdmin $targetAdmin -targetAdminPassword $targetAdminPassword -rootUserPassword $rootUserPassword -vcfUserPassword $vcfUserPassword -backupFilePath $vcfbackupFilePath -encryptionPassword $encryptionPassword -extractedSDDCDataFile $extractedSDDCDataFile',
            'Invoke-SDDCManagerRestore -extractedSDDCDataFile $extractedSDDCDataFile -backupFilePath $vcfbackupFilePath -vcfUserPassword $vcfUserPassword -localUserPassword $localUserPassword -rootUserPassword $rootUserPassword -encryptionPassword $encryptionPassword',
            'Update-ExtractedSDDCData -extractedSDDCDataFile $extractedSDDCDataFile -sddcManagerFQDN $sddcManagerFQDN -sddcManagerAdmin $sddcManagerAdmin -sddcManagerAdminPassword $sddcManagerAdminPassword -vCenterFQDN $restoredVcenterFqdn'
        )

        $recoverDefaultClusterCommandLines = @(
            'Backup-ClusterVMOverrides -clusterName $clusterName',
            'Backup-ClusterVMLocations -clusterName $clusterName',
            'Backup-ClusterDRSGroupsAndRules -clusterName $clusterName',
            'Backup-ClusterVMTags -clusterName $clusterName',
            'Remove-NonResponsiveHosts -vCenterFQDN $restoredVcenterFqdn -vCenterAdmin $restoredVcenterAdmin -vCenterAdminPassword $restoredVcenterAdminPassword -clusterName $clusterName -NsxManagerFQDN $restoredNsxManagerFqdn -NsxManagerAdmin $restoredNsxManagerAdmin -NsxManagerAdminPassword $restoredNsxManagerAdminPassword -NsxManagerRootPassword $restoredNsxManagerRootPassword',
            'Add-HostsToCluster -vCenterFQDN $restoredVcenterFqdn -vCenterAdmin $restoredVcenterAdmin -vCenterAdminPassword $restoredVcenterAdminPassword -clusterName $clusterName -sddcManagerFqdn $sddcManagerFqdn -sddcManagerAdmin $sddcManagerAdmin -sddcManagerAdminPassword $sddcManagerAdminPassword -extractedSDDCDataFile $extractedSDDCDataFile',
            'New-RebuiltVdsConfiguration -vCenterFQDN $restoredVcenterFqdn -vCenterAdmin $restoredVcenterAdmin -vCenterAdminPassword $restoredVcenterAdminPassword -clusterName $clusterName -extractedSDDCDataFile $extractedSDDCDataFile',
            'Watch-NsxHostTransportNodeInstallation -clusterName $clusterName -extractedSDDCDataFile $extractedSDDCDataFile',
            'Add-DiskgroupsToManagementHosts -targetFqdn $restoredVcenterFqdn -targetAdmin $restoredVcenterAdmin -targetAdminPassword $restoredVcenterAdminPassword -clusterName $clusterName -extractedSDDCDataFile $extractedSDDCDataFile',
            'Set-ManagementDatastorePolicy -vCenterFQDN $restoredVcenterFqdn -vCenterAdmin $restoredVcenterAdmin -vCenterAdminPassword $restoredVcenterAdminPassword -clusterName $clusterName -extractedSDDCDataFile $extractedSDDCDataFile',
            'New-ReconfiguredVsanStretchedCluster -vCenterFQDN $restoredVcenterFqdn -vCenterAdmin $restoredVcenterAdmin -vCenterAdminPassword $restoredVcenterAdminPassword -clusterName $clusterName -extractedSDDCDataFile $extractedSDDCDataFile',
            'Clear-vCenterAlarms -vCenterFQDN $restoredVcenterFqdn -vCenterAdmin $restoredVcenterAdmin -vCenterAdminPassword $restoredVcenterAdminPassword',
            'Update-DomainDatastoreID -extractedSDDCDataFile $extractedSDDCDataFile -vCenterFqdn $vCenterFqdn -clusterName $clusterName -VcfUserPassword $VcfUserPassword -RootPassword $RootPassword',
            'Update-ClusterHostSourceIDs -extractedSDDCDataFile $extractedSDDCDataFile -vCenterFqdn $vCenterFqdn -clusterName $clusterName -VcfUserPassword $VcfUserPassword -RootPassword $RootPassword',
            'Invoke-SddcManagerSSHKeyRefresh -vCenterFQDN $restoredVcenterFqdn -vCenterAdmin $restoredVcenterAdmin -vCenterAdminPassword $restoredVcenterAdminPassword -extractedSDDCDataFile $extractedSDDCDataFile -clusterName $clusterName -workloadDomain $workloadDomain -VcfUserPassword $VcfUserPassword',
            'Resolve-PhysicalHostServiceAccounts -targetFQDN $restoredVcenterFqdn -targetAdmin $restoredVcenterAdmin -targetAdminPassword $restoredVcenterAdminPassword -clusterName $clusterName -svcAccountPassword $svcAccountPassword -sddcManagerFqdn $sddcManagerFqdn -sddcManagerAdmin $sddcManagerAdmin -sddcManagerAdminPassword $sddcManagerAdminPassword',
            'Invoke-NSXEdgeClusterRecoverySelective -nsxManagerFqdn $restoredNsxManagerFqdn -nsxManagerAdmin $restoredNsxManagerAdmin -nsxManagerAdminPassword $restoredNsxManagerAdminPassword -vCenterFQDN $restoredVcenterFqdn -vCenterAdmin $restoredvCenterAdmin -vCenterAdminPassword $restoredvCenterAdminPassword -clusterName $clusterName -extractedSDDCDataFile $extractedSDDCDataFile'
        )
    }

    $global:managementDomainRestoresStepRows = @()
    foreach ($commandLine in $managementDomainRestoresCommandLines) {
        $row = New-StepRow $commandLine
        [void]$managementDomainRestoresStepsListBox.Items.Add($row.Panel)
        $global:managementDomainRestoresStepRows += $row
    }
    $global:recoverDefaultClusterStepRows = @()
    foreach ($commandLine in $recoverDefaultClusterCommandLines) {
        $row = New-StepRow $commandLine
        [void]$recoverDefaultClusterStepsListBox.Items.Add($row.Panel)
        $global:recoverDefaultClusterStepRows += $row
    }
    $global:allStepCommandLines = @($managementDomainRestoresCommandLines) + @($recoverDefaultClusterCommandLines)
  } catch {
    $statusTextBlock.Text = "Domain selection handler failed: $($_.Exception.Message)"
  }
}.GetNewClosure())

$runAllManagementDomainRestoresButton.Add_Click({
    try {
        foreach ($row in $global:managementDomainRestoresStepRows) {
            Invoke-Step $row.Dot $row.CommandLine
        }
    } catch {
        $statusTextBlock.Text = "Run All failed: $($_.Exception.Message)"
    }
}.GetNewClosure())

$runAllRecoverDefaultClusterButton.Add_Click({
    try {
        foreach ($row in $global:recoverDefaultClusterStepRows) {
            Invoke-Step $row.Dot $row.CommandLine
        }
    } catch {
        $statusTextBlock.Text = "Run All failed: $($_.Exception.Message)"
    }
}.GetNewClosure())

Start-TerminalReadyWatcher

[void]$app.Run($window)
'@

    $initialSessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $uiRunspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($initialSessionState)
    $uiRunspace.ApartmentState = [System.Threading.ApartmentState]::STA
    $uiRunspace.ThreadOptions = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
    $uiRunspace.Open()

    $uiPowerShell = [System.Management.Automation.PowerShell]::Create()
    $uiPowerShell.Runspace = $uiRunspace
    [void]$uiPowerShell.AddScript($uiScript)
    [void]$uiPowerShell.AddArgument($xamlPath)
    [void]$uiPowerShell.AddArgument($libPath)

    # Kept alive at module script scope so the async UI isn't torn down by GC while the window is open.
    $script:InstanceRecoveryOrchestratorUIRunspace = $uiRunspace
    $script:InstanceRecoveryOrchestratorUIPowerShell = $uiPowerShell
    $script:InstanceRecoveryOrchestratorUIAsyncResult = $uiPowerShell.BeginInvoke()

    LogMessage -type NOTE -message "Instance Recovery Orchestrator UI launched."
}
Export-ModuleMember -Function Start-InstanceRecoveryUI

#EndRegion UI Orchestrator
