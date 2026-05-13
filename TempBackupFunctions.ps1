# Copyright 2025 Broadcom. All Rights Reserved.
# SPDX-License-Identifier: BSD-2
#
# Companion helpers for VMware Cloud Foundation SDDC Manager file-based backup & restore APIs.
# Style aligned with VMware.CloudFoundation.InstanceRecovery.psm1 (LogMessage, Param blocks, Invoke-RestMethod).
#
# API references (curl / JSON shapes):
#   POST /v1/tokens
#   POST /v1/backups/tasks       — body: { "elements": [ { "resourceType": "SDDC_MANAGER" } ] }
#   GET  /v1/tasks/{id}          — poll backup until status not IN_PROGRESS (per product docs)
#   POST /v1/restores/tasks      — body: elements, backupFile, encryption.passphrase
#   GET  /v1/restores/tasks/{id}
#   POST /v1/vsp-clusters                   — deploy new VCFMS runtime (New-VCFManagementServicesRuntime)
#   POST /api/v1/identity/token (SR node)              — VCFMS SR bearer token (Get-VCFMSServicesRuntimeAccessToken)
#   POST /api/v1/system/trusted-certificates?action=add     — trust remote cert on SR (Add-VCFMSServicesRuntimeTrustedCertificate)
#   POST /api/v1/components/{clusterId}?action=apply        — apply SFTP backup config (Set-VCFMSServicesRuntimeSftpBackupConfiguration)
#   GET  /api/v1/system/backups                             — list backups by component (Get-VCFMSServicesRuntimeBackups)
#   POST /api/v1/system/backups?action=restore              — restore components (New-VCFMSRestoreSpec + Invoke-VCFMSServicesRuntimeRestore)
#   GET  /fleet-lcm/v1/components (FC node)                — list/filter components (Get-VCFMSFleetComponents)
#
# Usage:  Import-Module .\VMware.CloudFoundation.InstanceRecovery.psm1   # optional, for LogMessage
#         . .\TempBackupFunctions.ps1
#
# SSH / Postgres (Remove-SDDCManagerPlatformManagementClusterRecords): requires module Posh-SSH (see Instance Recovery module prerequisites).

Function Write-BackupFunctionsLog {
    Param (
        [Parameter(Mandatory = $true)] [String]$message,
        [Parameter(Mandatory = $false)] [ValidateSet("INFO", "ERROR", "WARNING", "NOTE", "WAIT", "ADVISORY")] [String]$type = "INFO"
    )
    If (Get-Command -Name LogMessage -ErrorAction SilentlyContinue) {
        LogMessage -type $type -message $message
    } Else {
        $timeStamp = Get-Date -Format "MM-dd-yyyy_HH:mm:ss"
        Write-Host "[$timeStamp] [$type] $message"
    }
}

Function Get-RestMethodParams {
    <#
    .SYNOPSIS
        Adds -SkipCertificateCheck on PowerShell 7+ to match the module's behavior for dev/lab APIs.
    #>
    Param(
        [Parameter(Mandatory = $true)] [hashtable]$BaseParams
    )
    If ($PSEdition -eq 'Core') {
        $BaseParams['SkipCertificateCheck'] = $true
    }
    Return $BaseParams
}

Function Get-SDDCManagerAccessToken {
    <#
    .SYNOPSIS
        Obtains a bearer token from SDDC Manager (POST /v1/tokens).
    .EXAMPLE
        Get-SDDCManagerAccessToken -sddcManagerFqdn "sfo-vcf01.sfo.rainpole.io" -username "admin@local" -password "VMw@re1!"
    #>
    Param(
        [Parameter(Mandatory = $true)] [String]$sddcManagerFqdn,
        [Parameter(Mandatory = $true)] [String]$username,
        [Parameter(Mandatory = $true)] [String]$password
    )
    $tokenUri = "https://$sddcManagerFqdn/v1/tokens"
    $tokenBody = @{ username = $username; password = $password } | ConvertTo-Json
    $params = Get-RestMethodParams @{
        Uri             = $tokenUri
        Method          = 'POST'
        ContentType     = 'application/json'
        Body            = $tokenBody
    }
    Try {
        $tokenResponse = Invoke-RestMethod @params
        Return $tokenResponse.accessToken
    } Catch {
        If (Get-Command -Name catchWriter -ErrorAction SilentlyContinue) {
            catchWriter -object $_
        } Else {
            Write-BackupFunctionsLog -type ERROR -message $_.Exception.Message
        }
        Throw $_
    }
}

Function Get-SDDCManagerBearerHeaders {
    Param(
        [Parameter(Mandatory = $true)] [String]$sddcManagerFqdn,
        [Parameter(Mandatory = $true)] [String]$username,
        [Parameter(Mandatory = $true)] [String]$password
    )
    $accessToken = Get-SDDCManagerAccessToken -sddcManagerFqdn $sddcManagerFqdn -username $username -password $password
    Return @{
        "Authorization" = "Bearer $accessToken"
        "Content-Type"  = "application/json"
        "Accept"        = "application/json"
    }
}

Function Start-SDDCManagerBackup {
    <#
    .SYNOPSIS
        Starts an SDDC Manager file-based backup task (POST /v1/backups/tasks).
    .DESCRIPTION
        Default body matches the documented sample:
        { "elements": [ { "resourceType": "SDDC_MANAGER" } ] }
        Pass -BackupSpecJson to override the entire JSON body when your environment requires additional fields.
    .EXAMPLE
        Start-SDDCManagerBackup -sddcManagerFqdn "sfo-vcf01.sfo.rainpole.io" -username "admin@local" -password "VMw@re1!"
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)] [String]$sddcManagerFqdn,
        [Parameter(Mandatory = $true)] [String]$username,
        [Parameter(Mandatory = $true)] [String]$password,
        [Parameter(Mandatory = $false)] [String]$BackupSpecJson,
        [Parameter(Mandatory = $false)] [Switch]$PassThru
    )
    $jumpboxName = hostname
    Write-BackupFunctionsLog -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $headers = Get-SDDCManagerBearerHeaders -sddcManagerFqdn $sddcManagerFqdn -username $username -password $password
    If ($BackupSpecJson) {
        $body = $BackupSpecJson
    } Else {
        $spec = @{
            elements = @(
                @{ resourceType = "SDDC_MANAGER" }
            )
        }
        $body = $spec | ConvertTo-Json -Depth 10
    }
    $uri = "https://$sddcManagerFqdn/v1/backups/tasks"
    $params = Get-RestMethodParams @{
        Uri         = $uri
        Method      = 'POST'
        Headers     = $headers
        Body        = $body
        ContentType = 'application/json'
    }
    Try {
        $response = Invoke-RestMethod @params
        Write-BackupFunctionsLog -type INFO -message "[$sddcManagerFqdn] Backup task submitted; id=$($response.id) status=$($response.status)"
        Write-BackupFunctionsLog -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
        If ($PassThru) { Return $response } Else { Return $response.id }
    } Catch {
        If (Get-Command -Name catchWriter -ErrorAction SilentlyContinue) {
            catchWriter -object $_
        } Else {
            Write-BackupFunctionsLog -type ERROR -message $_.Exception.Message
        }
        Throw $_
    }
}

Function Get-SDDCManagerVcfTask {
    <#
    .SYNOPSIS
        Retrieves a task by id (GET /v1/tasks/{id}) — used to poll backup operations per product documentation.
    #>
    Param(
        [Parameter(Mandatory = $true)] [String]$sddcManagerFqdn,
        [Parameter(Mandatory = $true)] [String]$username,
        [Parameter(Mandatory = $true)] [String]$password,
        [Parameter(Mandatory = $true)] [String]$taskId
    )
    $headers = Get-SDDCManagerBearerHeaders -sddcManagerFqdn $sddcManagerFqdn -username $username -password $password
    $uri = "https://$sddcManagerFqdn/v1/tasks/$taskId"
    $params = Get-RestMethodParams @{
        Uri     = $uri
        Method  = 'GET'
        Headers = $headers
    }
    Try {
        Return Invoke-RestMethod @params
    } Catch {
        If (Get-Command -Name catchWriter -ErrorAction SilentlyContinue) {
            catchWriter -object $_
        } Else {
            Write-BackupFunctionsLog -type ERROR -message $_.Exception.Message
        }
        Throw $_
    }
}

Function Wait-SDDCManagerVcfTask {
    <#
    .SYNOPSIS
        Polls GET /v1/tasks/{id} until the task leaves an in-progress state.
    #>
    Param(
        [Parameter(Mandatory = $true)] [String]$sddcManagerFqdn,
        [Parameter(Mandatory = $true)] [String]$username,
        [Parameter(Mandatory = $true)] [String]$password,
        [Parameter(Mandatory = $true)] [String]$taskId,
        [Parameter(Mandatory = $false)] [Int]$PollSeconds = 60
    )
    $jumpboxName = hostname
    Write-BackupFunctionsLog -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $inProgress = @("IN_PROGRESS", "IN PROGRESS", "PENDING")
    Do {
        $task = Get-SDDCManagerVcfTask -sddcManagerFqdn $sddcManagerFqdn -username $username -password $password -taskId $taskId
        Write-BackupFunctionsLog -type INFO -message "[$sddcManagerFqdn] Task $taskId status=$($task.status)"
        If ($task.status -in $inProgress) {
            Start-Sleep -Seconds $PollSeconds
        }
    } While ($task.status -in $inProgress)
    Write-BackupFunctionsLog -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
    Return $task
}

Function Start-SDDCManagerRestore {
    <#
    .SYNOPSIS
        Starts an SDDC Manager restore from a backup file already on the appliance (POST /v1/restores/tasks).
    .DESCRIPTION
        JSON shape matches Invoke-SDDCManagerRestore / product examples:
        backupFile path on the SDDC Manager VM (e.g. /tmp/backup.tar.gz), encryption passphrase, elements SDDC_MANAGER.
    .EXAMPLE
        Start-SDDCManagerRestore -sddcManagerFqdn "sfo-vcf01.sfo.rainpole.io" -localPassword "VMw@re1!" -backupFileOnAppliance "/tmp/vcf-backup.tar.gz" -encryptionPassphrase "VMwareBackup@1"
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)] [String]$sddcManagerFqdn,
        [Parameter(Mandatory = $true)] [String]$localPassword,
        [Parameter(Mandatory = $true)] [String]$backupFileOnAppliance,
        [Parameter(Mandatory = $true)] [String]$encryptionPassphrase,
        [Parameter(Mandatory = $false)] [String]$localUsername = "admin@local",
        [Parameter(Mandatory = $false)] [String]$RestoreSpecJson,
        [Parameter(Mandatory = $false)] [Switch]$PassThru
    )
    $jumpboxName = hostname
    Write-BackupFunctionsLog -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $headers = Get-SDDCManagerBearerHeaders -sddcManagerFqdn $sddcManagerFqdn -username $localUsername -password $localPassword
    If ($RestoreSpecJson) {
        $body = $RestoreSpecJson
    } Else {
        $spec = @{
            elements   = @(@{ resourceType = "SDDC_MANAGER" })
            backupFile = $backupFileOnAppliance
            encryption = @{ passphrase = $encryptionPassphrase }
        }
        $body = $spec | ConvertTo-Json -Depth 10
    }
    $uri = "https://$sddcManagerFqdn/v1/restores/tasks"
    $params = Get-RestMethodParams @{
        Uri         = $uri
        Method      = 'POST'
        Headers     = $headers
        Body        = $body
        ContentType = 'application/json'
    }
    Try {
        $response = Invoke-RestMethod @params
        Write-BackupFunctionsLog -type INFO -message "[$sddcManagerFqdn] Restore task submitted; id=$($response.id) status=$($response.status)"
        Write-BackupFunctionsLog -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
        If ($PassThru) { Return $response } Else { Return $response.id }
    } Catch {
        If (Get-Command -Name catchWriter -ErrorAction SilentlyContinue) {
            catchWriter -object $_
        } Else {
            Write-BackupFunctionsLog -type ERROR -message $_.Exception.Message
        }
        Throw $_
    }
}

Function Get-SDDCManagerRestoreTask {
    <#
    .SYNOPSIS
        Retrieves restore task status (GET /v1/restores/tasks/{id}).
    #>
    Param(
        [Parameter(Mandatory = $true)] [String]$sddcManagerFqdn,
        [Parameter(Mandatory = $true)] [String]$username,
        [Parameter(Mandatory = $true)] [String]$password,
        [Parameter(Mandatory = $true)] [String]$restoreTaskId
    )
    $headers = Get-SDDCManagerBearerHeaders -sddcManagerFqdn $sddcManagerFqdn -username $username -password $password
    $uri = "https://$sddcManagerFqdn/v1/restores/tasks/$restoreTaskId"
    $params = Get-RestMethodParams @{
        Uri     = $uri
        Method  = 'GET'
        Headers = $headers
    }
    Try {
        Return Invoke-RestMethod @params
    } Catch {
        If (Get-Command -Name catchWriter -ErrorAction SilentlyContinue) {
            catchWriter -object $_
        } Else {
            Write-BackupFunctionsLog -type ERROR -message $_.Exception.Message
        }
        Throw $_
    }
}

Function Wait-SDDCManagerRestoreTask {
    <#
    .SYNOPSIS
        Polls restore task until status is not in progress (matches Invoke-SDDCManagerRestore behavior).
    #>
    Param(
        [Parameter(Mandatory = $true)] [String]$sddcManagerFqdn,
        [Parameter(Mandatory = $true)] [String]$username,
        [Parameter(Mandatory = $true)] [String]$password,
        [Parameter(Mandatory = $true)] [String]$restoreTaskId,
        [Parameter(Mandatory = $false)] [Int]$PollSeconds = 60
    )
    $jumpboxName = hostname
    Write-BackupFunctionsLog -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $inProgress = @("IN_PROGRESS", "IN PROGRESS")
    Do {
        $task = Get-SDDCManagerRestoreTask -sddcManagerFqdn $sddcManagerFqdn -username $username -password $password -restoreTaskId $restoreTaskId
        Write-BackupFunctionsLog -type INFO -message "[$sddcManagerFqdn] Restore $restoreTaskId status=$($task.status)"
        If ($task.status -in $inProgress) {
            Start-Sleep -Seconds $PollSeconds
        }
    } While ($task.status -in $inProgress)
    Write-BackupFunctionsLog -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
    Return $task
}

Function Get-SDDCManagerBackupConfiguration {
    <#
    .SYNOPSIS
        Returns backup configuration (GET /v1/system/backup-configuration) — e.g. schedules, locations.
    #>
    Param(
        [Parameter(Mandatory = $true)] [String]$sddcManagerFqdn,
        [Parameter(Mandatory = $true)] [String]$username,
        [Parameter(Mandatory = $true)] [String]$password
    )
    $headers = Get-SDDCManagerBearerHeaders -sddcManagerFqdn $sddcManagerFqdn -username $username -password $password
    $uri = "https://$sddcManagerFqdn/v1/system/backup-configuration"
    $params = Get-RestMethodParams @{
        Uri     = $uri
        Method  = 'GET'
        Headers = $headers
    }
    Try {
        Return Invoke-RestMethod @params
    } Catch {
        If (Get-Command -Name catchWriter -ErrorAction SilentlyContinue) {
            catchWriter -object $_
        } Else {
            Write-BackupFunctionsLog -type ERROR -message $_.Exception.Message
        }
        Throw $_
    }
}

#Region VCF Management Services (VCFMS) — token + vsp-clusters API

Function Get-VCFMSServicesRuntimeAccessToken {
    <#
    .SYNOPSIS
        Obtains a bearer access token from a VCFMS services runtime node (POST /api/v1/identity/token).
    .DESCRIPTION
        The VCFMS SR token endpoint uses an OAuth2 password grant with a form-encoded body, which is
        different from the SDDC Manager token endpoint (JSON body, different response field name).
        Endpoint : POST https://<vcfmsSrFqdn>/api/v1/identity/token
        Body     : Content-Type: application/x-www-form-urlencoded
                   grant_type=password&username=admin@vsp.local&password=<password>
        Response : { "access_token": "..." }
    .EXAMPLE
        $token = Get-VCFMSServicesRuntimeAccessToken -vcfmsSrFqdn "sfo-sr01.sfo.rainpole.io" -password "VMw@re1!VMw@re1!"
    .PARAMETER vcfmsSrFqdn
        FQDN of the VCFMS services runtime (sr) node.
    .PARAMETER password
        Password for the admin@vsp.local account.
    .PARAMETER username
        Identity username. Defaults to admin@vsp.local.
    #>
    Param(
        [Parameter (Mandatory = $true)]  [String]$vcfmsSrFqdn,
        [Parameter (Mandatory = $true)]  [String]$password,
        [Parameter (Mandatory = $false)] [String]$username = "admin@vsp.local"
    )
    $uri = "https://$vcfmsSrFqdn/api/v1/identity/token"
    $formBody = "grant_type=password&username=$([Uri]::EscapeDataString($username))&password=$([Uri]::EscapeDataString($password))"
    $params = Get-RestMethodParams @{
        Uri         = $uri
        Method      = 'POST'
        ContentType = 'application/x-www-form-urlencoded'
        Body        = $formBody
    }
    Try {
        $response = Invoke-RestMethod @params
        Return $response.access_token
    } Catch {
        If (Get-Command -Name catchWriter -ErrorAction SilentlyContinue) {
            catchWriter -object $_
        } Else {
            Write-BackupFunctionsLog -type ERROR -message $_.Exception.Message
        }
        Throw $_
    }
}

Function Get-VCFMSServicesRuntimeBearerHeaders {
    <#
    .SYNOPSIS
        Returns a headers hashtable with a VCFMS SR bearer token, ready for Invoke-RestMethod calls.
    .EXAMPLE
        $headers = Get-VCFMSServicesRuntimeBearerHeaders -vcfmsSrFqdn "sfo-sr01.sfo.rainpole.io" -password "VMw@re1!VMw@re1!"
    #>
    Param(
        [Parameter (Mandatory = $true)]  [String]$vcfmsSrFqdn,
        [Parameter (Mandatory = $true)]  [String]$password,
        [Parameter (Mandatory = $false)] [String]$username = "admin@vsp.local"
    )
    $accessToken = Get-VCFMSServicesRuntimeAccessToken -vcfmsSrFqdn $vcfmsSrFqdn -password $password -username $username
    Return @{
        "Authorization" = "Bearer $accessToken"
        "Content-Type"  = "application/json"
        "Accept"        = "application/json"
    }
}

#EndRegion VCF Management Services (VCFMS) — token

#Region VCF Management Services (VCFMS) — Fleet Controller token

Function Get-VCFMSFleetControllerAccessToken {
    <#
    .SYNOPSIS
        Obtains a bearer access token from a VCFMS Fleet Controller node (POST /api/v1/identity/token).
    .DESCRIPTION
        Same OAuth2 password-grant / form-encoded flow as Get-VCFMSServicesRuntimeAccessToken but
        targets the Fleet Controller (FC) host. The FC token is required for the fleet-lcm API
        (e.g. GET /fleet-lcm/v1/components).
        Endpoint : POST https://<vcfmsFcFqdn>/api/v1/identity/token
        Body     : Content-Type: application/x-www-form-urlencoded
                   grant_type=password&username=admin@vsp.local&password=<password>
        Response : { "access_token": "..." }
    .EXAMPLE
        $token = Get-VCFMSFleetControllerAccessToken -vcfmsFcFqdn "flt-fc01.rainpole.io" -password "VMw@re1!VMw@re1!"
    .PARAMETER vcfmsFcFqdn
        FQDN of the VCFMS Fleet Controller (fc) node.
    .PARAMETER password
        Password for the admin@vsp.local account on the FC.
    .PARAMETER username
        Identity username. Defaults to admin@vsp.local.
    #>
    Param(
        [Parameter (Mandatory = $true)]  [String]$vcfmsFcFqdn,
        [Parameter (Mandatory = $true)]  [String]$password,
        [Parameter (Mandatory = $false)] [String]$username = "admin@vsp.local"
    )
    $uri = "https://$vcfmsFcFqdn/api/v1/identity/token"
    $formBody = "grant_type=password&username=$([Uri]::EscapeDataString($username))&password=$([Uri]::EscapeDataString($password))"
    $params = Get-RestMethodParams @{
        Uri         = $uri
        Method      = 'POST'
        ContentType = 'application/x-www-form-urlencoded'
        Body        = $formBody
    }
    Try {
        $response = Invoke-RestMethod @params
        Return $response.access_token
    } Catch {
        If (Get-Command -Name catchWriter -ErrorAction SilentlyContinue) {
            catchWriter -object $_
        } Else {
            Write-BackupFunctionsLog -type ERROR -message $_.Exception.Message
        }
        Throw $_
    }
}

Function Get-VCFMSFleetControllerBearerHeaders {
    <#
    .SYNOPSIS
        Returns a headers hashtable with a VCFMS Fleet Controller bearer token.
    .EXAMPLE
        $headers = Get-VCFMSFleetControllerBearerHeaders -vcfmsFcFqdn "flt-fc01.rainpole.io" -password "VMw@re1!VMw@re1!"
    #>
    Param(
        [Parameter (Mandatory = $true)]  [String]$vcfmsFcFqdn,
        [Parameter (Mandatory = $true)]  [String]$password,
        [Parameter (Mandatory = $false)] [String]$username = "admin@vsp.local"
    )
    $accessToken = Get-VCFMSFleetControllerAccessToken -vcfmsFcFqdn $vcfmsFcFqdn -password $password -username $username
    Return @{
        "Authorization" = "Bearer $accessToken"
        "Content-Type"  = "application/json"
        "Accept"        = "application/json"
    }
}

#EndRegion VCF Management Services (VCFMS) — Fleet Controller token

#Region VCF Management Services (VCFMS) — Fleet Controller component query

Function Get-VCFMSFleetComponents {
    <#
    .SYNOPSIS
        Retrieves VCFMS component records from the Fleet Controller
        (GET /fleet-lcm/v1/components?includeConsumptionVsp=true&includeVcdMigrator=true).
    .DESCRIPTION
        When no -ComponentTypes are supplied all components are returned.
        When one or more -ComponentTypes are supplied only those matching componentTypeDescription
        (case-insensitive) are returned.
        For components with componentTypeDescription "VCF services runtime" the FQDN field is
        included in the output automatically.
        Returns an array of PSCustomObjects. Also emits a formatted table to the host unless
        -PassThru is set.
    .EXAMPLE
        # All components
        Get-VCFMSFleetComponents -vcfmsFcFqdn "flt-fc01.rainpole.io" -fcPassword "VMw@re1!VMw@re1!"

    .EXAMPLE
        # One or more specific component types
        Get-VCFMSFleetComponents -vcfmsFcFqdn "flt-fc01.rainpole.io" -fcPassword "VMw@re1!VMw@re1!" `
            -ComponentTypes "VCF services runtime", "Log management"

    .EXAMPLE
        # Return objects only (no table output)
        $components = Get-VCFMSFleetComponents -vcfmsFcFqdn "flt-fc01.rainpole.io" -fcPassword "VMw@re1!VMw@re1!" -PassThru

    .PARAMETER vcfmsFcFqdn
        FQDN of the VCFMS Fleet Controller (fc) node.
    .PARAMETER fcPassword
        Password for admin@vsp.local on the Fleet Controller.
    .PARAMETER ComponentTypes
        Optional. One or more componentTypeDescription strings to filter on (case-insensitive).
        When omitted, all components are returned.
    .PARAMETER fcUsername
        Fleet Controller identity username. Defaults to admin@vsp.local.
    .PARAMETER PassThru
        When set, suppresses the Format-Table host output and returns only the object array.
    #>
    [CmdletBinding()]
    Param(
        [Parameter (Mandatory = $true)]  [String]$vcfmsFcFqdn,
        [Parameter (Mandatory = $true)]  [String]$fcPassword,
        [Parameter (Mandatory = $false)] [String[]]$ComponentTypes,
        [Parameter (Mandatory = $false)] [String]$fcUsername = "admin@vsp.local",
        [Parameter (Mandatory = $false)] [Switch]$PassThru
    )
    $jumpboxName = hostname
    Write-BackupFunctionsLog -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $headers = Get-VCFMSFleetControllerBearerHeaders -vcfmsFcFqdn $vcfmsFcFqdn -password $fcPassword -username $fcUsername
    $uri = "https://$vcfmsFcFqdn/fleet-lcm/v1/components?includeConsumptionVsp=true&includeVcdMigrator=true"
    $params = Get-RestMethodParams @{
        Uri     = $uri
        Method  = 'GET'
        Headers = $headers
    }
    Try {
        $response = Invoke-RestMethod @params
        $allComponents = $response.components
        If ($ComponentTypes -and $ComponentTypes.Count -gt 0) {
            $allComponents = $allComponents | Where-Object {
                $cd = $_.componentTypeDescription
                ($ComponentTypes | Where-Object { $cd -like $_ }) -or
                ($ComponentTypes | Where-Object { $cd -eq $_ })
            }
        }
        $results = [System.Collections.Generic.List[PSCustomObject]]::new()
        Foreach ($component in $allComponents) {
            $isRuntime = $component.componentTypeDescription -like "*VCF services runtime*"
            $obj = [PSCustomObject]@{
                Id                      = $component.id
                ComponentTypeDescription = $component.componentTypeDescription
                Fqdn                    = If ($isRuntime -and $component.PSObject.Properties['fqdn']) { $component.fqdn } Else { $null }
            }
            $results.Add($obj)
        }
        Write-BackupFunctionsLog -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
        If (-not $PassThru) {
            # Conditionally include Fqdn column only when at least one row has a value
            $hasFqdn = ($results | Where-Object { $null -ne $_.Fqdn }) -as [bool]
            $columns  = If ($hasFqdn) { @('Id', 'ComponentTypeDescription', 'Fqdn') } Else { @('Id', 'ComponentTypeDescription') }
            $results | Format-Table -Property $columns -AutoSize | Out-String | ForEach-Object { Write-Host $_.TrimEnd() }
        }
        Return $results
    } Catch {
        If (Get-Command -Name catchWriter -ErrorAction SilentlyContinue) {
            catchWriter -object $_
        } Else {
            Write-BackupFunctionsLog -type ERROR -message $_.Exception.Message
        }
        Throw $_
    }
}

#EndRegion VCF Management Services (VCFMS) — Fleet Controller component query

#Region VCF Management Services (VCFMS) — trusted certificates API

Function Get-TlsEndpointCertificatePem {
    <#
    .SYNOPSIS
        Retrieves the leaf TLS certificate from a remote HTTPS endpoint and returns it as a PEM string.
    .DESCRIPTION
        Uses System.Net.Sockets.TcpClient + SslStream — no openssl binary required. Equivalent to:
          echo | openssl s_client -connect <host>:<port> 2>/dev/null | openssl x509 -outform pem
        The returned string is the PEM block (-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----).
    .EXAMPLE
        $pem = Get-TlsEndpointCertificatePem -hostname "sfo-ins01.sfo.rainpole.io"
    .PARAMETER hostname
        FQDN or IP of the remote host.
    .PARAMETER port
        TCP port. Defaults to 443.
    #>
    Param(
        [Parameter (Mandatory = $true)]  [String]$hostname,
        [Parameter (Mandatory = $false)] [Int]$port = 443
    )
    $client = $null
    $sslStream = $null
    Try {
        $client    = New-Object System.Net.Sockets.TcpClient($hostname, $port)
        $callback  = { param($sender, $cert, $chain, $errors) $true }
        $sslStream = New-Object System.Net.Security.SslStream($client.GetStream(), $false, $callback)
        $sslStream.AuthenticateAsClient($hostname)
        $cert      = $sslStream.RemoteCertificate
        $cert2     = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert)
        $b64       = [Convert]::ToBase64String($cert2.RawData, 'InsertLineBreaks')
        Return "-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----"
    } Catch {
        If (Get-Command -Name catchWriter -ErrorAction SilentlyContinue) {
            catchWriter -object $_
        } Else {
            Write-BackupFunctionsLog -type ERROR -message $_.Exception.Message
        }
        Throw $_
    } Finally {
        If ($null -ne $sslStream) { $sslStream.Dispose() }
        If ($null -ne $client)    { $client.Dispose() }
    }
}

Function Add-VCFMSServicesRuntimeTrustedCertificate {
    <#
    .SYNOPSIS
        Retrieves the TLS certificate from a remote endpoint and adds it to the VCFMS SR trust store
        (POST /api/v1/system/trusted-certificates?action=add).
    .DESCRIPTION
        Combines Get-TlsEndpointCertificatePem with a POST to the SR trusted-certificates API.
        Equivalent to the two-step curl pattern:
          echo | openssl s_client -connect <host>:443 2>/dev/null | openssl x509 -outform pem > cert.pem
          jq -n --arg cert "$CERT_DATA" '{cert: $cert}' | \
            curl -k -X POST "https://<sr>/api/v1/system/trusted-certificates?action=add" ...
        Uses Get-VCFMSServicesRuntimeBearerHeaders internally to obtain the SR token.
    .EXAMPLE
        Add-VCFMSServicesRuntimeTrustedCertificate `
            -vcfmsSrFqdn    "sfo-sr01.sfo.rainpole.io" `
            -srPassword     "VMw@re1!VMw@re1!" `
            -remoteHostname "sfo-ins01.sfo.rainpole.io"
    .PARAMETER vcfmsSrFqdn
        FQDN of the VCFMS services runtime (sr) node.
    .PARAMETER srPassword
        Password for admin@vsp.local on the SR node.
    .PARAMETER remoteHostname
        FQDN or IP of the host whose certificate should be trusted (e.g. the VCF Installer node).
    .PARAMETER remotePort
        TCP port on the remote host. Defaults to 443.
    .PARAMETER srUsername
        SR identity username. Defaults to admin@vsp.local.
    .PARAMETER CertPem
        Optional. Supply a PEM string directly to skip the automatic certificate retrieval step.
    #>
    [CmdletBinding()]
    Param(
        [Parameter (Mandatory = $true)]  [String]$vcfmsSrFqdn,
        [Parameter (Mandatory = $true)]  [String]$srPassword,
        [Parameter (Mandatory = $true)]  [String]$remoteHostname,
        [Parameter (Mandatory = $false)] [Int]$remotePort = 443,
        [Parameter (Mandatory = $false)] [String]$srUsername = "admin@vsp.local",
        [Parameter (Mandatory = $false)] [String]$CertPem
    )
    $jumpboxName = hostname
    Write-BackupFunctionsLog -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    If (-not $CertPem) {
        Write-BackupFunctionsLog -type INFO -message "[$jumpboxName] Retrieving TLS certificate from ${remoteHostname}:${remotePort}"
        $CertPem = Get-TlsEndpointCertificatePem -hostname $remoteHostname -port $remotePort
        Write-BackupFunctionsLog -type INFO -message "[$jumpboxName] Certificate retrieved from $remoteHostname"
    }
    $headers = Get-VCFMSServicesRuntimeBearerHeaders -vcfmsSrFqdn $vcfmsSrFqdn -password $srPassword -username $srUsername
    $body = @{ cert = $CertPem } | ConvertTo-Json -Depth 5
    $uri = "https://$vcfmsSrFqdn/api/v1/system/trusted-certificates?action=add"
    $params = Get-RestMethodParams @{
        Uri     = $uri
        Method  = 'POST'
        Headers = $headers
        Body    = $body
    }
    Try {
        $response = Invoke-RestMethod @params
        Write-BackupFunctionsLog -type INFO -message "[$vcfmsSrFqdn] Certificate from $remoteHostname added to trust store"
        Write-BackupFunctionsLog -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
        Return $response
    } Catch {
        If (Get-Command -Name catchWriter -ErrorAction SilentlyContinue) {
            catchWriter -object $_
        } Else {
            Write-BackupFunctionsLog -type ERROR -message $_.Exception.Message
        }
        Throw $_
    }
}

#EndRegion VCF Management Services (VCFMS) — trusted certificates API

#Region VCF Management Services (VCFMS) — SFTP backup configuration API

Function Get-SftpServerFingerprint {
    <#
    .SYNOPSIS
        Retrieves the SSH host key fingerprint from an SFTP/SSH server using pure .NET.
    .DESCRIPTION
        Equivalent to: ssh-keyscan -p <port> <host> | ssh-keygen -lf -
        Opens a raw TCP connection, reads the SSH banner and KEX_INIT/HOST_KEY bytes, then
        computes the SHA-256 fingerprint as a base64-encoded string in the format:
          SHA256:<base64>
        This matches the fingerprint format expected by the VCFMS backup SFTP spec.
        No ssh-keyscan or ssh-keygen binary required.
    .EXAMPLE
        $fp = Get-SftpServerFingerprint -sftpHost "10.167.173.126"
    .PARAMETER sftpHost
        IP address or FQDN of the SFTP server.
    .PARAMETER sftpPort
        SSH port. Defaults to 22.
    #>
    Param(
        [Parameter (Mandatory = $true)]  [String]$sftpHost,
        [Parameter (Mandatory = $false)] [Int]$sftpPort = 22
    )
    $client = $null
    Try {
        Write-BackupFunctionsLog -type INFO -message "[$sftpHost] Connecting to port $sftpPort to retrieve SSH host key fingerprint"
        $client = New-Object System.Net.Sockets.TcpClient
        $client.Connect($sftpHost, $sftpPort)
        $stream = $client.GetStream()
        $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::ASCII)
        $writer = New-Object System.IO.StreamWriter($stream, [System.Text.Encoding]::ASCII)
        $writer.AutoFlush = $true

        # Read server banner
        $banner = $reader.ReadLine()
        Write-BackupFunctionsLog -type INFO -message "[$sftpHost] SSH banner: $banner"

        # Send client banner so the server proceeds to send KEX_INIT
        $writer.WriteLine("SSH-2.0-PowerShell_VCFMS_KeyScan")

        # Read raw SSH packets until we find the host key in SSH2_MSG_KEXDH_REPLY (msg 31) or
        # SSH2_MSG_KEX_ECDH_REPLY (msg 31) / SSH2_MSG_KEXDH_GEX_REPLY (msg 33).
        # We parse the packet stream minimally: 4-byte length, 1-byte padding length, then payload.
        $buffer = New-Object Byte[] 65536
        $received = 0
        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        While ([DateTime]::UtcNow -lt $deadline -and $received -lt $buffer.Length) {
            If ($stream.DataAvailable) {
                $read = $stream.Read($buffer, $received, $buffer.Length - $received)
                $received += $read
            } Else {
                Start-Sleep -Milliseconds 50
            }
        }

        # Locate the server host key blob: scan for RSA/ECDSA/Ed25519 key type strings in payload
        $raw = $buffer[0..($received - 1)]
        $rawStr = [System.Text.Encoding]::ASCII.GetString($raw)

        # Extract the host key blob by finding known SSH key type prefixes
        $keyTypes = @('ssh-rsa', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'ssh-ed25519')
        $hostKeyBytes = $null
        Foreach ($keyType in $keyTypes) {
            $keyTypeBytes = [System.Text.Encoding]::ASCII.GetBytes($keyType)
            # Search for 4-byte length prefix + key type bytes (standard SSH string encoding)
            $lenBytes = [BitConverter]::GetBytes([UInt32]$keyType.Length)
            If ([BitConverter]::IsLittleEndian) { [Array]::Reverse($lenBytes) }
            $searchPattern = $lenBytes + $keyTypeBytes
            For ($i = 0; $i -le ($raw.Length - $searchPattern.Length); $i++) {
                $match = $true
                For ($j = 0; $j -lt $searchPattern.Length; $j++) {
                    If ($raw[$i + $j] -ne $searchPattern[$j]) { $match = $false; Break }
                }
                If ($match) {
                    # Read the blob length that precedes our key-type string (4 bytes before $i)
                    If ($i -ge 4) {
                        $blobLenBytes = $raw[($i - 4)..($i - 1)]
                        If (-not [BitConverter]::IsLittleEndian) { [Array]::Reverse($blobLenBytes) }
                        Else {
                            $blobLenBytes = $blobLenBytes[3], $blobLenBytes[2], $blobLenBytes[1], $blobLenBytes[0]
                        }
                        $blobLen = [BitConverter]::ToUInt32($blobLenBytes, 0)
                        $blobEnd = ($i - 4) + 4 + [int]$blobLen
                        If ($blobEnd -le $raw.Length) {
                            $hostKeyBytes = $raw[($i - 4)..($blobEnd - 1)]
                            Write-BackupFunctionsLog -type INFO -message "[$sftpHost] Located host key type: $keyType (blob $blobLen bytes)"
                            Break
                        }
                    }
                }
            }
            If ($null -ne $hostKeyBytes) { Break }
        }

        If ($null -eq $hostKeyBytes) {
            Throw "Could not locate SSH host key blob in server response from ${sftpHost}:${sftpPort}. Try supplying -Fingerprint directly."
        }

        # SHA-256 fingerprint of the raw key blob (same as ssh-keygen -lf -)
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        # The blob to hash is the key blob *without* its 4-byte length prefix
        $keyBlobOnly = $hostKeyBytes[4..($hostKeyBytes.Length - 1)]
        $hashBytes = $sha256.ComputeHash($keyBlobOnly)
        $b64 = [Convert]::ToBase64String($hashBytes).TrimEnd('=')
        $fingerprint = "SHA256:$b64"
        Write-BackupFunctionsLog -type INFO -message "[$sftpHost] Fingerprint: $fingerprint"
        Return $fingerprint
    } Catch {
        If (Get-Command -Name catchWriter -ErrorAction SilentlyContinue) {
            catchWriter -object $_
        } Else {
            Write-BackupFunctionsLog -type ERROR -message $_.Exception.Message
        }
        Throw $_
    } Finally {
        If ($null -ne $client) { $client.Dispose() }
    }
}

Function Set-VCFMSServicesRuntimeSftpBackupConfiguration {
    <#
    .SYNOPSIS
        Applies SFTP backup settings to a VCFMS runtime component
        (POST /api/v1/components/{clusterId}?action=apply).
    .DESCRIPTION
        Optionally auto-retrieves the SFTP server fingerprint via Get-SftpServerFingerprint.
        Matches the curl sample body exactly:
          spec.configuration.backups.destination, encryptionPassphrase, storage.sftp.*
        Uses Get-VCFMSServicesRuntimeBearerHeaders for the SR token.
    .EXAMPLE
        Set-VCFMSServicesRuntimeSftpBackupConfiguration `
            -vcfmsSrFqdn          "sfo-sr01.sfo.rainpole.io" `
            -srPassword           "VMw@re1!VMw@re1!" `
            -clusterId            "1f5c79fe-e3aa-41b1-a5cf-774a6497fa3d" `
            -sftpHost             "10.167.173.126" `
            -sftpDirectory        "/media/backups/" `
            -sftpUsername         "svc-vcf-bck" `
            -sftpPassword         "VMw@re1!" `
            -encryptionPassphrase "VMw@re1!VMw@re1!"
    .PARAMETER vcfmsSrFqdn
        FQDN of the VCFMS services runtime (sr) node.
    .PARAMETER srPassword
        Password for admin@vsp.local on the SR node.
    .PARAMETER clusterId
        vSphere cluster id of the VCFMS runtime instance (from the original deployment).
    .PARAMETER sftpHost
        IP or FQDN of the SFTP backup server.
    .PARAMETER sftpPort
        SFTP port. Defaults to 22.
    .PARAMETER sftpDirectory
        Remote directory path for backup storage.
    .PARAMETER sftpUsername
        Username for the SFTP server.
    .PARAMETER sftpPassword
        Password for the SFTP server user.
    .PARAMETER encryptionPassphrase
        Passphrase used to encrypt backup files.
    .PARAMETER Fingerprint
        Optional. SHA-256 fingerprint string (SHA256:<base64>). If omitted, it is retrieved
        automatically from the SFTP server via Get-SftpServerFingerprint.
    .PARAMETER srUsername
        SR identity username. Defaults to admin@vsp.local.
    #>
    [CmdletBinding()]
    Param(
        [Parameter (Mandatory = $true)]  [String]$vcfmsSrFqdn,
        [Parameter (Mandatory = $true)]  [String]$srPassword,
        [Parameter (Mandatory = $true)]  [String]$clusterId,
        [Parameter (Mandatory = $true)]  [String]$sftpHost,
        [Parameter (Mandatory = $false)] [Int]$sftpPort = 22,
        [Parameter (Mandatory = $true)]  [String]$sftpDirectory,
        [Parameter (Mandatory = $true)]  [String]$sftpUsername,
        [Parameter (Mandatory = $true)]  [String]$sftpPassword,
        [Parameter (Mandatory = $true)]  [String]$encryptionPassphrase,
        [Parameter (Mandatory = $false)] [String]$Fingerprint,
        [Parameter (Mandatory = $false)] [String]$srUsername = "admin@vsp.local"
    )
    $jumpboxName = hostname
    Write-BackupFunctionsLog -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    If (-not $Fingerprint) {
        Write-BackupFunctionsLog -type INFO -message "[$jumpboxName] No fingerprint supplied; retrieving from ${sftpHost}:${sftpPort}"
        $Fingerprint = Get-SftpServerFingerprint -sftpHost $sftpHost -sftpPort $sftpPort
    }
    Write-BackupFunctionsLog -type INFO -message "[$vcfmsSrFqdn] Applying SFTP backup configuration for cluster $clusterId"
    $headers = Get-VCFMSServicesRuntimeBearerHeaders -vcfmsSrFqdn $vcfmsSrFqdn -password $srPassword -username $srUsername
    $spec = @{
        spec    = @{
            configuration = @{
                backups = @{
                    destination          = "sftp"
                    encryptionPassphrase = $encryptionPassphrase
                    storage              = @{
                        sftp = @{
                            directory   = $sftpDirectory
                            host        = $sftpHost
                            port        = [String]$sftpPort
                            username    = $sftpUsername
                            password    = $sftpPassword
                            fingerprint = $Fingerprint
                        }
                    }
                }
            }
        }
        options = @{}
    }
    $body = $spec | ConvertTo-Json -Depth 10
    $uri = "https://$vcfmsSrFqdn/api/v1/components/$clusterId`?action=apply"
    $params = Get-RestMethodParams @{
        Uri     = $uri
        Method  = 'POST'
        Headers = $headers
        Body    = $body
    }
    Try {
        $response = Invoke-RestMethod @params
        Write-BackupFunctionsLog -type INFO -message "[$vcfmsSrFqdn] SFTP backup configuration applied to cluster $clusterId"
        Write-BackupFunctionsLog -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
        Return $response
    } Catch {
        If (Get-Command -Name catchWriter -ErrorAction SilentlyContinue) {
            catchWriter -object $_
        } Else {
            Write-BackupFunctionsLog -type ERROR -message $_.Exception.Message
        }
        Throw $_
    }
}

#EndRegion VCF Management Services (VCFMS) — SFTP backup configuration API

#Region VCF Management Services (VCFMS) — backup listing API

Function Get-VCFMSServicesRuntimeBackups {
    <#
    .SYNOPSIS
        Retrieves and displays a list of backups from the VCFMS SR, optionally filtered to one or more
        component types (GET /api/v1/system/backups).
    .DESCRIPTION
        Returns a sorted, human-readable table of backups matching the jq pipeline logic:
          - filters to the requested component types in the order they are specified
          - parses the backup name timestamp (ISO8601 with hyphens for time separators) into a real date
          - calculates how many days ago each backup was created
        Outputs a PSCustomObject array with columns:
          ComponentType, Version, Name, Age, Path
        Also emits the table to the host via Format-Table (equivalent to "| column -t").
        Use -PassThru to suppress the Format-Table output and work with the objects directly.
    .EXAMPLE
        Get-VCFMSServicesRuntimeBackups -vcfmsSrFqdn "sfo-sr01.sfo.rainpole.io" -srPassword "VMw@re1!VMw@re1!"

    .EXAMPLE
        Get-VCFMSServicesRuntimeBackups -vcfmsSrFqdn "sfo-sr01.sfo.rainpole.io" -srPassword "VMw@re1!VMw@re1!" `
            -Components @("vsp", "salt", "vidb")

    .PARAMETER vcfmsSrFqdn
        FQDN of the VCFMS services runtime (sr) node.
    .PARAMETER srPassword
        Password for admin@vsp.local on the SR node.
    .PARAMETER Components
        Ordered list of component types to include. Results are returned in this order.
        Valid values: vsp, vcf-fleet-lcm, vcf-fleet-depot, vcf-sddc-lcm, salt, salt-raas, vidb, ops-logs.
        Defaults to all known component types in the canonical order.
    .PARAMETER srUsername
        SR identity username. Defaults to admin@vsp.local.
    .PARAMETER PassThru
        When set, suppresses the Format-Table host output and returns only the object array.
    #>
    [CmdletBinding()]
    Param(
        [Parameter (Mandatory = $true)]  [String]$vcfmsSrFqdn,
        [Parameter (Mandatory = $true)]  [String]$srPassword,
        [Parameter (Mandatory = $false)]
        [ValidateSet("vsp", "vcf-fleet-lcm", "vcf-fleet-depot", "vcf-sddc-lcm", "salt", "salt-raas", "vidb", "ops-logs")]
        [String[]]$Components = @("vsp", "vcf-fleet-lcm", "vcf-fleet-depot", "vcf-sddc-lcm", "salt", "salt-raas", "vidb", "ops-logs"),
        [Parameter (Mandatory = $false)] [String]$srUsername = "admin@vsp.local",
        [Parameter (Mandatory = $false)] [Switch]$PassThru
    )
    $jumpboxName = hostname
    Write-BackupFunctionsLog -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $headers = Get-VCFMSServicesRuntimeBearerHeaders -vcfmsSrFqdn $vcfmsSrFqdn -password $srPassword -username $srUsername
    $uri = "https://$vcfmsSrFqdn/api/v1/system/backups"
    $params = Get-RestMethodParams @{
        Uri     = $uri
        Method  = 'GET'
        Headers = $headers
    }
    Try {
        $response = Invoke-RestMethod @params
        $allBackups = $response.backups
        $now = [DateTime]::UtcNow
        $results = [System.Collections.Generic.List[PSCustomObject]]::new()
        Foreach ($componentType in $Components) {
            $matches = $allBackups | Where-Object { $_.component.type -eq $componentType }
            Foreach ($backup in $matches) {
                # Parse backup name timestamp — format uses hyphens for time separators:
                # e.g. "…2024-11-15T14-32-07Z" → normalise to "2024-11-15T14:32:07Z"
                $normalised = $backup.name -replace 'T(\d{2})-(\d{2})-(\d{2})Z', 'T$1:$2:$3Z'
                $backupDate = $null
                $daysAgo    = 'unknown'
                If ([DateTime]::TryParse($normalised, [ref]$backupDate)) {
                    $daysAgo = "$([Math]::Floor(($now - $backupDate.ToUniversalTime()).TotalDays)) days ago"
                }
                $results.Add([PSCustomObject]@{
                    ComponentType = $componentType
                    Version       = $backup.component.version
                    Name          = $backup.name
                    Age           = $daysAgo
                    Path          = $backup.path
                })
            }
        }
        Write-BackupFunctionsLog -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
        If (-not $PassThru) {
            $results | Format-Table -Property ComponentType, Version, Name, Age, Path -AutoSize | Out-String | ForEach-Object { Write-Host $_.TrimEnd() }
        }
        Return $results
    } Catch {
        If (Get-Command -Name catchWriter -ErrorAction SilentlyContinue) {
            catchWriter -object $_
        } Else {
            Write-BackupFunctionsLog -type ERROR -message $_.Exception.Message
        }
        Throw $_
    }
}

#EndRegion VCF Management Services (VCFMS) — backup listing API

#Region VCF Management Services (VCFMS) — restore API

Function New-VCFMSRestoreSpec {
    <#
    .SYNOPSIS
        Interactively builds a restore spec array from the output of Get-VCFMSServicesRuntimeBackups.
    .DESCRIPTION
        Presents the available backups for each requested component type one at a time and prompts the
        user to select which backup point to restore. Returns an array of hashtables:
          @( @{ path = "sftp://..."; point = "2026-03-23T16-45-31Z" }, ... )
        Pass the returned array directly to Invoke-VCFMSServicesRuntimeRestore via -RestoreComponents,
        or use -AsJson to get the serialised JSON string instead.
        Components are presented in the order supplied (defaults to canonical order).
    .EXAMPLE
        $spec = New-VCFMSRestoreSpec -backups $backups
        Invoke-VCFMSServicesRuntimeRestore -vcfmsSrFqdn "sfo-sr01.sfo.rainpole.io" -srPassword "..." -RestoreComponents $spec

    .EXAMPLE
        # Build spec and inspect JSON before submitting
        $json = New-VCFMSRestoreSpec -backups $backups -AsJson
        Write-Host $json

    .PARAMETER backups
        The PSCustomObject array returned by Get-VCFMSServicesRuntimeBackups.
    .PARAMETER Components
        Component types to include in the restore. Defaults to all types present in -backups.
    .PARAMETER AsJson
        Return the spec as a serialised JSON string instead of an object array.
    #>
    [CmdletBinding()]
    Param(
        [Parameter (Mandatory = $true)]  [PSCustomObject[]]$backups,
        [Parameter (Mandatory = $false)]
        [ValidateSet("vsp", "vcf-fleet-lcm", "vcf-fleet-depot", "vcf-sddc-lcm", "salt", "salt-raas", "vidb", "ops-logs")]
        [String[]]$Components,
        [Parameter (Mandatory = $false)] [Switch]$AsJson
    )
    If (-not $Components) {
        # Preserve order of first appearance in the backup list
        $seen = [System.Collections.Generic.List[String]]::new()
        Foreach ($b in $backups) {
            If (-not $seen.Contains($b.ComponentType)) { $seen.Add($b.ComponentType) }
        }
        $Components = $seen.ToArray()
    }
    $restoreComponents = [System.Collections.Generic.List[hashtable]]::new()
    Foreach ($componentType in $Components) {
        $available = @($backups | Where-Object { $_.ComponentType -eq $componentType })
        If ($available.Count -eq 0) {
            Write-BackupFunctionsLog -type WARNING -message "No backups found for component '$componentType' — skipping."
            Continue
        }
        Write-Host ""
        Write-Host " Available backups for component: $componentType" -ForegroundColor Cyan
        Write-Host ""
        $displayList = @()
        For ($i = 0; $i -lt $available.Count; $i++) {
            $displayList += [PSCustomObject]@{
                ID      = $i + 1
                Name    = $available[$i].Name
                Version = $available[$i].Version
                Age     = $available[$i].Age
                Path    = $available[$i].Path
            }
        }
        $displayList | Format-Table -Property ID, Name, Version, Age -AutoSize | Out-String | ForEach-Object { Write-Host $_.TrimEnd() }
        Do {
            Write-Host " Enter the ID of the backup to restore for '$componentType', or S to skip: " -ForegroundColor Yellow -NoNewline
            $selection = Read-Host
        } Until ($selection -eq 's' -or ($selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $available.Count))
        If ($selection -eq 's') {
            Write-BackupFunctionsLog -type ADVISORY -message "Skipped component '$componentType'."
            Continue
        }
        $chosen = $available[[int]$selection - 1]
        # Extract the point timestamp from the trailing segment of the path
        $point = ($chosen.Path -split '/')[-1]
        $restoreComponents.Add(@{
            path  = $chosen.Path
            point = $point
        })
        Write-BackupFunctionsLog -type INFO -message "Selected for '$componentType': $($chosen.Name)"
    }
    If ($restoreComponents.Count -eq 0) {
        Throw "No components selected — restore spec is empty."
    }
    If ($AsJson) {
        Return (@{ components = $restoreComponents.ToArray() } | ConvertTo-Json -Depth 10)
    }
    Return $restoreComponents.ToArray()
}

Function Invoke-VCFMSServicesRuntimeRestore {
    <#
    .SYNOPSIS
        Submits a restore operation to the VCFMS SR (POST /api/v1/system/backups?action=restore).
    .DESCRIPTION
        Accepts either:
          -RestoreComponents  : the array returned by New-VCFMSRestoreSpec (preferred)
          -RestoreSpecJson    : a fully-formed JSON string for scripted/unattended use
        The JSON body shape matches the documented curl sample:
          { "components": [ { "path": "sftp://...", "point": "2026-03-23T16-45-31Z" }, ... ] }
    .EXAMPLE
        # Interactive — build spec then restore
        $backups = Get-VCFMSServicesRuntimeBackups -vcfmsSrFqdn "sfo-sr01.sfo.rainpole.io" -srPassword "VMw@re1!VMw@re1!" -PassThru
        $spec    = New-VCFMSRestoreSpec -backups $backups
        Invoke-VCFMSServicesRuntimeRestore -vcfmsSrFqdn "sfo-sr01.sfo.rainpole.io" -srPassword "VMw@re1!VMw@re1!" -RestoreComponents $spec

    .EXAMPLE
        # Unattended — supply raw JSON
        Invoke-VCFMSServicesRuntimeRestore -vcfmsSrFqdn "sfo-sr01.sfo.rainpole.io" -srPassword "VMw@re1!VMw@re1!" -RestoreSpecJson $json

    .PARAMETER vcfmsSrFqdn
        FQDN of the VCFMS services runtime (sr) node.
    .PARAMETER srPassword
        Password for admin@vsp.local on the SR node.
    .PARAMETER RestoreComponents
        Array of @{ path; point } hashtables produced by New-VCFMSRestoreSpec.
    .PARAMETER RestoreSpecJson
        Fully-formed JSON string override. When supplied, -RestoreComponents is ignored.
    .PARAMETER srUsername
        SR identity username. Defaults to admin@vsp.local.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    Param(
        [Parameter (Mandatory = $true)]  [String]$vcfmsSrFqdn,
        [Parameter (Mandatory = $true)]  [String]$srPassword,
        [Parameter (Mandatory = $false)] [hashtable[]]$RestoreComponents,
        [Parameter (Mandatory = $false)] [String]$RestoreSpecJson,
        [Parameter (Mandatory = $false)] [String]$srUsername = "admin@vsp.local"
    )
    If (-not $RestoreComponents -and -not $RestoreSpecJson) {
        Throw "Either -RestoreComponents or -RestoreSpecJson must be supplied."
    }
    $jumpboxName = hostname
    Write-BackupFunctionsLog -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    If (-not $PSCmdlet.ShouldProcess($vcfmsSrFqdn, "Trigger VCFMS restore for $($RestoreComponents.Count) component(s)")) {
        Return
    }
    $headers = Get-VCFMSServicesRuntimeBearerHeaders -vcfmsSrFqdn $vcfmsSrFqdn -password $srPassword -username $srUsername
    If ($RestoreSpecJson) {
        $body = $RestoreSpecJson
    } Else {
        $body = @{ components = $RestoreComponents } | ConvertTo-Json -Depth 10
    }
    $uri = "https://$vcfmsSrFqdn/api/v1/system/backups?action=restore"
    $params = Get-RestMethodParams @{
        Uri     = $uri
        Method  = 'POST'
        Headers = $headers
        Body    = $body
    }
    Try {
        $response = Invoke-RestMethod @params
        Write-BackupFunctionsLog -type INFO -message "[$vcfmsSrFqdn] Restore request accepted"
        Write-BackupFunctionsLog -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
        Return $response
    } Catch {
        If (Get-Command -Name catchWriter -ErrorAction SilentlyContinue) {
            catchWriter -object $_
        } Else {
            Write-BackupFunctionsLog -type ERROR -message $_.Exception.Message
        }
        Throw $_
    }
}

#EndRegion VCF Management Services (VCFMS) — restore API

#Region VCF Management Services (VCFMS) — vsp-clusters API

Function New-VCFManagementServicesRuntime {
    <#
    .SYNOPSIS
        Deploys a new VCF Management Services (VCFMS) runtime instance via POST /v1/vsp-clusters.
    .DESCRIPTION
        The domain id, FQDNs, and clusterId must match the original Management Domain values.
        Uses Get-SDDCManagerBearerHeaders to obtain the bearer token automatically.
        Returns the 202-Accepted response object; poll with Get-SDDCManagerVcfTask to track progress.
    .EXAMPLE
        $spec = @{
            DomainId               = "0810c87d-3758-4c28-95fc-458b1196f4eb"
            PlatformFqdn           = "sfo-sr01.sfo.rainpole.io"
            InstanceFqdn           = "sfo-ic01.sfo.rainpole.io"
            FleetFqdn              = "flt-fc01.rainpole.io"
            SystemUserPassword     = "VMw@re1!VMw@re1!"
            Ipv4PoolAddresses      = @("10.11.99.29","10.11.99.30","10.11.99.31","10.11.99.32","10.11.99.33",
                                       "10.11.99.34","10.11.99.35","10.11.99.36","10.11.99.37","10.11.99.38",
                                       "10.11.99.39","10.11.99.40")
            Size                   = "small"
            NetworkMoId            = "dvportgroup-28"
            GatewayCidrIpv4        = "10.11.99.1/24"
            ClusterId              = "1f5c79fe-e3aa-41b1-a5cf-774a6497fa3d"
            InternalClusterCidrIpv4 = "198.18.0.0/15"
        }
        New-VCFManagementServicesRuntime -sddcManagerFqdn "sfo-vcf01.sfo.rainpole.io" -username "admin@local" -password "VMw@re1!" @spec

    .PARAMETER sddcManagerFqdn
        FQDN of the SDDC Manager appliance.

    .PARAMETER username
        Username to authenticate with SDDC Manager (e.g. admin@local).

    .PARAMETER password
        Password for the SDDC Manager user.

    .PARAMETER DomainId
        Management Domain id from SDDC Manager. Must match the original.

    .PARAMETER PlatformFqdn
        FQDN of the platform (sr) node. Must match the original.

    .PARAMETER InstanceFqdn
        FQDN of the instance (ic) node. Must match the original.

    .PARAMETER FleetFqdn
        FQDN of the fleet node. Must match the original.

    .PARAMETER SystemUserPassword
        Password for the VCFMS system user.

    .PARAMETER Ipv4PoolAddresses
        Array of IPv4 addresses for the pool (supply all 12 addresses from the original deployment).

    .PARAMETER Size
        Deployment size. Valid values: small, medium, large. Default: small.

    .PARAMETER NetworkMoId
        vSphere Managed Object ID of the target port group (e.g. dvportgroup-28).

    .PARAMETER GatewayCidrIpv4
        Gateway IP and prefix in CIDR notation (e.g. 10.11.99.1/24).

    .PARAMETER ClusterId
        vSphere cluster id. Must match the original.

    .PARAMETER InternalClusterCidrIpv4
        Internal cluster CIDR (e.g. 198.18.0.0/15).

    .PARAMETER VspClusterSpecJson
        Optional. Provide a fully-formed JSON string to override the entire request body.
    #>
    [CmdletBinding()]
    Param(
        [Parameter (Mandatory = $true)] [String]$sddcManagerFqdn,
        [Parameter (Mandatory = $true)] [String]$username,
        [Parameter (Mandatory = $true)] [String]$password,
        [Parameter (Mandatory = $true)] [String]$DomainId,
        [Parameter (Mandatory = $true)] [String]$PlatformFqdn,
        [Parameter (Mandatory = $true)] [String]$InstanceFqdn,
        [Parameter (Mandatory = $true)] [String]$FleetFqdn,
        [Parameter (Mandatory = $true)] [String]$SystemUserPassword,
        [Parameter (Mandatory = $true)] [String[]]$Ipv4PoolAddresses,
        [Parameter (Mandatory = $false)] [ValidateSet("small", "medium", "large")] [String]$Size = "small",
        [Parameter (Mandatory = $true)] [String]$NetworkMoId,
        [Parameter (Mandatory = $true)] [String]$GatewayCidrIpv4,
        [Parameter (Mandatory = $true)] [String]$ClusterId,
        [Parameter (Mandatory = $true)] [String]$InternalClusterCidrIpv4,
        [Parameter (Mandatory = $false)] [String]$VspClusterSpecJson
    )
    $jumpboxName = hostname
    Write-BackupFunctionsLog -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $headers = Get-SDDCManagerBearerHeaders -sddcManagerFqdn $sddcManagerFqdn -username $username -password $password
    If ($VspClusterSpecJson) {
        $body = $VspClusterSpecJson
    } Else {
        $spec = [ordered]@{
            domainId                = $DomainId
            platformFqdn            = $PlatformFqdn
            instanceFqdn            = $InstanceFqdn
            fleetFqdn               = $FleetFqdn
            systemUserPassword      = $SystemUserPassword
            type                    = "MANAGEMENT"
            ipv4Pool                = @{
                addresses = $Ipv4PoolAddresses
            }
            size                    = $Size
            networkMoId             = $NetworkMoId
            gatewayCidrIpv4         = $GatewayCidrIpv4
            clusterId               = $ClusterId
            internalClusterCidrIpv4 = $InternalClusterCidrIpv4
        }
        $body = $spec | ConvertTo-Json -Depth 10
    }
    $uri = "https://$sddcManagerFqdn/v1/vsp-clusters"
    $params = Get-RestMethodParams @{
        Uri         = $uri
        Method      = 'POST'
        Headers     = $headers
        Body        = $body
        ContentType = 'application/json'
    }
    Try {
        $response = Invoke-RestMethod @params
        Write-BackupFunctionsLog -type INFO -message "[$sddcManagerFqdn] VCFMS deploy task submitted; id=$($response.id) status=$($response.status)"
        Write-BackupFunctionsLog -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
        Return $response
    } Catch {
        If (Get-Command -Name catchWriter -ErrorAction SilentlyContinue) {
            catchWriter -object $_
        } Else {
            Write-BackupFunctionsLog -type ERROR -message $_.Exception.Message
        }
        Throw $_
    }
}

#EndRegion VCF Management Services (VCFMS) — vsp-clusters API

#Region SDDC Manager SSH / Postgres (platform database)

Function Escape-BashSingleQuoted {
    Param([Parameter(Mandatory = $true)] [String]$Value)
    # Embed a string inside bash single quotes: o'brien -> o'\''brien
    Return ($Value -replace "'", "'\''")
}

Function Connect-SDDCManagerPoshSshSession {
    <#
    .SYNOPSIS
        Opens an SSH session to the SDDC Manager appliance as user vcf (same pattern as VMware.CloudFoundation.InstanceRecovery.psm1).
    #>
    Param(
        [Parameter(Mandatory = $true)] [String]$sddcManagerFqdn,
        [Parameter(Mandatory = $true)] [String]$vcfPassword
    )
    Import-Module Posh-SSH -ErrorAction Stop
    $SecurePassword = ConvertTo-SecureString -String $vcfPassword -AsPlainText -Force
    $mycreds = New-Object System.Management.Automation.PSCredential ('vcf', $SecurePassword)
    Get-SSHTrustedHost | Remove-SSHTrustedHost | Out-Null
    $inmem = New-SSHMemoryKnownHost
    New-SSHTrustedHost -KnownHostStore $inmem -HostName $sddcManagerFqdn -FingerPrint ((Get-SSHHostKey -ComputerName $sddcManagerFqdn).fingerprint) | Out-Null
    Do {
        $sshSession = New-SSHSession -computername $sddcManagerFqdn -Credential $mycreds -KnownHost $inmem
    } Until ($sshSession)
    Return @{ Session = $sshSession; KnownHost = $inmem }
}

Function Invoke-SDDCManagerRemoteScriptAsRoot {
    <#
    .SYNOPSIS
        Runs bash on the appliance as root via: printf '%s\n' '<rootPassword>' | su -c 'echo <b64> | base64 -d | bash' root
    #>
    Param(
        [Parameter(Mandatory = $true)] $SshSession,
        [Parameter(Mandatory = $true)] [String]$RootPassword,
        [Parameter(Mandatory = $true)] [String]$BashScript
    )
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($BashScript.TrimEnd())
    $b64 = [Convert]::ToBase64String($bytes)
    $rootEsc = Escape-BashSingleQuoted -Value $RootPassword
    $remoteCmd = "printf '%s\n' '$rootEsc' | su -c `"echo $b64 | base64 -d | bash`" root"
    Return Invoke-SSHCommand -timeout 120 -sessionid $SshSession.SessionId -command $remoteCmd
}

Function Get-SDDCManagerManagementVspClusterId {
    <#
    .SYNOPSIS
        SSH as vcf, elevate to root, run psql against database platform and return the id for the MANAGEMENT vsp_clusters row.
    .DESCRIPTION
        Equivalent to: psql -U postgres -h localhost -d platform -c "SELECT id FROM vsp_clusters WHERE type = 'MANAGEMENT'"
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)] [String]$sddcManagerFqdn,
        [Parameter(Mandatory = $true)] [String]$vcfPassword,
        [Parameter(Mandatory = $true)] [String]$rootPassword,
        [Parameter(Mandatory = $false)] [String]$VspClustersTable = 'vsp_clusters',
        [Parameter(Mandatory = $false)] [String]$PostgresDatabase = 'platform'
    )
    $jumpboxName = hostname
    Write-BackupFunctionsLog -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    $template = @'
set -euo pipefail
PSQL=(/usr/bin/psql -U postgres -h localhost -d __POSTGRES_DB__)
ID=$("${PSQL[@]}" -t -A -c "SELECT id FROM __VSP_TABLE__ WHERE type = 'MANAGEMENT' LIMIT 1;" | tr -d '[:space:]')
echo "MANAGEMENT_VSP_CLUSTER_ID=${ID}"
'@
    $bash = $template.Replace('__POSTGRES_DB__', $PostgresDatabase).Replace('__VSP_TABLE__', $VspClustersTable)
    $ctx = $null
    Try {
        $ctx = Connect-SDDCManagerPoshSshSession -sddcManagerFqdn $sddcManagerFqdn -vcfPassword $vcfPassword
        $result = Invoke-SDDCManagerRemoteScriptAsRoot -SshSession $ctx.Session -RootPassword $rootPassword -BashScript $bash
        $outLines = if ($null -eq $result.Output) {
            @()
        } elseif ($result.Output -is [string]) {
            @($result.Output -split "`r?`n")
        } Else {
            @($result.Output)
        }
        $outText = ($outLines | Out-String).Trim()
        Write-BackupFunctionsLog -type INFO -message "[$sddcManagerFqdn] psql output:`n$outText"
        If ($null -ne $result.ExitStatus -and [int]$result.ExitStatus -ne 0) {
            Throw "Remote script exited with status $($result.ExitStatus)"
        }
        $line = ($outLines | Where-Object { $_ -match '^MANAGEMENT_VSP_CLUSTER_ID=' } | Select-Object -First 1)
        If (-not $line) {
            Throw "Could not parse MANAGEMENT_VSP_CLUSTER_ID from script output."
        }
        Return (($line -replace '^MANAGEMENT_VSP_CLUSTER_ID=', '').Trim())
    } Catch {
        If (Get-Command -Name catchWriter -ErrorAction SilentlyContinue) {
            catchWriter -object $_
        } Else {
            Write-BackupFunctionsLog -type ERROR -message $_.Exception.Message
        }
        Throw $_
    } Finally {
        If ($null -ne $ctx -and $null -ne $ctx.Session) {
            Remove-SSHSession -SSHSession $ctx.Session | Out-Null
        }
        Write-BackupFunctionsLog -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
    }
}

Function Remove-SDDCManagerPlatformManagementClusterRecords {
    <#
    .SYNOPSIS
        SSH as vcf, elevate to root, connect to Postgres (platform), remove the MANAGEMENT vsp_clusters row and matching svc-sddc-manager-admin credential.
    .DESCRIPTION
        Runs:
          SELECT id (recorded in script output) where type = MANAGEMENT;
          DELETE FROM <vsp_clusters> WHERE type = 'MANAGEMENT';
          DELETE FROM credential WHERE username = 'vsp/<id>/svc-sddc-manager-admin';
        Default table name is vsp_clusters. If your schema uses vsp_cluster, pass -VspClustersTable vsp_cluster.
    .EXAMPLE
        Remove-SDDCManagerPlatformManagementClusterRecords -sddcManagerFqdn "sfo-vcf01.sfo.rainpole.io" -vcfPassword "..." -rootPassword "..." -Confirm:$false
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $true)] [String]$sddcManagerFqdn,
        [Parameter(Mandatory = $true)] [String]$vcfPassword,
        [Parameter(Mandatory = $true)] [String]$rootPassword,
        [Parameter(Mandatory = $false)] [String]$VspClustersTable = 'vsp_clusters',
        [Parameter(Mandatory = $false)] [String]$CredentialTable = 'credential',
        [Parameter(Mandatory = $false)] [String]$PostgresDatabase = 'platform'
    )
    $jumpboxName = hostname
    Write-BackupFunctionsLog -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"
    If (-not $PSCmdlet.ShouldProcess($sddcManagerFqdn, "Delete MANAGEMENT row from $VspClustersTable and related credential in $PostgresDatabase")) {
        Return
    }
    $template = @'
set -euo pipefail
PSQL=(/usr/bin/psql -U postgres -h localhost -d __POSTGRES_DB__)
ID=$("${PSQL[@]}" -t -A -c "SELECT id FROM __VSP_TABLE__ WHERE type = 'MANAGEMENT' LIMIT 1;" | tr -d '[:space:]')
if [[ -z "$ID" ]]; then
  echo "No MANAGEMENT row found in __VSP_TABLE__; nothing to delete." >&2
  exit 1
fi
echo "Recorded MANAGEMENT vsp_cluster id: ${ID}"
"${PSQL[@]}" -v ON_ERROR_STOP=1 -c "DELETE FROM __VSP_TABLE__ WHERE type = 'MANAGEMENT';"
USER_NAME="vsp/${ID}/svc-sddc-manager-admin"
"${PSQL[@]}" -v ON_ERROR_STOP=1 -c "DELETE FROM __CRED_TABLE__ WHERE username='${USER_NAME}';"
echo "Deletes completed."
'@
    $bash = $template.Replace('__POSTGRES_DB__', $PostgresDatabase).Replace('__VSP_TABLE__', $VspClustersTable).Replace('__CRED_TABLE__', $CredentialTable)
    $ctx = $null
    Try {
        $ctx = Connect-SDDCManagerPoshSshSession -sddcManagerFqdn $sddcManagerFqdn -vcfPassword $vcfPassword
        $result = Invoke-SDDCManagerRemoteScriptAsRoot -SshSession $ctx.Session -RootPassword $rootPassword -BashScript $bash
        $outLines = if ($null -eq $result.Output) {
            @()
        } elseif ($result.Output -is [string]) {
            @($result.Output -split "`r?`n")
        } Else {
            @($result.Output)
        }
        $outText = ($outLines | Out-String).Trim()
        Write-BackupFunctionsLog -type INFO -message "[$sddcManagerFqdn] psql output:`n$outText"
        If ($null -ne $result.ExitStatus -and [int]$result.ExitStatus -ne 0) {
            Throw "Remote script exited with status $($result.ExitStatus)"
        }
    } Catch {
        If (Get-Command -Name catchWriter -ErrorAction SilentlyContinue) {
            catchWriter -object $_
        } Else {
            Write-BackupFunctionsLog -type ERROR -message $_.Exception.Message
        }
        Throw $_
    } Finally {
        If ($null -ne $ctx -and $null -ne $ctx.Session) {
            Remove-SSHSession -SSHSession $ctx.Session | Out-Null
        }
        Write-BackupFunctionsLog -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand)"
    }
}

#EndRegion SDDC Manager SSH / Postgres (platform database)
