Function LogMessage {
    Param (
        [Parameter (Mandatory = $true)] [AllowEmptyString()] [String]$message,
        [Parameter (Mandatory = $false)] [Switch]$nonewline,
        [Parameter (Mandatory = $false)] [ValidateSet("INFO", "ERROR", "WARNING", "EXCEPTION", "ADVISORY", "NOTE", "QUESTION", "WAIT")] [String]$type = "INFO"
    )

    If ($type -eq "INFO") {
        $messageColour = "92m"
    } elseIf ($type -in "ERROR", "EXCEPTION") {
        $messageColour = "91m"
    } elseIf ($type -in "WARNING", "ADVISORY", "QUESTION") {
        $messageColour = "93m"
    } elseIf ($type -in "NOTE", "WAIT") {
        $messageColour = "97m"
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
    (ByParameter) Instance FQDN for the VCFMS runtime. Must match the original.

    .PARAMETER FleetFqdn
    (ByParameter) Fleet FQDN for the VCFMS runtime. Must match the original.

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

        [Parameter(Mandatory = $true, ParameterSetName = "ByParameter")]
        [String] $InstanceFqdn,

        [Parameter(Mandatory = $true, ParameterSetName = "ByParameter")]
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

        $requestBody = @{
            domainId                = $domainId
            platformFqdn            = $PlatformFqdn
            instanceFqdn            = $InstanceFqdn
            fleetFqdn               = $FleetFqdn
            systemUserPassword      = $SystemUserPassword
            type                    = $Type
            ipv4Pool                = @{ addresses = $Ipv4Addresses }
            size                    = $Size
            networkMoId             = $NetworkMoId
            gatewayCidrIpv4         = $GatewayCidrIpv4
            clusterId               = $ClusterId
            internalClusterCidrIpv4 = $InternalClusterCidrIpv4
        } | ConvertTo-Json -Depth 5
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
        if ($taskResponse.errors) {
            foreach ($err in $taskResponse.errors) {
                LogMessage -type ERROR -message "[$SddcManagerFqdn] Error: $($err.message)"
            }
        }
    }

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
    return $taskResponse
}

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
            $taskResponse = Invoke-RestMethod -Uri $taskUri -Method GET -Headers $headers -SkipCertificateCheck
            $taskStatus = $taskResponse.status
            LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Status: $taskStatus"
        } catch {
            LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Error polling task (will retry): $($_.Exception.Message)"
            $newToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn $ServicesRuntimeFqdn -Username $ServicesRuntimeUsername -Password $ServicesRuntimePassword
            if ($newToken) {
                $headers["Authorization"] = "Bearer $newToken"
            }
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
    return $taskResponse
}

Function Set-VcfmsSftpBackupSettings {
    <#
    .SYNOPSIS
    Configures SFTP backup settings on a VCFMS Services Runtime instance.

    .DESCRIPTION
    The Set-VcfmsSftpBackupSettings cmdlet retrieves the SFTP server's SSH host key fingerprint, then applies SFTP backup configuration to the specified VCFMS component via POST /api/v1/components/{componentId}?action=apply.

    .EXAMPLE
    Set-VcfmsSftpBackupSettings -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!" -ComponentId "1f5c79fe-e3aa-41b1-a5cf-774a6497fa3d" -SftpHost "10.167.173.126" -SftpUsername "svc-vcf-bck" -SftpPassword "VMw@re1!" -SftpDirectory "/media/backups/" -EncryptionPassphrase "VMw@re1!VMw@re1!"

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

    $headers = @{
        "Authorization" = "Bearer $srToken"
        "Content-Type"  = "application/json"
    }

    # Build the request body
    $requestBody = @{
        spec = @{
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
            $taskResponse = Invoke-RestMethod -Uri $taskUri -Method GET -Headers $headers -SkipCertificateCheck
            $taskStatus = $taskResponse.status
            LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Status: $taskStatus"
        } catch {
            LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Error polling task (will retry): $($_.Exception.Message)"
            $newToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn $ServicesRuntimeFqdn -Username $ServicesRuntimeUsername -Password $ServicesRuntimePassword
            if ($newToken) {
                $headers["Authorization"] = "Bearer $newToken"
            }
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
    return $taskResponse
}

Function Get-VcfmsBackups {
    <#
    .SYNOPSIS
    Retrieves and displays VCFMS backup information for one or more component types.

    .DESCRIPTION
    The Get-VcfmsBackups cmdlet queries the VCFMS Services Runtime GET /api/v1/system/backups endpoint and returns backup details for the specified component types, sorted by component type and age. Output includes component type, version, backup name, age, and path.

    .EXAMPLE
    Get-VcfmsBackups -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!"

    .EXAMPLE
    Get-VcfmsBackups -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!" -Components "vsp","salt"

    .EXAMPLE
    Get-VcfmsBackups -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!" -VspId "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

    .PARAMETER ServicesRuntimeFqdn
    FQDN of the VCFMS Services Runtime instance.

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

    # Build ordered results filtered by requested components
    $results = @()
    $now = Get-Date

    foreach ($componentType in $Components) {
        $componentBackups = $allBackups | Where-Object { $_.component.type -eq $componentType }
        foreach ($backup in $componentBackups) {
            $backupName = $backup.name
            $normalizedName = $backupName -replace 'T(\d{2})-(\d{2})-(\d{2})Z', 'T$1:$2:$3Z'
            try {
                $backupDate = [datetime]::Parse($normalizedName, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal)
                $daysOld = [math]::Floor(($now - $backupDate).TotalDays)
                $ageDisplay = "$daysOld days ago"
            } catch {
                $ageDisplay = "unknown"
            }

            $results += [PSCustomObject]@{
                'Component' = $componentType
                'Version'   = $backup.component.version
                'Name'      = $backupName
                'Age'       = $ageDisplay
                'Path'      = $backup.path
            }
        }
    }

    if ($results.Count -eq 0) {
        LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] No backups found for components: $($Components -join ', ')"
        return
    }

    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Found $($results.Count) backup(s) for $($Components.Count) component type(s)"
    Write-Host ""
    $results | Format-Table -AutoSize -Property Component, Version, Name, Age, Path | Out-String | Write-Host

    # Offer to construct a restore JSON from the latest backup of each component
    Do {
        Write-Host " Would you like to construct a restore JSON with the latest backup of each component? (Y/N): " -ForegroundColor Yellow -NoNewline
        $buildJson = Read-Host
    } Until ($buildJson -in @("Y", "y", "N", "n"))

    if ($buildJson -in @("Y", "y")) {
        $restoreComponents = @()
        $explicitlyPassed = $PSBoundParameters.ContainsKey("Components")
        $restoreComponentTypes = if ($explicitlyPassed) { $Components } else { $Components | Where-Object { $_ -notin @("ops-logs", "vcfa") } }
        foreach ($componentType in $restoreComponentTypes) {
            $componentBackups = $allBackups | Where-Object { $_.component.type -eq $componentType }
            if (-not $componentBackups) { continue }

            $latestBackup = $null
            $latestDate = [datetime]::MinValue
            foreach ($backup in $componentBackups) {
                $normalizedName = $backup.name -replace 'T(\d{2})-(\d{2})-(\d{2})Z', 'T$1:$2:$3Z'
                try {
                    $backupDate = [datetime]::Parse($normalizedName, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal)
                    if ($backupDate -gt $latestDate) {
                        $latestDate = $backupDate
                        $latestBackup = $backup
                    }
                } catch {
                    if (-not $latestBackup) { $latestBackup = $backup }
                }
            }

            if ($latestBackup) {
                $restoreComponents += @{
                    path  = $latestBackup.path
                    point = $latestBackup.name
                }
            }
        }

        $restorePayload = @{ components = $restoreComponents } | ConvertTo-Json -Depth 5
        $outputFile = ".\restore-payload.json"
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

Function Restore-VcfmsBackup {
    <#
    .SYNOPSIS
    Restores VCFMS component backups from a user-provided JSON payload file.

    .DESCRIPTION
    The Restore-VcfmsBackup cmdlet submits a restore request to the VCFMS Services Runtime POST /api/v1/system/backups?action=restore endpoint.

    The restore payload is a JSON file containing the "components" array, where each entry specifies the SFTP path and restore point for one component. Use Get-VcfmsBackups to list available backups and their paths, then construct the JSON file with the desired restore points.

    The function displays the payload for confirmation before submitting, then polls the restore status until completion.

    .EXAMPLE
    # Step 1: List available backups to find paths and restore points
    Get-VcfmsBackups -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!"

    # Step 2: Create a JSON file (restore-payload.json) with the desired components:
    # {
    #   "components": [
    #     { "path": "sftp://svc-vcf-bck@10.167.173.126:22/media/backups/vcf/backups/.../vsp/.../2026-03-23T16-45-31Z", "point": "2026-03-23T16-45-31Z" },
    #     { "path": "sftp://svc-vcf-bck@10.167.173.126:22/media/backups/vcf/backups/.../salt/.../2026-03-23T17-13-37Z", "point": "2026-03-23T17-13-37Z" }
    #   ]
    # }

    # Step 3: Run the restore
    Restore-VcfmsBackup -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!" -RestoreJsonFile ".\restore-payload.json"

    .PARAMETER ServicesRuntimeFqdn
    FQDN of the VCFMS Services Runtime instance.

    .PARAMETER ServicesRuntimePassword
    Password for the Services Runtime admin user (used to obtain a token).

    .PARAMETER ServicesRuntimeUsername
    Username for the Services Runtime token. Default is "admin@vsp.local".

    .PARAMETER RestoreJsonFile
    Path to a JSON file containing the restore payload. The file must contain a "components" array with "path" and "point" for each component to restore.

    .PARAMETER PollIntervalSeconds
    Interval in seconds to poll the restore status. Default is 300 (5 minutes).
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $ServicesRuntimeFqdn,
        [Parameter(Mandatory = $true)][String] $ServicesRuntimePassword,
        [Parameter(Mandatory = $false)][String] $ServicesRuntimeUsername = "admin@vsp.local",
        [Parameter(Mandatory = $true)][String] $RestoreJsonFile,
        [Parameter(Mandatory = $false)][Int] $PollIntervalSeconds = 300
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
        $componentName = ($comp.path -split '/')  | Where-Object { $_ -in @("vsp", "vcf-fleet-lcm", "vcf-fleet-depot", "vcf-sddc-lcm", "salt", "salt-raas", "vidb", "ops-logs") } | Select-Object -First 1
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

    $headers = @{
        "Authorization" = "Bearer $srToken"
        "Content-Type"  = "application/json"
        "Accept"        = "application/json"
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
    LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Polling task status every $PollIntervalSeconds seconds"

    $taskUri = "https://$ServicesRuntimeFqdn/api/v1/tasks/$taskId"
    $taskStatus = "Running"
    Do {
        Start-Sleep -Seconds $PollIntervalSeconds

        try {
            $taskResponse = Invoke-RestMethod -Uri $taskUri -Method GET -Headers $headers -SkipCertificateCheck
            $taskStatus = $taskResponse.status
            $elapsed = ""
            if ($taskResponse.startTime) {
                $start = ConvertFrom-VcfmsTaskTimestampToUtc -Timestamp $taskResponse.startTime
                if ($start) {
                    $elapsed = " (running: $(Format-TimeSpanElapsedColons -Span ([datetime]::UtcNow - $start)))"
                }
            }
            LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Status: $taskStatus$elapsed"
        } catch {
            LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Error polling task (will retry): $($_.Exception.Message)"
            $newToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn $ServicesRuntimeFqdn -Username $ServicesRuntimeUsername -Password $ServicesRuntimePassword
            if ($newToken) {
                $headers["Authorization"] = "Bearer $newToken"
            }
        }
    } While ($taskStatus -in @("IN_PROGRESS", "IN PROGRESS", "PENDING", "RUNNING", "RESTORING", "Running", "Pending", "Queued"))

    if ($taskStatus -in @("SUCCESSFUL", "SUCCESS", "COMPLETED", "Succeeded")) {
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Restore completed successfully"
    } else {
        LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] Restore ended with status: $taskStatus"
        if ($taskResponse.messages) {
            foreach ($msg in $taskResponse.messages) {
                LogMessage -type ERROR -message "[$ServicesRuntimeFqdn] $msg"
            }
        }
    }

    $StopWatch.Stop()
    $minutes = (($StopWatch.Elapsed.Hours * 60) + $StopWatch.Elapsed.Minutes)
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $minutes minutes and $($StopWatch.Elapsed.Seconds) seconds"
}

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
            $newToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn $ServicesRuntimeFqdn -Username $ServicesRuntimeUsername -Password $ServicesRuntimePassword
            if ($newToken) {
                $headers["Authorization"] = "Bearer $newToken"
            }
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
            $taskResponse = Invoke-RestMethod -Uri $taskUri -Method GET -Headers $headers -SkipCertificateCheck
            $taskStatus = $taskResponse.status
            LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Status: $taskStatus"
        } catch {
            LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Error polling task (will retry): $($_.Exception.Message)"
            $newToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn $ServicesRuntimeFqdn -Username $ServicesRuntimeUsername -Password $ServicesRuntimePassword
            if ($newToken) {
                $headers["Authorization"] = "Bearer $newToken"
            }
        }
    } While ($taskStatus -notin $terminalStates)

    if ($taskStatus -in @("CANCELLED", "Cancelled")) {
        LogMessage -type INFO -message "[$ServicesRuntimeFqdn] Task $TaskId cancelled successfully"
    } else {
        LogMessage -type WARNING -message "[$ServicesRuntimeFqdn] Task $TaskId ended with status: $taskStatus"
    }

    return $taskResponse
}

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

Function Set-VcfmsComponentVips {
    <#
    .SYNOPSIS
    Updates the ingress VIPs for a VCFMS component via the Services Runtime apply API.

    .DESCRIPTION
    The Set-VcfmsComponentVips cmdlet locates the installed component of the specified type via
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
    Set-VcfmsComponentVips -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!" -ComponentType "vcfa" -Vips "10.0.0.5","10.0.0.6"

    .EXAMPLE
    Set-VcfmsComponentVips -ServicesRuntimeFqdn "lax-sr01.lax.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!" -ComponentType "vidb" -Vips "10.21.99.23" -DryRun

    .EXAMPLE
    Set-VcfmsComponentVips -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!" -ComponentType "ops-logs" -Vips "10.0.0.8","10.0.0.9" -Force

    .PARAMETER ServicesRuntimeFqdn
    FQDN of the VCFMS Services Runtime instance.

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

    # Include options like other apply operations (Set-VcfmsSftpBackupSettings); some stacks ignore partial applies without it.
    $payload = [ordered]@{
        spec = [ordered]@{
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
            $srToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn $ServicesRuntimeFqdn -Username $ServicesRuntimeUsername -Password $ServicesRuntimePassword
            if ($srToken) { $headers["Authorization"] = "Bearer $srToken" }
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
            $srToken = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn $ServicesRuntimeFqdn -Username $ServicesRuntimeUsername -Password $ServicesRuntimePassword
            if ($srToken) { $headers["Authorization"] = "Bearer $srToken" }
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
