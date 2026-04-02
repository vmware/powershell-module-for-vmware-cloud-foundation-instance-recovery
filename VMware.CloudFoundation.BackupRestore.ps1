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

Function Remove-SddcManagerVspClusterEntry {
    <#
    .SYNOPSIS
    Removes a vsp_cluster entry and its corresponding credential from the SDDC Manager Postgres database.

    .DESCRIPTION
    The Remove-SddcManagerVspClusterEntry cmdlet connects to the SDDC Manager appliance via SSH as the vcf user, elevates to root, queries the Postgres platform database for the vsp_cluster entry matching the specified type (MANAGEMENT or CONSUMPTION), and deletes both the cluster row and its associated service credential (where username = 'vsp/<vsp_cluster_id>/svc-sddc-manager-admin').

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
    $functionStartTime = Get-Date
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

    LogMessage -type INFO -message "[$SddcManagerFqdn] Found $ClusterType vsp_cluster_id: $vspClusterId"

    # Display the full row for confirmation
    LogMessage -type INFO -message "[$SddcManagerFqdn] Retrieving full row details"
    $stream.WriteLine("echo `"SELECT * FROM vsp_cluster WHERE vsp_cluster_id='$vspClusterId';`" | psql -U postgres -h localhost -d platform")
    Start-Sleep 5
    $detailOutput = $stream.Read()
    Write-Host ""
    Write-Host (& $cleanSshOutput $detailOutput)
    Write-Host ""

    $credentialUsername = "vsp/$vspClusterId/svc-sddc-manager-admin"

    # Prompt for confirmation before deleting
    Write-Host ""
    Write-Host " The following operations will be performed:" -ForegroundColor Yellow
    Write-Host "   1. DELETE FROM vsp_cluster WHERE vsp_cluster_id='$vspClusterId'" -ForegroundColor Cyan
    Write-Host "   2. DELETE FROM credential WHERE username='$credentialUsername'" -ForegroundColor Cyan
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
    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $(((Get-Date) - $functionStartTime).ToString('hh\:mm\:ss'))"
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

Function New-VcfmsRuntime {
    <#
    .SYNOPSIS
    Deploys a new VCF Management Services (VCFMS) runtime instance via the SDDC Manager API.

    .DESCRIPTION
    The New-VcfmsRuntime cmdlet calls the SDDC Manager POST /v1/vsp-clusters endpoint to deploy a new VCFMS runtime. Supports two modes:

    ByFile      - Supply a pre-built JSON payload file.
    ByParameter - Supply individual values; the management domain ID is automatically retrieved from the SDDC Manager /v1/domains API.

    In both modes the function retrieves an SDDC Manager token, displays the payload for verification, submits the deployment request, and polls the task until completion.

    .EXAMPLE
    New-VcfmsRuntime -SddcManagerFqdn "sfo-vcf01.sfo.rainpole.io" -SddcManagerUser "administrator@vsphere.local" -SddcManagerPassword "VMw@re1!VMw@re1!" -JsonFile ".\vcfms-runtime.json"

    .EXAMPLE
    New-VcfmsRuntime -SddcManagerFqdn "sfo-vcf01.sfo.rainpole.io" -SddcManagerUser "administrator@vsphere.local" -SddcManagerPassword "VMw@re1!VMw@re1!" -PlatformFqdn "sfo-sr01.sfo.rainpole.io" -InstanceFqdn "sfo-ic01.sfo.rainpole.io" -FleetFqdn "flt-fc01.rainpole.io" -SystemUserPassword "VMw@re1!VMw@re1!" -Ipv4Addresses "10.11.99.29","10.11.99.30","10.11.99.31" -Size "small" -NetworkMoId "dvportgroup-28" -GatewayCidrIpv4 "10.11.99.1/24" -ClusterId "1f5c79fe-e3aa-41b1-a5cf-774a6497fa3d" -InternalClusterCidrIpv4 "198.18.0.0/15"

    .PARAMETER SddcManagerFqdn
    FQDN of the SDDC Manager appliance.

    .PARAMETER SddcManagerUser
    API username for SDDC Manager (e.g. administrator@vsphere.local).

    .PARAMETER SddcManagerPassword
    Password for the SDDC Manager API user.

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
    $functionStartTime = Get-Date
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
            type                    = "MANAGEMENT"
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
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $(((Get-Date) - $functionStartTime).ToString('hh\:mm\:ss'))"
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

    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $(((Get-Date) - $functionStartTime).ToString('hh\:mm\:ss'))"
    return $taskResponse
}

Function Get-VcfmsServicesRuntimeToken {
    <#
    .SYNOPSIS
    Retrieves an access token from a VCFMS Services Runtime instance.

    .DESCRIPTION
    The Get-VcfmsServicesRuntimeToken cmdlet authenticates against the VCFMS Services Runtime /api/v1/identity/token endpoint using a form-urlencoded password grant and returns the access token string.

    .EXAMPLE
    $srToken = Get-VcfmsServicesRuntimeToken -ServiceRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -Password "VMw@re1!VMw@re1!"

    .EXAMPLE
    $srToken = Get-VcfmsServicesRuntimeToken -ServiceRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -Username "admin@vsp.local" -Password "VMw@re1!VMw@re1!"

    .PARAMETER ServiceRuntimeFqdn
    FQDN of the VCFMS Services Runtime instance (e.g. sfo-sr01.sfo.rainpole.io).

    .PARAMETER Username
    Username for the token request. Default is "admin@vsp.local".

    .PARAMETER Password
    Password for the services runtime user.
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $ServiceRuntimeFqdn,
        [Parameter(Mandatory = $false)][String] $Username = "admin@vsp.local",
        [Parameter(Mandatory = $true)][String] $Password
    )

    $jumpboxName = hostname
    LogMessage -type INFO -message "[$jumpboxName] Requesting VCFMS Services Runtime token from $ServiceRuntimeFqdn"

    $tokenUri = "https://$ServiceRuntimeFqdn/api/v1/identity/token"
    $tokenBody = "grant_type=password&username=$([uri]::EscapeDataString($Username))&password=$([uri]::EscapeDataString($Password))"

    try {
        $tokenResponse = Invoke-RestMethod -Uri $tokenUri -Method POST -ContentType "application/x-www-form-urlencoded" -Body $tokenBody -SkipCertificateCheck
        $accessToken = $tokenResponse.access_token
        if (-not $accessToken) {
            LogMessage -type ERROR -message "[$ServiceRuntimeFqdn] Token response did not contain an access_token."
            return $null
        }
        LogMessage -type INFO -message "[$ServiceRuntimeFqdn] Services Runtime token retrieved successfully"
        return $accessToken
    } catch {
        LogMessage -type ERROR -message "[$ServiceRuntimeFqdn] Failed to retrieve Services Runtime token: $($_.Exception.Message)"
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
    Add-VcfmsTrustedCertificate -ServiceRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServiceRuntimePassword "VMw@re1!VMw@re1!" -RemoteHostFqdn "sfo-ins01.sfo.rainpole.io"

    .EXAMPLE
    Add-VcfmsTrustedCertificate -ServiceRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServiceRuntimePassword "VMw@re1!VMw@re1!" -RemoteHostFqdn "sfo-ins01.sfo.rainpole.io" -RemoteHostPort 443

    .PARAMETER ServiceRuntimeFqdn
    FQDN of the VCFMS Services Runtime instance to add the trusted certificate to.

    .PARAMETER ServiceRuntimePassword
    Password for the Services Runtime admin user (used to obtain a token).

    .PARAMETER ServiceRuntimeUsername
    Username for the Services Runtime token. Default is "admin@vsp.local".

    .PARAMETER RemoteHostFqdn
    FQDN of the remote host whose TLS certificate should be retrieved and trusted (e.g. the VCF Installer).

    .PARAMETER RemoteHostPort
    Port to connect to on the remote host. Default is 443.

    .PARAMETER PollIntervalSeconds
    Interval in seconds to poll the task status. Default is 10.
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $ServiceRuntimeFqdn,
        [Parameter(Mandatory = $true)][String] $ServiceRuntimePassword,
        [Parameter(Mandatory = $false)][String] $ServiceRuntimeUsername = "admin@vsp.local",
        [Parameter(Mandatory = $true)][String] $RemoteHostFqdn,
        [Parameter(Mandatory = $false)][Int] $RemoteHostPort = 443,
        [Parameter(Mandatory = $false)][Int] $PollIntervalSeconds = 10
    )

    $jumpboxName = hostname
    $functionStartTime = Get-Date
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
    $srToken = Get-VcfmsServicesRuntimeToken -ServiceRuntimeFqdn $ServiceRuntimeFqdn -Username $ServiceRuntimeUsername -Password $ServiceRuntimePassword
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

    $trustUri = "https://$ServiceRuntimeFqdn/api/v1/system/trusted-certificates?action=add"
    LogMessage -type INFO -message "[$ServiceRuntimeFqdn] Adding trusted certificate for $RemoteHostFqdn"

    try {
        $response = Invoke-RestMethod -Uri $trustUri -Method POST -Headers $headers -Body $requestBody -SkipCertificateCheck
    } catch {
        LogMessage -type ERROR -message "[$ServiceRuntimeFqdn] Failed to add trusted certificate: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            try {
                $errorStream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($errorStream)
                $errorBody = $reader.ReadToEnd()
                LogMessage -type ERROR -message "[$ServiceRuntimeFqdn] Response body: $errorBody"
            } catch {}
        }
        return
    }

    # Check for a task ID in the response
    $taskId = $response.id
    if (-not $taskId) {
        LogMessage -type INFO -message "[$ServiceRuntimeFqdn] Certificate for $RemoteHostFqdn trusted successfully (no task returned)"
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $(((Get-Date) - $functionStartTime).ToString('hh\:mm\:ss'))"
        return $response
    }

    LogMessage -type INFO -message "[$ServiceRuntimeFqdn] Trust certificate task submitted: $taskId"
    LogMessage -type INFO -message "[$ServiceRuntimeFqdn] Polling task status every $PollIntervalSeconds seconds"

    $taskUri = "https://$ServiceRuntimeFqdn/api/v1/tasks/$taskId"
    $taskStatus = "IN_PROGRESS"
    Do {
        Start-Sleep -Seconds $PollIntervalSeconds

        try {
            $taskResponse = Invoke-RestMethod -Uri $taskUri -Method GET -Headers $headers -SkipCertificateCheck
            $taskStatus = $taskResponse.status
            LogMessage -type INFO -message "[$ServiceRuntimeFqdn] Status: $taskStatus"
        } catch {
            LogMessage -type WARNING -message "[$ServiceRuntimeFqdn] Error polling task (will retry): $($_.Exception.Message)"
            $newToken = Get-VcfmsServicesRuntimeToken -ServiceRuntimeFqdn $ServiceRuntimeFqdn -Username $ServiceRuntimeUsername -Password $ServiceRuntimePassword
            if ($newToken) {
                $headers["Authorization"] = "Bearer $newToken"
            }
        }
    } While ($taskStatus -in @("IN_PROGRESS", "IN PROGRESS", "PENDING", "RUNNING"))

    if ($taskStatus -in @("SUCCESSFUL", "SUCCESS", "COMPLETED", "Succeeded")) {
        LogMessage -type INFO -message "[$ServiceRuntimeFqdn] Certificate for $RemoteHostFqdn trusted successfully"
    } else {
        LogMessage -type ERROR -message "[$ServiceRuntimeFqdn] Trust certificate task ended with status: $taskStatus"
        if ($taskResponse.errors) {
            foreach ($err in $taskResponse.errors) {
                LogMessage -type ERROR -message "[$ServiceRuntimeFqdn] Error: $($err.message)"
            }
        }
    }

    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $(((Get-Date) - $functionStartTime).ToString('hh\:mm\:ss'))"
    return $taskResponse
}

Function Set-VcfmsSftpBackupSettings {
    <#
    .SYNOPSIS
    Configures SFTP backup settings on a VCFMS Services Runtime instance.

    .DESCRIPTION
    The Set-VcfmsSftpBackupSettings cmdlet retrieves the SFTP server's SSH host key fingerprint, then applies SFTP backup configuration to the specified VCFMS component via POST /api/v1/components/{componentId}?action=apply.

    .EXAMPLE
    Set-VcfmsSftpBackupSettings -ServiceRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServiceRuntimePassword "VMw@re1!VMw@re1!" -ComponentId "1f5c79fe-e3aa-41b1-a5cf-774a6497fa3d" -SftpHost "10.167.173.126" -SftpUsername "svc-vcf-bck" -SftpPassword "VMw@re1!VMw@re1!" -SftpDirectory "/media/backups/" -EncryptionPassphrase "VMw@re1!VMw@re1!"

    .PARAMETER ServiceRuntimeFqdn
    FQDN of the VCFMS Services Runtime instance.

    .PARAMETER ServiceRuntimePassword
    Password for the Services Runtime admin user (used to obtain a token).

    .PARAMETER ServiceRuntimeUsername
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
    Interval in seconds to poll the task status. Default is 10.
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $ServiceRuntimeFqdn,
        [Parameter(Mandatory = $true)][String] $ServiceRuntimePassword,
        [Parameter(Mandatory = $false)][String] $ServiceRuntimeUsername = "admin@vsp.local",
        [Parameter(Mandatory = $true)][String] $ComponentId,
        [Parameter(Mandatory = $true)][String] $SftpHost,
        [Parameter(Mandatory = $false)][String] $SftpPort = "22",
        [Parameter(Mandatory = $true)][String] $SftpUsername,
        [Parameter(Mandatory = $true)][String] $SftpPassword,
        [Parameter(Mandatory = $true)][String] $SftpDirectory,
        [Parameter(Mandatory = $true)][String] $EncryptionPassphrase,
        [Parameter(Mandatory = $false)][String] $SftpFingerprint,
        [Parameter(Mandatory = $false)][Int] $PollIntervalSeconds = 10
    )

    $jumpboxName = hostname
    $functionStartTime = Get-Date
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
    $srToken = Get-VcfmsServicesRuntimeToken -ServiceRuntimeFqdn $ServiceRuntimeFqdn -Username $ServiceRuntimeUsername -Password $ServiceRuntimePassword
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

    $applyUri = "https://$ServiceRuntimeFqdn/api/v1/components/${ComponentId}?action=apply"
    LogMessage -type INFO -message "[$ServiceRuntimeFqdn] Applying SFTP backup settings to component $ComponentId"

    try {
        $response = Invoke-RestMethod -Uri $applyUri -Method POST -Headers $headers -Body $requestBody -SkipCertificateCheck
    } catch {
        LogMessage -type ERROR -message "[$ServiceRuntimeFqdn] Failed to apply SFTP backup settings: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            try {
                $errorStream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($errorStream)
                $errorBody = $reader.ReadToEnd()
                LogMessage -type ERROR -message "[$ServiceRuntimeFqdn] Response body: $errorBody"
            } catch {}
        }
        return
    }

    # Check for a task ID in the response
    $taskId = $response.id
    if (-not $taskId) {
        LogMessage -type INFO -message "[$ServiceRuntimeFqdn] SFTP backup settings applied successfully (no task returned)"
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $(((Get-Date) - $functionStartTime).ToString('hh\:mm\:ss'))"
        return $response
    }

    LogMessage -type INFO -message "[$ServiceRuntimeFqdn] SFTP settings task submitted: $taskId"
    LogMessage -type INFO -message "[$ServiceRuntimeFqdn] Polling task status every $PollIntervalSeconds seconds"

    $taskUri = "https://$ServiceRuntimeFqdn/api/v1/tasks/$taskId"
    $taskStatus = "IN_PROGRESS"
    Do {
        Start-Sleep -Seconds $PollIntervalSeconds

        try {
            $taskResponse = Invoke-RestMethod -Uri $taskUri -Method GET -Headers $headers -SkipCertificateCheck
            $taskStatus = $taskResponse.status
            LogMessage -type INFO -message "[$ServiceRuntimeFqdn] Status: $taskStatus"
        } catch {
            LogMessage -type WARNING -message "[$ServiceRuntimeFqdn] Error polling task (will retry): $($_.Exception.Message)"
            $newToken = Get-VcfmsServicesRuntimeToken -ServiceRuntimeFqdn $ServiceRuntimeFqdn -Username $ServiceRuntimeUsername -Password $ServiceRuntimePassword
            if ($newToken) {
                $headers["Authorization"] = "Bearer $newToken"
            }
        }
    } While ($taskStatus -in @("IN_PROGRESS", "IN PROGRESS", "PENDING", "RUNNING"))

    if ($taskStatus -in @("SUCCESSFUL", "SUCCESS", "COMPLETED", "Succeeded")) {
        LogMessage -type INFO -message "[$ServiceRuntimeFqdn] SFTP backup settings applied successfully"
    } else {
        LogMessage -type ERROR -message "[$ServiceRuntimeFqdn] SFTP settings task ended with status: $taskStatus"
        if ($taskResponse.errors) {
            foreach ($err in $taskResponse.errors) {
                LogMessage -type ERROR -message "[$ServiceRuntimeFqdn] Error: $($err.message)"
            }
        }
    }

    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $(((Get-Date) - $functionStartTime).ToString('hh\:mm\:ss'))"
    return $taskResponse
}

Function Get-VcfmsBackups {
    <#
    .SYNOPSIS
    Retrieves and displays VCFMS backup information for one or more component types.

    .DESCRIPTION
    The Get-VcfmsBackups cmdlet queries the VCFMS Services Runtime GET /api/v1/system/backups endpoint and returns backup details for the specified component types, sorted by component type and age. Output includes component type, version, backup name, age, and path.

    .EXAMPLE
    Get-VcfmsBackups -ServiceRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServiceRuntimePassword "VMw@re1!VMw@re1!"

    .EXAMPLE
    Get-VcfmsBackups -ServiceRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServiceRuntimePassword "VMw@re1!VMw@re1!" -Components "vsp","salt"

    .PARAMETER ServiceRuntimeFqdn
    FQDN of the VCFMS Services Runtime instance.

    .PARAMETER ServiceRuntimePassword
    Password for the Services Runtime admin user (used to obtain a token).

    .PARAMETER ServiceRuntimeUsername
    Username for the Services Runtime token. Default is "admin@vsp.local".

    .PARAMETER Components
    One or more component types to display. Valid values: vsp, vcf-fleet-lcm, vcf-fleet-depot, vcf-sddc-lcm, salt, salt-raas, vidb, ops-logs. Default is all of them.
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $ServiceRuntimeFqdn,
        [Parameter(Mandatory = $true)][String] $ServiceRuntimePassword,
        [Parameter(Mandatory = $false)][String] $ServiceRuntimeUsername = "admin@vsp.local",
        [Parameter(Mandatory = $false)][ValidateSet("vsp", "vcf-fleet-lcm", "vcf-fleet-depot", "vcf-sddc-lcm", "salt", "salt-raas", "vidb", "ops-logs")][String[]] $Components = @("vsp", "vcf-fleet-lcm", "vcf-fleet-depot", "vcf-sddc-lcm", "salt", "salt-raas", "vidb", "ops-logs")
    )

    $jumpboxName = hostname
    $functionStartTime = Get-Date
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    # Get Services Runtime token
    $srToken = Get-VcfmsServicesRuntimeToken -ServiceRuntimeFqdn $ServiceRuntimeFqdn -Username $ServiceRuntimeUsername -Password $ServiceRuntimePassword
    if (-not $srToken) {
        LogMessage -type ERROR -message "[$jumpboxName] Unable to obtain Services Runtime token. Aborting."
        return
    }

    $headers = @{
        "Authorization" = "Bearer $srToken"
        "Accept"        = "application/json"
    }

    $backupsUri = "https://$ServiceRuntimeFqdn/api/v1/system/backups"
    LogMessage -type INFO -message "[$ServiceRuntimeFqdn] Retrieving backup list"

    try {
        $response = Invoke-RestMethod -Uri $backupsUri -Method GET -Headers $headers -SkipCertificateCheck
    } catch {
        LogMessage -type ERROR -message "[$ServiceRuntimeFqdn] Failed to retrieve backups: $($_.Exception.Message)"
        return
    }

    $allBackups = $response.backups
    if (-not $allBackups -or ($allBackups | Measure-Object).Count -eq 0) {
        LogMessage -type WARNING -message "[$ServiceRuntimeFqdn] No backups found."
        return
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
        LogMessage -type WARNING -message "[$ServiceRuntimeFqdn] No backups found for components: $($Components -join ', ')"
        return
    }

    LogMessage -type INFO -message "[$ServiceRuntimeFqdn] Found $($results.Count) backup(s) for $($Components.Count) component type(s)"
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
        $restoreComponentTypes = if ($explicitlyPassed) { $Components } else { $Components | Where-Object { $_ -ne "ops-logs" } }
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

    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $(((Get-Date) - $functionStartTime).ToString('hh\:mm\:ss'))"
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
    Get-VcfmsBackups -ServiceRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServiceRuntimePassword "VMw@re1!VMw@re1!"

    # Step 2: Create a JSON file (restore-payload.json) with the desired components:
    # {
    #   "components": [
    #     { "path": "sftp://svc-vcf-bck@10.167.173.126:22/media/backups/vcf/backups/.../vsp/.../2026-03-23T16-45-31Z", "point": "2026-03-23T16-45-31Z" },
    #     { "path": "sftp://svc-vcf-bck@10.167.173.126:22/media/backups/vcf/backups/.../salt/.../2026-03-23T17-13-37Z", "point": "2026-03-23T17-13-37Z" }
    #   ]
    # }

    # Step 3: Run the restore
    Restore-VcfmsBackup -ServiceRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServiceRuntimePassword "VMw@re1!VMw@re1!" -RestoreJsonFile ".\restore-payload.json"

    .PARAMETER ServiceRuntimeFqdn
    FQDN of the VCFMS Services Runtime instance.

    .PARAMETER ServiceRuntimePassword
    Password for the Services Runtime admin user (used to obtain a token).

    .PARAMETER ServiceRuntimeUsername
    Username for the Services Runtime token. Default is "admin@vsp.local".

    .PARAMETER RestoreJsonFile
    Path to a JSON file containing the restore payload. The file must contain a "components" array with "path" and "point" for each component to restore.

    .PARAMETER PollIntervalSeconds
    Interval in seconds to poll the restore status. Default is 300 (5 minutes).
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $ServiceRuntimeFqdn,
        [Parameter(Mandatory = $true)][String] $ServiceRuntimePassword,
        [Parameter(Mandatory = $false)][String] $ServiceRuntimeUsername = "admin@vsp.local",
        [Parameter(Mandatory = $true)][String] $RestoreJsonFile,
        [Parameter(Mandatory = $false)][Int] $PollIntervalSeconds = 300
    )

    $jumpboxName = hostname
    $functionStartTime = Get-Date
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
    $srToken = Get-VcfmsServicesRuntimeToken -ServiceRuntimeFqdn $ServiceRuntimeFqdn -Username $ServiceRuntimeUsername -Password $ServiceRuntimePassword
    if (-not $srToken) {
        LogMessage -type ERROR -message "[$jumpboxName] Unable to obtain Services Runtime token. Aborting."
        return
    }

    $headers = @{
        "Authorization" = "Bearer $srToken"
        "Content-Type"  = "application/json"
        "Accept"        = "application/json"
    }

    $restoreUri = "https://$ServiceRuntimeFqdn/api/v1/system/backups?action=restore"
    LogMessage -type INFO -message "[$ServiceRuntimeFqdn] Submitting restore request"

    try {
        $response = Invoke-RestMethod -Uri $restoreUri -Method POST -Headers $headers -Body $payloadContent -SkipCertificateCheck
    } catch {
        LogMessage -type ERROR -message "[$ServiceRuntimeFqdn] Restore request failed: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            try {
                $errorStream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($errorStream)
                $errorBody = $reader.ReadToEnd()
                LogMessage -type ERROR -message "[$ServiceRuntimeFqdn] Response body: $errorBody"
            } catch {}
        }
        return
    }

    LogMessage -type INFO -message "[$ServiceRuntimeFqdn] Restore request accepted"

    # Check for a task ID in the POST response
    $taskId = $response.id
    if (-not $taskId) {
        # POST /backups?action=restore does not return a task ID directly;
        # find the restore task by querying GET /api/v1/tasks
        LogMessage -type INFO -message "[$ServiceRuntimeFqdn] Searching for restore task via /api/v1/tasks"
        Start-Sleep -Seconds 5
        try {
            $tasksResponse = Invoke-RestMethod -Uri "https://$ServiceRuntimeFqdn/api/v1/tasks" -Method GET -Headers $headers -SkipCertificateCheck
            $restoreTask = $tasksResponse.tasks |
                Where-Object { $_.type -eq "com.vmware.vcfms.task.RestoreMultipleComponents" -and $_.status -notin @("Succeeded", "Failed", "Cancelled") } |
                Sort-Object createTime -Descending |
                Select-Object -First 1
            if ($restoreTask) {
                $taskId = $restoreTask.id
            }
        } catch {
            LogMessage -type WARNING -message "[$ServiceRuntimeFqdn] Could not query tasks endpoint: $($_.Exception.Message)"
        }
    }

    if (-not $taskId) {
        LogMessage -type WARNING -message "[$ServiceRuntimeFqdn] Could not find restore task. Use Watch-VcfmsTask -FindRunning to check progress."
        LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $(((Get-Date) - $functionStartTime).ToString('hh\:mm\:ss'))"
        return
    }

    LogMessage -type INFO -message "[$ServiceRuntimeFqdn] Restore task ID: $taskId"
    LogMessage -type INFO -message "[$ServiceRuntimeFqdn] Polling task status every $PollIntervalSeconds seconds"

    $taskUri = "https://$ServiceRuntimeFqdn/api/v1/tasks/$taskId"
    $taskStatus = "Running"
    Do {
        Start-Sleep -Seconds $PollIntervalSeconds

        try {
            $taskResponse = Invoke-RestMethod -Uri $taskUri -Method GET -Headers $headers -SkipCertificateCheck
            $taskStatus = $taskResponse.status
            $elapsed = ""
            if ($taskResponse.startTime) {
                try {
                    $start = [datetimeoffset]::Parse($taskResponse.startTime).UtcDateTime
                    $now = [datetime]::UtcNow
                    $elapsed = " (running: $(($now - $start).ToString('hh\:mm\:ss')))"
                } catch {}
            }
            LogMessage -type INFO -message "[$ServiceRuntimeFqdn] Status: $taskStatus$elapsed"
        } catch {
            LogMessage -type WARNING -message "[$ServiceRuntimeFqdn] Error polling task (will retry): $($_.Exception.Message)"
            $newToken = Get-VcfmsServicesRuntimeToken -ServiceRuntimeFqdn $ServiceRuntimeFqdn -Username $ServiceRuntimeUsername -Password $ServiceRuntimePassword
            if ($newToken) {
                $headers["Authorization"] = "Bearer $newToken"
            }
        }
    } While ($taskStatus -in @("IN_PROGRESS", "IN PROGRESS", "PENDING", "RUNNING", "RESTORING", "Running", "Pending", "Queued"))

    if ($taskStatus -in @("SUCCESSFUL", "SUCCESS", "COMPLETED", "Succeeded")) {
        LogMessage -type INFO -message "[$ServiceRuntimeFqdn] Restore completed successfully"
    } else {
        LogMessage -type ERROR -message "[$ServiceRuntimeFqdn] Restore ended with status: $taskStatus"
        if ($taskResponse.messages) {
            foreach ($msg in $taskResponse.messages) {
                LogMessage -type ERROR -message "[$ServiceRuntimeFqdn] $msg"
            }
        }
    }

    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $(((Get-Date) - $functionStartTime).ToString('hh\:mm\:ss'))"
}

Function Get-VcfmsFleetControllerToken {
    <#
    .SYNOPSIS
    Retrieves an access token from a VCFMS Fleet Controller instance.

    .DESCRIPTION
    The Get-VcfmsFleetControllerToken cmdlet authenticates against the VCFMS Fleet Controller /api/v1/identity/token endpoint using a form-urlencoded password grant and returns the access token string.

    .EXAMPLE
    $fcToken = Get-VcfmsFleetControllerToken -FleetControllerFqdn "flt-fc01.rainpole.io" -Password "VMw@re1!VMw@re1!"

    .PARAMETER FleetControllerFqdn
    FQDN of the VCFMS Fleet Controller instance.

    .PARAMETER Username
    Username for the token request. Default is "admin@vsp.local".

    .PARAMETER Password
    Password for the Fleet Controller user.
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $FleetControllerFqdn,
        [Parameter(Mandatory = $false)][String] $Username = "admin@vsp.local",
        [Parameter(Mandatory = $true)][String] $Password
    )

    $jumpboxName = hostname
    LogMessage -type INFO -message "[$jumpboxName] Requesting VCFMS Fleet Controller token from $FleetControllerFqdn"

    $tokenUri = "https://$FleetControllerFqdn/api/v1/identity/token"
    $tokenBody = "grant_type=password&username=$([uri]::EscapeDataString($Username))&password=$([uri]::EscapeDataString($Password))"

    try {
        $tokenResponse = Invoke-RestMethod -Uri $tokenUri -Method POST -ContentType "application/x-www-form-urlencoded" -Body $tokenBody -SkipCertificateCheck
        $accessToken = $tokenResponse.access_token
        if (-not $accessToken) {
            LogMessage -type ERROR -message "[$FleetControllerFqdn] Token response did not contain an access_token."
            return $null
        }
        LogMessage -type INFO -message "[$FleetControllerFqdn] Fleet Controller token retrieved successfully"
        return $accessToken
    } catch {
        LogMessage -type ERROR -message "[$FleetControllerFqdn] Failed to retrieve Fleet Controller token: $($_.Exception.Message)"
        return $null
    }
}

Function Get-VcfmsComponents {
    <#
    .SYNOPSIS
    Retrieves VCFMS component IDs from the Fleet Controller. Optionally filters by component type description.

    .DESCRIPTION
    The Get-VcfmsComponents cmdlet queries the VCFMS Fleet Controller GET /fleet-lcm/v1/components endpoint and returns component details. If no ComponentTypes are specified, all components are returned. If one or more types are specified, only matching components are returned. For "VCF services runtime" components, the FQDN is also included in the output.

    .EXAMPLE
    Get-VcfmsComponents -FleetControllerFqdn "flt-fc01.rainpole.io" -FleetControllerPassword "VMw@re1!VMw@re1!"

    .EXAMPLE
    Get-VcfmsComponents -FleetControllerFqdn "flt-fc01.rainpole.io" -FleetControllerPassword "VMw@re1!VMw@re1!" -ComponentTypes "Log management","Salt master"

    .EXAMPLE
    Get-VcfmsComponents -FleetControllerFqdn "flt-fc01.rainpole.io" -FleetControllerPassword "VMw@re1!VMw@re1!" -ComponentTypes "VCF services runtime"

    .PARAMETER FleetControllerFqdn
    FQDN of the VCFMS Fleet Controller instance.

    .PARAMETER FleetControllerPassword
    Password for the Fleet Controller admin user (used to obtain a token).

    .PARAMETER FleetControllerUsername
    Username for the Fleet Controller token. Default is "admin@vsp.local".

    .PARAMETER ComponentTypes
    One or more component type descriptions to filter by (e.g. "VCF Operations", "Salt master", "VCF services runtime"). If not specified, all components are returned.
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $FleetControllerFqdn,
        [Parameter(Mandatory = $true)][String] $FleetControllerPassword,
        [Parameter(Mandatory = $false)][String] $FleetControllerUsername = "admin@vsp.local",
        [Parameter(Mandatory = $false)][String[]] $ComponentTypes
    )

    $jumpboxName = hostname
    $functionStartTime = Get-Date
    LogMessage -type NOTE -message "[$jumpboxName] Starting Task $($MyInvocation.MyCommand)"

    # Get Fleet Controller token
    $fcToken = Get-VcfmsFleetControllerToken -FleetControllerFqdn $FleetControllerFqdn -Username $FleetControllerUsername -Password $FleetControllerPassword
    if (-not $fcToken) {
        LogMessage -type ERROR -message "[$jumpboxName] Unable to obtain Fleet Controller token. Aborting."
        return
    }

    $headers = @{
        "Authorization" = "Bearer $fcToken"
        "Accept"        = "application/json"
    }

    $componentsUri = "https://$FleetControllerFqdn/fleet-lcm/v1/components?includeConsumptionVsp=true&includeVcdMigrator=true"
    LogMessage -type INFO -message "[$FleetControllerFqdn] Retrieving VCFMS components"

    try {
        $response = Invoke-RestMethod -Uri $componentsUri -Method GET -Headers $headers -SkipCertificateCheck
    } catch {
        LogMessage -type ERROR -message "[$FleetControllerFqdn] Failed to retrieve components: $($_.Exception.Message)"
        return
    }

    $allComponents = $response.components
    if (-not $allComponents -or ($allComponents | Measure-Object).Count -eq 0) {
        LogMessage -type WARNING -message "[$FleetControllerFqdn] No components found."
        return
    }

    # Filter by component types if specified
    if ($ComponentTypes -and $ComponentTypes.Count -gt 0) {
        $filteredComponents = $allComponents | Where-Object { $_.componentTypeDescription -in $ComponentTypes }
    } else {
        $filteredComponents = $allComponents
    }

    if (-not $filteredComponents -or ($filteredComponents | Measure-Object).Count -eq 0) {
        LogMessage -type WARNING -message "[$FleetControllerFqdn] No components found matching: $($ComponentTypes -join ', ')"
        return
    }

    # Build result objects
    $results = @()
    foreach ($comp in $filteredComponents) {
        $obj = [PSCustomObject]@{
            'Id'          = $comp.id
            'Type'        = $comp.componentTypeDescription
        }
        if ($comp.componentTypeDescription -eq "VCF services runtime" -and $comp.fqdn) {
            $obj | Add-Member -NotePropertyName 'Fqdn' -NotePropertyValue $comp.fqdn
        }
        $results += $obj
    }

    $filterMsg = if ($ComponentTypes) { "matching: $($ComponentTypes -join ', ')" } else { "(all)" }
    LogMessage -type INFO -message "[$FleetControllerFqdn] Found $($results.Count) component(s) $filterMsg"
    Write-Host ""
    $results | Format-Table -AutoSize | Out-String | Write-Host

    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $(((Get-Date) - $functionStartTime).ToString('hh\:mm\:ss'))"
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
    $task = Watch-VcfmsTask -ServiceRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServiceRuntimePassword "VMw@re1!VMw@re1!" -TaskId "un56awijhfbudjma4mjin3cjwi"

    .EXAMPLE
    Watch-VcfmsTask -ServiceRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServiceRuntimePassword "VMw@re1!VMw@re1!" -FindRunning

    .PARAMETER ServiceRuntimeFqdn
    FQDN of the VCFMS Services Runtime instance.

    .PARAMETER ServiceRuntimePassword
    Password for the Services Runtime admin user.

    .PARAMETER ServiceRuntimeUsername
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
        [String] $ServiceRuntimeFqdn,

        [Parameter(Mandatory = $true, ParameterSetName = "Monitor")]
        [Parameter(Mandatory = $true, ParameterSetName = "FindRunning")]
        [String] $ServiceRuntimePassword,

        [Parameter(Mandatory = $false, ParameterSetName = "Monitor")]
        [Parameter(Mandatory = $false, ParameterSetName = "FindRunning")]
        [String] $ServiceRuntimeUsername = "admin@vsp.local",

        [Parameter(Mandatory = $true, ParameterSetName = "Monitor")]
        [String] $TaskId,

        [Parameter(Mandatory = $true, ParameterSetName = "FindRunning")]
        [Switch] $FindRunning,

        [Parameter(Mandatory = $false, ParameterSetName = "Monitor")]
        [Int] $PollIntervalSeconds = 30
    )

    $jumpboxName = hostname
    $terminalStates = @("COMPLETED", "FAILED", "CANCELLED", "ERROR", "SUCCESS", "SUCCESSFUL", "Succeeded", "Failed")

    $srToken = Get-VcfmsServicesRuntimeToken -ServiceRuntimeFqdn $ServiceRuntimeFqdn -Username $ServiceRuntimeUsername -Password $ServiceRuntimePassword
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
        $tasksUri = "https://$ServiceRuntimeFqdn/api/v1/tasks"
        LogMessage -type INFO -message "[$ServiceRuntimeFqdn] Querying all tasks"

        try {
            $response = Invoke-RestMethod -Uri $tasksUri -Method GET -Headers $headers -SkipCertificateCheck
        } catch {
            LogMessage -type ERROR -message "[$ServiceRuntimeFqdn] Failed to retrieve tasks: $($_.Exception.Message)"
            return
        }

        $allTasks = $response.tasks
        if (-not $allTasks -or ($allTasks | Measure-Object).Count -eq 0) {
            LogMessage -type INFO -message "[$ServiceRuntimeFqdn] No tasks found"
            return
        }

        $runningTasks = $allTasks | Where-Object { $_.status -notin $terminalStates }

        if (-not $runningTasks -or ($runningTasks | Measure-Object).Count -eq 0) {
            LogMessage -type INFO -message "[$ServiceRuntimeFqdn] No running tasks found"
            return
        }

        $now = [datetime]::UtcNow
        $results = @()
        foreach ($task in $runningTasks) {
            $running = ""
            if ($task.startTime) {
                try {
                    $start = [datetimeoffset]::Parse($task.startTime).UtcDateTime
                    $running = ($now - $start).ToString('hh\:mm\:ss')
                } catch {}
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

        LogMessage -type INFO -message "[$ServiceRuntimeFqdn] Found $($results.Count) running task(s)"
        Write-Host ""
        $results | Format-Table -AutoSize | Out-String | Write-Host
        return
    }

    # --- Monitor mode: poll a specific task ---
    $taskUri = "https://$ServiceRuntimeFqdn/api/v1/tasks/$TaskId"

    LogMessage -type INFO -message "[$ServiceRuntimeFqdn] Monitoring task $TaskId (polling every ${PollIntervalSeconds}s)"

    Do {
        Start-Sleep -Seconds $PollIntervalSeconds
        try {
            $taskResponse = Invoke-RestMethod -Uri $taskUri -Method GET -Headers $headers -SkipCertificateCheck
            $taskStatus = $taskResponse.status
            $elapsed = ""
            if ($taskResponse.startTime -and $taskResponse.endTime) {
                try {
                    $start = [datetimeoffset]::Parse($taskResponse.startTime).UtcDateTime
                    $end = [datetimeoffset]::Parse($taskResponse.endTime).UtcDateTime
                    $elapsed = " (elapsed: $(($end - $start).ToString('hh\:mm\:ss')))"
                } catch {}
            } elseif ($taskResponse.startTime) {
                try {
                    $start = [datetimeoffset]::Parse($taskResponse.startTime).UtcDateTime
                    $now = [datetime]::UtcNow
                    $elapsed = " (running: $(($now - $start).ToString('hh\:mm\:ss')))"
                } catch {}
            }
            LogMessage -type INFO -message "[$ServiceRuntimeFqdn] Status: $taskStatus$elapsed"
        } catch {
            LogMessage -type WARNING -message "[$ServiceRuntimeFqdn] Error polling task (will retry): $($_.Exception.Message)"
            $newToken = Get-VcfmsServicesRuntimeToken -ServiceRuntimeFqdn $ServiceRuntimeFqdn -Username $ServiceRuntimeUsername -Password $ServiceRuntimePassword
            if ($newToken) {
                $headers["Authorization"] = "Bearer $newToken"
            }
            $taskStatus = "POLLING_ERROR"
        }
    } While ($taskStatus -notin $terminalStates)

    if ($taskStatus -in @("COMPLETED", "SUCCESS", "SUCCESSFUL", "Succeeded")) {
        LogMessage -type INFO -message "[$ServiceRuntimeFqdn] Task $TaskId completed successfully"
    } else {
        LogMessage -type ERROR -message "[$ServiceRuntimeFqdn] Task $TaskId ended with status: $taskStatus"
        if ($taskResponse.messages) {
            foreach ($msg in $taskResponse.messages) {
                LogMessage -type ERROR -message "[$ServiceRuntimeFqdn] $msg"
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
    Stop-VcfmsTask -ServiceRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServiceRuntimePassword "VMw@re1!VMw@re1!" -TaskId "2gvic5inrfauxgcnb6askblveu"

    .PARAMETER ServiceRuntimeFqdn
    FQDN of the VCFMS Services Runtime instance.

    .PARAMETER ServiceRuntimePassword
    Password for the Services Runtime admin user.

    .PARAMETER ServiceRuntimeUsername
    Username for the Services Runtime token. Default is "admin@vsp.local".

    .PARAMETER TaskId
    The task ID to cancel.

    .PARAMETER PollIntervalSeconds
    Interval in seconds to poll the task status after cancellation. Default is 10.
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $ServiceRuntimeFqdn,
        [Parameter(Mandatory = $true)][String] $ServiceRuntimePassword,
        [Parameter(Mandatory = $false)][String] $ServiceRuntimeUsername = "admin@vsp.local",
        [Parameter(Mandatory = $true)][String] $TaskId,
        [Parameter(Mandatory = $false)][Int] $PollIntervalSeconds = 10
    )

    $jumpboxName = hostname
    $terminalStates = @("COMPLETED", "FAILED", "CANCELLED", "ERROR", "SUCCESS", "SUCCESSFUL", "Succeeded", "Failed", "Cancelled")

    $srToken = Get-VcfmsServicesRuntimeToken -ServiceRuntimeFqdn $ServiceRuntimeFqdn -Username $ServiceRuntimeUsername -Password $ServiceRuntimePassword
    if (-not $srToken) {
        LogMessage -type ERROR -message "[$jumpboxName] Unable to obtain Services Runtime token. Aborting."
        return
    }

    $headers = @{
        "Authorization" = "Bearer $srToken"
        "Accept"        = "application/json"
    }

    $cancelUri = "https://$ServiceRuntimeFqdn/api/v1/tasks/${TaskId}?action=cancel"
    LogMessage -type INFO -message "[$ServiceRuntimeFqdn] Cancelling task $TaskId"

    try {
        $response = Invoke-RestMethod -Uri $cancelUri -Method POST -Headers $headers -SkipCertificateCheck
        LogMessage -type INFO -message "[$ServiceRuntimeFqdn] Task $TaskId cancel request submitted"
    } catch {
        LogMessage -type ERROR -message "[$ServiceRuntimeFqdn] Failed to cancel task $TaskId : $($_.Exception.Message)"
        if ($_.Exception.Response) {
            try {
                $errorStream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($errorStream)
                $errorBody = $reader.ReadToEnd()
                LogMessage -type ERROR -message "[$ServiceRuntimeFqdn] Response body: $errorBody"
            } catch {}
        }
        return
    }

    # Poll until the task reaches a terminal state
    LogMessage -type INFO -message "[$ServiceRuntimeFqdn] Polling task status every $PollIntervalSeconds seconds"
    $taskUri = "https://$ServiceRuntimeFqdn/api/v1/tasks/$TaskId"
    $taskStatus = "Cancelling"
    Do {
        Start-Sleep -Seconds $PollIntervalSeconds
        try {
            $taskResponse = Invoke-RestMethod -Uri $taskUri -Method GET -Headers $headers -SkipCertificateCheck
            $taskStatus = $taskResponse.status
            LogMessage -type INFO -message "[$ServiceRuntimeFqdn] Status: $taskStatus"
        } catch {
            LogMessage -type WARNING -message "[$ServiceRuntimeFqdn] Error polling task (will retry): $($_.Exception.Message)"
            $newToken = Get-VcfmsServicesRuntimeToken -ServiceRuntimeFqdn $ServiceRuntimeFqdn -Username $ServiceRuntimeUsername -Password $ServiceRuntimePassword
            if ($newToken) {
                $headers["Authorization"] = "Bearer $newToken"
            }
        }
    } While ($taskStatus -notin $terminalStates)

    if ($taskStatus -in @("CANCELLED", "Cancelled")) {
        LogMessage -type INFO -message "[$ServiceRuntimeFqdn] Task $TaskId cancelled successfully"
    } else {
        LogMessage -type WARNING -message "[$ServiceRuntimeFqdn] Task $TaskId ended with status: $taskStatus"
    }

    return $taskResponse
}

Function Remove-VcfmsComponent {
    <#
    .SYNOPSIS
    Deletes one or more VCFMS components via the Fleet Controller API, processing them serially and waiting for each task to complete before proceeding.

    .DESCRIPTION
    The Remove-VcfmsComponent cmdlet calls DELETE /fleet-lcm/v1/components/{componentId} for each component ID provided. Components are deleted one at a time in the order given, and the function monitors each deletion task via the Fleet Controller /fleet-lcm/v1/tasks endpoint until it reaches a terminal state before starting the next. If a deletion fails, processing stops. Use Get-VcfmsComponents to discover component IDs.

    .EXAMPLE
    Remove-VcfmsComponent -FleetControllerFqdn "flt-fc01.rainpole.io" -FleetControllerPassword "VMw@re1!VMw@re1!" -ComponentIds "4e38afb4-ac83-481b-876f-922497eaada7"

    .EXAMPLE
    Remove-VcfmsComponent -FleetControllerFqdn "flt-fc01.rainpole.io" -FleetControllerPassword "VMw@re1!VMw@re1!" -ComponentIds "4e38afb4-ac83-481b-876f-922497eaada7","a669bd76-e75c-4c88-8e9e-a0e6526f4d28","3544191a-dc7a-409f-8c7a-4cd6cf5d93ca"

    .PARAMETER FleetControllerFqdn
    FQDN of the VCFMS Fleet Controller instance.

    .PARAMETER FleetControllerPassword
    Password for the Fleet Controller admin user.

    .PARAMETER FleetControllerUsername
    Username for the Fleet Controller token. Default is "admin@vsp.local".

    .PARAMETER ComponentIds
    One or more component IDs to delete. Processed serially in the order provided.

    .PARAMETER PollIntervalSeconds
    Interval in seconds to poll each deletion task. Default is 30.
    #>

    Param(
        [Parameter(Mandatory = $true)][String] $FleetControllerFqdn,
        [Parameter(Mandatory = $true)][String] $FleetControllerPassword,
        [Parameter(Mandatory = $false)][String] $FleetControllerUsername = "admin@vsp.local",
        [Parameter(Mandatory = $true)][String[]] $ComponentIds,
        [Parameter(Mandatory = $false)][Int] $PollIntervalSeconds = 30
    )

    $jumpboxName = hostname
    $functionStartTime = Get-Date
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
        LogMessage -type INFO -message "[$FleetControllerFqdn] Deleting component $current of $($ComponentIds.Count): $componentId"

        $fcToken = Get-VcfmsFleetControllerToken -FleetControllerFqdn $FleetControllerFqdn -Username $FleetControllerUsername -Password $FleetControllerPassword
        if (-not $fcToken) {
            LogMessage -type ERROR -message "[$FleetControllerFqdn] Unable to obtain Fleet Controller token. Stopping."
            break
        }

        $headers = @{
            "Authorization" = "Bearer $fcToken"
            "Accept"        = "application/json"
        }

        $deleteUri = "https://$FleetControllerFqdn/fleet-lcm/v1/components/$componentId"

        try {
            $response = Invoke-RestMethod -Uri $deleteUri -Method DELETE -Headers $headers -SkipCertificateCheck
        } catch {
            LogMessage -type ERROR -message "[$FleetControllerFqdn] DELETE failed for component $componentId : $($_.Exception.Message)"
            if ($_.Exception.Response) {
                try {
                    $errorStream = $_.Exception.Response.GetResponseStream()
                    $reader = New-Object System.IO.StreamReader($errorStream)
                    $errorBody = $reader.ReadToEnd()
                    LogMessage -type ERROR -message "[$FleetControllerFqdn] Response body: $errorBody"
                } catch {}
            }
            $results += [PSCustomObject]@{ ComponentId = $componentId; TaskId = $null; Status = "DELETE_FAILED" }
            $current++
            continue
        }

        $taskId = $response.id
        $taskDesc = $response.description.localizedMessage
        if ($taskDesc) {
            LogMessage -type INFO -message "[$FleetControllerFqdn] $taskDesc"
        }

        if ($taskId) {
            LogMessage -type INFO -message "[$FleetControllerFqdn] Deletion task: $taskId"
            $taskUri = "https://$FleetControllerFqdn/fleet-lcm/v1/tasks/$taskId"
            $taskStatus = "IN_PROGRESS"

            Do {
                Start-Sleep -Seconds $PollIntervalSeconds
                try {
                    $taskResponse = Invoke-RestMethod -Uri $taskUri -Method GET -Headers $headers -SkipCertificateCheck
                    $taskStatus = $taskResponse.status
                    LogMessage -type INFO -message "[$FleetControllerFqdn] Status: $taskStatus"
                } catch {
                    LogMessage -type WARNING -message "[$FleetControllerFqdn] Error polling task (will retry): $($_.Exception.Message)"
                    $newToken = Get-VcfmsFleetControllerToken -FleetControllerFqdn $FleetControllerFqdn -Username $FleetControllerUsername -Password $FleetControllerPassword
                    if ($newToken) {
                        $headers["Authorization"] = "Bearer $newToken"
                    }
                }
            } While ($taskStatus -notin $terminalStates)

            $finalStatus = $taskStatus
            $results += [PSCustomObject]@{ ComponentId = $componentId; TaskId = $taskId; Status = $finalStatus }

            if ($finalStatus -in @("COMPLETED", "SUCCESS", "SUCCESSFUL", "Succeeded")) {
                LogMessage -type INFO -message "[$FleetControllerFqdn] Component $componentId deleted successfully"
            } else {
                LogMessage -type ERROR -message "[$FleetControllerFqdn] Component $componentId deletion ended with status: $finalStatus. Stopping."
                if ($taskResponse.description.localizedMessage) {
                    LogMessage -type ERROR -message "[$FleetControllerFqdn] $($taskResponse.description.localizedMessage)"
                }
                break
            }
        } else {
            LogMessage -type INFO -message "[$FleetControllerFqdn] Component $componentId deleted (no async task returned)"
            $results += [PSCustomObject]@{ ComponentId = $componentId; TaskId = $null; Status = "COMPLETED" }
        }

        $current++
    }

    Write-Host ""
    Write-Host " Deletion Summary:" -ForegroundColor Cyan
    $results | Format-Table -AutoSize -Property ComponentId, TaskId, Status | Out-String | Write-Host

    LogMessage -type NOTE -message "[$jumpboxName] Completed Task $($MyInvocation.MyCommand) in $(((Get-Date) - $functionStartTime).ToString('hh\:mm\:ss'))"
}
