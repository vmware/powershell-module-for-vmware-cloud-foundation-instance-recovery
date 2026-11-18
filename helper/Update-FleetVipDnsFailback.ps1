<#
.SYNOPSIS
Moves the fleet component VIP DNS entries to the original site's network for a Fleet Disaster Recovery failback.

.DESCRIPTION
Standalone script intended to be run by Invoke-UserScript (child pwsh process, no parameters, exit code 0 = success).
Modelled on Platform Tools' Remove-BindDnsEntry / New-BindDnsEntry: the forward (A) and reverse (PTR) records are
removed from, and added to, the BIND zone files on the PTR router over SSH, then BIND is restarted.

Re-creates each FQDN as 10.11.yy.zz. yy and zz are taken from the IP address each FQDN resolves to before its
entries are removed. The matching script for the other direction is Update-FleetVipDnsFailover.ps1.

  1. Resolves every FQDN and works out its new IP. Nothing is changed unless every FQDN can be processed.
  2. Removes the old forward and reverse records and adds the new ones (creating a missing zone file if needed).
  3. Restarts BIND once, then confirms every FQDN resolves, forward and reverse, to its new IP.

Safe to re-run. An FQDN that already resolves to the target network is left alone, and if all of them do the
script exits 0 without touching DNS.

Exit code: 0 = success, 1 = failure (any [ERROR] line also marks the Invoke-UserScript task as failed).
Requires the Posh-SSH module and network access to the PTR router.

.EXAMPLE
pwsh -NoProfile -File .\Update-FleetVipDnsFailback.ps1
#>

# ======================================================================================
# VARIABLES TO SET - replace every <placeholder> before running
# ======================================================================================

# --- PTR router that hosts the BIND zones
$routerAddress     = '10.11.10.4'
$routerUser        = 'root'
$routerPassword    = 'VMw@re1!'

# --- FQDNs to move
$fqdns = @(
    'flt-logs01.rainpole.io',
    'flt-idb01.rainpole.io',
    'flt-fc01.rainpole.io',
    'flt-vcfa-sr01.rainpole.io',
    'flt-auto01.rainpole.io'
)

# --- Second octet of the 10.xx.yy.zz network the entries are moved to
$targetSecondOctet = '11'

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

# Runs a command on the PTR router and throws if it exits non-zero. Returns the command output.
Function Invoke-PtrCommand {
    Param([Parameter(Mandatory)] [string]$Command)
    $result = Invoke-SSHCommand -SessionId $script:sshSession.SessionId -Command $Command -TimeOut 300
    If ($result.ExitStatus -ne 0) {
        Throw "Command on $routerAddress failed (exit code $($result.ExitStatus)): $Command $($result.Error -join ' ')"
    }
    Return $result.Output
}

# Queries the PTR router's DNS directly so results are never served from the jumpbox's cache.
Function Get-ForwardIp {
    Param([Parameter(Mandatory)] [string]$Fqdn)
    $record = Resolve-DnsName -Name $Fqdn -Type A -Server $routerAddress -DnsOnly -ErrorAction SilentlyContinue | Where-Object { $_.Type -eq 'A' } | Select-Object -First 1
    If ($record) {
        Return [string]$record.IPAddress
    }
    Return $null
}

Function Get-ReverseName {
    Param([Parameter(Mandatory)] [string]$IpAddress)
    $record = Resolve-DnsName -Name $IpAddress -Type PTR -Server $routerAddress -DnsOnly -ErrorAction SilentlyContinue | Where-Object { $_.Type -eq 'PTR' } | Select-Object -First 1
    If ($record) {
        Return ([string]$record.NameHost).TrimEnd('.')
    }
    Return $null
}

# Creates the zone file (and its named.conf.local stanza) if it is not already on the router. Content is sent
# base64 encoded so no shell quoting is needed.
Function Confirm-BindZone {
    Param([Parameter(Mandatory)] [string]$Zone, [Parameter(Mandatory)] [bool]$Reverse)
    $zoneFile = "/etc/bind/zones/$Zone.zonedb"
    If ((Invoke-PtrCommand "[ -f $zoneFile ] && echo present || echo missing") -contains 'present') {
        Return
    }
    LogMessage -type INFO -message "$tag Creating zone $Zone"
    $lines = @()
    If ($Reverse) {
        $lines += "`$ORIGIN`t$Zone."
    }
    $lines += "`$TTL 3600"
    $lines += "@`tIN`tSOA`tlocalhost.`tadministrator.rainpole.io. ("
    $lines += "`t`t`t2`t; Serial"
    $lines += "`t`t`t604800`t; Refresh"
    $lines += "`t`t`t86400`t; Retry"
    $lines += "`t`t`t2419200`t; Expire"
    $lines += "`t`t`t604800 )`t; Negative Cache TTL"
    $lines += "@`tIN`tNS`tlocalhost."
    $lines += "@`tIN`tA`t127.0.0.1"
    $zoneB64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(($lines -join "`n") + "`n"))
    Invoke-PtrCommand "echo $zoneB64 | base64 -d > $zoneFile" | Out-Null

    $stanza = "`nzone `"$Zone`" {`n    type master;`n    file `"$zoneFile`";`n};`n"
    $stanzaB64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($stanza))
    Invoke-PtrCommand "grep -q 'zones/$Zone.zonedb' /etc/bind/named.conf.local || echo $stanzaB64 | base64 -d >> /etc/bind/named.conf.local" | Out-Null
}

Try {
    # ---------------- 0. Validate input ----------------
    Test-Placeholders
    If (-not (Get-Module -ListAvailable -Name Posh-SSH)) {
        Throw "Posh-SSH module is not installed"
    }
    $direction = 'Failback'
    $targetOctet = $targetSecondOctet
    $tag = "[DNS]"

    # ---------------- 1. Note existing IPs and work out the new ones ----------------
    LogMessage -type INFO -message "$tag $direction - moving $($fqdns.Count) fleet VIP DNS entries to 10.$targetOctet.yy.zz"
    $changes = @()
    ForEach ($fqdn in $fqdns) {
        $oldIp = Get-ForwardIp -Fqdn $fqdn
        If (-not $oldIp) {
            Throw "Forward lookup for $fqdn not found"
        }
        If ($oldIp -notmatch '^10\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') {
            Throw "$fqdn resolves to $oldIp, which is not in the expected 10.xx.yy.zz format"
        }
        $oldOctet = $Matches[1]
        $newIp = "10.$targetOctet.$($Matches[2]).$($Matches[3])"
        If ($oldOctet -eq $targetOctet) {
            LogMessage -type INFO -message "$tag $fqdn already $oldIp - no change"
            Continue
        }
        $ptrOwner = Get-ReverseName -IpAddress $newIp
        If ($ptrOwner -and $ptrOwner -ne $fqdn) {
            Throw "Reverse lookup for $newIp already exists for $ptrOwner"
        }
        LogMessage -type INFO -message "$tag $fqdn $oldIp -> $newIp"
        $changes += [pscustomobject]@{ Fqdn = $fqdn; OldIp = $oldIp; NewIp = $newIp }
    }
    If ($changes.Count -eq 0) {
        LogMessage -type INFO -message "$tag $direction DNS entries are already in place"
        Exit 0
    }

    # ---------------- 2. Remove the old records, add the new ones ----------------
    $securePassword = ConvertTo-SecureString -String $routerPassword -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential ($routerUser, $securePassword)
    $knownHosts = New-SSHMemoryKnownHost
    $fingerprint = $null
    For ($attempt = 1; $attempt -le 5 -and -not $fingerprint; $attempt++) {
        $fingerprint = (Get-SSHHostKey -ComputerName $routerAddress -ErrorAction SilentlyContinue).Fingerprint
        If (-not $fingerprint) {
            Start-Sleep -Seconds 5
        }
    }
    If (-not $fingerprint) {
        Throw "Unable to read the SSH host key from $routerAddress"
    }
    New-SSHTrustedHost -KnownHostStore $knownHosts -HostName $routerAddress -FingerPrint $fingerprint | Out-Null
    $script:sshSession = New-SSHSession -ComputerName $routerAddress -Credential $credential -KnownHost $knownHosts

    ForEach ($change in $changes) {
        $shortName = $change.Fqdn.Split('.', 2)[0]
        $forwardZone = $change.Fqdn.Split('.', 2)[1]
        $oldOctets = $change.OldIp.Split('.')
        $newOctets = $change.NewIp.Split('.')
        $oldReverseZone = "$($oldOctets[2]).$($oldOctets[1]).$($oldOctets[0]).in-addr.arpa"
        $newReverseZone = "$($newOctets[2]).$($newOctets[1]).$($newOctets[0]).in-addr.arpa"
        $forwardFile = "/etc/bind/zones/$forwardZone.zonedb"
        $oldReverseFile = "/etc/bind/zones/$oldReverseZone.zonedb"
        $newReverseFile = "/etc/bind/zones/$newReverseZone.zonedb"
        $escapedOldIp = $change.OldIp -replace '\.', '\.'
        $escapedFqdn = $change.Fqdn -replace '\.', '\.'

        # Remove forward and reverse (same sed approach as Platform Tools, anchored to the exact record)
        Invoke-PtrCommand "sed -i '/^${shortName}[[:space:]]*IN[[:space:]]*A[[:space:]]*${escapedOldIp}[[:space:]]*`$/d' $forwardFile" | Out-Null
        Invoke-PtrCommand "[ ! -f $oldReverseFile ] || sed -i '/^$($oldOctets[3])[[:space:]]*IN[[:space:]]*PTR[[:space:]]*${escapedFqdn}\.\?[[:space:]]*`$/d' $oldReverseFile" | Out-Null

        # Add forward and reverse
        Confirm-BindZone -Zone $forwardZone -Reverse $false
        Confirm-BindZone -Zone $newReverseZone -Reverse $true
        Invoke-PtrCommand "sed -i -e '`$a\' $forwardFile && echo '$shortName`tIN`tA`t$($change.NewIp)' >> $forwardFile" | Out-Null
        Invoke-PtrCommand "sed -i -e '`$a\' $newReverseFile && echo '$($newOctets[3])`tIN`tPTR`t$($change.Fqdn).' >> $newReverseFile" | Out-Null
    }

    LogMessage -type INFO -message "$tag Restarting BIND"
    Invoke-PtrCommand "systemctl restart bind9.service" | Out-Null
    Remove-SSHSession -SessionId $script:sshSession.SessionId | Out-Null
    $script:sshSession = $null

    # ---------------- 3. Confirm the new records resolve ----------------
    ForEach ($change in $changes) {
        $verified = $false
        For ($attempt = 1; $attempt -le 6 -and -not $verified; $attempt++) {
            $verified = (Get-ForwardIp -Fqdn $change.Fqdn) -eq $change.NewIp -and (Get-ReverseName -IpAddress $change.NewIp) -eq $change.Fqdn
            If (-not $verified) {
                Start-Sleep -Seconds 5
            }
        }
        If (-not $verified) {
            Throw "$($change.Fqdn) does not resolve (forward and reverse) to $($change.NewIp) after the change"
        }
    }

    LogMessage -type INFO -message "$tag $direction DNS entries updated and verified ($($changes.Count) FQDNs)"
    Exit 0
} Catch {
    LogMessage -type ERROR -message "$($_.Exception.Message)"
    If ($script:sshSession) {
        Remove-SSHSession -SessionId $script:sshSession.SessionId -ErrorAction SilentlyContinue | Out-Null
    }
    Exit 1
}
