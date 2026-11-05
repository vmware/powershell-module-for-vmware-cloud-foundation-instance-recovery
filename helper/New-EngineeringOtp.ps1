<#
.SYNOPSIS
Generates a 12-hour engineering one-time code for the Recovery Coordinator UI

.DESCRIPTION
Signs the current UTC time (whole minutes) with the engineer's private key (created once by
New-EngineeringOtpKeyPair.ps1). The resulting code is base64url(4-byte issue time + 64-byte signature).
The UI verifies it with the embedded public key and accepts it from the issue time until 12 hours later.
The private key is never stored in this script -- it is read from -PrivateKeyPath and unlocked with a
passphrase prompt each run.

.EXAMPLE
./New-EngineeringOtp.ps1 -PrivateKeyPath '~/secure/vcf-rc-otp-private.pem'
#>
Param(
    [Parameter(Mandatory = $true)][string]$PrivateKeyPath
)
$ErrorActionPreference = 'Stop'
$resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($PrivateKeyPath)
if (-not (Test-Path -LiteralPath $resolved)) { throw "Private key file '$resolved' not found." }
$passphrase = Read-Host -AsSecureString -Prompt 'Private key passphrase'

$ecdsa = [System.Security.Cryptography.ECDsa]::Create()
try {
    $ecdsa.ImportFromEncryptedPem((Get-Content -LiteralPath $resolved -Raw), [System.Net.NetworkCredential]::new('', $passphrase).Password)

    $issued = [uint32][Math]::Floor([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() / 60)
    $issuedBytes = [BitConverter]::GetBytes($issued)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($issuedBytes) }

    # Domain-separation prefix must match Test-EngineeringModeOtp in the UI script.
    $data = [System.Text.Encoding]::UTF8.GetBytes('VCFRC-ENG-OTP') + $issuedBytes
    $signature = $ecdsa.SignData($data, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
} finally { $ecdsa.Dispose() }

$code = [Convert]::ToBase64String($issuedBytes + $signature).TrimEnd('=').Replace('+', '-').Replace('/', '_')
$expires = [DateTimeOffset]::FromUnixTimeSeconds([int64]$issued * 60).AddHours(12).ToLocalTime()
Write-Host "One-time code (valid until $($expires.ToString('yyyy-MM-dd HH:mm:ss zzz'))):"
Write-Host $code
