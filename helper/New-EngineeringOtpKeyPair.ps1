<#
.SYNOPSIS
Creates the ECDSA P-256 keypair used to sign Recovery Coordinator engineering one-time codes (run once)

.DESCRIPTION
Writes the PRIVATE key to -PrivateKeyPath as a passphrase-encrypted PKCS#8 PEM file and prints the
PUBLIC key (base64) to paste into $script:EngineeringOtpPublicKey in xaml\VCFRecoveryCoordinatorUI.ps1.
Keep the private key file OUTSIDE this repository (e.g. a password vault or a locked-down share);
only people who hold it can generate valid codes with New-EngineeringOtp.ps1. The public key is safe to
commit -- it can verify codes but never create them.

.EXAMPLE
./New-EngineeringOtpKeyPair.ps1 -PrivateKeyPath '~/secure/vcf-rc-otp-private.pem'
#>
Param(
    [Parameter(Mandatory = $true)][string]$PrivateKeyPath
)
$ErrorActionPreference = 'Stop'
$resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($PrivateKeyPath)
if (Test-Path -LiteralPath $resolved) { throw "'$resolved' already exists; refusing to overwrite an existing key." }

$passphrase = Read-Host -AsSecureString -Prompt 'Passphrase to protect the private key'
$confirm = Read-Host -AsSecureString -Prompt 'Confirm passphrase'
$plain = [System.Net.NetworkCredential]::new('', $passphrase).Password
if ($plain.Length -lt 8 -or $plain -cne [System.Net.NetworkCredential]::new('', $confirm).Password) {
    throw 'Passphrases must match and be at least 8 characters.'
}

$ecdsa = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
try {
    Set-Content -LiteralPath $resolved -Value $ecdsa.ExportEncryptedPkcs8PrivateKeyPem($plain, [System.Security.Cryptography.PbeParameters]::new('Aes256Cbc', 'SHA256', 100000))
    $publicKey = [Convert]::ToBase64String($ecdsa.ExportSubjectPublicKeyInfo())
} finally { $ecdsa.Dispose() }

Write-Host "Private key written to: $resolved"
Write-Host 'Paste this into $script:EngineeringOtpPublicKey in xaml\VCFRecoveryCoordinatorUI.ps1:'
Write-Host $publicKey
