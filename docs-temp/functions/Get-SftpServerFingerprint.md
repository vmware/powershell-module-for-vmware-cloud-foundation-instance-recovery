# Get-SftpServerFingerprint

## Synopsis

Retrieves the SHA-256 host key fingerprint from an SFTP server.

## Syntax

```powershell
Get-SftpServerFingerprint [-sftpHost] <String> [[-sftpPort] <Int32>] [<CommonParameters>]
```

## Description

The `Get-SftpServerFingerprint` cmdlet opens a raw TCP connection to the SSH/SFTP server, exchanges banners to prompt the server's key exchange, locates the host key blob in the packet stream, and computes a `SHA256:<base64>` fingerprint. No `ssh-keyscan` or `ssh-keygen` binary is required. Equivalent to:

```bash
ssh-keyscan -p 22 <host> | ssh-keygen -lf -
```

The returned fingerprint string is in the format expected by the VCFMS SFTP backup specification (e.g. `SHA256:abc123...`). Supports key types `ssh-rsa`, `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`, and `ssh-ed25519`.

## Examples

### Example 1

```powershell
$fp = Get-SftpServerFingerprint -sftpHost "10.167.173.126"
```

## Parameters

### -sftpHost

The IP address or FQDN of the SFTP server.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -sftpPort

The SSH port. Defaults to `22`.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: 22
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
