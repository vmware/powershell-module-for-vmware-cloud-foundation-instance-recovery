# Set-VcfmsSftpBackupSettings

## Synopsis

Configures SFTP backup settings on a VCFMS Services Runtime instance.

## Syntax

```powershell
Set-VcfmsSftpBackupSettings [-ServicesRuntimeFqdn] <String> [-ServicesRuntimePassword] <String> [-ComponentId] <String> [-SftpHost] <String> [-SftpUsername] <String> [-SftpPassword] <String> [-SftpDirectory] <String> [-EncryptionPassphrase] <String> [[-SftpPort] <String>] [[-SftpFingerprint] <String>] [[-ServicesRuntimeUsername] <String>] [[-PollIntervalSeconds] <Int32>] [<CommonParameters>]
```

## Description

The `Set-VcfmsSftpBackupSettings` cmdlet applies SFTP backup configuration to the specified VCFMS component via `POST /api/v1/components/{ComponentId}?action=apply`. If `-SftpFingerprint` is not supplied, the SSH host key fingerprint is automatically retrieved from the SFTP server using `ssh-keyscan`.

## Examples

### Example 1

Apply SFTP backup configuration with automatic fingerprint retrieval.

```powershell
Set-VcfmsSftpBackupSettings `
    -ServicesRuntimeFqdn     "sfo-sr01.sfo.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
    -ComponentId             "1f5c79fe-e3aa-41b1-a5cf-774a6497fa3d" `
    -SftpHost                "10.167.173.126" `
    -SftpDirectory           "/media/backups/" `
    -SftpUsername            "svc-vcf-bck" `
    -SftpPassword            "VMw@re1!" `
    -EncryptionPassphrase    "VMw@re1!VMw@re1!"
```

### Example 2

Supply the SFTP fingerprint directly.

```powershell
Set-VcfmsSftpBackupSettings `
    -ServicesRuntimeFqdn     "sfo-sr01.sfo.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
    -ComponentId             "1f5c79fe-e3aa-41b1-a5cf-774a6497fa3d" `
    -SftpHost                "10.167.173.126" `
    -SftpDirectory           "/media/backups/" `
    -SftpUsername            "svc-vcf-bck" `
    -SftpPassword            "VMw@re1!" `
    -EncryptionPassphrase    "VMw@re1!VMw@re1!" `
    -SftpFingerprint         "SHA256:abc123..."
```

## Parameters

### -ServicesRuntimeFqdn

The fully qualified domain name of the VCFMS Services Runtime instance.

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

### -ServicesRuntimePassword

The password for the Services Runtime admin user (used to obtain a token).

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ComponentId

The component ID (cluster ID) of the VCFMS runtime instance to apply the SFTP settings to.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SftpHost

The IP address or FQDN of the SFTP backup server.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SftpUsername

The username for authenticating to the SFTP server.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 5
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SftpPassword

The password for authenticating to the SFTP server.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 6
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SftpDirectory

The remote directory path on the SFTP server for backup storage (e.g. `/media/backups/`).

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 7
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -EncryptionPassphrase

The passphrase used to encrypt backup files at rest.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 8
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SftpPort

The SSH port on the SFTP server. Defaults to `22`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 22
Accept pipeline input: False
Accept wildcard characters: False
```

### -SftpFingerprint

Optional. The SHA-256 fingerprint of the SFTP server's SSH host key. If omitted, it is retrieved automatically via `ssh-keyscan`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ServicesRuntimeUsername

The Services Runtime identity username. Defaults to `admin@vsp.local`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: admin@vsp.local
Accept pipeline input: False
Accept wildcard characters: False
```

### -PollIntervalSeconds

Interval in seconds to poll the apply task status. Defaults to `60`.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 60
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
