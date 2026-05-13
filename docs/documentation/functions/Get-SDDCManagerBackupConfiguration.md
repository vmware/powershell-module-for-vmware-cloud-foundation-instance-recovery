# Get-SDDCManagerBackupConfiguration

## Synopsis

Retrieves the backup configuration from SDDC Manager.

## Syntax

```powershell
Get-SDDCManagerBackupConfiguration [-sddcManagerFqdn] <String> [-username] <String> [-password] <String> [<CommonParameters>]
```

## Description

The `Get-SDDCManagerBackupConfiguration` cmdlet calls `GET /v1/system/backup-configuration` and returns the current backup settings, including schedules and backup locations. Useful for verifying that an SFTP backup destination is configured before triggering a backup task.

## Examples

### Example 1

```powershell
Get-SDDCManagerBackupConfiguration -sddcManagerFqdn "sfo-vcf01.sfo.rainpole.io" -username "admin@local" -password "VMw@re1!"
```

## Parameters

### -sddcManagerFqdn

The fully qualified domain name of the SDDC Manager appliance.

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

### -username

The username to authenticate with SDDC Manager.

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

### -password

The password for the SDDC Manager user.

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

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
