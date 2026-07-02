# Set-ServicesRuntimeBackupSchedule

## Synopsis

Configures the full and incremental backup schedule on a VCFMS Services Runtime instance.

## Syntax

```powershell
Set-ServicesRuntimeBackupSchedule [-ServicesRuntimeFqdn] <String> [-ServicesRuntimePassword] <String> [-FullBackupEnabled] <Boolean> [-IncrementalBackupEnabled] <Boolean> [[-FullBackupSchedule] <String>] [[-IncrementalBackupSchedule] <String>] [[-ServicesRuntimeUsername] <String>] [[-ComponentId] <String>] [[-PollIntervalSeconds] <Int32>] [<CommonParameters>]
```

## Description

The `Set-ServicesRuntimeBackupSchedule` cmdlet applies a scheduled backup configuration to the specified VCFMS component via `POST /api/v1/components/{ComponentId}?action=apply`. Full and incremental backups are each independently enabled/disabled and given a cron schedule. `-FullBackupSchedule` is required when `-FullBackupEnabled` is `$true`, and `-IncrementalBackupSchedule` is required when `-IncrementalBackupEnabled` is `$true`. If `-ComponentId` is not supplied, the component of type `vsp` is resolved automatically from `GET /api/v1/components`.

## Examples

### Example 1

Enable both full and incremental backups on a schedule, automatically resolving the VSP component.

```powershell
Set-ServicesRuntimeBackupSchedule `
    -ServicesRuntimeFqdn       "sfo-sr01.sfo.rainpole.io" `
    -ServicesRuntimePassword   "VMw@re1!VMw@re1!" `
    -FullBackupEnabled         $true `
    -FullBackupSchedule        "0 2 * * 0" `
    -IncrementalBackupEnabled  $true `
    -IncrementalBackupSchedule "0 2 * * 1-6"
```

### Example 2

Disable scheduled backups for a specific component ID.

```powershell
Set-ServicesRuntimeBackupSchedule `
    -ServicesRuntimeFqdn      "sfo-sr01.sfo.rainpole.io" `
    -ServicesRuntimePassword  "VMw@re1!VMw@re1!" `
    -ComponentId              "1f5c79fe-e3aa-41b1-a5cf-774a6497fa3d" `
    -FullBackupEnabled        $false `
    -IncrementalBackupEnabled $false
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

### -FullBackupEnabled

Whether scheduled full backups are enabled.

```yaml
Type: Boolean
Parameter Sets: (All)
Aliases:

Required: True
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -IncrementalBackupEnabled

Whether scheduled incremental backups are enabled.

```yaml
Type: Boolean
Parameter Sets: (All)
Aliases:

Required: True
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -FullBackupSchedule

Cron schedule for full backups. Required when `-FullBackupEnabled` is `$true`.

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

### -IncrementalBackupSchedule

Cron schedule for incremental backups. Required when `-IncrementalBackupEnabled` is `$true`.

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

### -ComponentId

The component ID (cluster ID) of the VCFMS runtime instance to apply the backup schedule to. If omitted, the component of type `vsp` is resolved automatically.

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
