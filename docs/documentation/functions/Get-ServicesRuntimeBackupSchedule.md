# Get-ServicesRuntimeBackupSchedule

## Synopsis

Retrieves the existing full and incremental backup schedule from a VCFMS Services Runtime instance.

## Syntax

```powershell
Get-ServicesRuntimeBackupSchedule [-ServicesRuntimeFqdn] <String> [-ServicesRuntimePassword] <String> [[-ServicesRuntimeUsername] <String>] [[-ComponentId] <String>] [<CommonParameters>]
```

## Description

The `Get-ServicesRuntimeBackupSchedule` cmdlet retrieves the specified component's detail via `GET /api/v1/components/{ComponentId}` and returns the backup schedule found at `spec.configuration.backups` (full and incremental enable/schedule values). If `-ComponentId` is not supplied, the component of type `vsp` is resolved automatically from `GET /api/v1/components`.

## Examples

### Example 1

Retrieve the backup schedule, automatically resolving the VSP component.

```powershell
Get-ServicesRuntimeBackupSchedule -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!"
```

### Example 2

Retrieve the backup schedule for a specific component ID.

```powershell
Get-ServicesRuntimeBackupSchedule -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!" -ComponentId "1f5c79fe-e3aa-41b1-a5cf-774a6497fa3d"
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

The component ID (cluster ID) to retrieve the backup schedule from. If omitted, the component of type `vsp` is resolved automatically.

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

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
