# Start-ServicesRuntimeComponentBackup

## Synopsis

Takes an on-demand backup of one or more VCFMS components.

## Syntax

```powershell
Start-ServicesRuntimeComponentBackup [-FleetLCMFqdn] <String> [-FleetLCMPassword] <String> [[-FleetLCMUsername] <String>] [-ServicesRuntimeFqdn] <String> [-ServicesRuntimePassword] <String> [[-ServicesRuntimeUsername] <String>] [[-ComponentIds] <String[]>] [[-PollIntervalSeconds] <Int32>] [<CommonParameters>]
```

## Description

The `Start-ServicesRuntimeComponentBackup` cmdlet retrieves the list of registered VCFMS components from the Fleet LCM, groups and sorts them by the VCF instance (Services Runtime / VSP cluster, identified by each component's `vspCluster.fqdn`) they are hosted on, and prompts you to pick a single VCF instance before selecting one, several, or all of that instance's components to back up. Components with no `vspCluster` association (fleet-wide OVA components such as VCF Automation) are grouped under `Fleet-wide`. `VCF Operations`, `VCF Operations for networks`, `Telemetry`, `Real-time metrics store`, `Real-time metrics`, and `Migration service engine` are excluded entirely, as file-based backup is not supported for those component types. It then submits a backup task to the target Services Runtime instance via `POST /api/v1/system/backups?action=backup` and polls the task until it reaches a terminal state.

Pass `-ComponentIds` to skip the interactive selection and back up a known set of components directly. All specified component IDs must belong to the same VCF instance.

## Examples

### Example 1

Interactively select components to back up.

```powershell
Start-ServicesRuntimeComponentBackup `
    -FleetLCMFqdn            "flt-fc01.rainpole.io" `
    -FleetLCMPassword        "VMw@re1!VMw@re1!" `
    -ServicesRuntimeFqdn     "sfo-sr01.sfo.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!"
```

### Example 2

Back up a known set of components without the interactive prompt.

```powershell
Start-ServicesRuntimeComponentBackup `
    -FleetLCMFqdn            "flt-fc01.rainpole.io" `
    -FleetLCMPassword        "VMw@re1!VMw@re1!" `
    -ServicesRuntimeFqdn     "sfo-sr01.sfo.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
    -ComponentIds            "4e38afb4-ac83-481b-876f-922497eaada7","a669bd76-e75c-4c88-8e9e-a0e6526f4d28"
```

## Parameters

### -FleetLCMFqdn

FQDN of the VCFMS Fleet LCM instance used to enumerate components.

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

### -FleetLCMPassword

Password for the Fleet LCM admin user (used to obtain a token).

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

### -FleetLCMUsername

Username for the Fleet LCM token.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: admin@vsp.local
Accept pipeline input: False
Accept wildcard characters: False
```

### -ServicesRuntimeFqdn

FQDN of the VCFMS Services Runtime instance that will run the backup task.

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

### -ServicesRuntimePassword

Password for the Services Runtime admin user.

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

### -ServicesRuntimeUsername

Username for the Services Runtime token.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 6
Default value: admin@vsp.local
Accept pipeline input: False
Accept wildcard characters: False
```

### -ComponentIds

One or more component IDs to back up. If not specified, the cmdlet displays a numbered list of components and prompts for a selection.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 7
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -PollIntervalSeconds

Interval in seconds to poll the backup task status.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 8
Default value: 30
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
