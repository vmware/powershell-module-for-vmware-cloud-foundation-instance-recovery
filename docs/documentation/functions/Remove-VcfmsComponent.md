# Remove-VcfmsComponent

## Synopsis

Deletes one or more VCFMS components via the Fleet LCM API, processing them serially and waiting for each deletion task to complete.

## Syntax

```powershell
Remove-VcfmsComponent [-FleetLCMFqdn] <String> [-FleetLCMPassword] <String> [-ComponentIds] <String[]> [[-FleetLCMUsername] <String>] [[-PollIntervalSeconds] <Int32>] [<CommonParameters>]
```

## Description

The `Remove-VcfmsComponent` cmdlet calls `DELETE /fleet-lcm/v1/components/{componentId}` for each component ID provided, processing them one at a time in the order given. The function monitors each deletion task via the Fleet LCM `/fleet-lcm/v1/tasks` endpoint until it reaches a terminal state before starting the next deletion. If a deletion fails, processing stops. Use `Get-VcfmsComponents` to discover component IDs. The operator is prompted to confirm before any deletions are executed.

## Examples

### Example 1

Delete a single component.

```powershell
Remove-VcfmsComponent `
    -FleetLCMFqdn     "flt-fc01.rainpole.io" `
    -FleetLCMPassword "VMw@re1!VMw@re1!" `
    -ComponentIds     "4e38afb4-ac83-481b-876f-922497eaada7"
```

### Example 2

Delete multiple components serially.

```powershell
Remove-VcfmsComponent `
    -FleetLCMFqdn     "flt-fc01.rainpole.io" `
    -FleetLCMPassword "VMw@re1!VMw@re1!" `
    -ComponentIds     "4e38afb4-ac83-481b-876f-922497eaada7","a669bd76-e75c-4c88-8e9e-a0e6526f4d28"
```

## Parameters

### -FleetLCMFqdn

FQDN of the VCFMS Fleet LCM instance.

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

Password for the Fleet LCM admin user.

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

### -ComponentIds

One or more component IDs to delete. Processed serially in the order provided.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: True
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -FleetLCMUsername

Username for the Fleet LCM token request. Defaults to `admin@vsp.local`.

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

Interval in seconds to poll each deletion task. Defaults to `30`.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 30
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
