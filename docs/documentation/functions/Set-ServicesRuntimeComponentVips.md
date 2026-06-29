# Set-ServicesRuntimeComponentVips

## Synopsis

Updates the VIP configuration for a VCFMS component on a Services Runtime cluster.

## Syntax

```powershell
Set-ServicesRuntimeComponentVips [-ServicesRuntimeFqdn] <String> [-ServicesRuntimePassword] <String> [-ComponentType] <String> [-Vips] <String[]> [[-ServicesRuntimeUsername] <String>] [[-PollIntervalSeconds] <Int32>] [[-ComponentId] <String>] [<CommonParameters>]
```

## Description

The `Set-ServicesRuntimeComponentVips` cmdlet applies a new VIP configuration to the specified VCFMS component type via `POST /api/v1/components/{componentId}?action=apply`. The component ID is resolved automatically from `GET /api/v1/components` by matching on the component type unless `-ComponentId` is supplied directly. Supported component types are `vcfa`, `vidb`, and `ops-logs`.

## Examples

### Example 1

Update the Identity Broker VIP.

```powershell
Set-ServicesRuntimeComponentVips `
    -ServicesRuntimeFqdn     "sfo-sr01.sfo.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
    -ComponentType           "vidb" `
    -Vips                    "10.0.0.5"
```

### Example 2

Update VCF Automation VIPs with multiple addresses.

```powershell
Set-ServicesRuntimeComponentVips `
    -ServicesRuntimeFqdn     "sfo-sr01.sfo.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
    -ComponentType           "vcfa" `
    -Vips                    "10.0.0.5","10.0.0.6"
```

## Parameters

### -ServicesRuntimeFqdn

FQDN of the VCFMS Services Runtime instance.

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

Password for the Services Runtime admin user.

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

### -ComponentType

The component type whose VIPs will be updated. Valid values: `vcfa`, `vidb`, `ops-logs`.

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

### -Vips

One or more IPv4 VIP addresses to apply to the component.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: True
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ServicesRuntimeUsername

Username for the Services Runtime token request. Defaults to `admin@vsp.local`.

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

Interval in seconds to poll the apply task status. Defaults to `30`.

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

### -ComponentId

Optional. If supplied, targets this component UUID directly instead of resolving by type from `GET /api/v1/components`.

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
