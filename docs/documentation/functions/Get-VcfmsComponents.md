# Get-VcfmsComponents

## Synopsis

Retrieves VCFMS component IDs from the Fleet LCM, optionally filtered by component type description.

## Syntax

```powershell
Get-VcfmsComponents [-FleetLCMFqdn] <String> [-FleetLCMPassword] <String> [[-ComponentTypes] <String[]>] [[-FleetLCMUsername] <String>] [<CommonParameters>]
```

## Description

The `Get-VcfmsComponents` cmdlet queries the VCFMS Fleet LCM `GET /fleet-lcm/v1/components` endpoint and returns component details. If no component types are specified, all components are returned. If one or more types are specified, only matching components are returned. For `VCF services runtime` components, the FQDN is included in the output.

## Examples

### Example 1

Retrieve all components.

```powershell
Get-VcfmsComponents `
    -FleetLCMFqdn      "flt-fc01.rainpole.io" `
    -FleetLCMPassword  "VMw@re1!VMw@re1!"
```

### Example 2

Retrieve only services runtime components.

```powershell
Get-VcfmsComponents `
    -FleetLCMFqdn      "flt-fc01.rainpole.io" `
    -FleetLCMPassword  "VMw@re1!VMw@re1!" `
    -ComponentTypes    "VCF services runtime"
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

### -ComponentTypes

One or more component type descriptions to filter by. When omitted all components are returned.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
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

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
