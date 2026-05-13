# Get-VCFMSFleetComponents

## Synopsis

Retrieves VCFMS component records from the Fleet Controller.

## Syntax

```powershell
Get-VCFMSFleetComponents [-vcfmsFcFqdn] <String> [-fcPassword] <String> [[-ComponentTypes] <String[]>] [[-fcUsername] <String>] [-PassThru] [<CommonParameters>]
```

## Description

The `Get-VCFMSFleetComponents` cmdlet calls `GET /fleet-lcm/v1/components?includeConsumptionVsp=true&includeVcdMigrator=true` on the Fleet Controller and returns a table of component id and type. When no `-ComponentTypes` filter is supplied, all components are returned. For components of type `VCF services runtime`, the FQDN column is automatically included. Emits a formatted table to the host unless `-PassThru` is set.

## Examples

### Example 1

Return all components.

```powershell
Get-VCFMSFleetComponents -vcfmsFcFqdn "flt-fc01.rainpole.io" -fcPassword "VMw@re1!VMw@re1!"
```

### Example 2

Filter to specific component types.

```powershell
Get-VCFMSFleetComponents -vcfmsFcFqdn "flt-fc01.rainpole.io" -fcPassword "VMw@re1!VMw@re1!" `
    -ComponentTypes "VCF services runtime", "Log management"
```

### Example 3

Capture the component id for downstream use.

```powershell
$components = Get-VCFMSFleetComponents -vcfmsFcFqdn "flt-fc01.rainpole.io" -fcPassword "VMw@re1!VMw@re1!" -PassThru
$logMgmtId  = ($components | Where-Object { $_.ComponentTypeDescription -eq "Log management" }).Id
```

## Parameters

### -vcfmsFcFqdn

The fully qualified domain name of the VCFMS Fleet Controller (fc) node.

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

### -fcPassword

The password for `admin@vsp.local` on the Fleet Controller.

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

Optional. One or more `componentTypeDescription` strings to filter on (case-insensitive). When omitted, all components are returned.

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

### -fcUsername

The Fleet Controller identity username. Defaults to `admin@vsp.local`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: admin@vsp.local
Accept pipeline input: False
Accept wildcard characters: False
```

### -PassThru

When set, suppresses the `Format-Table` host output and returns only the object array.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
