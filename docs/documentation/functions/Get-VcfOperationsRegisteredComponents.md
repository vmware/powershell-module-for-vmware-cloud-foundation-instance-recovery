# Get-VcfOperationsRegisteredComponents

## Synopsis

Retrieves registered fleet component IDs and related details from a VCF Operations instance.

## Syntax

```powershell
Get-VcfOperationsRegisteredComponents [-VcfOperationsFqdn] <String> [-Password] <String> [[-Username] <String>] [[-AuthSource] <String>] [<CommonParameters>]
```

## Description

The `Get-VcfOperationsRegisteredComponents` cmdlet queries the VCF Operations internal `/suite-api/internal/components` endpoint and returns a structured object containing:

- `components` — Filtered component summaries (including `componentVersion`) for types `FLEET_LCM`, `SALT_RAAS`, `VIDB`, and `LI`.
- `vsp` — VSP component details (including `componentVersion`) referenced by the filtered components (null, a single object, or an array when multiple are present).
- `vcfa` — VCFA component details (including `componentVersion`) if one is registered, otherwise null.

A VCF Operations token is obtained automatically.

## Examples

### Example 1

```powershell
$result = Get-VcfOperationsRegisteredComponents `
    -VcfOperationsFqdn "flt-ops01a.rainpole.io" `
    -Password          "VMw@re1!VMw@re1!"
```

### Example 2

```powershell
$result = Get-VcfOperationsRegisteredComponents `
    -VcfOperationsFqdn "flt-ops01a.rainpole.io" `
    -Username          "admin" `
    -Password          "VMw@re1!VMw@re1!" `
    -AuthSource        "local"
```

## Parameters

### -VcfOperationsFqdn

FQDN of the VCF Operations instance.

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

### -Password

Password for the VCF Operations user.

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

### -Username

Username for the VCF Operations API. Defaults to `admin`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: admin
Accept pipeline input: False
Accept wildcard characters: False
```

### -AuthSource

Authentication source for the VCF Operations API. Defaults to `local`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: local
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
