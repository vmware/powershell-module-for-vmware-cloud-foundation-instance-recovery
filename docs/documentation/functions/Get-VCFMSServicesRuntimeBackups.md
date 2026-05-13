# Get-VCFMSServicesRuntimeBackups

## Synopsis

Retrieves and displays available backups from the VCFMS Services Runtime, optionally filtered by component type and VSP instance.

## Syntax

```powershell
Get-VcfmsBackups [-ServicesRuntimeFqdn] <String> [-ServicesRuntimePassword] <String> [[-Components] <String[]>] [[-ServicesRuntimeUsername] <String>] [[-VspId] <String>] [<CommonParameters>]
```

## Description

The `Get-VcfmsBackups` cmdlet queries the VCFMS Services Runtime `GET /api/v1/system/backups` endpoint and returns backup details for the specified component types, sorted by component type and age. Output includes component type, version, backup name, age, and path.

When `-VspId` is supplied, results are filtered to only those backups whose path contains `/vcf/backups/<VspId>/`, allowing you to scope output to a specific VSP instance when multiple are present in the backup store.

After displaying the table, the cmdlet optionally constructs a `restore-payload.json` file containing the latest backup of each component, ready for use with `Restore-VcfmsBackup`.

## Examples

### Example 1

Display all component backups.

```powershell
Get-VcfmsBackups -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!"
```

### Example 2

Filter to specific components.

```powershell
Get-VcfmsBackups -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
    -Components "vsp","salt","vidb"
```

### Example 3

Scope results to a specific VSP instance.

```powershell
Get-VcfmsBackups -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
    -VspId "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
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

### -Components

One or more component types to display. Valid values: `vsp`, `vcf-fleet-lcm`, `vcf-fleet-depot`, `vcf-sddc-lcm`, `salt`, `salt-raas`, `vidb`, `ops-logs`, `vcfa`. Defaults to all types in canonical order. When the optional restore JSON is generated without explicitly passing `-Components`, `ops-logs` and `vcfa` are excluded from the JSON (include them by passing `-Components` explicitly).

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: vsp, vcf-fleet-lcm, vcf-fleet-depot, vcf-sddc-lcm, salt, salt-raas, vidb, ops-logs, vcfa
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
Position: 4
Default value: admin@vsp.local
Accept pipeline input: False
Accept wildcard characters: False
```

### -VspId

When specified, only backups whose path contains `/vcf/backups/<VspId>/` are returned. Use this to scope results to a specific VSP instance when multiple instances are present in the backup store.

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
