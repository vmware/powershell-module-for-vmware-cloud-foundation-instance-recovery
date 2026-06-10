# Invoke-VcfmsFleetComponentRegistration

## Synopsis

Updates fleet component registrations on a VCFMS Services Runtime cluster by running a remote script on the control plane node.

## Syntax

```powershell
# By VCF instance name
Invoke-VcfmsFleetComponentRegistration [-ServicesRuntimeFqdn] <String> [-ServicesRuntimePassword] <String> [-TargetVcfInstance] <String> [-DryRun] [[-RemoteScriptTimeout] <Int32>] [<CommonParameters>]

# By FQDN pattern
Invoke-VcfmsFleetComponentRegistration [-ServicesRuntimeFqdn] <String> [-ServicesRuntimePassword] <String> [-TargetFqdn] <String> [-DryRun] [[-RemoteScriptTimeout] <Int32>] [<CommonParameters>]

# By SDDC LCM ID
Invoke-VcfmsFleetComponentRegistration [-ServicesRuntimeFqdn] <String> [-ServicesRuntimePassword] <String> [-TargetSddcId] <String> [-DryRun] [[-RemoteScriptTimeout] <Int32>] [<CommonParameters>]
```

## Description

The `Invoke-VcfmsFleetComponentRegistration` cmdlet uploads the bundled `update_fleet_component_registration.sh` script to the Services Runtime control plane node via SSH and executes it as root, passing the target selector. Use `-DryRun` to preview changes without writing to the database. If a worker node is supplied the function automatically connects to the control plane instead.

## Examples

### Example 1

Update registration by VCF instance name.

```powershell
Invoke-VcfmsFleetComponentRegistration `
    -ServicesRuntimeFqdn     "lax-sr01.lax.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
    -TargetVcfInstance       "vcf01"
```

### Example 2

Update registration by FQDN pattern (dry run).

```powershell
Invoke-VcfmsFleetComponentRegistration `
    -ServicesRuntimeFqdn     "lax-sr01.lax.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
    -TargetFqdn              "lax" `
    -DryRun
```

### Example 3

Update registration by SDDC LCM UUID.

```powershell
Invoke-VcfmsFleetComponentRegistration `
    -ServicesRuntimeFqdn     "lax-sr01.lax.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
    -TargetSddcId            "7a07f2c3-be5b-420a-8ce3-64b20f4ec52a"
```

## Parameters

### -ServicesRuntimeFqdn

FQDN or IP of any Services Runtime cluster node. Worker nodes are automatically redirected to the control plane.

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

Password for vmware-system-user (SSH login and sudo elevation).

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

### -TargetVcfInstance

VCF instance name to target (e.g. `vcf01`). Mutually exclusive with `-TargetFqdn` and `-TargetSddcId`.

```yaml
Type: String
Parameter Sets: ByVcfInstance
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -TargetFqdn

FQDN substring pattern to match (e.g. `lax`). Mutually exclusive with `-TargetVcfInstance` and `-TargetSddcId`.

```yaml
Type: String
Parameter Sets: ByFqdn
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -TargetSddcId

Exact UUID of the SDDC LCM entry. Mutually exclusive with `-TargetVcfInstance` and `-TargetFqdn`.

```yaml
Type: String
Parameter Sets: BySddcId
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DryRun

When specified, passes `--dry-run` to the script. No database changes are made; the script shows what would be updated.

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

### -RemoteScriptTimeout

Seconds to wait for the remote script to complete. Defaults to `300` (5 minutes).

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 300
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
