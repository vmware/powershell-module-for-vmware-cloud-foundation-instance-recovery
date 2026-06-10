# New-ServicesRuntime

## Synopsis

Deploys a new VCF Management Services (VCFMS) runtime instance via the SDDC Manager API.

## Syntax

```powershell
# By pre-built JSON file
New-ServicesRuntime [-SddcManagerFqdn] <String> [-SddcManagerUser] <String> [-SddcManagerPassword] <String> [-Type] <String> [-JsonFile] <String> [[-PollIntervalSeconds] <Int32>] [<CommonParameters>]

# By individual parameters
New-ServicesRuntime [-SddcManagerFqdn] <String> [-SddcManagerUser] <String> [-SddcManagerPassword] <String> [-Type] <String> [-PlatformFqdn] <String> [-SystemUserPassword] <String> [-Ipv4Addresses] <String[]> [-Size] <String> [-NetworkMoId] <String> [-GatewayCidrIpv4] <String> [-ClusterId] <String> [-InternalClusterCidrIpv4] <String> [[-InstanceFqdn] <String>] [[-FleetFqdn] <String>] [[-PollIntervalSeconds] <Int32>] [<CommonParameters>]
```

## Description

The `New-ServicesRuntime` cmdlet calls the SDDC Manager `POST /v1/vsp-clusters` endpoint to deploy a new VCFMS runtime. It supports two parameter sets:

**ByFile** — Supply a pre-built JSON payload file.

**ByParameter** — Supply individual values; the management domain ID is automatically retrieved from the SDDC Manager `/v1/domains` API.

In both modes the function displays the payload for review (with `systemUserPassword` redacted), prompts the operator to confirm before submitting, then polls the task to completion.

## Examples

### Example 1

Deploy a Management runtime from a JSON file.

```powershell
New-ServicesRuntime `
    -SddcManagerFqdn     "sfo-vcf01.sfo.rainpole.io" `
    -SddcManagerUser     "administrator@vsphere.local" `
    -SddcManagerPassword "VMw@re1!VMw@re1!" `
    -Type                "MANAGEMENT" `
    -JsonFile            ".\vcfms-runtime.json"
```

### Example 2

Deploy a Consumption runtime from a JSON file.

```powershell
New-ServicesRuntime `
    -SddcManagerFqdn     "sfo-vcf01.sfo.rainpole.io" `
    -SddcManagerUser     "administrator@vsphere.local" `
    -SddcManagerPassword "VMw@re1!VMw@re1!" `
    -Type                "CONSUMPTION" `
    -JsonFile            ".\vcfms-consumption.json"
```

## Parameters

### -SddcManagerFqdn

FQDN of the SDDC Manager appliance.

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

### -SddcManagerUser

API username for SDDC Manager (e.g. `administrator@vsphere.local`).

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

### -SddcManagerPassword

Password for the SDDC Manager API user.

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

### -Type

Type of VCFMS runtime to deploy. Valid values: `MANAGEMENT`, `CONSUMPTION`.

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

### -JsonFile

Path to a JSON file containing the full VCFMS runtime deployment payload. Used with the `ByFile` parameter set.

```yaml
Type: String
Parameter Sets: ByFile
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -PlatformFqdn

Platform FQDN for the VCFMS runtime. Used with the `ByParameter` parameter set.

```yaml
Type: String
Parameter Sets: ByParameter
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -InstanceFqdn

Instance FQDN for the VCFMS runtime. Required when `-Type` is `MANAGEMENT`. Used with the `ByParameter` parameter set.

```yaml
Type: String
Parameter Sets: ByParameter
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -FleetFqdn

Fleet FQDN for the VCFMS runtime. Required when `-Type` is `MANAGEMENT`. Used with the `ByParameter` parameter set.

```yaml
Type: String
Parameter Sets: ByParameter
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SystemUserPassword

System user password for the VCFMS runtime. Used with the `ByParameter` parameter set.

```yaml
Type: String
Parameter Sets: ByParameter
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Ipv4Addresses

Array of IPv4 addresses for the VCFMS IP pool. Used with the `ByParameter` parameter set.

```yaml
Type: String[]
Parameter Sets: ByParameter
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Size

Deployment size (e.g. `small`, `medium`, `large`). Used with the `ByParameter` parameter set.

```yaml
Type: String
Parameter Sets: ByParameter
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -NetworkMoId

Managed Object ID of the dvportgroup (e.g. `dvportgroup-28`). Used with the `ByParameter` parameter set.

```yaml
Type: String
Parameter Sets: ByParameter
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -GatewayCidrIpv4

Gateway CIDR in IPv4 format (e.g. `10.11.99.1/24`). Used with the `ByParameter` parameter set.

```yaml
Type: String
Parameter Sets: ByParameter
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ClusterId

Cluster ID from the original deployment. Used with the `ByParameter` parameter set.

```yaml
Type: String
Parameter Sets: ByParameter
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -InternalClusterCidrIpv4

Internal cluster CIDR in IPv4 format (e.g. `198.18.0.0/15`). Used with the `ByParameter` parameter set.

```yaml
Type: String
Parameter Sets: ByParameter
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -PollIntervalSeconds

Interval in seconds to poll the deployment task status. Defaults to `300` (5 minutes).

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
