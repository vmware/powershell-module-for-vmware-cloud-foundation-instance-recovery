# New-VCFManagementServicesRuntime

## Synopsis

Deploys a new VCF Management Services (VCFMS) runtime instance.

## Syntax

```powershell
New-VCFManagementServicesRuntime [-sddcManagerFqdn] <String> [-username] <String> [-password] <String> [-DomainId] <String> [-PlatformFqdn] <String> [-InstanceFqdn] <String> [-FleetFqdn] <String> [-SystemUserPassword] <String> [-Ipv4PoolAddresses] <String[]> [[-Size] <String>] [-NetworkMoId] <String> [-GatewayCidrIpv4] <String> [-ClusterId] <String> [-InternalClusterCidrIpv4] <String> [[-VspClusterSpecJson] <String>] [<CommonParameters>]
```

## Description

The `New-VCFManagementServicesRuntime` cmdlet posts to `POST /v1/vsp-clusters` on SDDC Manager to deploy a new VCFMS runtime instance. The domain id, FQDNs, and cluster id must all match the original Management Domain values. Returns the 202-Accepted task response; use `Wait-SDDCManagerVcfTask` to poll for completion.

## Examples

### Example 1

```powershell
$addresses = "10.11.99.29","10.11.99.30","10.11.99.31","10.11.99.32","10.11.99.33",
             "10.11.99.34","10.11.99.35","10.11.99.36","10.11.99.37","10.11.99.38",
             "10.11.99.39","10.11.99.40"

$task = New-VCFManagementServicesRuntime `
    -sddcManagerFqdn         "sfo-vcf01.sfo.rainpole.io" `
    -username                "admin@local" `
    -password                "VMw@re1!" `
    -DomainId                "0810c87d-3758-4c28-95fc-458b1196f4eb" `
    -PlatformFqdn            "sfo-sr01.sfo.rainpole.io" `
    -InstanceFqdn            "sfo-ic01.sfo.rainpole.io" `
    -FleetFqdn               "flt-fc01.rainpole.io" `
    -SystemUserPassword      "VMw@re1!VMw@re1!" `
    -Ipv4PoolAddresses       $addresses `
    -Size                    "small" `
    -NetworkMoId             "dvportgroup-28" `
    -GatewayCidrIpv4         "10.11.99.1/24" `
    -ClusterId               "1f5c79fe-e3aa-41b1-a5cf-774a6497fa3d" `
    -InternalClusterCidrIpv4 "198.18.0.0/15"

Wait-SDDCManagerVcfTask -sddcManagerFqdn "sfo-vcf01.sfo.rainpole.io" -username "admin@local" -password "VMw@re1!" -taskId $task.id
```

## Parameters

### -sddcManagerFqdn

The fully qualified domain name of the SDDC Manager appliance.

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

### -username

The username to authenticate with SDDC Manager (e.g. `admin@local`).

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

### -password

The password for the SDDC Manager user.

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

### -DomainId

The Management Domain id from SDDC Manager. Must match the original.

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

### -PlatformFqdn

The FQDN of the platform (sr) node. Must match the original.

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

### -InstanceFqdn

The FQDN of the instance (ic) node. Must match the original.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 6
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -FleetFqdn

The FQDN of the fleet node. Must match the original.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 7
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SystemUserPassword

The password for the VCFMS system user.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 8
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Ipv4PoolAddresses

Array of IPv4 addresses for the pool. Supply all addresses from the original deployment (typically 12).

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: True
Position: 9
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Size

The deployment size. Valid values are `small`, `medium`, or `large`. Defaults to `small`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 10
Default value: small
Accept pipeline input: False
Accept wildcard characters: False
```

### -NetworkMoId

The vSphere Managed Object ID of the target distributed port group (e.g. `dvportgroup-28`).

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 11
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -GatewayCidrIpv4

The gateway IP address and prefix length in CIDR notation (e.g. `10.11.99.1/24`).

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 12
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ClusterId

The vSphere cluster id. Must match the original.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 13
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -InternalClusterCidrIpv4

The internal cluster CIDR range (e.g. `198.18.0.0/15`).

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 14
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -VspClusterSpecJson

Optional. A fully-formed JSON string to override the entire request body.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 15
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
