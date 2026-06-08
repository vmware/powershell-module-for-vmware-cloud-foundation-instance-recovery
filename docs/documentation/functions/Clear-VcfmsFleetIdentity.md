# Clear-VcfmsFleetIdentity

## Synopsis

Removes the fleet ingress VIP configuration from a VCFMS Services Runtime cluster.

## Syntax

```powershell
Clear-VcfmsFleetIdentity [-ServicesRuntimeFqdn] <String> [-ServicesRuntimePassword] <String> [[-ServicesRuntimeUsername] <String>] [[-KubeconfigPath] <String>] [[-KubeconfigOutputDir] <String>] [[-PollIntervalSeconds] <Int32>] [<CommonParameters>]
```

## Description

The `Clear-VcfmsFleetIdentity` cmdlet clears the fleet ingress configuration previously applied by `Set-VcfmsFleetIdentity`. It submits the same apply payload shape but with a blank `fqdn` and an empty VIP array (`spec.configuration.ingress.fleet.fqdn = ""`, `spec.configuration.ingress.fleet.vips.ipv4 = []`), effectively removing the fleet VIP from the ingress spec.

The VSP component ID is read from the `vmsp-platform` namespace label and the resulting task is polled to completion.

## Examples

### Example 1

Clear the fleet VIP with automatic kubeconfig retrieval.

```powershell
Clear-VcfmsFleetIdentity `
    -ServicesRuntimeFqdn     "sfo-sr01.sfo.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!"
```

### Example 2

Use an existing kubeconfig.

```powershell
Clear-VcfmsFleetIdentity `
    -ServicesRuntimeFqdn     "sfo-sr01.sfo.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
    -KubeconfigPath          "C:\kubeconfigs\sfo-sr01.kubeconfig"
```

## Parameters

### -ServicesRuntimeFqdn

FQDN of the Services Runtime cluster. Required for the API apply call and for automatic kubeconfig retrieval.

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

Password for the Services Runtime admin user and vmware-system-user SSH access.

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

### -KubeconfigPath

Path to an existing kubeconfig for the Services Runtime cluster. Takes precedence over automatic retrieval.

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

### -KubeconfigOutputDir

Directory where the auto-retrieved kubeconfig is written. Defaults to the current directory.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: .
Accept pipeline input: False
Accept wildcard characters: False
```

### -PollIntervalSeconds

Interval in seconds between task status polls. Defaults to `60`.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 60
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
