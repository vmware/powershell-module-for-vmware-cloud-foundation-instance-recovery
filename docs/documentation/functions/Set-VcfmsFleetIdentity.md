# Set-VcfmsFleetIdentity

## Synopsis

Applies fleet identity TLS secrets and configures fleet ingress on a recovery VCFMS Services Runtime cluster.

## Syntax

```powershell
Set-VcfmsFleetIdentity [-BackupYamlDir] <String> [-FleetFqdn] <String> [-FleetVip] <String> [-ServicesRuntimeFqdn] <String> [-ServicesRuntimePassword] <String> [[-ServicesRuntimeUsername] <String>] [[-KubeconfigPath] <String>] [[-KubeconfigOutputDir] <String>] [[-PollIntervalSeconds] <Int32>] [<CommonParameters>]
```

## Description

The `Set-VcfmsFleetIdentity` cmdlet performs two steps:

**Step 1** — Applies fleet TLS secrets from a backup extraction using `kubectl apply`:
- `ingress-fleet-tls.yaml`
- `ingress-fleet-tls-ndc.yaml`

**Step 2** — Configures fleet ingress via the Services Runtime API by reading the VSP component ID from the `vmsp-platform` namespace label (`component.vmsp.vmware.com/id`), then posting an apply task to patch `spec.configuration.ingress.fleet` with the provided Fleet FQDN and VIP.

Both YAML files must exist in `-BackupYamlDir`. Use `New-ExtractVcfmsBackup` to produce the required files. Use `Clear-VcfmsFleetIdentity` to remove the fleet VIP configuration.

## Examples

### Example 1

Apply fleet identity with automatic kubeconfig retrieval.

```powershell
Set-VcfmsFleetIdentity `
    -BackupYamlDir           "C:\backup-yaml" `
    -ServicesRuntimeFqdn     "sfo-sr01.sfo.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
    -FleetFqdn               "flt-fc01.sfo.rainpole.io" `
    -FleetVip                "10.50.0.10"
```

### Example 2

Supply an existing kubeconfig.

```powershell
Set-VcfmsFleetIdentity `
    -BackupYamlDir           "C:\backup-yaml" `
    -KubeconfigPath          "C:\kubeconfigs\sfo-sr01.kubeconfig" `
    -ServicesRuntimeFqdn     "sfo-sr01.sfo.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
    -FleetFqdn               "flt-fc01.sfo.rainpole.io" `
    -FleetVip                "10.50.0.10"
```

## Parameters

### -BackupYamlDir

Directory containing the YAML files produced by `New-ExtractVcfmsBackup`. Must contain both `ingress-fleet-tls.yaml` and `ingress-fleet-tls-ndc.yaml`.

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

### -FleetFqdn

FQDN of the Fleet LCM instance to configure in the ingress spec.

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

### -FleetVip

IPv4 VIP address for the Fleet LCM ingress spec.

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

### -ServicesRuntimeFqdn

FQDN of the Services Runtime cluster. Required for the API apply call and for automatic kubeconfig retrieval.

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

### -ServicesRuntimePassword

Password for the Services Runtime admin user and vmware-system-user SSH access.

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

Path to an existing kubeconfig for the recovery Services Runtime cluster. Takes precedence over automatic retrieval.

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

Interval in seconds between task status polls. Defaults to `30`.

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
