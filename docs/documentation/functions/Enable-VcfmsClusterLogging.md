# Enable-VcfmsClusterLogging

## Synopsis

Enables logging on a VCFMS Services Runtime cluster by configuring a VCF Operations log management target.

## Syntax

```powershell
Enable-VcfmsClusterLogging [-ServicesRuntimeFqdn] <String> [-ServicesRuntimePassword] <String> [-LogManagementVip] <String> [[-ServicesRuntimeUsername] <String>] [[-LogManagementPort] <String>] [[-ComponentId] <String>] [[-PollIntervalSeconds] <Int32>] [[-KubeconfigPath] <String>] [[-KubeconfigOutputDir] <String>] [<CommonParameters>]
```

## Description

The `Enable-VcfmsClusterLogging` cmdlet enables log forwarding on a VCFMS Services Runtime cluster after a successful log management restore. It posts a component apply task that sets `spec.configuration.logs.type` to `ops` with the supplied Log Management VIP host, scheme, and port. After a successful apply, it validates the health of the `logging-operator-fluentd` StatefulSet via `Confirm-VcfmsFluentdOperatorState`.

## Examples

### Example 1

Enable logging with automatic kubeconfig retrieval.

```powershell
Enable-VcfmsClusterLogging `
    -ServicesRuntimeFqdn     "lax-sr01.lax.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
    -LogManagementVip        "flt-logs01.rainpole.io"
```

### Example 2

Supply a specific VSP component ID and an existing kubeconfig.

```powershell
Enable-VcfmsClusterLogging `
    -ServicesRuntimeFqdn     "lax-sr01.lax.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
    -LogManagementVip        "flt-logs01.rainpole.io" `
    -ComponentId             "e319236e-867e-4779-9270-4921bddf4f1f" `
    -KubeconfigPath          "C:\kubeconfigs\lax-sr01.kubeconfig"
```

## Parameters

### -ServicesRuntimeFqdn

FQDN of the VCFMS Services Runtime instance on the recovery site.

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

### -LogManagementVip

FQDN or IP of the Log Management VIP that the Services Runtime should forward logs to.

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

### -LogManagementPort

Port for the log management endpoint. Defaults to `9543`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 9543
Accept pipeline input: False
Accept wildcard characters: False
```

### -ComponentId

Optional. VSP component ID to target. When omitted the cmdlet resolves the first `vsp` component from `GET /api/v1/components`.

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

### -KubeconfigPath

Optional. Path to an existing kubeconfig for post-apply validation. When omitted the kubeconfig is retrieved automatically.

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

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
