# Disable-VcfmsClusterLogging

## Synopsis

Disables logging on a VCFMS Services Runtime cluster by applying a `logs.type=none` configuration.

## Syntax

```powershell
Disable-VcfmsClusterLogging [-ServicesRuntimeFqdn] <String> [-ServicesRuntimePassword] <String> [[-ServicesRuntimeUsername] <String>] [[-ComponentId] <String>] [[-PollIntervalSeconds] <Int32>] [[-KubeconfigPath] <String>] [[-KubeconfigOutputDir] <String>] [<CommonParameters>]
```

## Description

The `Disable-VcfmsClusterLogging` cmdlet posts a component apply task to the VCFMS Services Runtime API that sets `spec.configuration.logs.type` to `none`, then polls the task until it reaches a terminal state. After a successful apply, the cmdlet validates the health of the `logging-operator-fluentd` StatefulSet via `Confirm-VcfmsFluentdOperatorState`.

The VSP component ID can be supplied directly via `-ComponentId`, or resolved automatically from the Services Runtime components API by matching the first component of type `vsp`.

## Examples

### Example 1

Disable logging and auto-retrieve kubeconfig for post-apply validation.

```powershell
Disable-VcfmsClusterLogging `
    -ServicesRuntimeFqdn     "lax-sr01.lax.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!"
```

### Example 2

Supply an existing kubeconfig.

```powershell
Disable-VcfmsClusterLogging `
    -ServicesRuntimeFqdn     "lax-sr01.lax.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
    -KubeconfigPath          "C:\kubeconfigs\lax-sr01.kubeconfig"
```

## Parameters

### -ServicesRuntimeFqdn

FQDN of the VCFMS Services Runtime instance.

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

### -ComponentId

Optional. VSP component ID to apply the logging change to. When omitted the cmdlet resolves the first `vsp` component from `GET /api/v1/components`.

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

Path to an existing kubeconfig for post-apply validation. When omitted the kubeconfig is retrieved automatically.

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
