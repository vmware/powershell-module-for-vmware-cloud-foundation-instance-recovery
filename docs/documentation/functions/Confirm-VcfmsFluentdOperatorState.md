# Confirm-VcfmsFluentdOperatorState

## Synopsis

Validates the health of the fluentd logging operator StatefulSet on a VCFMS Services Runtime cluster and attempts automatic remediation if unhealthy.

## Syntax

```powershell
Confirm-VcfmsFluentdOperatorState [[-KubeconfigPath] <String>] [[-ServicesRuntimeFqdn] <String>] [[-ServicesRuntimePassword] <String>] [[-KubeconfigOutputDir] <String>] [<CommonParameters>]
```

## Description

The `Confirm-VcfmsFluentdOperatorState` cmdlet checks the rollout and readiness status of the `logging-operator-fluentd` StatefulSet in the `vmsp-platform` namespace by running:

```
kubectl -n vmsp-platform rollout status sts/logging-operator-fluentd
kubectl -n vmsp-platform get sts logging-operator-fluentd
```

A healthy response shows `partitioned roll out complete` and `READY = 1/1`. If the StatefulSet is not healthy, the cmdlet automatically flushes the Fluentd buffer, scales down to 0 replicas, waits 15 seconds, scales back up to 1, and re-checks the health.

The kubeconfig is resolved in this order:
1. `-KubeconfigPath` if supplied.
2. Auto-retrieved from the Services Runtime node when `-ServicesRuntimeFqdn` and `-ServicesRuntimePassword` are supplied.

## Examples

### Example 1

Use an existing kubeconfig.

```powershell
Confirm-VcfmsFluentdOperatorState `
    -KubeconfigPath "C:\kubeconfigs\sfo-sr01.kubeconfig"
```

### Example 2

Retrieve kubeconfig automatically.

```powershell
Confirm-VcfmsFluentdOperatorState `
    -ServicesRuntimeFqdn     "sfo-sr01.sfo.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!"
```

## Parameters

### -KubeconfigPath

Path to an existing kubeconfig file for the Services Runtime cluster.

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

### -ServicesRuntimeFqdn

FQDN of the Services Runtime cluster. Used to retrieve the kubeconfig automatically when `-KubeconfigPath` is not supplied.

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

### -ServicesRuntimePassword

Password for the vmware-system-user on the Services Runtime node, also used for sudo elevation.

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

Directory where the retrieved kubeconfig is written. Defaults to the current directory. Only used when the kubeconfig is retrieved automatically.

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
