# Remove-VcfmsRecoveredComponents

## Synopsis

Cleans up recovered fleet components from a VCF Management Services instance on the recovery site.

## Syntax

```powershell
Remove-VcfmsRecoveredComponents [-ServicesRuntimeFqdn] <String> [-ServicesRuntimePassword] <String> [[-KubeconfigPath] <String>] [[-KubeconfigOutputDir] <String>] [<CommonParameters>]
```

## Description

The `Remove-VcfmsRecoveredComponents` cmdlet performs the cleanup of recovered fleet components from a VCFMS Services Runtime cluster as part of failback preparation. It runs two operations using the resolved kubeconfig:

**Step 1a** — Deletes the recovered component Kubernetes resources:
```
kubectl delete component ops-logs salt-raas vidb vcf-fleet-depot vcf-fleet-lcm
```

**Step 1b** — Removes matching rows from the `vcf-sddc-lcm` postgres database. Both `vcf-sddc-lcm-db-0` and `vcf-sddc-lcm-db-1` are attempted, since only one pod is active at any given time. The failure of the standby pod is expected and treated as a warning rather than an error.

The kubeconfig is resolved in this order:
1. `-KubeconfigPath` if supplied.
2. Auto-retrieved from the Services Runtime node via `Get-VcfmsServicesRuntimeKubeconfig`.

## Examples

### Example 1

Auto-retrieve kubeconfig.

```powershell
Remove-VcfmsRecoveredComponents `
    -ServicesRuntimeFqdn     "lax-sr01.lax.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!"
```

### Example 2

Use an existing kubeconfig.

```powershell
Remove-VcfmsRecoveredComponents `
    -ServicesRuntimeFqdn     "lax-sr01.lax.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
    -KubeconfigPath          "C:\kubeconfigs\lax-sr01.kubeconfig"
```

## Parameters

### -ServicesRuntimeFqdn

FQDN or IP of any Services Runtime cluster node. If a worker node is supplied the function automatically resolves and connects to the control plane.

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

Password for vmware-system-user SSH login, used for kubeconfig retrieval.

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

### -KubeconfigPath

Optional. Path to an existing kubeconfig for the Services Runtime cluster. Takes precedence over automatic retrieval.

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
