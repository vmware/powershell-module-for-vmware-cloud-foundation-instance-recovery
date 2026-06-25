# Update-ServicesRuntimePackageDeployment

## Synopsis

Updates the vSphere placement configuration in the vmsp-platform PackageDeployment on a Services Runtime cluster.

## Syntax

```powershell
Update-ServicesRuntimePackageDeployment [-ServicesRuntimeFqdn] <String> [-ServicesRuntimePassword] <String> [-vCenterFqdn] <String> [[-vCenterUsername] <String>] [-vCenterPassword] <String> [-TargetDatacenter] <String> [-TargetCluster] <String> [-TargetDatastore] <String> [-TargetDpG] <String> [-TargetFolder] <String> [[-TargetRP] <String>] [-TargetTemplate] <String> [[-OutputDir] <String>] [-DryRun] [<CommonParameters>]
```

## Description

The `Update-ServicesRuntimePackageDeployment` cmdlet performs the following steps:

1. Connects to vCenter via PowerCLI and resolves Managed Object Reference IDs and inventory paths for the target datacenter, cluster, datastore, distributed port group, VM folder, resource pool, and VM template.
2. Retrieves the Services Runtime cluster KUBECONFIG from the control plane node via SSH. If a worker node FQDN is supplied the control plane is resolved automatically.
3. Patches the `vmsp-platform` PackageDeployment (`pd/vmsp-platform` in namespace `vmsp-platform`) with the resolved vSphere placement values using `kubectl patch --type=merge`.

Use `-DryRun` to display the computed patch JSON without applying it to the cluster.

## Examples

### Example 1

Update the PackageDeployment vSphere placement configuration.

```powershell
Update-ServicesRuntimePackageDeployment `
    -ServicesRuntimeFqdn     "sfo-sr01.sfo.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
    -vCenterFqdn             "sfo-m01-vc01.sfo.rainpole.io" `
    -vCenterUsername         "administrator@vsphere.local" `
    -vCenterPassword         "VMw@re1!VMw@re1!" `
    -TargetDatacenter        "sfo-m01-dc01" `
    -TargetCluster           "sfo-m01-cl02" `
    -TargetDatastore         "sfo-m01-cl02-vsan01" `
    -TargetDpG               "sfo-m01-cl02-vds01-pg-vcf-mgmt" `
    -TargetFolder            "vcf-management-services" `
    -TargetRP                "Resources" `
    -TargetTemplate          "vcf-services-runtime-template-9.1.0.0.25370367"
```

### Example 2

Preview the computed patch without applying it (dry run).

```powershell
Update-ServicesRuntimePackageDeployment `
    -ServicesRuntimeFqdn     "sfo-sr01.sfo.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
    -vCenterFqdn             "sfo-m01-vc01.sfo.rainpole.io" `
    -vCenterUsername         "administrator@vsphere.local" `
    -vCenterPassword         "VMw@re1!VMw@re1!" `
    -TargetDatacenter        "sfo-m01-dc01" `
    -TargetCluster           "sfo-m01-cl02" `
    -TargetDatastore         "sfo-m01-cl02-vsan01" `
    -TargetDpG               "sfo-m01-cl02-vds01-pg-vcf-mgmt" `
    -TargetFolder            "vcf-management-services" `
    -TargetRP                "Resources" `
    -TargetTemplate          "vcf-services-runtime-template-9.1.0.0.25370367" `
    -DryRun
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

Password for vmware-system-user (SSH login).

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

### -vCenterFqdn

FQDN of the vCenter Server that manages the target vSphere inventory.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -vCenterUsername

Username for vCenter authentication.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: administrator@vsphere.local
Accept pipeline input: False
Accept wildcard characters: False
```

### -vCenterPassword

Password for the vCenter user.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -TargetDatacenter

Name of the target vSphere datacenter.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -TargetCluster

Name of the target vSphere cluster.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -TargetDatastore

Name of the target datastore.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -TargetDpG

Name of the target distributed port group.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -TargetFolder

Name of the target VM folder.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -TargetRP

Name of the target resource pool. Defaults to `Resources` (the cluster root pool).

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: Resources
Accept pipeline input: False
Accept wildcard characters: False
```

### -TargetTemplate

Name of the target VM template.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -OutputDir

Directory where the retrieved kubeconfig file is written. Defaults to the current directory.

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

### -DryRun

When specified, displays the computed patch JSON without applying it to the cluster.

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

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
