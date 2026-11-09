# New-NSXManagerOvaDeployment

## Synopsis

Presents a list of NSX Managers associated with the provided VCF workload domain, and deploys an NSX Manager from OVA using data previously extracted from the SDDC Manager backup.

## Syntax

```powershell
New-NSXManagerOvaDeployment [[-targetFqdn] <String>] [[-targetAdmin] <String>] [-targetAdminPassword] <String> [-extractedSDDCDataFile] <String> [-workloadDomain] <String> [-restoredNsxManagerDeploymentSize] <String> [-nsxManagerOvaFile] <String> [[-targetType] <String>] [<CommonParameters>]
```

## Description

The `New-NSXManagerOvaDeployment` cmdlet presents a list of NSX Managers associated with the provided VCF workload domain, and deploys the selected NSX Manager from OVA using data previously extracted from the SDDC Manager backup. The target can be a vCenter Server instance or, with `-targetType esx`, a single ESX host.

## Examples

### Example 1

```powershell
New-NSXManagerOvaDeployment -targetFqdn "sfo-m01-vc02.sfo.rainpole.io" -targetAdmin "administrator@vsphere.local" -targetAdminPassword "VMw@re1!" -extractedSDDCDataFile ".\extracted-sddc-data.json" -workloadDomain "sfo-m01" -restoredNsxManagerDeploymentSize medium -nsxManagerOvaFile "F:\OVA\nsx-unified-appliance-3.2.2.1.0.21487565.ova" -targetType "vcenter"
```

### Example 2

```powershell
New-NSXManagerOvaDeployment -targetFqdn "sfo01-m01-esx01.sfo.rainpole.io" -targetAdmin "root" -targetAdminPassword "VMw@re1!" -extractedSDDCDataFile ".\extracted-sddc-data.json" -workloadDomain "sfo-m01" -restoredNsxManagerDeploymentSize medium -nsxManagerOvaFile "F:\OVA\nsx-unified-appliance-3.2.2.1.0.21487565.ova" -targetType "esx"
```

### Example 3

Deploys to the first ESX host of the management domain; `-targetFqdn` is omitted.

```powershell
New-NSXManagerOvaDeployment -targetAdmin "root" -targetAdminPassword "VMw@re1!" -extractedSDDCDataFile ".\extracted-sddc-data.json" -workloadDomain "sfo-m01" -restoredNsxManagerDeploymentSize medium -nsxManagerOvaFile "F:\OVA\nsx-unified-appliance-3.2.2.1.0.21487565.ova" -targetType "esx"
```

## Parameters

### -targetFqdn

FQDN of the target vCenter Server instance or ESX host to deploy the NSX Manager OVA to. Optional: when omitted and `-targetType` is `esx`, it defaults to the first ESX host of the management domain in the extracted SDDC data. If it is omitted and no host can be determined, the task stops with an error.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -targetAdmin

Admin user for the target vCenter Server instance or ESX host to deploy the NSX Manager OVA to. Optional: when omitted and `-targetType` is `esx`, it defaults to `root`. If it is omitted for a `vcenter` target, the task stops with an error.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: None (`root` when `-targetType` is `esx`)
Accept pipeline input: False
Accept wildcard characters: False
```

### -targetAdminPassword

Admin password for the target vCenter Server instance or ESX host to deploy the NSX Manager OVA to.

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

### -extractedSDDCDataFile

Relative or absolute path to the `extracted-sddc-data.json` file (previously created by `New-ExtractDataFromSDDCBackup`) on the local filesystem.

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

### -workloadDomain

Name of the workload domain that the NSX Manager to be deployed is associated with.

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

### -restoredNsxManagerDeploymentSize

Size of the NSX Manager appliance to deploy.

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

### -nsxManagerOvaFile

Relative or absolute path to the NSX Manager OVA on the local filesystem.

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

### -targetType

Type of the deployment target. Valid values are `vcenter` and `esx`. When `esx`, the appliance is deployed directly to the ESX host and connected to the `vm_mgmt` network.

```yaml
Type: String
Parameter Sets: (All)
Aliases:
Accepted values: vcenter, esx

Required: False
Position: 8
Default value: vcenter
Accept pipeline input: False
Accept wildcard characters: False
```

### -ProgressAction

Progress Action.

```yaml
Type: ActionPreference
Parameter Sets: (All)
Aliases: proga

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
