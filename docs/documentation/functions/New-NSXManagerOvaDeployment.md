# New-NSXManagerOvaDeployment

## Synopsis

Presents a list of NSX ManAgers associated with the provided VCF Workload Domain, and deploys an NSX Manager from OVA using data previously extracted from the SDDC Manager backup.

## Syntax

```powershell
New-NSXManagerOvaDeployment [-tempvCenterFqdn] <String> [-tempvCenterAdmin] <String> [-tempvCenterAdminPassword] <String> [-extractedSDDCDataFile] <String> [-workloadDomain] <String> [-restoredNsxManagerDeploymentSize] <String> [-nsxManagerOvaFile] <String> [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## Description

The `New-NSXManagerOvaDeployment` resents a list of NSX ManAgers associated with the provided VCF Workload Domain, and deploys an NSX Manager from OVA using data previously extracted from the SDDC Manager backup.

## Examples

### Example 1

```powershell
New-NSXManagerOvaDeployment -tempvCenterFqdn "sfo-m01-vc02.sfo.rainpole.io" -tempvCenterAdmin "administrator@vsphere.local" -tempvCenterAdminPassword "VMw@re1!" -extractedSDDCDataFile ".\extracted-sddc-data.json" -workloadDomain "sfo-m01" -restoredNsxManagerDeploymentSize medium -nsxManagerOvaFile "F:\OVA\nsx-unified-appliance-3.2.2.1.0.21487565.ova"
```

## Parameters

### -tempvCenterFqdn

Fully qualified domain name of the target vCenter Server instance to deploy the NSX Manager OVA to.

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

### -tempvCenterAdmin

Admin user for the target vCenter Server instance to deploy the NSX Manager OVA to.

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

### -tempvCenterAdminPassword

Admin password for the target vCenter Server instance to deploy the NSX Manager OVA to.

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

Relative or absolute to the `extracted-sddc-data.json` file (previously created by `New-ExtractDataFromSDDCBackup`) on the local filesystem.

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

Name of the workload domain that the NSX Manager to deployed to is associated with.

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

Relative or absolute to the NSX Manager OVA on the local filesystem.

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
