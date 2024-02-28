# New-vCenterOvaDeployment

## Synopsis

Deploys a vCenter Server appliance from OVA using data previously extracted from the SDDC Manager backup.

## Syntax

```powershell
New-vCenterOvaDeployment [-tempvCenterFqdn] <String> [-tempvCenterAdmin] <String> [-tempvCenterAdminPassword] <String> [-extractedSDDCDataFile] <String> [-workloadDomain] <String> [-restoredvCenterDeploymentSize] <String> [-vCenterOvaFile] <String> [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## Description

The `New-vCenterOvaDeployment` deploys a vCenter Server appliance from OVA using data previously extracted from the SDDC Manager backup.

## Examples

### Example 1

```powershell
New-vCenterOvaDeployment -tempvCenterFqdn "sfo-m01-vc02.sfo.rainpole.io" -tempvCenterAdmin "administrator@vsphere.local" -tempvCenterAdminPassword "VMw@re1!" -extractedSDDCDataFile ".\extracted-sddc-data.json" -workloadDomain "sfo-m01" -restoredvCenterDeploymentSize "small" -vCenterOvaFile "F:\OVA\VMware-vCenter-Server-Appliance-7.0.3.01400-21477706_OVF10.ova"
```

## Parameters

### -tempvCenterFqdn

Fully qualified domain name of the target vCenter Server instance to deploy the vCenter Server OVA to.

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

Admin user for the target vCenter Server instance to deploy the vCenter Server OVA to.

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

Admin password for the target vCenter Server instance to deploy the vCenter Server OVA to.

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

Name of the workload domain that the vCenter Server instance to deployed to is associated with.

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

### -restoredvCenterDeploymentSize

Size of the vCenter Server appliance to deploy.

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

### -vCenterOvaFile

Relative or absolute to the vCenter Server OVA on the local filesystem.

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
