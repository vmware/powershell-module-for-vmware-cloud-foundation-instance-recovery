# Move-ClusterHostsToRestoredVcenter

## Synopsis

Moves ESXi Hosts from a temporary vCenter Server / vSphere cluster to the restored vCenter Server / vSphere cluster.

Used for management domain cluster recovery.

## Syntax

```powershell
Move-ClusterHostsToRestoredVcenter [-tempvCenterFqdn] <String> [-tempvCenterAdmin] <String> [-tempvCenterAdminPassword] <String> [-clusterName] <String> [-restoredvCenterFQDN] <String> [-restoredvCenterAdmin] <String> [-restoredvCenterAdminPassword] <String> [-extractedSDDCDataFile] <String> [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## Description

The `Move-ClusterHostsToRestoredVcenter` cmdlet moves ESXi Hosts from a temporary vCenter Server / vSphere cluster to the restored vCenter Server / vSphere cluster.
Used for management domain cluster recovery.

## Examples

### Example 1

```powershell
Move-ClusterHostsToRestoredVcenter -tempvCenterFqdn "sfo-m01-vc02.sfo.rainpole.io" -tempvCenterAdmin "administrator@vsphere.local" -tempvCenterAdminPassword "VMw@re1!" -restoredvCenterFQDN "sfo-m01-vc01.sfo.rainpole.io" -restoredvCenterAdmin "administrator@vsphere.local" -restoredvCenterAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01" -extractedSDDCDataFile ".\extracted-sddc-data.json"
```

## Parameters

### -tempvCenterFqdn

Fully qualified domain name of the temporary vCenter Server instance.

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

Admin user for the temporary vCenter Server instance.

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

Admin password for the temporary vCenter Server instance.

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

### -clusterName

Name of the restored vSphere cluster instance in the temporary vCenter.

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

### -restoredvCenterFQDN

Fully qualified domain name of the restored vCenter Server instance.

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

### -restoredvCenterAdmin

Admin user for the restored vCenter Server instance.

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

### -restoredvCenterAdminPassword

Admin password for the restored vCenter Server instance.

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

### -extractedSDDCDataFile

Relative or absolute to the `extracted-sddc-data.json` file (previously created by `New-ExtractDataFromSDDCBackup`) on the local filesystem.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 8
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
