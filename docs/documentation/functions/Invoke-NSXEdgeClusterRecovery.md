# Invoke-NSXEdgeClusterRecovery

## Synopsis

Redeploys the NSX Edges from the provided vSphere cluster.

## Syntax

```powershell
Invoke-NSXEdgeClusterRecovery [-nsxManagerFqdn] <String> [-nsxManagerAdmin] <String> [-nsxManagerAdminPassword] <String> [-vCenterFQDN] <String> [-vCenterAdmin] <String> [-vCenterAdminPassword] <String> [-clusterName] <String> [-extractedSDDCDataFile] <String> [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## Description

The `Invoke-NSXEdgeClusterRecovery` cmdlet redeploys the NSX Edges from the provided vSphere cluster.

## Examples

### Example 1

```powershell
Invoke-NSXEdgeClusterRecovery -nsxManagerFqdn "sfo-m01-nsx01.sfo.rainpole.io" -nsxManagerAdmin "admin" -nsxManagerAdminPassword "VMw@re1!VMw@re1!" -vCenterFQDN "sfo-m01-vc01.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01"
```

## Parameters

### -nsxManagerFqdn

Fully qualified domain name of the NSX Manager whose Edges need to be redeployed.

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

### -nsxManagerAdmin

Admin user for the NSX Manager whose Edges need to be redeployed.

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

### -nsxManagerAdminPassword

Admin Password of the NSX Manager whose Edges need to be redeployed.

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

### -vCenterFQDN

Fully qualified domain name of the vCenter Server instance that hosts the vSphere cluster whose Edges need to be redeployed.

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

### -vCenterAdmin

Admin user for the vCenter Server instance that hosts the vSphere cluster whose NSX Edges need to be redeployed.

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

### -vCenterAdminPassword

Admin password for the vCenter Server instance that hosts the vSphere cluster whose NSX Edges need to be redeployed.

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

### -clusterName

Name of the vSphere cluster instance whose Edges need to be redeployed.

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
