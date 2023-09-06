# Move-ClusterVMsToFirstHost

## Synopsis

Moves all virtual machines in a cluster to a single ESXi host.

## Syntax

```powershell
Move-ClusterVMsToFirstHost [-vCenterFQDN] <String> [-vCenterAdmin] <String> [-vCenterAdminPassword] <String> [-clusterName] <String> [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## Description

The `Move-ClusterVMsToFirstHost` cmdlet moves all virtual machines in a cluster to a single ESXi host.

## Examples

### Example 1

```powershell
Move-ClusterVMsToFirstHost -vCenterFQDN "sfo-m01-vc02.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01"
```

## Parameters

### -vCenterFQDN

Fully qualified domain name of the vCenter Server instance hosting the virtual machines to be moved.

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

### -vCenterAdmin

Admin user for the vCenter Server instance hosting the virtual machines to be moved.

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

### -vCenterAdminPassword

Admin password for the vCenter Server instance hosting the virtual machines to be moved.

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

Name of the vSphere cluster instance hosting the virtual machines to be moved.

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
