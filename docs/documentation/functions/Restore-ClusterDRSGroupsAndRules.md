# Restore-ClusterDRSGroupsAndRules

## Synopsis

Restores the vSphere DRS Groups and Rules for the specified cluster.

## Syntax

```powershell
Restore-ClusterDRSGroupsAndRules [-clusterName] <String> [-jsonFile] <String> [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## Description

The `Restore-ClusterDRSGroupsAndRules` cmdlet restores the vSphere DRS Groups and Rules for the specified cluster.

## Examples

### Example 1

```powershell
Restore-ClusterDRSGroupsAndRules -clusterName "sfo-m01-cl01" -jsonFile ".\sfo-m01-cl01-drsConfiguration.json"
```

## Parameters

### -clusterName

Cluster whose vSphere DRS Groups and Rules you will restore.

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

### -jsonFile

Path to the JSON file that contains the backup for the vSphere DRS Groups and Rules for the cluster.

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
