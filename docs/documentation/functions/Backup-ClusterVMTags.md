# Backup-ClusterVMTags

## Synopsis

Backs up the VM tags for the specified cluster.

## Syntax

```powershell
Backup-ClusterVMTags [-clusterName] <String> [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## Description

The `Backup-ClusterVMTags` cmdlet backs up the VM tags for the specified cluster.

## Examples

### Example 1

```powershell
Backup-ClusterVMTags -clusterName "sfo-m01-cl01"
```

## Parameters

### -clusterName

Cluster whose VM tags you wish to backup.

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
