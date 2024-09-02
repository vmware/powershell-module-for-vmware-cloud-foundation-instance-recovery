# Add-AdditionalNSXManagers

## Synopsis

Adds second and third NSX managers to a cluster after the restore of the first NSX Manager.

## Syntax

```powershell
Add-AdditionalNSXManagers [-workloadDomain] <String> [-extractedSDDCDataFile] <String> [<CommonParameters>]
```

## Description

The `Add-AdditionalNSXManagers` cmdlet adds second and third NSX managers to a cluster after the restore of the first NSX Manager.

## Examples

### Example 1

```powershell
Add-AdditionalNSXManagers -workloadDomain "sfo-m01" -extractedSDDCDataFile ".\extracted-sddc-data.json"
```

## Parameters

### -workloadDomain

Name of the VCF workload domain that the NSX Managers to be added are associated with.

```yaml
Type: ActionPreference
Parameter Sets: (All)
Aliases: proga

Required: True
Position: Named
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
Position: 5
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
