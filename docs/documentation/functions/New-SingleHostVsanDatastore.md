# New-SingleHostVsanDatastore

## Synopsis

Interactively guides the creation of a vSAN datastore on the first host in the default management cluster.

## Syntax

```powershell
New-SingleHostVsanDatastore [-extractedSDDCDataFile] <String> [<CommonParameters>]
```

## Description

The `New-SingleHostVsanDatastore` cmdlet connects to the first host in the default management cluster identified in the extracted SDDC data, retrieves credentials automatically, and presents an interactive disk selection process to create a vSAN OSA or ESA datastore. The cmdlet presents available eligible local disks and prompts the operator to select cache and capacity disks. Assumes a standardised disk layout across all hosts in the cluster. Use `Add-DiskgroupsToManagementHosts` afterwards to expand the datastore to the remaining hosts.

## Examples

### Example 1

```powershell
New-SingleHostVsanDatastore -extractedSDDCDataFile ".\extracted-sddc-data.json"
```

## Parameters

### -extractedSDDCDataFile

Relative or absolute path to the `extracted-sddc-data.json` file previously created by `New-ExtractDataFromSDDCBackup`.

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

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
