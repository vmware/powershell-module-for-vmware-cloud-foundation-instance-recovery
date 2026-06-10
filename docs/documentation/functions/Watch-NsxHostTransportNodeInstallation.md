# Watch-NsxHostTransportNodeInstallation

## Synopsis

Monitors the installation of NSX on all host transport nodes in a cluster until all nodes report a successful configuration state.

## Syntax

```powershell
Watch-NsxHostTransportNodeInstallation [-clusterName] <String> [-extractedSDDCDataFile] <String> [<CommonParameters>]
```

## Description

The `Watch-NsxHostTransportNodeInstallation` cmdlet polls the NSX Manager API for every host transport node belonging to the specified vSphere cluster and waits until the top-level configuration state for each node reports `success` and the node connectivity status reports `UP`. Progress is logged for each host on every poll cycle. The NSX Manager FQDN and credentials are resolved automatically from the extracted SDDC data. The function polls every 30 seconds with a 60-minute timeout.

## Examples

### Example 1

```powershell
Watch-NsxHostTransportNodeInstallation `
    -clusterName           "sfo-m01-cl01" `
    -extractedSDDCDataFile ".\extracted-sddc-data.json"
```

## Parameters

### -clusterName

Name of the vSphere cluster whose host transport nodes will be monitored.

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

### -extractedSDDCDataFile

Relative or absolute path to the `extracted-sddc-data.json` file previously created by `New-ExtractDataFromSDDCBackup`.

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

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
