# New-PrepareManagementHostNetworking

## Synopsis

Interactively prepares host networking on the management cluster by creating vSphere Standard Switches based on the VDS configuration from the extracted SDDC backup.

## Syntax

```powershell
New-PrepareManagementHostNetworking [-extractedSDDCDataFile] <String> [[-mtu] <String>] [<CommonParameters>]
```

## Description

The `New-PrepareManagementHostNetworking` cmdlet connects to the first host in the default management cluster, presents the available physical NICs alongside the VDS configuration from the extracted SDDC data, and interactively guides the operator to create matching vSphere Standard Switches with the correct NIC-to-uplink mappings. Assumes a standardised NIC configuration across all hosts in the cluster.

## Examples

### Example 1

```powershell
New-PrepareManagementHostNetworking -extractedSDDCDataFile ".\extracted-sddc-data.json"
```

### Example 2

Specify a custom MTU.

```powershell
New-PrepareManagementHostNetworking `
    -extractedSDDCDataFile ".\extracted-sddc-data.json" `
    -mtu                   "1500"
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

### -mtu

MTU value to assign to the virtual standard switches. Defaults to `9000`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: 9000
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
