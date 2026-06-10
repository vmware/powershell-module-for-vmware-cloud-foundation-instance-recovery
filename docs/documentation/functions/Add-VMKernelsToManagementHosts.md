# Add-VMKernelsToManagementHosts

## Synopsis

Adds vMotion and vSAN VMkernel adapters to all ESXi hosts in the default management cluster using IP addressing from the extracted SDDC backup data.

## Syntax

```powershell
Add-VMKernelsToManagementHosts [-extractedSDDCDataFile] <String> [<CommonParameters>]
```

## Description

The `Add-VMKernelsToManagementHosts` cmdlet iterates over every host in the default management cluster and creates vMotion and vSAN portgroups and VMkernel adapters on the appropriate vSphere Standard Switch, using VLAN IDs, MTU, subnet masks, gateways, and per-host IP addresses sourced directly from the `extracted-sddc-data.json` file.

## Examples

### Example 1

```powershell
Add-VMKernelsToManagementHosts -extractedSDDCDataFile ".\extracted-sddc-data.json"
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
