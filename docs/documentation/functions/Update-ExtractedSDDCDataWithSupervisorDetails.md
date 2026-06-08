# Update-ExtractedSDDCDataWithSupervisorDetails

## Synopsis

Updates an extracted SDDC Data JSON file with Supervisor Cluster details from a restored vCenter.

## Syntax

```powershell
Update-ExtractedSDDCDataWithSupervisorDetails [-extractedSDDCDataFile] <String> [-vCenterFQDN] <String> [<CommonParameters>]
```

## Description

The `Update-ExtractedSDDCDataWithSupervisorDetails` cmdlet queries a restored vCenter for all enabled Supervisor Clusters associated with the workload domain matching the provided vCenter FQDN. For each supervisor it resolves the associated content library and its backing datastore (vSphere datastore or NFS), then injects a `supervisors` property into the matching workload domain entry in the extracted SDDC data JSON file.

Credentials are derived from the existing `extracted-sddc-data.json` SSO password entries.

## Examples

### Example 1

```powershell
Update-ExtractedSDDCDataWithSupervisorDetails `
    -extractedSDDCDataFile ".\extracted-sddc-data.json" `
    -vCenterFQDN           "sfo-m01-vc01.sfo.rainpole.io"
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

### -vCenterFQDN

FQDN of the restored vCenter to query for Supervisor Cluster details.

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
