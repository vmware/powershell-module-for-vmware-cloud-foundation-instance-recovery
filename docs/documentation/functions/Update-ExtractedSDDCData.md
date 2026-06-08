# Update-ExtractedSDDCData

## Synopsis

Updates an extracted SDDC Data JSON file with cluster names, datastore names, and port group names retrieved from a live vCenter.

## Syntax

```powershell
Update-ExtractedSDDCData [-extractedSDDCDataFile] <String> [-sddcManagerFQDN] <String> [-sddcManagerAdmin] <String> [-sddcManagerAdminPassword] <String> [-vCenterFQDN] <String> [<CommonParameters>]
```

## Description

The `Update-ExtractedSDDCData` cmdlet enriches the `extracted-sddc-data.json` file produced by `New-ExtractDataFromSDDCBackup` with data that is not captured in the SDDC Manager backup. It connects to the specified vCenter, iterates over each workload domain whose vCenter FQDN matches the supplied value, and injects cluster names, primary datastore names, primary datastore storage policy names, and port group names (VM Management, Management, vMotion, vSAN) into the JSON.

## Examples

### Example 1

```powershell
Update-ExtractedSDDCData `
    -extractedSDDCDataFile    ".\extracted-sddc-data.json" `
    -sddcManagerFQDN          "sfo-vcf01.sfo.rainpole.io" `
    -sddcManagerAdmin         "administrator@vsphere.local" `
    -sddcManagerAdminPassword "VMw@re1!VMw@re1!" `
    -vCenterFQDN              "sfo-m01-vc01.sfo.rainpole.io"
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

### -sddcManagerFQDN

FQDN of the SDDC Manager instance to query.

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

### -sddcManagerAdmin

Admin username for SDDC Manager (e.g. `administrator@vsphere.local`).

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

### -sddcManagerAdminPassword

Password for the SDDC Manager admin user.

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

### -vCenterFQDN

FQDN of the vCenter to query for cluster, datastore, and port group details.

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
