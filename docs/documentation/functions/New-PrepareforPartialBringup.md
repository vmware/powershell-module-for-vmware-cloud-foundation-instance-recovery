# New-PrepareforPartialBringup

## Synopsis

Prepares a running Cloud Builder system to perform a partial VCF bringup suitable for VCF Instance Recovery.

## Syntax

```powershell
New-PrepareforPartialBringup [-extractedSDDCDataFile] <String> [-cloudBuilderFQDN] <String> [-cloudBuilderAdminUserPassword] <String> [-cloudBuilderRootUserPassword] <String> [<CommonParameters>]
```

## Description

The `New-PartialManagementDomainDeployment` cmdlet submits a partial bringup spec to cloudbuilder and performs validation and bringup.

## Examples

### Example 1

```powershell
New-PrepareforPartialBringup "-extractedSDDCDataFile .\extracted-sddc-data.json" -cloudBuilderFQDN "sfo-cb01.sfo.rainpole.io" -cloudBuilderAdminUserPassword "VMw@re1!" -cloudBuilderRootUserPassword "VMw@re1!"
```

## Parameters

### -extractedSDDCDataFile

Relative or absolute to the `extracted-sddc-data.json` file (previously created by `New-ExtractDataFromSDDCBackup`) on the local filesystem.

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

### -cloudBuilderFQDN

FQDN of the cloud builder appliance.

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

### -cloudBuilderAdminUserPassword

Password for the cloud builder admin user account.

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

### -cloudBuilderRootUserPassword

Password for the cloud builder root user account.

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
