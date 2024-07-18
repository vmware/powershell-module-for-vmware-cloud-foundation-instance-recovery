# New-PartialManagementDomainDeployment

## Synopsis

Submits a partial bringup spec to cloudbuilder. Performs validation and bringup.

## Syntax

```powershell
New-PartialManagementDomainDeployment [-partialBringupSpecFile] <String> [-extractedSDDCDataFile] <String> [-cloudBuilderFQDN] <String> [-cloudBuilderAdminUserPassword] <String> [<CommonParameters>]
```

## Description

The `New-PartialManagementDomainDeployment` cmdlet submits a partial bringup spec to cloudbuilder and performs validation and bringup.

## Examples

### Example 1

```powershell
New-PartialManagementDomainDeployment -partialBringupSpecFile ".\sfo-m01-partial-bringup-spec.json"  -extractedSDDCDataFile ".\extracted-sddc-data.json" -cloudBuilderFQDN "sfo-cb01.sfo.rainpole.io" -cloudBuilderAdminUserPassword "VMw@re1!VMw@re1!"
```

## Parameters

### -partialBringupSpecFile

Path to the partial bringup spec.

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

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
