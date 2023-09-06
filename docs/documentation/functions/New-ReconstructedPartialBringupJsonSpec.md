# New-ReconstructedPartialBringupJsonSpec

## Synopsis

Reconstructs a management domain bringup JSON spec based on information scraped from the backup being restored from.

## Syntax

```powershell
New-ReconstructedPartialBringupJsonSpec [-tempVcenterIp] <String> [-tempVcenterHostname] <String> [-extractedSDDCDataFile] <String> [-vcfLocalUserPassword] <String> [-vcfRootUserPassword] <String> [-vcfRestApiPassword] <String> [-vcfSecondUserPassword] <String> [-transportVlanId] <String> [-dedupEnabled] <Boolean> [-vds0nics] <Array> [-vcenterServerSize] <String> [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## Description

The `New-ReconstructedPartialBringupJsonSpec` cmdlet reconstructs a management domain bringup JSON spec based on information scraped from the backup being restored from.

## Examples

### Example 1

```powershell
New-ReconstructedPartialBringupJsonSpec -extractedSDDCDataFile ".\extracted-sddc-data.json" -tempVcenterIp "172.16.11.170" -tempVcenterHostname "sfo-m01-vc02" -vcfLocalUserPassword "VMw@re1!VMw@re1!" -vcfRootUserPassword "VMw@re1!" -vcfRestApiPassword "VMw@re1!" -vcfSecondUserPassword "VMw@re1!" -transportVlanId 1614 -dedupEnabled $false -vds0nics "vmnic0","vmnic1" -vcenterServerSize "small"
```

## Parameters

### -tempVcenterIp

As a temporary vCenter will be used, a temporary IP Address must be provided for use.

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

### -tempVcenterHostname

As a temporary vCenter will be used, a temporary hostname must be provided for use.

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

### -vcfLocalUserPassword

Password to be assigned to the local user account.

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

### -vcfRootUserPassword

Password to be assigned to the root user account.

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

### -vcfRestApiPassword

Password to be assigned to the API user account.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 6
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -vcfSecondUserPassword

Password to be assigned to the vcf user account.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 7
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -transportVlanId

VLAN ID to be used for the transport VLAN.
Should be the same as that used in the original build.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 8
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -dedupEnabled

Boolean value to specify with depude should be enabled or not.

```yaml
Type: Boolean
Parameter Sets: (All)
Aliases:

Required: True
Position: 9
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -vds0nics

Comma separated list of vmnics to assign to the first vds in the format "vmnic0","vmnic1".

```yaml
Type: Array
Parameter Sets: (All)
Aliases:

Required: True
Position: 10
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -vcenterServerSize

Size of the vCenter Server appliance to be deployed for the temporary vCenter.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 11
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
