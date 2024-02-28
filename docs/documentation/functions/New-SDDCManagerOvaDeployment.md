# New-SDDCManagerOvaDeployment

## Synopsis

Deploys an SDDC Manager appliance from OVA using data previously extracted from the SDDC Manager backup.

## Syntax

```powershell
New-SDDCManagerOvaDeployment [-tempvCenterFqdn] <String> [-tempvCenterAdmin] <String> [-tempvCenterAdminPassword] <String> [-extractedSDDCDataFile] <String> [-sddcManagerOvaFile] <String> [-rootUserPassword] <String> [-vcfUserPassword] <String> [-localUserPassword] <String> [-basicAuthUserPassword] <String> [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## Description

The `New-SDDCManagerOvaDeployment` deploys an SDDC Manager appliance from OVA using data previously extracted from the SDDC Manager backup.

## Examples

### Example 1

```powershell
New-SDDCManagerOvaDeployment -tempvCenterFqdn "sfo-m01-vc02.sfo.rainpole.io" -tempvCenterAdmin "administrator@vsphere.local" -tempvCenterAdminPassword "VMw@re1!" -extractedSDDCDataFile ".\extracted-sddc-data.json" -sddcManagerOvaFile "F:\OVA\VCF-SDDC-Manager-Appliance-4.5.1.0-21682411.ova" -rootUserPassword "VMw@re1!" -vcfUserPassword "VMw@re1!" -localUserPassword "VMw@re1!" -basicAuthUserPassword "VMw@re1!"
```

## Parameters

### -tempvCenterFqdn

Fully qualified domain name of the target vCenter Server instance to deploy the SDDC Manager OVA to.

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

### -tempvCenterAdmin

Admin user for the target vCenter Server instance to deploy the SDDC Manager OVA to.

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

### -tempvCenterAdminPassword

Admin password for the target vCenter Server instance to deploy the SDDC Manager OVA to.

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

### -extractedSDDCDataFile

Relative or absolute to the `extracted-sddc-data.json` file (previously created by `New-ExtractDataFromSDDCBackup`) on the local filesystem.

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

### -sddcManagerOvaFile

Relative or absolute to the SDDC Manager OVA on the local filesystem.

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

### -rootUserPassword

Password for the root user on the newly deployed appliance.

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

### -vcfUserPassword

Password for the vcf user on the newly deployed appliance.

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

### -localUserPassword

Password for the local admin user on the newly deployed appliance.

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

### -basicAuthUserPassword

Password for the basic auth user on the newly deployed appliance.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 9
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
