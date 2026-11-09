# New-SDDCManagerOvaDeployment

## Synopsis

Deploys an SDDC Manager appliance from OVA using data previously extracted from the SDDC Manager backup.

## Syntax

```powershell
New-SDDCManagerOvaDeployment [[-targetFqdn] <String>] [-targetAdmin] <String> [-targetAdminPassword] <String> [-extractedSDDCDataFile] <String> [-sddcManagerOvaFile] <String> [-rootUserPassword] <String> [-vcfUserPassword] <String> [-localUserPassword] <String> [-basicAuthUserPassword] <String> [[-targetType] <String>] [<CommonParameters>]
```

## Description

The `New-SDDCManagerOvaDeployment` cmdlet deploys an SDDC Manager appliance from OVA using data previously extracted from the SDDC Manager backup. The target can be a vCenter Server instance or, with `-targetType esx`, a single ESX host.

## Examples

### Example 1

```powershell
New-SDDCManagerOvaDeployment -targetFqdn "sfo-m01-vc02.sfo.rainpole.io" -targetAdmin "administrator@vsphere.local" -targetAdminPassword "VMw@re1!" -extractedSDDCDataFile ".\extracted-sddc-data.json" -sddcManagerOvaFile "F:\OVA\VCF-SDDC-Manager-Appliance-4.5.1.0-21682411.ova" -rootUserPassword "VMw@re1!" -vcfUserPassword "VMw@re1!" -localUserPassword "VMw@re1!VMw@re1!" -basicAuthUserPassword "VMw@re1!" -targetType "vcenter"
```

### Example 2

```powershell
New-SDDCManagerOvaDeployment -targetFqdn "sfo01-m01-esx01.sfo.rainpole.io" -targetAdmin "root" -targetAdminPassword "VMw@re1!" -extractedSDDCDataFile ".\extracted-sddc-data.json" -sddcManagerOvaFile "F:\OVA\VCF-SDDC-Manager-Appliance-4.5.1.0-21682411.ova" -rootUserPassword "VMw@re1!" -vcfUserPassword "VMw@re1!" -localUserPassword "VMw@re1!VMw@re1!" -basicAuthUserPassword "VMw@re1!" -targetType "esx"
```

### Example 3

Deploys to the first ESX host of the management domain; `-targetFqdn` is omitted.

```powershell
New-SDDCManagerOvaDeployment -targetAdmin "root" -targetAdminPassword "VMw@re1!" -extractedSDDCDataFile ".\extracted-sddc-data.json" -sddcManagerOvaFile "F:\OVA\VCF-SDDC-Manager-Appliance-4.5.1.0-21682411.ova" -rootUserPassword "VMw@re1!" -vcfUserPassword "VMw@re1!" -localUserPassword "VMw@re1!VMw@re1!" -basicAuthUserPassword "VMw@re1!" -targetType "esx"
```

## Parameters

### -targetFqdn

FQDN of the target vCenter Server instance or ESX host to deploy the SDDC Manager OVA to. Optional: when omitted and `-targetType` is `esx`, it defaults to the first ESX host of the management domain in the extracted SDDC data. If it is omitted and no host can be determined, the task stops with an error.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -targetAdmin

Admin user for the target vCenter Server instance or ESX host to deploy the SDDC Manager OVA to.

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

### -targetAdminPassword

Admin password for the target vCenter Server instance or ESX host to deploy the SDDC Manager OVA to.

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

Relative or absolute path to the `extracted-sddc-data.json` file (previously created by `New-ExtractDataFromSDDCBackup`) on the local filesystem.

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

Relative or absolute path to the SDDC Manager OVA on the local filesystem.

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

### -targetType

Type of the deployment target. Valid values are `vcenter` and `esx`. When `esx`, the appliance is deployed directly to the ESX host and connected to the `vm_mgmt` network.

```yaml
Type: String
Parameter Sets: (All)
Aliases:
Accepted values: vcenter, esx

Required: False
Position: 10
Default value: vcenter
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
