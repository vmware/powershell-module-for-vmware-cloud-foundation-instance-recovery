# Invoke-SDDCManagerRestore

## Synopsis

Restores SDDC Manager from backup.

## Syntax

```powershell
Invoke-SDDCManagerRestore -[extractedSDDCDataFile] <String> [-backupFilePath] <String> [-rootUserPassword] <String> [-vcfUserPassword] <String> [-localUserPassword] <String> [-basicAuthUserPassword] <String> [<CommonParameters>]
```

## Description

The Invoke-SDDCManagerRestore cmdlet restores SDDC Manager from backup

## Examples

### Example 1

```powershell
Invoke-SDDCManagerRestore -extractedSDDCDataFile ".\extracted-sddc-data.json" -backupFilePath "F:\backup\vcf-backup-sfo-vcf01-sfo-rainpole-io-2023-09-19-10-53-02.tar.gz" -rootUserPassword "VMw@re1!" -vcfUserPassword "VMw@re1!" -localUserPassword "VMw@re1!VMw@re1!" -basicAuthUserPassword "VMw@re1!"
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

### -backupFilePath

Path to the SDDC Manager backup archive.

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

### -rootUserPassword

Root user Password of the SDDC manager appliance.

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

### -vcfUserPassword

vcf user Password of the SDDC manager appliance.

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

### -localUserPassword

Local admin user Password of the SDDC manager appliance.

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
