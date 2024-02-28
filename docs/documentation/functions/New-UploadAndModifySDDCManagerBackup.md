# New-UploadAndModifySDDCManagerBackup

## Synopsis

Uploads the provided SDDC Manager backup file to SDDC Manager, decrypts and extracts it, replaces the SSH keys for the management domain vCenter with the current keys, then compresses and re-encrypts the files ready for subsequent restore.

## Syntax

```powershell
New-UploadAndModifySDDCManagerBackup [-rootUserPassword] <String> [-vcfUserPassword] <String> [-backupFilePath] <String> [-encryptionPassword] <String> [-extractedSDDCDataFile] <String> [-tempvCenterFqdn] <String> [-tempvCenterAdmin] <String> [-tempvCenterAdminPassword] <String> [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## Description

The `New-UploadAndModifySDDCManagerBackup` cmdlet uploads the provided SDDC Manager backup file to SDDC Manager, decrypts and extracts it, replaces the SSH keys for the management domain vCenter with the current keys, then compresses and re-encrypts the files ready for subsequent restore.

## Examples

### Example 1

```powershell
New-UploadAndModifySDDCManagerBackup -rootUserPassword "VMw@re1!" -vcfUserPassword "VMw@re1!" -backupFilePath "F:\backup\vcf-backup-sfo-vcf01-sfo-rainpole-io-2023-09-19-10-53-02.tar.gz" -encryptionPassword "VMw@re1!VMw@re1!" -extractedSDDCDataFile ".\extracted-sddc-data.json" -tempvCenterFqdn "sfo-m01-vc02.sfo.rainpole.io" -tempvCenterAdmin "Administrator@vsphere.local" -tempvCenterAdminPassword VMw@re1!"
```

## Parameters

### -rootUserPassword

Password for the root user of the SDDC Manager appliance.

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

### -vcfUserPassword

Password for the vcf user of the SDDC Manager appliance.

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

### -backupFilePath

Relative or absolute to the SDDC Manager backup file on the local filesystem.

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

### -encryptionPassword

The password that should be used to decrypt the SDDC Manager backup file ie the password that was used to encrypt it originally.

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

### -extractedSDDCDataFile

Relative or absolute to the `extracted-sddc-data.json` file (previously created by `New-ExtractDataFromSDDCBackup`) on the local filesystem.

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

### -tempvCenterFqdn

Fully qualified domain name of the target vCenter that hosts the SDDC Manager VM.

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

### -tempvCenterAdmin

Admin user for the target vCenter that hosts the SDDC Manager VM.

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

### -tempvCenterAdminPassword

Admin password for the target vCenter that hosts the SDDC Manager VM.

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
