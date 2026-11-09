# New-UploadAndModifySDDCManagerBackup

## Synopsis

Uploads the provided SDDC Manager backup file to SDDC Manager, decrypts and extracts it, replaces the SSH keys for the management domain vCenter with the current keys, then compresses and re-encrypts the files ready for subsequent restore.

## Syntax

```powershell
# Plain text encryption password
New-UploadAndModifySDDCManagerBackup [-rootUserPassword] <String> [-vcfUserPassword] <String> [-backupFilePath] <String> [-encryptionPassword] <String> [-extractedSDDCDataFile] <String> [[-targetFqdn] <String>] [[-targetAdmin] <String>] [-targetAdminPassword] <String> [[-targetType] <String>] [<CommonParameters>]

# Secure string encryption password
New-UploadAndModifySDDCManagerBackup [-rootUserPassword] <String> [-vcfUserPassword] <String> [-backupFilePath] <String> [[-secureEncryptionPassword] <SecureString>] [-extractedSDDCDataFile] <String> [[-targetFqdn] <String>] [[-targetAdmin] <String>] [-targetAdminPassword] <String> [[-targetType] <String>] [<CommonParameters>]
```

## Description

The `New-UploadAndModifySDDCManagerBackup` cmdlet uploads the provided SDDC Manager backup file to SDDC Manager, decrypts and extracts it, replaces the SSH keys for the management domain vCenter with the current keys, then compresses and re-encrypts the files ready for subsequent restore. The SDDC Manager VM is reached through a vCenter Server instance or, with `-targetType esx`, directly through the ESX host it runs on.

## Examples

### Example 1

```powershell
New-UploadAndModifySDDCManagerBackup -rootUserPassword "VMw@re1!" -vcfUserPassword "VMw@re1!" -backupFilePath "F:\backup\vcf-backup-sfo-vcf01-sfo-rainpole-io-2023-09-19-10-53-02.tar.gz" -encryptionPassword "VMw@re1!VMw@re1!" -extractedSDDCDataFile ".\extracted-sddc-data.json" -targetFqdn "sfo-m01-vc02.sfo.rainpole.io" -targetAdmin "Administrator@vsphere.local" -targetAdminPassword "VMw@re1!" -targetType "vcenter"
```

### Example 2

```powershell
New-UploadAndModifySDDCManagerBackup -rootUserPassword "VMw@re1!" -vcfUserPassword "VMw@re1!" -backupFilePath "F:\backup\vcf-backup-sfo-vcf01-sfo-rainpole-io-2023-09-19-10-53-02.tar.gz" -encryptionPassword "VMw@re1!VMw@re1!" -extractedSDDCDataFile ".\extracted-sddc-data.json" -targetFqdn "sfo01-m01-esx01.sfo.rainpole.io" -targetAdmin "root" -targetAdminPassword "VMw@re1!" -targetType "esx"
```

### Example 3

Connects to the first ESX host of the management domain; `-targetFqdn` is omitted.

```powershell
New-UploadAndModifySDDCManagerBackup -rootUserPassword "VMw@re1!" -vcfUserPassword "VMw@re1!" -backupFilePath "F:\backup\vcf-backup-sfo-vcf01-sfo-rainpole-io-2023-09-19-10-53-02.tar.gz" -encryptionPassword "VMw@re1!VMw@re1!" -extractedSDDCDataFile ".\extracted-sddc-data.json" -targetAdmin "root" -targetAdminPassword "VMw@re1!" -targetType "esx"
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

Relative or absolute path to the SDDC Manager backup file on the local filesystem.

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

The password used to decrypt the SDDC Manager backup file, i.e. the password it was originally encrypted with. Mutually exclusive with `-secureEncryptionPassword`.

```yaml
Type: String
Parameter Sets: PlainPassword
Aliases:

Required: True
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -secureEncryptionPassword

The same password as a SecureString, so the plain text never has to appear on the command line. Mutually exclusive with `-encryptionPassword`.

```yaml
Type: SecureString
Parameter Sets: SecurePassword
Aliases:

Required: False
Position: 5
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
Position: 6
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -targetFqdn

FQDN of the target vCenter Server instance or ESX host that hosts the SDDC Manager VM. Optional: when omitted and `-targetType` is `esx`, it defaults to the first ESX host of the management domain in the extracted SDDC data. If it is omitted and no host can be determined, the task stops with an error.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 7
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -targetAdmin

Admin user for the target vCenter Server instance or ESX host that hosts the SDDC Manager VM. Optional: when omitted and `-targetType` is `esx`, it defaults to `root`. If it is omitted for a `vcenter` target, the task stops with an error.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 8
Default value: None (`root` when `-targetType` is `esx`)
Accept pipeline input: False
Accept wildcard characters: False
```

### -targetAdminPassword

Admin password for the target vCenter Server instance or ESX host that hosts the SDDC Manager VM.

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

Type of the target. Valid values are `vcenter` and `esx`.

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
