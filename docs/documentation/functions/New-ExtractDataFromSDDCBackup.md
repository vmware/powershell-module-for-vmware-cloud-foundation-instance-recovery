# New-ExtractDataFromSDDCBackup

## Synopsis

Decrypts and extracts the contents of the provided SDDC Manager backup, parses it for information required for instance recovery and stores the data in a file called `extracted-sddc-data.json`.

## Syntax

```powershell
New-ExtractDataFromSDDCBackup [-vcfBackupFilePath] <String>  [-encryptionPassword] <String> [-managementVcenterBackupFolderPath] <String> [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## Description

The `New-ExtractDataFromSDDCBackup` cmdlet decrypts and extracts the contents of the provided SDDC Manager backup, parses it for information required for instance recovery and stores the data in a file called `extracted-sddc-data.json`.

## Examples

### Example 1

```powershell
New-ExtractDataFromSDDCBackup -vcfBackupFilePath "F:\backup\vcf-backup-sfo-vcf01-sfo-rainpole-io-2023-09-19-10-53-02.tar.gz" -encryptionPassword "VMw@re1!VMw@re1!" -managementVcenterBackupFolderPath "10.221.78.133/F$/backup/vCenter/sn_sfo-m01-vc01.sfo.rainpole.io/M_8.0.1.00100_20231121-104120_"
```

## Parameters

### -vcfBackupFilePath

Relative or absolute to the SDDC Manager backup file on the local filesystem.

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

### -encryptionPassword

The password that should be used to decrypt the SDDC Manager backup file ie the password that was used to encrypt it originally.

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

### -managementVcenterBackupFolderPath

SMB path to the management vCenter Server backup location.

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
