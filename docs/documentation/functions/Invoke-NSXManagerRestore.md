# Invoke-NSXManagerRestore

## Synopsis

Performs the restore of an NSX Manager from a user chosen backup presented from a list available on supplied SFTP server.

## Syntax

```powershell
Invoke-NSXManagerRestore [-extractedSDDCDataFile] <String> [-workloadDomain] <String> [-sftpServer] <String> [-sftpUser] <String> [-sftpPassword] <String> [-sftpServerBackupPath] <String> [-backupPassphrase] <String> [<CommonParameters>]
```

## Description

The Invoke-NSXManagerRestore performs the restore of an NSX Manager from a user chosen backup presented from a list available on supplied SFTP server.

## Examples

### Example 1

```powershell
Invoke-NSXManagerRestore -extractedSDDCDataFile ".\extracted-sddc-data.json" -workloadDomain "sfo-m01" -sftpServer "10.50.5.66" -sftpUser svc-bkup-user -sftpPassword "VMw@re1!" -sftpServerBackupPath "/media/backups" -backupPassphrase "VMw@re1!VMw@re1!"
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

### -workloadDomain

Name of the VCF workload domain that the NSX Manager to be restored is associated with.

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

### -sftpServer

Address of the SFTP server that hosts the NSX Manager backups.

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

### -sftpUser

Username for connection to the SFTP server that hosts the NSX Manager backups.

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


### -sftpPassword

Password for the user (passed as the stpUser parameter) for connection to the SFTP server that hosts the NSX Manager backups.

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

### -sftpServerBackupPath

Path to the folder on the server (passed as the sftpServer parameter) where the NSX Manager backups exist.

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

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
