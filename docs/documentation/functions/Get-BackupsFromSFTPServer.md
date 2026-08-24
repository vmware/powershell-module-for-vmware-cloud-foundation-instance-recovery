# Get-BackupsFromSFTPServer

## Synopsis

Retrieves and displays VCF Fleet component backup information from a remote SFTP server.

## Syntax

```powershell
Get-BackupsFromSFTPServer [-sftpServer] <String> [-sftpUser] <String> [-sftpPassword] <String> [-sftpServerBackupPath] <String> [-vspId] <String> [[-componentNames] <String[]>] [<CommonParameters>]
```

## Description

The `Get-BackupsFromSFTPServer` cmdlet connects to a remote SFTP server and walks the backup folder structure (`<sftpServerBackupPath>/<vspId>/<version>/<component>/<subId>/<version>/<dated backup>`) to find backups for the specified component types, groups them by backup rank (rank 1 = most recent backup of each component, rank 2 = second most recent, and so on), and lets the user interactively select a backup group. Output includes component type, version, backup name, age, and path, mirroring the behavior of `Get-ServicesRuntimeComponentBackups`.

If `-sftpServerBackupPath` does not already end with `/vcf/backups`, it is appended automatically. After displaying the results, the cmdlet optionally generates a `restore-payload.json` file containing the selected backup of each component, with each path prefixed as `sftp://<sftpUser>@<sftpServer>:22`.

## Examples

### Example 1

Display all component backups for a VSP instance.

```powershell
Get-BackupsFromSFTPServer `
    -sftpServer           "10.50.5.66" `
    -sftpUser             "svc-bkup-user" `
    -sftpPassword         "VMw@re1!" `
    -sftpServerBackupPath "/media/backups/vcf/backups" `
    -vspId                "e6b2ad0a-b76f-4080-b9db-aa338bacdc64"
```

### Example 2

Filter to specific components.

```powershell
Get-BackupsFromSFTPServer `
    -sftpServer           "10.50.5.66" `
    -sftpUser             "svc-bkup-user" `
    -sftpPassword         "VMw@re1!" `
    -sftpServerBackupPath "/media/backups/vcf/backups" `
    -vspId                "e6b2ad0a-b76f-4080-b9db-aa338bacdc64" `
    -componentNames       "vcf-fleet-lcm","salt-raas"
```

## Parameters

### -sftpServer

Address of the SFTP server that hosts the VCF Fleet backups.

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

### -sftpUser

Username for connection to the SFTP server that hosts the VCF Fleet backups.

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

### -sftpPassword

Password for the user (passed as the sftpUser parameter) for connection to the SFTP server that hosts the VCF Fleet backups.

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

### -sftpServerBackupPath

Path on the SFTP server under which the VCF instance backup folder (named for its instance ID) resides. If the path does not already end with `/vcf/backups`, it is appended automatically.

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

### -vspId

ID of the VCF instance (the top level folder under sftpServerBackupPath) whose backups should be searched.

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

### -componentNames

Names of the components to find backups for.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 6
Default value: vcf-fleet-lcm, vcf-fleet-depot, salt-raas, vidb
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
