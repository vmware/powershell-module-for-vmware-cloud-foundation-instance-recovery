# Invoke-vCenterRestore

## Synopsis

Restores a vCenter appliance using the specified backup.

## Syntax

```powershell
Invoke-vCenterRestore [-vCenterFqdn] <String> [-vCenterAdmin] <String> [-vCenterAdminPassword] ["VMw@re1!"] [-extractedSDDCDataFile] <String> [-workloadDomain] <String> [-vCenterBackupPath] <String> [-locationtype] <String> [-locationUser] <String> [-locationPassword] <String> [<CommonParameters>]
```

## Description

The Invoke-vCenterRestore restores a vCenter appliance using the specified backup.

## Examples

### Example 1

```powershell
Invoke-vCenterRestore -vCenterFqdn "sfo-m01-vc02.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" "-extractedSDDCDataFile .\extracted-sddc-data.json" -workloadDomain "sfo-m01" -vCenterBackupPath "10.50.5.63/F$/Backups/vcenter-backup/sn_sfo-m01-vc01.sfo.rainpole.io/M_8.0.2.00100_20231209-074557_" -locationtype "SMB" -locationUser "Administrator" -locationPassword "VMw@re1!"
```

## Parameters

### -vCenterFQDN

Fully qualified domain name of the vCenter Server instance that hosts the vSphere cluster whose Edges need to be redeployed.

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

### -vCenterAdmin

Admin user for the vCenter Server instance that hosts the vSphere cluster whose NSX Edges need to be redeployed.

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

### -vCenterAdminPassword

Admin password for the vCenter Server instance that hosts the vSphere cluster whose NSX Edges need to be redeployed.

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

Workload domain name associated with the vCenter Server being restored.

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

### -vCenterBackupPath

Path to the vCenter Server backup.

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

### -locationtype

Type of backup location. Valid types are FTP, FTPS, HTTP, HTTPS, SFTP, NFS, or SMB.

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

### -locationUser

User account for connecting to the backup location passed with vCenterBackupPath.

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

### -backupPassword

Password to decrypt an encrypted vCenter Server backup file.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
