# Invoke-SupervisorRestore

## Synopsis

Restores a vSphere Supervisor Cluster from a backup archive on the vCenter appliance.

## Syntax

```powershell
Invoke-SupervisorRestore [-vCenterFQDN] <String> [-vCenterAdmin] <String> [-vCenterAdminPassword] <String> [-vCenterRootPassword] <String> [-supervisorName] <String> [-backupFilePath] <String> [<CommonParameters>]
```

## Description

The `Invoke-SupervisorRestore` cmdlet uploads a Supervisor Cluster backup archive to the vCenter appliance via SCP, resolves the Supervisor ID and matching backup archive ID via the vCenter REST API, initiates a restore job, and monitors the restore task to completion.

## Examples

### Example 1

```powershell
Invoke-SupervisorRestore `
    -vCenterFQDN          "sfo-m01-vc01.sfo.rainpole.io" `
    -vCenterAdmin         "administrator@vsphere.local" `
    -vCenterAdminPassword "VMw@re1!" `
    -vCenterRootPassword  "VMw@re1!VMw@re1!" `
    -supervisorName       "sfo-m01-cl01" `
    -backupFilePath       "C:\backups\supervisor-backup.tar.gz"
```

## Parameters

### -vCenterFQDN

FQDN of the vCenter instance hosting the Supervisor Cluster.

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

### -vCenterAdmin

Admin user for the vCenter REST API (used for session token and supervisor queries).

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

### -vCenterAdminPassword

Password for the vCenter admin user.

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

### -vCenterRootPassword

Root password for SCP access to the vCenter appliance.

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

### -supervisorName

Display name of the Supervisor Cluster to restore (e.g. `sfo-m01-cl01`).

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

### -backupFilePath

Local path to the Supervisor Cluster backup archive file to upload and restore from.

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

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
