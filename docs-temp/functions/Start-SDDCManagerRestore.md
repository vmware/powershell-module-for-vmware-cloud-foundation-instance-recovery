# Start-SDDCManagerRestore

## Synopsis

Starts an SDDC Manager restore from a backup file already present on the appliance.

## Syntax

```powershell
Start-SDDCManagerRestore [-sddcManagerFqdn] <String> [-localPassword] <String> [-backupFileOnAppliance] <String> [-encryptionPassphrase] <String> [[-localUsername] <String>] [[-RestoreSpecJson] <String>] [-PassThru] [<CommonParameters>]
```

## Description

The `Start-SDDCManagerRestore` cmdlet posts a restore request to `POST /v1/restores/tasks`. The backup file must already be present on the SDDC Manager appliance (e.g. copied to `/tmp`). Authenticates using the `admin@local` account by default. Returns the restore task id, or the full response object when `-PassThru` is set. Poll progress with `Wait-SDDCManagerRestoreTask`.

## Examples

### Example 1

```powershell
Start-SDDCManagerRestore -sddcManagerFqdn "sfo-vcf01.sfo.rainpole.io" -localPassword "VMw@re1!" -backupFileOnAppliance "/tmp/vcf-backup.tar.gz" -encryptionPassphrase "VMwareBackup@1"
```

## Parameters

### -sddcManagerFqdn

The fully qualified domain name of the SDDC Manager appliance.

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

### -localPassword

Password for the local admin account (`admin@local`) on the SDDC Manager appliance.

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

### -backupFileOnAppliance

Full path to the backup archive on the SDDC Manager appliance (e.g. `/tmp/vcf-backup.tar.gz`).

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

### -encryptionPassphrase

The passphrase used to decrypt the backup archive.

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

### -localUsername

The local admin username. Defaults to `admin@local`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
Default value: admin@local
Accept pipeline input: False
Accept wildcard characters: False
```

### -RestoreSpecJson

Optional. A fully-formed JSON string to override the entire request body.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 6
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -PassThru

When set, returns the full response object instead of just the task id string.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
