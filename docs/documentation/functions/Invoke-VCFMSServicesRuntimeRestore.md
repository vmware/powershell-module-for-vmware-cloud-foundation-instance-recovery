# Invoke-VCFMSServicesRuntimeRestore

## Synopsis

Submits a VCFMS Services Runtime restore operation from a JSON payload file.

## Syntax

```powershell
Restore-VcfmsBackup [-ServicesRuntimeFqdn] <String> [-ServicesRuntimePassword] <String> [-RestoreJsonFile] <String> [[-ServicesRuntimeUsername] <String>] [[-PollIntervalSeconds] <Int32>] [<CommonParameters>]
```

## Description

The `Restore-VcfmsBackup` cmdlet submits a restore request to `POST /api/v1/system/backups?action=restore` on the VCFMS Services Runtime. The restore payload is read from a JSON file containing a `components` array where each entry specifies the SFTP path and restore point for one component.

The cmdlet displays the payload for review before submitting, then polls the restore task until it reaches a terminal state. Use `Get-VcfmsBackups` to list available backups and their paths, then construct the JSON file with the desired restore points.

The restore payload file format:

```json
{
  "components": [
    { "path": "sftp://svc-vcf-bck@10.167.173.126:22/media/backups/vcf/backups/.../vsp/.../2026-03-23T16-45-31Z", "point": "2026-03-23T16-45-31Z" },
    { "path": "sftp://svc-vcf-bck@10.167.173.126:22/media/backups/vcf/backups/.../salt/.../2026-03-23T17-13-37Z", "point": "2026-03-23T17-13-37Z" }
  ]
}
```

## Examples

### Example 1

List available backups, then run the restore using a saved payload file.

```powershell
# Step 1: List available backups to find paths and restore points
Get-VcfmsBackups -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!"

# Step 2: Create restore-payload.json with the desired components (see format above)

# Step 3: Run the restore
Restore-VcfmsBackup -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -ServicesRuntimePassword "VMw@re1!VMw@re1!" -RestoreJsonFile ".\restore-payload.json"
```

### Example 2

Restore with a custom poll interval.

```powershell
Restore-VcfmsBackup `
    -ServicesRuntimeFqdn     "sfo-sr01.sfo.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
    -RestoreJsonFile         ".\restore-payload.json" `
    -PollIntervalSeconds     60
```

## Parameters

### -ServicesRuntimeFqdn

The fully qualified domain name of the VCFMS Services Runtime instance.

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

### -ServicesRuntimePassword

The password for the Services Runtime admin user (used to obtain a token).

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

### -RestoreJsonFile

Path to a JSON file containing the restore payload. The file must contain a `components` array with `path` and `point` for each component to restore.

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

### -ServicesRuntimeUsername

The Services Runtime identity username. Defaults to `admin@vsp.local`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: admin@vsp.local
Accept pipeline input: False
Accept wildcard characters: False
```

### -PollIntervalSeconds

Interval in seconds to poll the restore task status. Defaults to `300` (5 minutes).

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
Default value: 300
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
