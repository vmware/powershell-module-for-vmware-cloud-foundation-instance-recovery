# Restore-VcfmsBackup

## Synopsis

Submits a VCFMS Services Runtime restore operation from a JSON payload file and monitors the task to completion.

## Syntax

```powershell
Restore-VcfmsBackup [-ServicesRuntimeFqdn] <String> [-ServicesRuntimePassword] <String> [-RestoreJsonFile] <String> [[-ServicesRuntimeUsername] <String>] [[-PollIntervalSeconds] <Int32>] [<CommonParameters>]
```

## Description

The `Restore-VcfmsBackup` cmdlet reads a restore payload from a JSON file and submits it to `POST /api/v1/system/backups?action=restore` on the VCFMS Services Runtime. The JSON file must contain a `components` array where each entry specifies the SFTP `path` and `point` for one component to restore. The cmdlet displays the payload before submitting, then polls the restore task until it reaches a terminal state.

Payload file format:

```json
{
  "components": [
    { "path": "sftp://user@host:22/backups/vsp/.../2026-01-01T00-00-00Z", "point": "2026-01-01T00-00-00Z" },
    { "path": "sftp://user@host:22/backups/salt/.../2026-01-01T01-00-00Z", "point": "2026-01-01T01-00-00Z" }
  ]
}
```

Use `Get-VcfmsBackups` to list available backups and build the payload file.

## Examples

### Example 1

```powershell
Restore-VcfmsBackup `
    -ServicesRuntimeFqdn     "sfo-sr01.sfo.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
    -RestoreJsonFile         ".\restore-payload.json"
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

Path to a JSON file containing the restore payload with a `components` array.

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
Position: Named
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
Position: Named
Default value: 300
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
