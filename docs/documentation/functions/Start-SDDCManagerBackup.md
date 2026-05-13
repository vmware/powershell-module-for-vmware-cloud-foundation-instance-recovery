# Start-SDDCManagerBackup

## Synopsis

Starts an SDDC Manager file-based backup task.

## Syntax

```powershell
Start-SDDCManagerBackup [-sddcManagerFqdn] <String> [-username] <String> [-password] <String> [[-BackupSpecJson] <String>] [-PassThru] [<CommonParameters>]
```

## Description

The `Start-SDDCManagerBackup` cmdlet submits a backup task to SDDC Manager via `POST /v1/backups/tasks`. By default it posts the standard body `{ "elements": [ { "resourceType": "SDDC_MANAGER" } ] }`. Returns the task id by default, or the full response object when `-PassThru` is supplied. Poll task progress with `Wait-SDDCManagerVcfTask`.

## Examples

### Example 1

```powershell
Start-SDDCManagerBackup -sddcManagerFqdn "sfo-vcf01.sfo.rainpole.io" -username "admin@local" -password "VMw@re1!"
```

### Example 2

Poll until complete.

```powershell
$taskId = Start-SDDCManagerBackup -sddcManagerFqdn "sfo-vcf01.sfo.rainpole.io" -username "admin@local" -password "VMw@re1!"
Wait-SDDCManagerVcfTask -sddcManagerFqdn "sfo-vcf01.sfo.rainpole.io" -username "admin@local" -password "VMw@re1!" -taskId $taskId
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

### -username

The username to authenticate with SDDC Manager.

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

### -password

The password for the SDDC Manager user.

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

### -BackupSpecJson

Optional. A fully-formed JSON string to override the entire request body. Use when your environment requires additional fields beyond the default spec.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
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
