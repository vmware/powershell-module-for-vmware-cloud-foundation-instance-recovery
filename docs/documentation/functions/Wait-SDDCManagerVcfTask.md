# Wait-SDDCManagerVcfTask

## Synopsis

Polls an SDDC Manager task until it leaves an in-progress state.

## Syntax

```powershell
Wait-SDDCManagerVcfTask [-sddcManagerFqdn] <String> [-username] <String> [-password] <String> [-taskId] <String> [[-PollSeconds] <Int32>] [<CommonParameters>]
```

## Description

The `Wait-SDDCManagerVcfTask` cmdlet repeatedly calls `GET /v1/tasks/{id}` and logs the current status until the task status is no longer `IN_PROGRESS`, `IN PROGRESS`, or `PENDING`. Returns the final task object. Used after `Start-SDDCManagerBackup` to block until the backup completes.

## Examples

### Example 1

```powershell
Wait-SDDCManagerVcfTask -sddcManagerFqdn "sfo-vcf01.sfo.rainpole.io" -username "admin@local" -password "VMw@re1!" -taskId "3b48ffc5-fafd-46e5-88ee-ce3ccc4d7a93"
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

### -taskId

The task id returned by `Start-SDDCManagerBackup` or another task-submitting function.

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

### -PollSeconds

Interval in seconds between status checks. Defaults to `60`.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
Default value: 60
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
