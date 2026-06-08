# Stop-VcfmsTask

## Synopsis

Cancels a running task on a VCFMS Services Runtime instance.

## Syntax

```powershell
Stop-VcfmsTask [-ServicesRuntimeFqdn] <String> [-ServicesRuntimePassword] <String> [-TaskId] <String> [[-ServicesRuntimeUsername] <String>] [[-PollIntervalSeconds] <Int32>] [<CommonParameters>]
```

## Description

The `Stop-VcfmsTask` cmdlet sends a cancel request to a Services Runtime task via `POST /api/v1/tasks/{taskId}?action=cancel`, then polls `GET /api/v1/tasks/{taskId}` until the task reaches a terminal state. Use `Get-VcfmsTask` (or the `-FindRunning` mode) to find task IDs.

## Examples

### Example 1

```powershell
Stop-VcfmsTask `
    -ServicesRuntimeFqdn     "sfo-sr01.sfo.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
    -TaskId                  "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
```

## Parameters

### -ServicesRuntimeFqdn

FQDN of the VCFMS Services Runtime instance.

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

Password for the Services Runtime admin user.

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

### -TaskId

UUID of the task to cancel.

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

Username for the Services Runtime token request. Defaults to `admin@vsp.local`.

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

Interval in seconds to poll for the cancelled state. Defaults to `30`.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 30
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
