# Wait-SDDCManagerRestoreTask

## Synopsis

Polls an SDDC Manager restore task until it leaves an in-progress state.

## Syntax

```powershell
Wait-SDDCManagerRestoreTask [-sddcManagerFqdn] <String> [-username] <String> [-password] <String> [-restoreTaskId] <String> [[-PollSeconds] <Int32>] [<CommonParameters>]
```

## Description

The `Wait-SDDCManagerRestoreTask` cmdlet repeatedly calls `GET /v1/restores/tasks/{id}` and logs the current status until the task is no longer `IN_PROGRESS` or `IN PROGRESS`. Returns the final task object.

## Examples

### Example 1

```powershell
Wait-SDDCManagerRestoreTask -sddcManagerFqdn "sfo-vcf01.sfo.rainpole.io" -username "admin@local" -password "VMw@re1!" -restoreTaskId "b751c4ec-344f-4e71-8586-00d8fdf834e4"
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

### -restoreTaskId

The restore task id returned by `Start-SDDCManagerRestore`.

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
