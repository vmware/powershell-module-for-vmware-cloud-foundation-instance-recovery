# Wait-NSXTEdgeDeployment

## Synopsis

Polls the NSX Manager API until the expected number of Edge transport nodes matching a name pattern are deployed and report an UP connectivity status.

## Syntax

```powershell
Wait-NSXTEdgeDeployment [-nsxtManagerFqdn] <String> [-nsxtUsername] <String> [-nsxtPassword] <String> [-edgeNamePattern] <String> [[-expectedEdgeCount] <Int32>] [[-pollIntervalSeconds] <Int32>] [[-timeoutMinutes] <Int32>] [<CommonParameters>]
```

## Description

The `Wait-NSXTEdgeDeployment` cmdlet polls `GET /api/v1/transport-nodes?node_types=EdgeNode` and the per-node status endpoint on a configured interval until the required number of Edge nodes matching the provided name pattern are both found and report `status = UP` and `control_connection_status = UP`. Returns when the condition is met or logs a warning if the timeout is reached.

## Examples

### Example 1

Wait for two Edges matching `sfo-m01-en01` prefix with default timeout.

```powershell
Wait-NSXTEdgeDeployment `
    -nsxtManagerFqdn   "sfo-m01-nsx01.sfo.rainpole.io" `
    -nsxtUsername      "admin" `
    -nsxtPassword      "VMw@re1!VMw@re1!" `
    -edgeNamePattern   "sfo-m01-en01"
```

### Example 2

Wait for four Edges with a 60-minute timeout.

```powershell
Wait-NSXTEdgeDeployment `
    -nsxtManagerFqdn   "sfo-m01-nsx01.sfo.rainpole.io" `
    -nsxtUsername      "admin" `
    -nsxtPassword      "VMw@re1!VMw@re1!" `
    -edgeNamePattern   "sfo-m01-en01" `
    -expectedEdgeCount 4 `
    -timeoutMinutes    60
```

## Parameters

### -nsxtManagerFqdn

FQDN of the NSX Manager to poll.

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

### -nsxtUsername

Admin username for the NSX Manager API.

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

### -nsxtPassword

Admin password for the NSX Manager API.

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

### -edgeNamePattern

Name prefix pattern to match against Edge transport node display names (matched as `<edgeNamePattern>*`).

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

### -expectedEdgeCount

Number of Edge nodes expected to be deployed and UP. Defaults to `2`.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 2
Accept pipeline input: False
Accept wildcard characters: False
```

### -pollIntervalSeconds

Interval in seconds between API polls. Defaults to `30`.

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

### -timeoutMinutes

Maximum time in minutes to wait before giving up. Defaults to `30`.

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
