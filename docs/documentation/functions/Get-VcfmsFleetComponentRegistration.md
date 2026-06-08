# Get-VcfmsFleetComponentRegistration

## Synopsis

Retrieves and displays the current fleet component registration state from a VCFMS Services Runtime cluster.

## Syntax

```powershell
Get-VcfmsFleetComponentRegistration [-ServicesRuntimeFqdn] <String> [-ServicesRuntimePassword] <String> [[-RemoteScriptTimeout] <Int32>] [<CommonParameters>]
```

## Description

The `Get-VcfmsFleetComponentRegistration` cmdlet uploads the bundled `update_fleet_component_registration.sh` script to the Services Runtime control plane node via SSH and executes it with the `--dry-run` flag, which reports the current registration state without making any changes. If a worker node is supplied the function automatically connects to the control plane.

## Examples

### Example 1

```powershell
Get-VcfmsFleetComponentRegistration `
    -ServicesRuntimeFqdn     "lax-sr01.lax.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!"
```

## Parameters

### -ServicesRuntimeFqdn

FQDN or IP of any Services Runtime cluster node. Worker nodes are automatically redirected to the control plane.

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

Password for vmware-system-user (SSH login and sudo elevation).

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

### -RemoteScriptTimeout

Seconds to wait for the remote script to complete. Defaults to `300` (5 minutes).

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
