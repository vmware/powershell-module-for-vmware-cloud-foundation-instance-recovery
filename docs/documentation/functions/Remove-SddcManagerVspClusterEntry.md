# Remove-SddcManagerVspClusterEntry

## Synopsis

Removes stale VSP cluster entries from the SDDC Manager database after a management cluster recovery.

## Syntax

```powershell
Remove-SddcManagerVspClusterEntry [-sddcManagerFQDN] <String> [-sddcManagerRootPassword] <String> [-vCenterFQDN] <String> [<CommonParameters>]
```

## Description

The `Remove-SddcManagerVspClusterEntry` cmdlet connects to the SDDC Manager appliance via SSH and removes stale platform management cluster records from the internal database. This is required after recovering a management cluster where the original cluster entry is no longer valid. The cmdlet connects as the `vcf` user, elevates to root, and executes the necessary database cleanup commands.

## Examples

### Example 1

```powershell
Remove-SddcManagerVspClusterEntry `
    -sddcManagerFQDN         "sfo-vcf01.sfo.rainpole.io" `
    -sddcManagerRootPassword "VMw@re1!VMw@re1!" `
    -vCenterFQDN             "sfo-m01-vc01.sfo.rainpole.io"
```

## Parameters

### -sddcManagerFQDN

FQDN of the SDDC Manager appliance.

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

### -sddcManagerRootPassword

Root password for the SDDC Manager appliance, used for SSH access and privilege elevation.

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

### -vCenterFQDN

FQDN of the vCenter whose stale cluster entry should be removed from the SDDC Manager database.

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

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
