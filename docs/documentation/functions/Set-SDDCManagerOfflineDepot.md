# Set-SDDCManagerOfflineDepot

## Synopsis

Configures SDDC Manager to use an offline depot for VCF bundle downloads.

## Syntax

```powershell
Set-SDDCManagerOfflineDepot [-sddcManagerFqdn] <String> [-sddcManagerUser] <String> [-sddcManagerPassword] <String> [-offlineDepotFqdn] <String> [-offlineDepotPort] <Int32> [-offlineDepotUsername] <String> [-offlineDepotPassword] <String> [<CommonParameters>]
```

## Description

The `Set-SDDCManagerOfflineDepot` cmdlet reconfigures the SDDC Manager depot to use an offline (air-gapped) depot. It removes the existing depot services configuration, trusts the offline depot's TLS certificate on the SDDC Manager appliance via SSH, and then applies the new offline depot configuration via the SDDC Manager API.

The original depot configuration is saved to `originalDepotServicesconfig.json` in the current directory before any changes are made. Use `Set-SDDCManagerFDSDepot` to revert to the original configuration.

## Examples

### Example 1

```powershell
Set-SDDCManagerOfflineDepot `
    -sddcManagerFqdn     "sfo-vcf01.sfo.rainpole.io" `
    -sddcManagerUser     "administrator@vsphere.local" `
    -sddcManagerPassword "VMw@re1!VMw@re1!" `
    -offlineDepotFqdn    "depot.rainpole.io" `
    -offlineDepotPort    443 `
    -offlineDepotUsername "svc-depot" `
    -offlineDepotPassword "VMw@re1!"
```

## Parameters

### -sddcManagerFqdn

FQDN of the SDDC Manager instance.

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

### -sddcManagerUser

Admin username for SDDC Manager.

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

### -sddcManagerPassword

Password for the SDDC Manager admin user. Also used for SSH access and root elevation on the appliance.

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

### -offlineDepotFqdn

FQDN of the offline depot server.

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

### -offlineDepotPort

HTTPS port of the offline depot server.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: True
Position: 5
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -offlineDepotUsername

Username for authenticating to the offline depot.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 6
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -offlineDepotPassword

Password for authenticating to the offline depot.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 7
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
