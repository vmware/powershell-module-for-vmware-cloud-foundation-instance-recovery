# Set-SDDCManagerFDSDepot

## Synopsis

Restores the SDDC Manager depot configuration to the original Fleet Depot Service (FDS) settings from a saved JSON file.

## Syntax

```powershell
Set-SDDCManagerFDSDepot [-sddcManagerFqdn] <String> [-sddcManagerUser] <String> [-sddcManagerPassword] <String> [-originalConfigurationFile] <String> [<CommonParameters>]
```

## Description

The `Set-SDDCManagerFDSDepot` cmdlet reverts the SDDC Manager depot from an offline depot back to the original Fleet Depot Service configuration. It reads the saved depot services configuration from a JSON file (previously captured by `Set-SDDCManagerOfflineDepot`), deletes the current depot configuration via the SDDC Manager API, and reinstates the original services configuration.

## Examples

### Example 1

```powershell
Set-SDDCManagerFDSDepot `
    -sddcManagerFqdn           "sfo-vcf01.sfo.rainpole.io" `
    -sddcManagerUser           "administrator@vsphere.local" `
    -sddcManagerPassword       "VMw@re1!VMw@re1!" `
    -originalConfigurationFile ".\originalDepotServicesconfig.json"
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

Password for the SDDC Manager admin user.

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

### -originalConfigurationFile

Path to the JSON file containing the original depot services configuration, as saved by `Set-SDDCManagerOfflineDepot`.

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

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
