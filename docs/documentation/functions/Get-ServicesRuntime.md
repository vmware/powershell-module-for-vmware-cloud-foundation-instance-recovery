# Get-ServicesRuntime

## Synopsis

Retrieves the list of ServicesRuntime instances registered with SDDC Manager.

## Syntax

```powershell
Get-ServicesRuntime [-SddcManagerFqdn] <String> [-SddcManagerUser] <String> [-SddcManagerPassword] <String> [<CommonParameters>]
```

## Description

The `Get-ServicesRuntime` cmdlet calls the SDDC Manager `GET /v1/vsp-clusters` endpoint and returns the registered VCFMS Services Runtime instances. For each instance, a JSON file is written to the current working directory using the short name of `platformFqdn` as the filename (e.g. `lax-sr01.json`). The JSON payload is in the format accepted by `New-ServicesRuntime`; populate `systemUserPassword` in the file before use. CONSUMPTION-type clusters omit `instanceFqdn` and `fleetFqdn`.

## Examples

### Example 1

Retrieve all ServicesRuntime instances and write a JSON file per instance to the current directory.

```powershell
Get-ServicesRuntime -SddcManagerFqdn "sfo-vcf01.sfo.rainpole.io" -SddcManagerUser "administrator@vsphere.local" -SddcManagerPassword "VMw@re1!VMw@re1!"
```

## Parameters

### -SddcManagerFqdn

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

### -SddcManagerUser

API username for SDDC Manager (e.g. `administrator@vsphere.local`).

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

### -SddcManagerPassword

Password for the SDDC Manager API user.

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
