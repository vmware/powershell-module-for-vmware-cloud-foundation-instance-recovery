# Get-VCFMSFleetControllerAccessToken

## Synopsis

Obtains a bearer access token from a VCFMS Fleet Controller node.

## Syntax

```powershell
Get-VCFMSFleetControllerAccessToken [-vcfmsFcFqdn] <String> [-password] <String> [[-username] <String>] [<CommonParameters>]
```

## Description

The `Get-VCFMSFleetControllerAccessToken` cmdlet authenticates against the Fleet Controller identity API (`POST /api/v1/identity/token`) using the same OAuth2 password-grant / form-encoded flow as `Get-VCFMSServicesRuntimeAccessToken`, but targets the Fleet Controller host. The FC token is required for fleet-lcm API calls such as `GET /fleet-lcm/v1/components`.

## Examples

### Example 1

```powershell
$token = Get-VCFMSFleetControllerAccessToken -vcfmsFcFqdn "flt-fc01.rainpole.io" -password "VMw@re1!VMw@re1!"
```

## Parameters

### -vcfmsFcFqdn

The fully qualified domain name of the VCFMS Fleet Controller (fc) node.

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

### -password

The password for the FC identity account.

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

### -username

The FC identity username. Defaults to `admin@vsp.local`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: admin@vsp.local
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
