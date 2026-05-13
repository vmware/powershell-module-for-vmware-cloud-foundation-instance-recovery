# Get-VCFMSServicesRuntimeAccessToken

## Synopsis

Obtains a bearer access token from a VCFMS Services Runtime node.

## Syntax

```powershell
Get-VcfmsServicesRuntimeToken [-ServicesRuntimeFqdn] <String> [-Password] <String> [[-Username] <String>] [<CommonParameters>]
```

## Description

The `Get-VcfmsServicesRuntimeToken` cmdlet authenticates against the VCFMS Services Runtime identity API (`POST /api/v1/identity/token`) using an OAuth2 password grant with a form-encoded body. The response field `access_token` is returned as a string. This differs from the SDDC Manager token flow which uses a JSON body and returns `accessToken`.

## Examples

### Example 1

```powershell
$token = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -Password "VMw@re1!VMw@re1!"
```

### Example 2

Specify an alternate username.

```powershell
$token = Get-VcfmsServicesRuntimeToken -ServicesRuntimeFqdn "sfo-sr01.sfo.rainpole.io" -Username "admin@vsp.local" -Password "VMw@re1!VMw@re1!"
```

## Parameters

### -ServicesRuntimeFqdn

The fully qualified domain name of the VCFMS Services Runtime instance.

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

### -Password

The password for the Services Runtime identity account.

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

### -Username

The Services Runtime identity username. Defaults to `admin@vsp.local`.

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
