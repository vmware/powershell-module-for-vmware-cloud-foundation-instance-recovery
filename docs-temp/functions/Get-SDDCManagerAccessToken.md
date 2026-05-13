# Get-SDDCManagerAccessToken

## Synopsis

Obtains a bearer access token from SDDC Manager.

## Syntax

```powershell
Get-SDDCManagerAccessToken [-sddcManagerFqdn] <String> [-username] <String> [-password] <String> [<CommonParameters>]
```

## Description

The `Get-SDDCManagerAccessToken` cmdlet authenticates against the SDDC Manager API (`POST /v1/tokens`) and returns the raw bearer token string. The token is used by other functions in this module to construct authorization headers.

## Examples

### Example 1

```powershell
Get-SDDCManagerAccessToken -sddcManagerFqdn "sfo-vcf01.sfo.rainpole.io" -username "admin@local" -password "VMw@re1!"
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

The username to authenticate with (e.g. `admin@local`).

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

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
