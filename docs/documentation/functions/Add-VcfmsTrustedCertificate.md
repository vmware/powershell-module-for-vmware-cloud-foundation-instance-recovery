# Add-VcfmsTrustedCertificate

## Synopsis

Retrieves the TLS certificate from a remote host and adds it as a trusted certificate on a VCFMS Services Runtime instance.

## Syntax

```powershell
Add-VcfmsTrustedCertificate [-ServicesRuntimeFqdn] <String> [-ServicesRuntimePassword] <String> [-RemoteHostFqdn] <String> [[-ServicesRuntimeUsername] <String>] [[-RemoteHostPort] <Int32>] [[-PollIntervalSeconds] <Int32>] [<CommonParameters>]
```

## Description

The `Add-VcfmsTrustedCertificate` cmdlet connects to the specified remote host over TLS to retrieve its certificate in PEM format, then adds it as a trusted certificate on the VCFMS Services Runtime via `POST /api/v1/system/trusted-certificates?action=add`. A Services Runtime token is obtained automatically.

## Examples

### Example 1

Trust the certificate from a remote host using the default port.

```powershell
Add-VcfmsTrustedCertificate `
    -ServicesRuntimeFqdn     "sfo-sr01.sfo.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
    -RemoteHostFqdn          "sfo-ins01.sfo.rainpole.io"
```

### Example 2

Trust the certificate from a remote host on a custom port.

```powershell
Add-VcfmsTrustedCertificate `
    -ServicesRuntimeFqdn     "sfo-sr01.sfo.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
    -RemoteHostFqdn          "sfo-ins01.sfo.rainpole.io" `
    -RemoteHostPort          8443
```

## Parameters

### -ServicesRuntimeFqdn

FQDN of the VCFMS Services Runtime instance to add the trusted certificate to.

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

Password for the Services Runtime admin user (used to obtain a token).

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

### -RemoteHostFqdn

FQDN of the remote host whose TLS certificate should be retrieved and trusted.

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

### -ServicesRuntimeUsername

Username for the Services Runtime token request. Defaults to `admin@vsp.local`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: admin@vsp.local
Accept pipeline input: False
Accept wildcard characters: False
```

### -RemoteHostPort

HTTPS port to connect to on the remote host. Defaults to `443`.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 443
Accept pipeline input: False
Accept wildcard characters: False
```

### -PollIntervalSeconds

Interval in seconds to poll the trust task status. Defaults to `10`.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 10
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
