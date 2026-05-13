# Add-VCFMSServicesRuntimeTrustedCertificate

## Synopsis

Retrieves the TLS certificate from a remote host and adds it to the VCFMS Services Runtime trust store.

## Syntax

```powershell
Add-VcfmsTrustedCertificate [-ServicesRuntimeFqdn] <String> [-ServicesRuntimePassword] <String> [-RemoteHostFqdn] <String> [[-RemoteHostPort] <Int32>] [[-ServicesRuntimeUsername] <String>] [[-PollIntervalSeconds] <Int32>] [<CommonParameters>]
```

## Description

The `Add-VcfmsTrustedCertificate` cmdlet connects to the specified remote host to retrieve its TLS certificate in PEM format, then adds it as a trusted certificate on the VCFMS Services Runtime via `POST /api/v1/system/trusted-certificates?action=add`. A Services Runtime token is obtained automatically using `Get-VcfmsServicesRuntimeToken`. Equivalent to the two-step curl pattern:

```bash
echo | openssl s_client -connect <host>:443 2>/dev/null | openssl x509 -outform pem > cert.pem
jq -n --arg cert "$CERT_DATA" '{cert: $cert}' | curl -k -X POST "https://<sr>/api/v1/system/trusted-certificates?action=add" ...
```

Typically used to trust the VCF Installer certificate on a newly deployed VCFMS instance.

## Examples

### Example 1

Trust the VCF Installer certificate automatically.

```powershell
Add-VcfmsTrustedCertificate `
    -ServicesRuntimeFqdn     "sfo-sr01.sfo.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
    -RemoteHostFqdn          "sfo-ins01.sfo.rainpole.io"
```

### Example 2

Trust a certificate on a non-standard port.

```powershell
Add-VcfmsTrustedCertificate `
    -ServicesRuntimeFqdn     "sfo-sr01.sfo.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
    -RemoteHostFqdn          "sfo-ins01.sfo.rainpole.io" `
    -RemoteHostPort          8443
```

## Parameters

### -ServicesRuntimeFqdn

The fully qualified domain name of the VCFMS Services Runtime instance to add the trusted certificate to.

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

The password for the Services Runtime admin user (used to obtain a token).

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

The FQDN or IP address of the host whose TLS certificate should be retrieved and trusted (e.g. the VCF Installer).

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

### -RemoteHostPort

The TCP port to connect to on the remote host. Defaults to `443`.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: 443
Accept pipeline input: False
Accept wildcard characters: False
```

### -ServicesRuntimeUsername

The Services Runtime identity username. Defaults to `admin@vsp.local`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
Default value: admin@vsp.local
Accept pipeline input: False
Accept wildcard characters: False
```

### -PollIntervalSeconds

Interval in seconds to poll the trust certificate task status. Defaults to `10`.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 6
Default value: 10
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
