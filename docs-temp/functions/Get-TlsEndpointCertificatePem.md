# Get-TlsEndpointCertificatePem

## Synopsis

Retrieves the leaf TLS certificate from a remote HTTPS endpoint and returns it as a PEM string.

## Syntax

```powershell
Get-TlsEndpointCertificatePem [-hostname] <String> [[-port] <Int32>] [<CommonParameters>]
```

## Description

The `Get-TlsEndpointCertificatePem` cmdlet opens a TLS connection to the specified host and port using `System.Net.Sockets.TcpClient` and `System.Net.Security.SslStream`, retrieves the leaf certificate, and returns it as a PEM-encoded string (`-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----`). No `openssl` binary is required. Equivalent to:

```bash
echo | openssl s_client -connect <host>:<port> 2>/dev/null | openssl x509 -outform pem
```

Typically used before `Add-VCFMSServicesRuntimeTrustedCertificate` to inspect a certificate before trusting it.

## Examples

### Example 1

```powershell
$pem = Get-TlsEndpointCertificatePem -hostname "sfo-ins01.sfo.rainpole.io"
Write-Host $pem
```

## Parameters

### -hostname

The FQDN or IP address of the remote host.

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

### -port

The TCP port. Defaults to `443`.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: 443
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
