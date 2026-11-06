# Add-OfflineDepotTrustedCertificate

## Synopsis

Trusts the TLS certificate presented by an offline depot on the Windows machine running the Recovery Coordinator.

## Syntax

```powershell
Add-OfflineDepotTrustedCertificate [-offlineDepotFqdn] <String> [[-offlineDepotPort] <Int32>] [<CommonParameters>]
```

## Description

The `Add-OfflineDepotTrustedCertificate` cmdlet connects to the offline depot, captures the certificate chain it presents, and imports each certificate into the local machine's Trusted Root Certification Authorities store (`Cert:\LocalMachine\Root`), so that subsequent HTTPS requests from this machine to the depot validate without certificate errors. Certificates already present in the store (matched by thumbprint) are skipped.

The cmdlet must be run from an elevated session on Windows.

## Examples

### Example 1

```powershell
Add-OfflineDepotTrustedCertificate -offlineDepotFqdn "depot.rainpole.io" -offlineDepotPort 443
```

## Parameters

### -offlineDepotFqdn

FQDN of the offline depot whose certificate should be trusted.

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

### -offlineDepotPort

HTTPS port of the offline depot.

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
