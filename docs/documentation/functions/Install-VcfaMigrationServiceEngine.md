# Install-VcfaMigrationServiceEngine

## Synopsis

Stages and installs the Migration Service Engine component on a VCF Automation Services Runtime cluster.

## Syntax

```powershell
Install-VcfaMigrationServiceEngine [-VcfaServiceRuntimeFqdn] <String> [-VcfaServiceRuntimePassword] <String> [-RepositoryUrl] <String> [[-VcfaServiceRuntimeUsername] <String>] [[-Version] <String>] [[-InstallSize] <String>] [[-StagePollIntervalSeconds] <Int32>] [[-InstallPollIntervalSeconds] <Int32>] [<CommonParameters>]
```

## Description

The `Install-VcfaMigrationServiceEngine` cmdlet stages and installs the Migration Service Engine on a VCF Automation Services Runtime cluster. The Migration Service Engine is not captured in VCF Automation backups and must be reinstalled after a restore.

The cmdlet performs three steps:
1. Acquires an access token from the VCF Automation Services Runtime API.
2. Stages the `migration-service` binary via `POST /api/v1/components?action=stage` using the supplied offline depot manifest URL, then polls the stage task to completion.
3. Installs the `migration-service` component via `POST /api/v1/components?action=install`, then polls the install task to completion.

## Examples

### Example 1

Stage and install using the default version.

```powershell
Install-VcfaMigrationServiceEngine `
    -VcfaServiceRuntimeFqdn     "flt-vcfa-sr01.rainpole.io" `
    -VcfaServiceRuntimePassword "VMw@re1!VMw@re1!" `
    -RepositoryUrl              "https://depot.rainpole.io/package-pool/depot-manifest-migration-service-9.1.0.0.25370929.yaml"
```

### Example 2

Supply a specific version and offline depot manifest URL.

```powershell
Install-VcfaMigrationServiceEngine `
    -VcfaServiceRuntimeFqdn     "flt-vcfa-sr01.rainpole.io" `
    -VcfaServiceRuntimePassword "VMw@re1!VMw@re1!" `
    -Version                    "9.1.0.0.25370929" `
    -RepositoryUrl              "https://depot.rainpole.io/package-pool/depot-manifest-migration-service-9.1.0.0.25370929.yaml"
```

## Parameters

### -VcfaServiceRuntimeFqdn

FQDN of the VCF Automation Services Runtime cluster.

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

### -VcfaServiceRuntimePassword

Password for the VCF Automation Services Runtime admin user.

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

### -RepositoryUrl

URL to the depot manifest YAML for the migration-service version being staged. Must point to an accessible offline or internal depot. No default value — this parameter is always required.

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

### -VcfaServiceRuntimeUsername

Username for the token request. Defaults to `admin@vsp.local`.

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

### -Version

Version string for the migration-service component to stage and install. Defaults to `9.1.0.0.25370929`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 9.1.0.0.25370929
Accept pipeline input: False
Accept wildcard characters: False
```

### -InstallSize

Deployment size for the Migration Service Engine. Defaults to `small`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: small
Accept pipeline input: False
Accept wildcard characters: False
```

### -StagePollIntervalSeconds

Interval in seconds between task status polls during the stage operation. Defaults to `30`.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 30
Accept pipeline input: False
Accept wildcard characters: False
```

### -InstallPollIntervalSeconds

Interval in seconds between task status polls during the install operation. Defaults to `30`.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 30
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
