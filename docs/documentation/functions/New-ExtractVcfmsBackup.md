# New-ExtractVcfmsBackup

## Synopsis

Extracts YAML configuration files and generates a restore JSON payload from a VCFMS Services Runtime backup.

## Syntax

```powershell
New-ExtractVcfmsBackup [-ServicesRuntimeFqdn] <String> [-ServicesRuntimePassword] <String> [-SftpHost] <String> [-SftpUsername] <String> [-SftpPassword] <String> [[-SftpPort] <String>] [[-Components] <String[]>] [[-ServicesRuntimeUsername] <String>] [[-VspId] <String>] [[-OutputDir] <String>] [<CommonParameters>]
```

## Description

The `New-ExtractVcfmsBackup` cmdlet lists available VCFMS backups, prompts the operator to select a backup point for each component type, downloads the selected backup archives from SFTP, extracts specific YAML configuration files (including `ingress-fleet-tls.yaml` and `ingress-fleet-tls-ndc.yaml`) to the output directory, and writes a `restore-payload.json` file ready for use with `Restore-VcfmsBackup`.

## Examples

### Example 1

Extract backup files using the default component set.

```powershell
New-ExtractVcfmsBackup `
    -ServicesRuntimeFqdn     "sfo-sr01.sfo.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
    -SftpHost                "10.167.173.126" `
    -SftpUsername            "svc-vcf-bck" `
    -SftpPassword            "VMw@re1!" `
    -OutputDir               "C:\vcfms-backup-extract"
```

### Example 2

Extract a specific VSP instance backup.

```powershell
New-ExtractVcfmsBackup `
    -ServicesRuntimeFqdn     "sfo-sr01.sfo.rainpole.io" `
    -ServicesRuntimePassword "VMw@re1!VMw@re1!" `
    -SftpHost                "10.167.173.126" `
    -SftpUsername            "svc-vcf-bck" `
    -SftpPassword            "VMw@re1!" `
    -VspId                   "a1b2c3d4-e5f6-7890-abcd-ef1234567890" `
    -OutputDir               "C:\vcfms-backup-extract"
```

## Parameters

### -ServicesRuntimeFqdn

FQDN of the VCFMS Services Runtime instance.

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

Password for the Services Runtime admin user.

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

### -SftpHost

IP address or FQDN of the SFTP backup server.

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

### -SftpUsername

Username for authenticating to the SFTP server.

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

### -SftpPassword

Password for authenticating to the SFTP server.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 5
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SftpPort

SSH port on the SFTP server. Defaults to `22`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 22
Accept pipeline input: False
Accept wildcard characters: False
```

### -Components

One or more component types to include. Defaults to `vsp`, `vcf-fleet-lcm`, `vcf-fleet-depot`, `vcf-sddc-lcm`, `salt`, `salt-raas`, `vidb`, `ops-logs`, `vcfa`.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: vsp, vcf-fleet-lcm, vcf-fleet-depot, vcf-sddc-lcm, salt, salt-raas, vidb, ops-logs, vcfa
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

### -VspId

When specified, only backups whose path contains `/vcf/backups/<VspId>/` are considered.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -OutputDir

Local directory where extracted YAML files and the restore payload JSON are written. Defaults to the current directory.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: .
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
