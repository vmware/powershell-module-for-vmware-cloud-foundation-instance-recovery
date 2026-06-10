# Invoke-SddcManagerBundleDownload

## Synopsis

Downloads VCF bundles from the configured depot on a SDDC Manager appliance via SSH.

## Syntax

```powershell
Invoke-SddcManagerBundleDownload [-sddcManagerFqdn] <String> [-vcfUserPassword] <String> [-rootPassword] <String> [-adminPassword] <String> [-VcfVersion] <String> [-WaitForCompletion] [<CommonParameters>]
```

## Description

The `Invoke-SddcManagerBundleDownload` cmdlet generates and executes a bash script on the SDDC Manager appliance via SSH that retrieves the bundle IDs for the specified VCF version from the depot API and triggers a download for each bundle. When `-WaitForCompletion` is specified the script polls until all bundles have reached a downloaded state.

## Examples

### Example 1

Trigger bundle downloads without waiting.

```powershell
Invoke-SddcManagerBundleDownload `
    -sddcManagerFqdn "sfo-vcf01.sfo.rainpole.io" `
    -vcfUserPassword "VMw@re1!VMw@re1!" `
    -rootPassword    "VMw@re1!VMw@re1!" `
    -adminPassword   "VMw@re1!VMw@re1!" `
    -VcfVersion      "9.1.0.0"
```

### Example 2

Trigger bundle downloads and wait for all to complete.

```powershell
Invoke-SddcManagerBundleDownload `
    -sddcManagerFqdn    "sfo-vcf01.sfo.rainpole.io" `
    -vcfUserPassword    "VMw@re1!VMw@re1!" `
    -rootPassword       "VMw@re1!VMw@re1!" `
    -adminPassword      "VMw@re1!VMw@re1!" `
    -VcfVersion         "9.1.0.0" `
    -WaitForCompletion
```

## Parameters

### -sddcManagerFqdn

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

### -vcfUserPassword

SSH password for the `vcf` user on the SDDC Manager appliance.

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

### -rootPassword

Root password for the SDDC Manager appliance, used for privilege elevation.

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

### -adminPassword

Password for the `admin@local` API user on SDDC Manager, used for token acquisition inside the generated script.

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

### -VcfVersion

The VCF version to download bundles for (e.g. `"9.1.0.0"`).

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

### -WaitForCompletion

When specified, the generated script polls until all triggered bundle downloads have completed before exiting.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
