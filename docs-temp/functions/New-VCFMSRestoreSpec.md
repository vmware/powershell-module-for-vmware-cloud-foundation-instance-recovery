# New-VCFMSRestoreSpec

## Synopsis

Interactively builds a restore component spec from the output of `Get-VCFMSServicesRuntimeBackups`.

## Syntax

```powershell
New-VCFMSRestoreSpec [-backups] <PSCustomObject[]> [[-Components] <String[]>] [-AsJson] [<CommonParameters>]
```

## Description

The `New-VCFMSRestoreSpec` cmdlet presents the available backups for each component type one at a time and prompts the user to select which backup point to restore. Returns an array of `@{ path = "sftp://..."; point = "..." }` hashtables suitable for passing directly to `Invoke-VCFMSServicesRuntimeRestore` via `-RestoreComponents`. Use `-AsJson` to return a serialised JSON string for review or scripted use.

Components are processed in the order supplied (defaults to canonical order as returned by `Get-VCFMSServicesRuntimeBackups`). Any component can be skipped by entering `S` at the prompt.

## Examples

### Example 1

Build spec interactively then restore.

```powershell
$backups = Get-VCFMSServicesRuntimeBackups -vcfmsSrFqdn "sfo-sr01.sfo.rainpole.io" -srPassword "VMw@re1!VMw@re1!" -PassThru
$spec    = New-VCFMSRestoreSpec -backups $backups
Invoke-VCFMSServicesRuntimeRestore -vcfmsSrFqdn "sfo-sr01.sfo.rainpole.io" -srPassword "VMw@re1!VMw@re1!" -RestoreComponents $spec -Confirm:$false
```

### Example 2

Inspect the JSON before submitting.

```powershell
$json = New-VCFMSRestoreSpec -backups $backups -AsJson
Write-Host $json
```

## Parameters

### -backups

The `PSCustomObject` array returned by `Get-VCFMSServicesRuntimeBackups -PassThru`.

```yaml
Type: PSCustomObject[]
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Components

Component types to include in the restore. Defaults to all types present in `-backups` in order of first appearance. Valid values: `vsp`, `vcf-fleet-lcm`, `vcf-fleet-depot`, `vcf-sddc-lcm`, `salt`, `salt-raas`, `vidb`, `ops-logs`.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AsJson

When set, returns the restore spec as a serialised JSON string instead of an object array.

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
