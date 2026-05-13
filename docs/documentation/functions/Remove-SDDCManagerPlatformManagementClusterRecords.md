# Remove-SDDCManagerPlatformManagementClusterRecords

## Synopsis

Removes the MANAGEMENT cluster row and its associated credential from the SDDC Manager Postgres database.

## Syntax

```powershell
Remove-SDDCManagerPlatformManagementClusterRecords [-sddcManagerFqdn] <String> [-vcfPassword] <String> [-rootPassword] <String> [[-VspClustersTable] <String>] [[-CredentialTable] <String>] [[-PostgresDatabase] <String>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## Description

The `Remove-SDDCManagerPlatformManagementClusterRecords` cmdlet connects to the SDDC Manager appliance via SSH as the `vcf` user, elevates to `root`, and runs the following sequence against the Postgres `platform` database:

1. Retrieves the `id` of the MANAGEMENT row from `vsp_clusters`.
2. Deletes the MANAGEMENT row: `DELETE FROM vsp_clusters WHERE type = 'MANAGEMENT'`.
3. Deletes the associated credential: `DELETE FROM credential WHERE username = 'vsp/<id>/svc-sddc-manager-admin'`.

This operation is required during a VCFMS instance recovery workflow before redeploying a new runtime. Supports `-WhatIf` and prompts for confirmation by default due to its high impact. Requires the **Posh-SSH** module.

## Examples

### Example 1

```powershell
Remove-SDDCManagerPlatformManagementClusterRecords -sddcManagerFqdn "sfo-vcf01.sfo.rainpole.io" -vcfPassword "VMw@re1!" -rootPassword "VMw@re1!" -Confirm:$false
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

### -vcfPassword

Password for the `vcf` SSH user on the SDDC Manager appliance.

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

Password for the `root` user on the SDDC Manager appliance.

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

### -VspClustersTable

Postgres table name for the cluster records. Defaults to `vsp_clusters`. Pass `vsp_cluster` if your environment uses the singular form.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: vsp_clusters
Accept pipeline input: False
Accept wildcard characters: False
```

### -CredentialTable

Postgres table name for the credential records. Defaults to `credential`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
Default value: credential
Accept pipeline input: False
Accept wildcard characters: False
```

### -PostgresDatabase

The Postgres database name. Defaults to `platform`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 6
Default value: platform
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
