# Get-SDDCManagerManagementVspClusterId

## Synopsis

Retrieves the id of the MANAGEMENT row from the `vsp_clusters` table in the SDDC Manager Postgres database.

## Syntax

```powershell
Get-SDDCManagerManagementVspClusterId [-sddcManagerFqdn] <String> [-vcfPassword] <String> [-rootPassword] <String> [[-VspClustersTable] <String>] [[-PostgresDatabase] <String>] [<CommonParameters>]
```

## Description

The `Get-SDDCManagerManagementVspClusterId` cmdlet connects to the SDDC Manager appliance via SSH as the `vcf` user, elevates to `root`, then queries the Postgres `platform` database. Equivalent to running:

```sql
SELECT id FROM vsp_clusters WHERE type = 'MANAGEMENT' LIMIT 1;
```

Requires the **Posh-SSH** module.

## Examples

### Example 1

```powershell
Get-SDDCManagerManagementVspClusterId -sddcManagerFqdn "sfo-vcf01.sfo.rainpole.io" -vcfPassword "VMw@re1!" -rootPassword "VMw@re1!"
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

The Postgres table name to query. Defaults to `vsp_clusters`.

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

### -PostgresDatabase

The Postgres database name. Defaults to `platform`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
Default value: platform
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
