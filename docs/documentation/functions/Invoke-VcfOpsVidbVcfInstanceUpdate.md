# Invoke-VcfOpsVidbVcfInstanceUpdate

## Synopsis

Re-associates an external Identity Broker (VIDB) with a new VCF instance in VCF Operations after a disaster recovery failover.

## Syntax

```powershell
Invoke-VcfOpsVidbVcfInstanceUpdate [-VcfOpsFqdn] <String> [-VcfOpsRootPassword] <String> [-VcfOpsAdminPassword] <String> [-VidbFqdn] <String> [[-VcfOpsAdminUsername] <String>] [[-VcfInstanceId] <String>] [[-SsoDomainId] <String>] [[-RemoteScriptTimeout] <Int32>] [<CommonParameters>]
```

## Description

The `Invoke-VcfOpsVidbVcfInstanceUpdate` cmdlet re-associates an external Identity Broker with a new VCF instance in VCF Operations after a disaster recovery failover. It performs two interactive discovery steps before executing the remediation script:

**Step 3** — Queries the VCF Operations API to list all registered VCF adapter instances and presents a numbered list for operator selection. Skipped when `-VcfInstanceId` is supplied.

**Step 4** — Queries the `kv_vidb_sso_domain` table in the VCF Operations postgres database via SSH and presents a numbered list of stale SSO domain entries for operator selection. Skipped when `-SsoDomainId` is supplied.

The cmdlet then uploads the bundled `update-vidb-vcf-instance.sh` script to the VCF Operations primary node via SSH (as root) and executes it. SSH reachability is verified before attempting a connection. SSH must be enabled on the VCF Operations appliance (`Administration > Support > SSH Service`).

## Examples

### Example 1

Interactive — VCF instance and SSO domain are selected from discovered lists.

```powershell
Invoke-VcfOpsVidbVcfInstanceUpdate `
    -VcfOpsFqdn          "flt-ops01a.rainpole.io" `
    -VcfOpsRootPassword  "VMw@re1!VMw@re1!" `
    -VcfOpsAdminPassword "VMw@re1!VMw@re1!" `
    -VidbFqdn            "flt-idb01.rainpole.io"
```

### Example 2

Non-interactive — VCF instance and SSO domain ID supplied directly.

```powershell
Invoke-VcfOpsVidbVcfInstanceUpdate `
    -VcfOpsFqdn          "flt-ops01a.rainpole.io" `
    -VcfOpsRootPassword  "VMw@re1!VMw@re1!" `
    -VcfOpsAdminPassword "VMw@re1!VMw@re1!" `
    -VidbFqdn            "flt-idb01.rainpole.io" `
    -VcfInstanceId       "e1855511-d704-49ea-8caa-a45895dd0137" `
    -SsoDomainId         "8aa85146-c6ef-4758-9346-4957e4a67dc4"
```

## Parameters

### -VcfOpsFqdn

FQDN of the VCF Operations primary node. SSH is opened to this host as root.

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

### -VcfOpsRootPassword

Root password for SSH access to the VCF Operations primary node.

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

### -VcfOpsAdminPassword

Password for the VCF Operations admin user. Used to acquire an API token for discovery queries and passed to the remote script.

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

### -VidbFqdn

FQDN of the external Identity Broker (VIDB), e.g. `flt-idb01.rainpole.io`.

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

### -VcfOpsAdminUsername

Username for the VCF Operations API. Defaults to `admin`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: admin
Accept pipeline input: False
Accept wildcard characters: False
```

### -VcfInstanceId

Optional. UUID of the new VCF instance to associate with the Identity Broker. When omitted the function queries the VCF Operations API and presents a numbered list for selection.

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

### -SsoDomainId

Optional. UUID key to remove from the `kv_vidb_sso_domain` table. When omitted the function queries the postgres database and presents a numbered list. Enter `S` at the prompt to skip cleanup.

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

### -RemoteScriptTimeout

Seconds to wait for the remote script to complete. Defaults to `1500` (25 minutes), accommodating the built-in 20-minute VIDB eligibility poll.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 1500
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
