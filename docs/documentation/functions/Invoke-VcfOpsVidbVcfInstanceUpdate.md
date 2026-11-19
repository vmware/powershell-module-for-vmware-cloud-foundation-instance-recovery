# Invoke-VcfOpsVidbVcfInstanceUpdate

## Synopsis

Re-associates an external Identity Broker (VIDB) with a new VCF instance in VCF Operations after a disaster recovery failover.

## Syntax

```powershell
Invoke-VcfOpsVidbVcfInstanceUpdate -VcfOpsFqdn <String> -VcfOpsRootPassword <String>
    -VcfOpsAdminPassword <String> [-VcfOpsAdminUsername <String>] [-VidbFqdn <String>]
    [-opsRegisteredComponentsFile <String>] [-ServicesRuntimeFqdn <String>]
    [-SddcManagerUser <String>] [-SddcManagerPassword <String>] [-IdentityBrokerTenant <String>]
    [-VcfInstanceId <String>] [-SsoRealmId <String>] [-RemoteScriptTimeout <Int32>] [<CommonParameters>]
```

## Description

The cmdlet reads the Identity Broker FQDN and the target Services Runtime's SDDC Manager FQDN from `VCFOps-Registered-Component-Details.json`. It queries SDDC Manager for the management domain vCenter FQDN using [Get Domains](https://developer.broadcom.com/xapis/sddc-manager-api/latest/v1/domains/get/).

The cmdlet queries `/suite-api/internal/vidb/vidbs` on VCF Operations. The management vCenter record supplies `vcfInstanceId`, and the Identity Broker record supplies `ssoDomainId`. The lookup must return a single matching record with the required ID for each value being discovered.

The cmdlet uploads and runs `migrate-vidb-vcf-instance.sh` on the VCF Operations primary node over SSH as root. Enable SSH on the appliance under **Administration > Support > SSH Service** before running the cmdlet.

## Examples

### Example 1

Discover the VCF instance and SSO Realm IDs automatically.

```powershell
Invoke-VcfOpsVidbVcfInstanceUpdate `
    -VcfOpsFqdn          "flt-ops01a.rainpole.io" `
    -VcfOpsRootPassword  "VMw@re1!VMw@re1!" `
    -VcfOpsAdminPassword "VMw@re1!VMw@re1!" `
    -opsRegisteredComponentsFile ".\VCFOps-Registered-Component-Details.json" `
    -ServicesRuntimeFqdn "lax-sr01.lax.rainpole.io" `
    -SddcManagerUser     $sddcManagerAdmin `
    -SddcManagerPassword $sddcManagerAdminPassword
```

### Example 2

Supply the VCF instance and SSO Realm IDs directly.

```powershell
Invoke-VcfOpsVidbVcfInstanceUpdate `
    -VcfOpsFqdn          "flt-ops01a.rainpole.io" `
    -VcfOpsRootPassword  "VMw@re1!VMw@re1!" `
    -VcfOpsAdminPassword "VMw@re1!VMw@re1!" `
    -VidbFqdn            "flt-idb01.rainpole.io" `
    -VcfInstanceId       "e1855511-d704-49ea-8caa-a45895dd0137" `
    -SsoRealmId         "8aa85146-c6ef-4758-9346-4957e4a67dc4"
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

FQDN of the external Identity Broker (VIDB). Defaults to the VIDB entry in the registered components file.

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

### -opsRegisteredComponentsFile

Path to the JSON file produced by `Get-VcfOperationsRegisteredComponents`. The cmdlet uses it to discover the Identity Broker FQDN and the SDDC Manager for the target Services Runtime.

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

### -ServicesRuntimeFqdn

FQDN of the target VCF Management Services Runtime. Required for automatic VCF instance ID discovery.

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

### -SddcManagerUser

SDDC Manager API username. Required for automatic VCF instance ID discovery.

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

### -SddcManagerPassword

SDDC Manager API password. Required for automatic VCF instance ID discovery.

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

### -IdentityBrokerTenant

Tenant path segment for an optional Identity Broker OIDC discovery endpoint reachability check.

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

### -VcfInstanceId

Optional override for the UUID of the target VCF instance. By default, the cmdlet looks up the UUID using the management domain vCenter FQDN.

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

### -SsoRealmId

Optional override for the SSO Realm UUID. By default, the cmdlet uses the `ssoDomainId` associated with the Identity Broker FQDN.

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
