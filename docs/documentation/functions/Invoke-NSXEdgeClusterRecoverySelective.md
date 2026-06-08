# Invoke-NSXEdgeClusterRecoverySelective

## Synopsis

Selectively redeploys missing NSX Edges from the specified vSphere cluster based on operator selection.

## Syntax

```powershell
Invoke-NSXEdgeClusterRecoverySelective [-nsxManagerFqdn] <String> [-nsxManagerAdmin] <String> [-nsxManagerAdminPassword] <String> [-vCenterFQDN] <String> [-vCenterAdmin] <String> [-vCenterAdminPassword] <String> [-clusterName] <String> [-extractedSDDCDataFile] <String> [<CommonParameters>]
```

## Description

The `Invoke-NSXEdgeClusterRecoverySelective` cmdlet discovers all NSX Edges associated with the provided vSphere cluster, compares them against the vCenter VM inventory to determine which Edge VMs are present or missing, and presents the results as a numbered list. The operator enters a comma-separated list of IDs to selectively redeploy only the missing Edges.

## Examples

### Example 1

```powershell
Invoke-NSXEdgeClusterRecoverySelective `
    -nsxManagerFqdn          "sfo-m01-nsx01.sfo.rainpole.io" `
    -nsxManagerAdmin         "admin" `
    -nsxManagerAdminPassword "VMw@re1!VMw@re1!" `
    -vCenterFQDN             "sfo-m01-vc01.sfo.rainpole.io" `
    -vCenterAdmin            "administrator@vsphere.local" `
    -vCenterAdminPassword    "VMw@re1!" `
    -clusterName             "sfo-m01-cl01" `
    -extractedSDDCDataFile   ".\extracted-sddc-data.json"
```

## Parameters

### -nsxManagerFqdn

FQDN of the NSX Manager whose Edges need to be redeployed.

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

### -nsxManagerAdmin

Admin username for the NSX Manager.

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

### -nsxManagerAdminPassword

Admin password for the NSX Manager.

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

### -vCenterFQDN

FQDN of the vCenter instance that hosts the cluster.

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

### -vCenterAdmin

Admin user of the vCenter instance.

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

### -vCenterAdminPassword

Admin password for the vCenter instance.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 6
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -clusterName

Name of the vSphere cluster whose NSX Edges need to be redeployed.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 7
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -extractedSDDCDataFile

Relative or absolute path to the `extracted-sddc-data.json` file previously created by `New-ExtractDataFromSDDCBackup`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 8
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
