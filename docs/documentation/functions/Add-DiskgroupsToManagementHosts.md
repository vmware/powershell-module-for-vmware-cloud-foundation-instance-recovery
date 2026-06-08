# Add-DiskgroupsToManagementHosts

## Synopsis

Expands a single-host vSAN OSA datastore to the remaining hosts in the management cluster by replicating the disk group configuration from the first host.

## Syntax

```powershell
Add-DiskgroupsToManagementHosts [-targetFQDN] <String> [-targetAdmin] <String> [-targetAdminPassword] <String> [-clusterName] <String> [-extractedSDDCDataFile] <String> [<CommonParameters>]
```

## Description

The `Add-DiskgroupsToManagementHosts` cmdlet reads the existing vSAN OSA disk group configuration from the first host in the cluster (previously configured by `New-SingleHostVsanDatastore`) and uses it as a reference to create matching disk groups on all remaining hosts that do not yet have disk groups. Disk matching across hosts is performed positionally by runtime name sort order, which assumes a standardised disk layout across all hosts. Not suitable for vSAN ESA clusters.

## Examples

### Example 1

```powershell
Add-DiskgroupsToManagementHosts `
    -targetFQDN           "sfo-m01-vc01.sfo.rainpole.io" `
    -targetAdmin          "administrator@vsphere.local" `
    -targetAdminPassword  "VMw@re1!" `
    -clusterName          "sfo-m01-cl01" `
    -extractedSDDCDataFile ".\extracted-sddc-data.json"
```

## Parameters

### -targetFQDN

FQDN of the vCenter instance hosting the cluster where the vSAN datastore will be expanded.

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

### -targetAdmin

Admin user of the vCenter instance hosting the cluster.

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

### -targetAdminPassword

Admin password for the vCenter instance.

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

### -clusterName

Name of the vSphere cluster where the vSAN datastore will be expanded.

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

### -extractedSDDCDataFile

Relative or absolute path to the `extracted-sddc-data.json` file previously created by `New-ExtractDataFromSDDCBackup`.

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

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
