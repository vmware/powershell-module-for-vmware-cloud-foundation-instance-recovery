# Set-ManagementDatastorePolicy

## Synopsis

Sets the default storage policy on the vSAN datastore and applies it to all VMs in the management cluster.

## Syntax

```powershell
Set-ManagementDatastorePolicy [-vCenterFQDN] <String> [-vCenterAdmin] <String> [-vCenterAdminPassword] <String> [-clusterName] <String> [-extractedSDDCDataFile] <String> [<CommonParameters>]
```

## Description

The `Set-ManagementDatastorePolicy` cmdlet retrieves the primary datastore storage policy from the extracted SDDC data and applies it as the default policy on the vSAN datastore for the specified cluster. It also applies the policy to all VMs on the cluster (excluding vCLS VMs) to ensure storage policy compliance. Requires that `Update-ExtractedSDDCData` has been run to populate the `primaryDatastorePolicy` field in the extracted data.

## Examples

### Example 1

```powershell
Set-ManagementDatastorePolicy `
    -vCenterFQDN           "sfo-m01-vc01.sfo.rainpole.io" `
    -vCenterAdmin          "administrator@vsphere.local" `
    -vCenterAdminPassword  "VMw@re1!" `
    -clusterName           "sfo-m01-cl01" `
    -extractedSDDCDataFile ".\extracted-sddc-data.json"
```

## Parameters

### -vCenterFQDN

FQDN of the vCenter instance hosting the cluster.

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

### -vCenterAdmin

Admin user of the vCenter instance.

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

### -vCenterAdminPassword

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

Name of the vSphere cluster whose vSAN datastore policy will be set.

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
