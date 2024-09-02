# New-RebuiltVdsConfiguration

## Synopsis

Guides the rebuild of the VDS configuration on a recovered cluster based on the configuration present in the backup data.

## Syntax

```powershell
New-RebuiltVdsConfiguration [-vCenterFQDN] <String> [-vCenterAdmin] <String> [-vCenterAdminPassword] <String> [-clusterName] <String> [-extractedSDDCDataFile] <String> [<CommonParameters>]
```

## Description

The New-RebuiltVdsConfiguration cmdlet guides the rebuild of the VDS configuration on a recovered cluster based on the configuration present in the backup data. It leverage the first host in the cluster as a reference host for NIC layout to allow the user to choose the NIC to VDS/Function mapping. Should only be used if the NIC configuration is standardized across the hosts

## Examples

### Example 1

```powershell
New-RebuiltVdsConfiguration -vCenterFQDN "sfo-m01-vc01.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01" -extractedSDDCDataFile ".\extracted-sddc-data.json"
```

## Parameters

### -vCenterFQDN

FQDN of the vCenter instance hosting the cluster where the VDS will be rebuilt.

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

Admin user of the vCenter instance hosting the cluster where the VDS will be rebuilt.

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

Admin password for the vCenter instance hosting the cluster where the VDS will be rebuilt.

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

Name of the vSphere cluster instance where the VDS will be rebuilt.

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

Relative or absolute to the extracted-sddc-data.json file (previously created by New-ExtractDataFromSDDCBackup) somewhere on the local filesystem.

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
