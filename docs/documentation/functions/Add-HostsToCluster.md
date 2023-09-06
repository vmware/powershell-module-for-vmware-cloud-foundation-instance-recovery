# Add-HostsToCluster

## Synopsis

Adds ESXi hosts to a vSphere cluster using data from the SDDC Manager backup.

## Syntax

```powershell
Add-HostsToCluster [-vCenterFQDN] <String> [-vCenterAdmin] <String> [-vCenterAdminPassword] <String> [-clusterName] <String> [-extractedSDDCDataFile] <String> [-sddcManagerFQDN] <String> [-sddcManagerAdmin] <String> [-sddcManagerAdminPassword] <String> [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## Description

The `Add-HostsToCluster` cmdlet adds ESXi hosts to a vSphere cluster using data from the SDDC Manager backup.

## Examples

### Example 1

```powershell
Add-HostsToCluster -vCenterFQDN "sfo-m01-vc02.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01"  -extractedSDDCDataFile ".\extracted-sddc-data.json" -sddcManagerFQDN "sfo-vcf01.sfo.rainpole.io" -sddcManagerAdmin "administrator@vsphere.local" -sddcManagerAdminPassword "VMw@re1!"
```

## Parameters

### -vCenterFQDN

Fully qualified domain name of the vCenter Server instance hosting the vSphere cluster to which the ESXi hosts will be added.

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

Admin user for the vCenter Server instance hosting the vSphere cluster to which the ESXi hosts will be added.

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

Admin password for the vCenter Server instance hosting the vSphere cluster to which the ESXi hosts will be added.

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

Name of the vSphere cluster instance to which the ESXi hosts will be added.

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

Relative or absolute to the `extracted-sddc-data.json` file (previously created by `New-ExtractDataFromSDDCBackup`) on the local filesystem.

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

### -sddcManagerFQDN

FQDN of SDDC Manager.

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

### -sddcManagerAdmin

SDDC Manager API username with ADMIN role.

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

### -sddcManagerAdminPassword

SDDC Manager API username password.

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

### -ProgressAction

Progress Action.

```yaml
Type: ActionPreference
Parameter Sets: (All)
Aliases: proga

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
