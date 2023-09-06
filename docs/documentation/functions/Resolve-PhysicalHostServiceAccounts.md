# Resolve-PhysicalHostServiceAccounts

## Synopsis

Creates a new VCF Service Account on each ESXi host and remediates the SDDC Manager inventory.

## Syntax

```powershell
Resolve-PhysicalHostServiceAccounts [-vCenterFQDN] <String> [-vCenterAdmin] <String> [-vCenterAdminPassword] <String> [-clusterName] <String> [-svcAccountPassword] <String> [-sddcManagerFQDN] <String> [-sddcManagerAdmin] <String> [-sddcManagerAdminPassword] <String> [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## Description

The `Resolve-PhysicalHostServiceAccounts` cmdlet creates a new VCF Service Account on each ESXi host and remediates the SDDC Manager inventory.

## Examples

### Example 1

```powershell
Resolve-PhysicalHostServiceAccounts -vCenterFQDN "sfo-w01-vc01.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -clusterName "sfo-w01-cl01" -svcAccountPassword "VMw@re123!" -sddcManagerFQDN "sfo-vcf01.sfo.rainpole.io" -sddcManagerAdmin "administrator@vsphere.local" -sddcManagerAdminPassword "VMw@re1!"
```

## Parameters

### -vCenterFQDN

Fully qualified domain name of the vCenter Server instance hosting the ESXi hosts to be updated.

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

Admin user for the vCenter Server instance hosting the ESXi hosts to be updated.

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

Admin password for the vCenter Server instance hosting the ESXi hosts to be updated.

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

Name of the vSphere cluster instance hosting the ESXi hosts to be updated.

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

### -svcAccountPassword

Service account password to be used.

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
