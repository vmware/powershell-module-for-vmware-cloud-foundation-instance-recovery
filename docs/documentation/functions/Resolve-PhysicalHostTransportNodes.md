# Resolve-PhysicalHostTransportNodes

## Synopsis

Resolves the state of ESXi Transport Nodes in a restored NSX Manager when the ESXi hosts have been rebuilt.

## Syntax

```powershell
Resolve-PhysicalHostTransportNodes [-vCenterFQDN] <String> [-vCenterAdmin] <String> [-vCenterAdminPassword] <String> [-clusterName] <String> [-nsxManagerFqdn] <String> [-nsxManagerAdmin] <String> [-nsxManagerAdminPassword] <String> [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## Description

The `Resolve-PhysicalHostTransportNodes` cmdlet resolves the state of ESXi Transport Nodes in a restored NSX Manager when the ESXi hosts have been rebuilt.

## Examples

### Example 1

```powershell
Resolve-PhysicalHostTransportNodes -vCenterFQDN "sfo-m01-vc01.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01" -NsxManagerFQDN "sfo-m01-nsx01a.sfo.rainpole.io" -NsxManagerAdmin "admin" -NsxManagerAdminPassword "VMw@re1!VMw@re1!"
```

## Parameters

### -vCenterFQDN

Fully qualified domain name of the vCenter Server instance that hosts the vSphere cluster whose ESXi hosts need to be resolved.

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

Admin user for the vCenter Server instance that hosts the vSphere cluster whose ESXi hosts need to be resolved.

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

Admin password for the vCenter Server instance that hosts the vSphere cluster whose ESXi hosts need to be resolved.

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

Name of the vSphere cluster instance whose ESXi hosts need to be resolved.

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

### -nsxManagerFqdn

Fully qualified domain name of the NSX Manager where hosts need to be resolved.

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

### -nsxManagerAdmin

Admin user for the NSX Manager where hosts need to be resolved.

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

### -nsxManagerAdminPassword

Admin Password of the NSX Manager where hosts need to be resolved.

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
