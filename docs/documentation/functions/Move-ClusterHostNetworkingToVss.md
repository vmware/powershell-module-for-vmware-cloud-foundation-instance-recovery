# Move-ClusterHostNetworkingToVss

## Synopsis

Moves all ESXi hosts in a cluster from a vSphere Distributed Switch to a vSphere Standard Switch.

## Syntax

```powershell
Move-ClusterHostNetworkingToVss [-vCenterFQDN] <String> [-vCenterAdmin] <String> [-vCenterAdminPassword] <String> [-clusterName] <String> [-vdsName] <String> [-mtu] <String> [-vmnic] <String> [-mgmtVlanId] <String> [-vMotionVlanId] <String> [-vSanVlanId] <String> [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## Description

The `Move-ClusterHostNetworkingToVss` cmdlet moves all ESXi hosts in a cluster from a vSphere Distributed Switch to a vSphere Standard Switch.

## Examples

### Example 1

```powershell
Move-ClusterHostNetworkingToVss -vCenterFQDN "sfo-m01-vc02.sfo.rainpole.io" -vCenterAdmin "administrator@vsphere.local" -vCenterAdminPassword "VMw@re1!" -clusterName "sfo-m01-cl01" -vdsName "sfo-m01-cl01-vds01" -mtu 9000 -vmnic "vmnic1" -mgmtVlanId 1611 -vMotionVlanId 1612 -vSanVlanId 1613
```

## Parameters

### -vCenterFQDN

Fully qualified domain name of the vCenter Server instance hosting the vSphere cluster which should be moved.

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

Admin user for the vCenter Server instance hosting the vSphere cluster which should be moved.

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

Admin password for the vCenter Server instance hosting the vSphere cluster which should be moved.

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

Name of the vSphere cluster instance hosting the virtual machines to be moved.

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

### -vdsName

Name of the vDS from which the ESXi hosts should be moved.

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

### -mtu

MTU to be assigned to the temporary vSphere Standard Switch.

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

### -vmnic

vmnic to be moved from the vSphere Distributed Switch to the vSphere Standard Switch.

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

### -mgmtVlanId

Management network VLAN ID.

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

### -vMotionVlanId

vMotion network VLAN ID.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 9
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -vSanVlanId

vSAN network VLAN ID.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 10
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
