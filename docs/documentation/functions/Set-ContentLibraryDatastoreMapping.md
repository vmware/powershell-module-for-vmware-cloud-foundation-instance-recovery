# Set-ContentLibraryDatastoreMapping

## Synopsis

Updates the backing datastore for a vCenter Content Library after a recovery where the datastore name or URI has changed.

## Syntax

```powershell
Set-ContentLibraryDatastoreMapping [-vCenterFQDN] <String> [-vCenterAdmin] <String> [-vCenterAdminPassword] <String> [-vCenterRootPassword] <String> [-contentLibraryName] <String> [-datastoreName] <String> [<CommonParameters>]
```

## Description

The `Set-ContentLibraryDatastoreMapping` cmdlet connects to a vCenter appliance via SSH as root and updates the `storageuri` value in the `cl_storage` table of the Content Library postgres database (`vcdb`) to reflect the new datastore backing. It resolves the correct storage URI by querying the vCenter API for the target datastore, updates the database record for the specified content library, verifies the change, and then restarts the Content Library service.

## Examples

### Example 1

```powershell
Set-ContentLibraryDatastoreMapping `
    -vCenterFQDN          "sfo-m01-vc01.sfo.rainpole.io" `
    -vCenterAdmin         "administrator@vsphere.local" `
    -vCenterAdminPassword "VMw@re1!" `
    -vCenterRootPassword  "VMw@re1!VMw@re1!" `
    -contentLibraryName   "sfo-m01-lib01" `
    -datastoreName        "sfo-m01-cl01-ds01"
```

## Parameters

### -vCenterFQDN

FQDN of the vCenter instance hosting the Content Library.

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

Admin user for the vCenter REST API.

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

Password for the vCenter admin user.

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

### -vCenterRootPassword

Root password for SSH access to the vCenter appliance.

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

### -contentLibraryName

Name of the Content Library whose datastore backing should be updated.

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

### -datastoreName

Name of the target datastore to map the Content Library to.

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

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
