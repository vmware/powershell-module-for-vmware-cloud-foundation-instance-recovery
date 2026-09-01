# Confirm-ContentLibraryDatastoreFolder

## Synopsis

Checks for the presence of a content library folder on the target datastore and creates it if absent.

## Syntax

```powershell
Confirm-ContentLibraryDatastoreFolder [-vCenterFQDN] <String> [-vCenterAdmin] <String> [-vCenterAdminPassword] <String> [-datastoreName] <String> [-contentLibraryName] <String> [<CommonParameters>]
```

## Description

The `Confirm-ContentLibraryDatastoreFolder` cmdlet connects to the specified vCenter, resolves the named content library to its GUID, locates the named datastore, and verifies that a folder in the format `contentlib-<libraryId>` exists at the root of that datastore. If the folder is not found it is created.

For vSAN datastores (both OSA and ESA), the function uses the PowerCLI VimDatastore PSDrive provider, which wraps vSphere's Datastore Browser API (`MakeDirectory`). vCenter exposes this API uniformly for all datastore types it manages, so the same code path also handles VMFS and NFS datastores that are registered as named datastores in vCenter.

> **Note:** This function is not applicable to content libraries backed by a raw NFS mount point (storage backing type `OTHER`). In that case the folder is managed by the NFS server itself and no vSphere datastore object exists to operate against.

## Examples

### Example 1

Confirm (and create if missing) the content library folder on a vSAN datastore.

```powershell
Confirm-ContentLibraryDatastoreFolder `
    -vCenterFQDN          "sfo-m01-vc01.sfo.rainpole.io" `
    -vCenterAdmin         "administrator@vsphere.local" `
    -vCenterAdminPassword "VMware1!" `
    -datastoreName        "sfo-m01-cl01-ds-vsan01" `
    -contentLibraryName   "sfo-m01-cl01"
```

## Parameters

### -vCenterFQDN

FQDN of the vCenter instance that owns the target datastore.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -vCenterAdmin

Admin user for the vCenter instance.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
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
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -datastoreName

Name of the datastore on which to confirm the content library folder.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -contentLibraryName

Name of the content library. Its GUID is resolved via `Get-ContentLibrary` and the folder name is constructed as `contentlib-<libraryId>`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
