# Set-ContentLibraryDatastoreMapping

## Synopsis

Updates the backing datastore for a vCenter Content Library after a recovery where the datastore name or URI has changed.

## Syntax

```powershell
Set-ContentLibraryDatastoreMapping [-vCenterFQDN] <String> [-vCenterRootPassword] <String> [-contentLibraryName] <String[]> [-datastoreName] <String> [<CommonParameters>]
```

## Description

The `Set-ContentLibraryDatastoreMapping` cmdlet connects to a vCenter appliance via SSH as root and remaps one or more Content Libraries to a new backing datastore by updating the vCenter database (`VCDB`) directly. The target datastore's MoRef is looked up once in `vc.vpx_datastore`. Then, for each named library, the cmdlet:

1. Resolves the library ID and vCenter server GUID from `vc.cl_library`, and its storage ID from `vc.cl_library_storage`.
2. Updates `storageuri` in `vc.cl_storage` to `Datastore:<datastoreMoRef>:<serverGuid>` and verifies it by reading the value back.
3. Sets `ondisk = false` on every file record belonging to the library in `vc.cl_file`, so content is fetched again from its source rather than assumed to be present, and verifies that no files remain marked `ondisk = true`. Files are matched to the library through `cl_file_version`, `cl_libraryitemversion` and `cl_libraryitem`, because `cl_file.storageid` can be NULL. The number of file records found is logged, so a library with no matching records is visible rather than passing the check trivially.

Once all libraries have been processed, the `vmware-content-library` service is restarted a single time and the cmdlet waits for the restart to complete (up to 180 seconds). The restart runs detached on the appliance, so it is not interrupted when the SSH session closes.

A library that cannot be found in the database is logged as an error and skipped; the remaining libraries are still processed. If no library was updated, the service is not restarted. If the target datastore cannot be found, the cmdlet stops before changing anything.

The cmdlet is safe to run more than once: re-running sets the same `storageuri` and `ondisk` values and restarts the service again.

> **Note:** The `ondisk = false` reset is intended for subscribed libraries that fetch content on demand. For a local library whose files are no longer on the datastore, resetting the flag does not recover the content; restore it from backup or re-import it.

> **Note:** All libraries named in a single call are mapped to the same datastore (`-datastoreName`).

## Examples

### Example 1

Remap a single Content Library.

```powershell
Set-ContentLibraryDatastoreMapping `
    -vCenterFQDN         "sfo-m01-vc01.sfo.rainpole.io" `
    -vCenterRootPassword "VMw@re1!VMw@re1!" `
    -contentLibraryName  "sfo-m01-lib01" `
    -datastoreName       "sfo-m01-cl01-ds01"
```

### Example 2

Remap several Content Libraries in one call, with a single service restart. The names can be given as an array or as a comma separated string (`"sv-cl01,Kubernetes Service Content Library"`).

```powershell
Set-ContentLibraryDatastoreMapping `
    -vCenterFQDN         "sfo-w01-vc01.sfo.rainpole.io" `
    -vCenterRootPassword "VMw@re1!VMw@re1!" `
    -contentLibraryName  @("sv-cl01", "Kubernetes Service Content Library") `
    -datastoreName       "sfo-w01-cl01-ds-vsan01"
```

## Parameters

### -vCenterFQDN

FQDN of the vCenter instance hosting the Content Libraries.

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

### -vCenterRootPassword

Root password for SSH access to the vCenter appliance.

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

Name of one or more Content Libraries whose datastore backing should be updated, as an array and/or a comma separated string. Each element is split on commas and trimmed, so library names must not contain commas.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -datastoreName

Name of the target datastore to map the Content Libraries to. It is the same for every library in the call.

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
