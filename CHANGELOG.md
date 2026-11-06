# Release History

## v9.1.2.1000
- Fleet Component Recovery: replaced the "Original VCF Installer Available" toggle with a "Binary Sourcing" choice between an unauthorized offline depot (default) and an authorized offline depot with the original VCF Installer
- Added `-unauthorizedDepot` to `Set-SDDCManagerOfflineDepot` (no depot credentials)
- Added `-unauthorizedDepot`, `-offlineDepotFqdn` and `-offlineDepotPort` to `Get-BackupsFromSFTPServer` to add a `packageUrl` for each depot-hosted component to the restore JSON
- Added `Add-OfflineDepotTrustedCertificate`
- Renamed the `remoteHostFqdn` variable to `vcfInstallerFqdn` in the Fleet Component Recovery variables file
- Merged `VMware.CloudFoundation.InstanceRecovery` and `VMware.CloudFoundation.RecoveryCoordinator` into a single module, `VCF.RecoveryCoordinator`
- Reorganised plans into `plans/<ibr|fdr>` and `templates/<variable-files|answer-files>/<ibr|fdr>`; `recovery-plan-catalog.json` now lives in `plans`, and `xaml` at the module root
- Engineering mode now also accepts a signed 12-hour one-time code (`helper/New-EngineeringOtp.ps1`) alongside the password
- Updated `Invoke-NSXEdgeClusterRecovery`
- Updated `Invoke-NSXEdgeClusterRecoverySelective`

## v9.1.1.1002
> Released: 2026-09-24
- Added `Update-VcfmsVcfaRegistration`
- Updated `Invoke-VcfOpsVidbVcfInstanceUpdate`
- Updated `Set-ServicesRuntimeScale`
- Updated `Set-ServicesRuntimeSftpBackupSettings`
- Updated `Get-ServicesRuntimeComponentBackups`
- Fixed `Invoke-VcfmsFleetComponentRegistration`

## v9.1.1.1001
> Released: 2026-09-14
- Initial support for VCF 9.1.1
- Added `Get-BackupsFromSFTPServer` to find and interactively select VCF Fleet component backups directly from an SFTP server, with an option to generate a `restore-payload.json`.
- Added `Set-ServicesRuntimeScale`

## v9.1.0.1003
> Released: 2026-07-29
- Minor aesthetic fixes

## v9.1.0.1002
> Released: 2026-06-29
- Initial support for VCF 9.1.0

## v9.0.1
> Released: 2025-09-23
- Initial release of `VMware.CloudFoundation.InstanceRecovery` for VCF 9.x.
