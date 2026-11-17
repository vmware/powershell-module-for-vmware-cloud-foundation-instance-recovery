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
- Additional Cluster Recovery: storage clusters and compute clusters are only listed in Discovered Infrastructure when Engineering mode is enabled (driven by `engineeringOnlyClusterTypes` in `recovery-plan-catalog.json`)
- Fleet Disaster Recovery (FDR) is no longer engineering-only
- FDR failover and failback plans: added a "User Provided DNS Entry Modification Script" toggle (off by default, which keeps the manual confirmation task) and `helper/Update-FleetVipDns.ps1` as a ready-made `-Failover` / `-Failback` script
- Added `-ScriptArguments` to `Invoke-UserScript`
- FDR plans: rationalised the variables. Duplicates are merged (e.g. `vcfOperationsFqdn`, `vcfOperationsAdminPassword`, `vcfaServicesRuntimePassword`, `sftpHost`/`sftpUsername`/`sftpDirectory`) and values that can be assumed or derived are no longer asked for. The plans no longer use an extracted SDDC data file
- Added `Get-OpsRegisteredComponentValue` and `-opsRegisteredComponentsFile` to `Get-BackupsFromSFTPServer`, `New-ServicesRuntime`, `Set-ServicesRuntimeSftpBackupSettings`, `Add-VcfmsTrustedCertificate`, `Restore-ServicesRuntimeComponentBackup`, `Set-ServicesRuntimeScale`, `Set-ServicesRuntimeComponentVips`, `Set-VcfmsFleetIdentity`, `Invoke-VcfOpsVidbVcfInstanceUpdate`, `Invoke-VcfmsFleetComponentRegistration`, `Invoke-VcfmsVcfaRegistration` and `Update-VcfmsVcfaRegistration`, so values such as the fleet, Identity Broker and VCF Automation Services Runtime FQDNs, the VSP ID and the target VCF instance can be read from `VCFOps-Registered-Component-Details.json` instead of being passed
- `Restore-ServicesRuntimeComponentBackup` now defaults `-RestoreJsonFile` to `.\restore-payload.json`
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
