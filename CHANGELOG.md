# Release History

## v9.1.0.1004
> Released: 2026-08-05
- Updated support statement on README
- Add Get-ServicesRuntime function
- Add support for managing services runtime component backup schedules (Get-ServicesRuntimeBackupSchedule, Set-ServicesRuntimeBackupSchedule, Start-ServicesRuntimeComponentBackup)
- Rename Get-RegisteredComponentIds to Get-VcfOperationsRegisteredComponents and include component version in its output
- Further fix for NSX Edge recovery when edges are deployed to a manually created portgroup
- Fix for OVA deployment to ESX for workload domains (previously restricted to the management domain)

## v9.1.0.1003
> Released: 2026-07-08
- Fix for NSX Edge recovery for edges deployed to manually created portgroups
- Fix for deploying workload domain vCenter & NSX OVA to esx

## v9.1.0.1002
> Released: 2026-06-29
- Initial support for VCF 9.1.0

## v9.0.1
> Released: 2025-09-23
- Initial release of `VMware.CloudFoundation.InstanceRecovery` for VCF 9.x.
