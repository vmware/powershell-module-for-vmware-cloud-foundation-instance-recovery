# Release History

## v1.0.12

> Released: 2024-08-28

- Enhanced `New-ExtractDataFromSDDCBackup` to leverage the vCenter Server backup for additional data.
- Added `New-PartialManagementDomainDeployment` to perform the partial bringup.
- Added support for clusters with multiple vDS.
- Added support for VMware Cloud Foundation 5.2.x.
- Enhanced ` upport for vSAN ESA configurations.
- Enhanced `Remove-NonResponsiveHosts` to resolve handling transport node cleanup in versions of VCF using NSX 3.1.3 or higher.
- Added check to `Confirm-VCFInstanceRecoveryPreReqs` for more than 1 concurrent VI server connections.

## v1.0.10

> Released: 2024-05-29

- Made `New-RebuiltVdsConfigure` more idempotent so that it can be rerun.

## v1.0.9

> Released: 2024-03-27

- Initial release of `VMware.CloudFoundation.InstanceRecovery`.
