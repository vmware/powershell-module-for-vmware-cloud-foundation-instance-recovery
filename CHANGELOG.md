# Release History

## v9.0.2.1003
> Released: 2026-04-xx

- [Added] API based vCenter restore method

## v9.0.2.1002
> Released: 2026-04-16

- [Added] Ability to discover OVFTool from environment path and then default back to expected location if not found there
- [Changed] `New-VVFBasedPartialBringupValidation` and `New-VVFBasedPartialBringup` functions that are more compatible with all systems for showing progress.
- [Changed] `Invoke-vCenterRestore` to detect failed restore attempts
- [Fixed] Incorrect handling of sso credentials in `Invoke-vCenterRestore` when more than one domain with the same sso domain exists
- [Fixed] Delayed deployment of addtional NSX manager nodes in `New-NSXManagerOvaDeployment`
- [Fixed] Primary datastore name retrieval on clusters with multiple datastores

## v9.0.2.1001
> Released: 2026-04-08

- [Changed] nicindexing changed to match vmnic numbering
- [Changed] Handling of single NTP and single DNS server for `New-VVFBasedPartialBringup`
- [Fixed] Fix overlay network issue in single vDS configurations during `New-VVFBasedPartialBringup`
- [Fixed] Poor display of time taken in `New-VVFBasedPartialBringup`

## v9.0.2.1000
> Released: 2026-04-07

- [Added] Timings to Functions
- [Added] `New-VVFBasedPartialBringupValidation` and `New-VVFBasedPartialBringup` functions
- [Changed] Handle multiple ip address retrieval during `New-ExtractDataFromSDDCBackup`
- [Changed] IP Pools for VVF Partial bringup now handle multiple ip ranges instead of just one
- [Changed] DNS Resolution failures handled gracefully and warning given

## v9.0.1
> Released: 2025-09-23

- [Added] Initial release of `VMware.CloudFoundation.InstanceRecovery` for VCF 9.x.
