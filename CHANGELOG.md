# Release History

## v1.0.7

> Released: 2023-11-xx

- Added `Invoke-SDDCManagerRestore` to automated recovery
- Enhanced OSD output for all functions to include message time and timestamps, better handlong of ovftool output
- Added `--X:waitForIp` to NSX Manager deployment to ensure appliance is near ready for use before continuing

## v1.0.6

> Released: 2023-11-20

- Modified `New-ExtractDataFromSDDCBackup` to capture data on all clusters in a workload domain rather than just the primaryCluster
- Modified `New-ReconstructedPartialBringupJsonSpec` to handle changes in `New-ExtractDataFromSDDCBackup`
- Modified `Restore-ClusterDRSGroupsAndRules` to skip attempted recreation of DRS Anti-Affinity rules with a single member (illegal config)
- Modified several functions to ensure all provide feedback to user on progress

## v1.0.5

> Released: 2023-11-15

- Added `New-ReconstructedPartialBringupJsonSpec` (experimental) for recreation of VMware Cloud Foundation partial bringup JSON from backup data. Not all bringup configurations have been tested.
- Modified `Invoke-NSXEdgeClusterRecovery` to redeploy edges in `NODE_READY` state in addition to `MPA_DISCONNECTED` and `VM_PLACEMENT_REFRESH_FAILED`
- Modified `Invoke-NSXEdgeClusterRecovery` to handle datastore moref being different due to cluster rebuild
- Modified `New-NSXManagerOvaDeployment` to ensure SSH is enabled
- Modified `New-SDDCManagerOvaDeployment` to pass BACKUP_USER password retreived from backup data.
- Modified `New-ExtractDataFromSDDCBackup` to gather significantly more detail to support `New-ReconstructedPartialBringupJsonSpec`
- Modified `Confirm-VCFInstanceRecoveryPreReqs` to check for presence of OpenSSL in the Windows $PATH variable
- Modified multiple functions to standardize on input variable names

## v1.0.4

> Released: 2023-11-10

- Modified `New-NSXManagerOvaDeployment` to support passing of desired appliance size
- Modified `Invoke-NSXEdgeClusterRecovery` to support passing of target resourcepool as alternative to cluster
- Modified `Invoke-NSXEdgeClusterRecovery` to redeploy edges in `VM_PLACEMENT_REFRESH_FAILED` state in addition to `MPA_DISCONNECTED`

## v1.0.3

> Released: 2023-10-20

- Added `New-SDDCManagerOvaDeployment`
- Added `New-vCenterOvaDeployment`
- Modified `New-ExtractDataFromSDDCBackup` to add vCenter detail to the workloadDomains section of the extract JSON
- Modified `New-ExtractDataFromSDDCBackup` to modify capture sufficient SDDC Manager detail for redeployment
- Added Descriptions and Example usage to all exported functions 

## v1.0.2

> Released: 2023-10-18

- Initial Release
