# Release History

## v1.0.4

> Released: 2023-11-10

- Updated `New-NSXManagerOvaDeployment` to support passing of desired appliance size
- Updated `Invoke-NSXEdgeClusterRecovery` to support passing of target resourcepool as alternative to cluster
- Updated `Invoke-NSXEdgeClusterRecovery` to redeploy edges in `VM_PLACEMENT_REFRESH_FAILED` state in addition to `MPA_DISCONNECTED`

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
