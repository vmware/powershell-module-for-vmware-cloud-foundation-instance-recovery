# VMware.CloudFoundation.InstanceRecovery



## Getting started

- Verify that your system has Microsoft PowerShell 5.1 or 7.x installed. 
- Verify that your system has OpenSSL version 1.0.2g or higher installed and added to the Windows PATH system variable.
- Install supporting modules from the PowerShell Gallery by running the following commands.​
- Install-Module -Name VMware.PowerCLI -MinimumVersion 13.1.0
- Install-Module -Name PowerVCF -MinimumVersion 2.3.0
- Install-Module -Name PoshSSH
- Import the following modules by running the following commands
- Import-Module -Name VMware.PowerCLI -MinimumVersion 13.1.0
- Import-Module -Name PowerVCF -MinimumVersion 2.3.0
- Import-Module -Name PoshSSH
- Import-Module .\VMware.CloudFoundation.InstanceRecovery.psm1

## Authors
- Ken Gould - VMware CIBG
- Brian O'Connell - VMware CIBG