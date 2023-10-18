# VCFInstanceRecovery

## Getting started

- Verify you are using Windows Server 2019
- Verify that your system has Microsoft PowerShell 7.x installed. 
- Verify that your system has OpenSSL version 1.0.2g or higher installed and added to the Windows PATH system variable.
- Install supporting modules from the PowerShell Gallery by running the following commands.​
- Install-Module -Name VMware.PowerCLI -MinimumVersion 13.1.0 -scope AllUsers -force
- Install-Module -Name PowerVCF -MinimumVersion 2.4.0 -scope AllUsers -force
- Install-Module -Name PoshSSH -MinimumVersion 3.0.8 -scope AllUsers -force
- Import-Module -Name VCFInstanceRecovery -MinimumVersion 1.0.2 -scope AllUsers -force

## Authors
- Ken Gould - VMware CIBG
- Brian O'Connell - VMware CIBG