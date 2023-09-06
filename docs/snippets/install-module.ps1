Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name VMware.PowerCLI -MinimumVersion 13.1.0 -Repository PSGallery
Install-Module -Name PowerVCF -MinimumVersion 2.4.0 -Repository PSGallery
Install-Module -Name 7Zip4PowerShell -MinimumVersion 2.4.0 -Repository PSGallery
Install-Module -Name Posh-SSH -MinimumVersion 3.0.8 -Repository PSGallery
Install-Module -Name VMware.CloudFoundation.InstanceRecovery -Repository PSGallery
