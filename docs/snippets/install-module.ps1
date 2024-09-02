Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name VMware.PowerCLI -RequiredVersion 13.3.0 -Repository PSGallery
Install-Module -Name 7Zip4PowerShell -RequiredVersion 2.4.0 -Repository PSGallery
Install-Module -Name Posh-SSH -RequiredVersion 3.0.8 -Repository PSGallery
Install-Module -Name VMware.CloudFoundation.InstanceRecovery -Repository PSGallery
