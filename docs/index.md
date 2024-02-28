<!-- markdownlint-disable first-line-h1 no-inline-html -->

<img src="assets/images/icon-color.svg" alt="PowerShell Module for VMware Cloud Foundation Recovery" width="150">

# PowerShell Module for VMware Cloud Foundation Recovery

`VMware.CloudFoundation.Recovery` is a PowerShell module that has been written to support the ability to automate and accelerate the recovery of a [VMware Cloud Foundation][docs-vmware-cloud-foundation] instance through the use of
PowerShell cmdlets.

[:material-powershell: &nbsp; PowerShell Gallery][psgallery-module-recovery]{ .md-button .md-button--primary }.

## Requirements.

### Platforms

The following table lists the supported platforms for this module.

Platform                                                     | Support
-------------------------------------------------------------|------------------------------------
:fontawesome-solid-cloud: &nbsp; VMware Cloud Foundation 5.1 | :fontawesome-solid-check:{ .green }
:fontawesome-solid-cloud: &nbsp; VMware Cloud Foundation 5.0 | :fontawesome-solid-check:{ .green }
:fontawesome-solid-cloud: &nbsp; VMware Cloud Foundation 4.5 | :fontawesome-solid-check:{ .green }

### Operating Systems

The following table lists the supported operating systems for this module.

Operating System                                                     | Version
---------------------------------------------------------------------|-----------
:fontawesome-brands-windows: &nbsp; Microsoft Windows Server         | 2019, 2022

### PowerShell

The following table lists the supported editions and versions of PowerShell for this module.

Edition                                                              | Version
---------------------------------------------------------------------|----------
:material-powershell: &nbsp; [PowerShell Core][microsoft-powershell] | >= 7.2.0

### Module Dependencies

The following table lists the required dependencies for this module.

Dependency                                           | Version   | Publisher                 | Reference
-----------------------------------------------------|-----------|---------------------------|---------------------------------------------------------------------------
[VMware.PowerCLI][psgallery-module-powercli]         | >= 13.1.0 | Broadcom                  | :fontawesome-solid-book: &nbsp; [Documentation][developer-module-powercli]
[PowerVCF][psgallery-module-powervcf]                | >= 2.4.0  | Broadcom                  | :fontawesome-solid-book: &nbsp; [Documentation][docs-module-powervcf]
[Posh-SSH][psgallery-module-poshssh]                 | >= 3.0.8  | Carlos Perez              | :fontawesome-brands-github: &nbsp; [GitHUb][github-module-poshssh]
[7Zip4Powershell][psgallery-module-7zip4powershell]  | >= 2.4.0  | Thomas Freudenberg        | :fontawesome-brands-github: &nbsp; [GitHub][github-module-7zip4powershell]
[OpenSSL for Windows][download-win64openssl]         | >= 3.2.1  | Shining Light Productions | :octicons-package-dependencies-24: &nbsp; [Download][download-win64openssl]

[docs-vmware-cloud-foundation]: https://docs.vmware.com/en/VMware-Cloud-Foundation/index.html
[microsoft-powershell]: https://docs.microsoft.com/en-us/powershell
[psgallery-module-7zip4powershell]: https://www.powershellgallery.com/packages/7Zip4Powershell
[psgallery-module-poshssh]: https://www.powershellgallery.com/packages/Posh-SSH
[psgallery-module-powercli]: https://www.powershellgallery.com/packages/VMware.PowerCLI
[psgallery-module-powervcf]: https://www.powershellgallery.com/packages/PowerVCF
[psgallery-module-recovery]: https://www.powershellgallery.com/packages/VMware.CloudFoundation.Recovery
[developer-module-powercli]: https://developer.vmware.com/tool/vmware-powercli
[docs-module-powervcf]: https://vmware.github.io/powershell-module-for-vmware-cloud-foundation
[github-module-7zip4powershell]: https://github.com/thoemmi/7Zip4Powershell
[github-module-poshssh]: https://github.com/darkoperator/Posh-SSH
[download-win64openssl]: https://slproweb.com/products/Win32OpenSSL.html
