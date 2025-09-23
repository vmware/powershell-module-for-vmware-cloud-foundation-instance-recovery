<!-- markdownlint-disable first-line-h1 no-inline-html -->

<img src="assets/images/icon-color.svg" alt="PowerShell Module for VMware Cloud Foundation Instance Recovery" width="150">

# PowerShell Module for VMware Cloud Foundation Instance Recovery

`VMware.CloudFoundation.InstanceRecovery` is a PowerShell module that has been written to support
the ability to automate and accelerate the recovery of a VMware Cloud Foundation instance through
the use of PowerShell cmdlets.

[:material-powershell: &nbsp; PowerShell Gallery][psgallery-module-recovery]{ .md-button .md-button--primary }.

## Requirements

### VMware Cloud Foundation

The following table lists the supported releases for this module.

| Platform                                                       | Support                             |
|----------------------------------------------------------------| ----------------------------------- |
| :fontawesome-solid-cloud: &nbsp; VMware Cloud Foundation 9.0.x | :fontawesome-solid-check:{ .green } |

### PowerShell

The following table lists the supported editions and versions of PowerShell for this module.

Edition                                                              | Version
---------------------------------------------------------------------|----------
:material-powershell: &nbsp; [PowerShell Core][microsoft-powershell] | >= 7.5.3

### Module Dependencies

The following table lists the required dependencies for this module.

Dependency                                           | Version   | Publisher                 | Reference
-----------------------------------------------------|-----------|---------------------------|---------------------------------------------------------------------------
[VCF.PowerCLI][psgallery-module-powercli]            | 9.0.0     | Broadcom                  | :fontawesome-solid-book: &nbsp; [Documentation][developer-module-powercli]
[Posh-SSH][psgallery-module-poshssh]                 | 3.2.4     | Carlos Perez              | :fontawesome-brands-github: &nbsp; [GitHUb][github-module-poshssh]
[OpenSSL for Windows][download-win64openssl]         | 3.2.1     | Shining Light Productions | :octicons-package-dependencies-24: &nbsp; [Download][download-win64openssl]

[microsoft-powershell]: https://docs.microsoft.com/en-us/powershell
[psgallery-module-poshssh]: https://www.powershellgallery.com/packages/Posh-SSH
[psgallery-module-powercli]: https://www.powershellgallery.com/packages/VCF.PowerCLI
[psgallery-module-recovery]: https://www.powershellgallery.com/packages/VMware.CloudFoundation.InstanceRecovery
[developer-module-powercli]: https://developer.broadcom.com/powercli
[docs-module-powervcf]: https://vmware.github.io/powershell-module-for-vmware-cloud-foundation
[github-module-poshssh]: https://github.com/darkoperator/Posh-SSH
[download-win64openssl]: https://slproweb.com/products/Win32OpenSSL.html
