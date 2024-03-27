# Installing the Module

Verify that your system has a [supported edition and version](index.md#powershell) of PowerShell installed.

=== ":material-pipe: &nbsp; Connected Environment"

    For environments connected to the Internet, you can install the [module dependencies](index.md#module-dependencies) from the PowerShell Gallery by running the following commands in the PowerShell console:

    ```powershell
    --8<-- "./docs/snippets/install-module.ps1"
    ```

=== ":material-pipe-disconnected: &nbsp; Disconnected Environment"

    For environments disconnected from the Internet _(e.g., dark-site, air-gapped)_, you can save the [module dependencies](index.md#module-dependencies) from the PowerShell Gallery by running the following commands in the PowerShell console:

    === ":fontawesome-brands-windows: &nbsp; Windows"

        From a system with an Internet connection, save the module dependencies from the PowerShell Gallery by running the following commands in the PowerShell console:

        ```powershell
        --8<-- "./docs/snippets/save-module-local-windows.ps1"
        ```

        From the system with the Internet connection, copy the module dependencies to a target system by running the following commands in the PowerShell console:

        ```powershell
        --8<-- "./docs/snippets/copy-module-local-windows.ps1"
        ```

Once installed, any cmdlets associated with `VMware.CloudFoundation.InstanceRecovery` and the its dependencies will be available for use.

To view the cmdlets for available in the module, run the following command in the PowerShell console.

```powershell
Get-Command -Module VMware.CloudFoundation.InstanceRecovery
```

To view the help for any cmdlet, run the `Get-Help` command in the PowerShell console.

For example:

```powershell
Get-Help -Name <cmdlet-name>
```

```powershell
Get-Help -Name <cmdlet-name> -Examples
```
