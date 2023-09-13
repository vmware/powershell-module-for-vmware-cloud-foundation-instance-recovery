#Module to Assist in VCF Full Instance Recovery

#Region Execute
$vCenterFQDN = "sfo-w02-vc01.sfo.rainpole.io"
$vCenterAdmin = "Administrator@vsphere.local"
$vCenterAdminPassword = "VMw@re1!"
$clusterName = "sfo-w02-cl01"
$esxiRootPassword = "VMw@re1!"
$nsxManager = "sfo-w02-nsx01a.sfo.rainpole.io"
$nsxAdmin = "admin"
$nsxAdminPassword = "VMw@re1!VMw@re1!"
$sddcManagerFQDN = "sfo-vcf01.sfo.rainpole.io"
$sddcManagerUser = "Administrator@vsphere.local"
$sddcManagerPassword = "VMw@re1!"


#Resolve-PhysicalHostServiceAccounts -vCenterFQDN $vCenterFQDN -vCenterAdmin $vCenterAdmin -vCenterAdminPassword $vCenterAdminPassword -clusterName $clusterName -esxiRootPassword $esxiRootPassword
#Resolve-PhysicalHostTransportNodes -vCenterFQDN $vCenterFQDN -vCenterAdmin $vCenterAdmin -vCenterAdminPassword $vCenterAdminPassword -clusterName $clusterName -nsxManager $nsxManager -username $nsxAdmin -password $nsxAdminPassword
#Remove-NonResponsiveHosts -vCenterFQDN $vCenterFQDN -vCenterAdmin $vCenterAdmin -vCenterAdminPassword $vCenterAdminPassword -clusterName $cluster
#Add-HostsToCluster -vCenterFQDN $vCenterFQDN -vCenterAdmin $vCenterAdmin -vCenterAdminPassword $vCenterAdminPassword -clusterName $clusterName -esxiRootPassword $esxiRootPassword -sddcManagerFQDN $sddcManagerFQDN -sddcManagerUser $sddcManagerUser -sddcManagerPassword $sddcManagerPassword

#EndRegion Execute
#Region vCenter Functions
Function Resolve-PhysicalHostServiceAccounts
{
    Param(
    [Parameter (Mandatory=$true)][String] $vCenterFQDN,
    [Parameter (Mandatory=$true)][String] $vCenterAdmin,
    [Parameter (Mandatory=$true)][String] $vCenterAdminPassword,
    [Parameter (Mandatory=$true)][String] $clusterName,
    [Parameter (Mandatory=$true)][String] $svcAccountPassword,
    [Parameter (Mandatory=$true)][String] $esxiRootPassword,
    [Parameter (Mandatory=$true)][String] $sddcManagerFQDN,
    [Parameter (Mandatory=$true)][String] $sddcManagerUser,
    [Parameter (Mandatory=$true)][String] $sddcManagerPassword
    )
    $vCenterConnection = Connect-VIServer -server $vCenterFQDN -username $vCenterAdmin -password $vCenterAdminPassword
    $clusterHosts = Get-Cluster -name $clusterName | Get-VMHost
    Disconnect-VIServer * -confirm:$false

    Foreach ($hostInstance in $clusterHosts)
        {
            Connect-VIServer -Server $hostInstance.name -User root -Password $esxiRootPassword | Out-Null
            $esxiHostName =  $hostInstance.name.Split(".")[0]
            $svcAccountName = "svc-vcf-$esxiHostName"
            $accountExists = Get-VMHostAccount -Server $hostInstance.Name -User $svcAccountName -erroraction SilentlyContinue *>$null
            If (!$accountExists)
            {
                New-VMHostAccount -Id $svcAccountName -Password VMw@re1! -Description "ESXi User" | Out-Null
                New-VIPermission -Entity (Get-Folder root) -Principal $svcAccountName -Role Admin | Out-Null
                Disconnect-VIServer $hostInstance.name -confirm:$false | Out-Null
            }
    }

    $tokenRequest = Request-VCFToken -fqdn $sddcManagerFQDN -username $sddcManagerUser -password $sddcManagerPassword

    Foreach ($hostInstance in $clusterHosts)
    {
        Remove-Variable credentialsObject -ErrorAction SilentlyContinue
        Remove-Variable elementsObject -ErrorAction SilentlyContinue
        Remove-Variable esxHostObject -ErrorAction SilentlyContinue

        $esxiHostName =  $hostInstance.name.Split(".")[0]
        $svcAccountName = "svc-vcf-$esxiHostName"
        
        $credentialsObject += [pscustomobject]@{
            'username' = $svcAccountName
            'password' = $svcAccountPassword
        }
        
        $elementsObject += [pscustomobject]@{
            'resourceName' = $hostInstance.name
            'resourceType' = 'ESXI'
            'credentials' = @($credentialsObject)
        }

        $esxHostObject += [pscustomobject]@{
            'operationType' = 'REMEDIATE'
            'elements' = @($elementsObject)
        }

        $esxiHostJson = $esxHostObject | Convertto-Json -depth 10

        $taskID = (Set-VCFCredential -json $esxiHostJson).id
        Do
        {
            Sleep 5
            $taskStatus = (Get-VCFCredentialTask -id $taskID).status
        } Until ($taskStatus -eq "SUCCESSFUL")
        Write-Output "[$($hostInstance.name)] Password Remediation $taskStatus"
    }
}

Function Set-PhysicalHostServiceAccountPasswords
{
    Param(
        [Parameter (Mandatory=$true)][String] $vCenterFQDN,
        [Parameter (Mandatory=$true)][String] $vCenterAdmin,
        [Parameter (Mandatory=$true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory=$true)][String] $clusterName,
        [Parameter (Mandatory=$true)][String] $svcAccountPassword,
        [Parameter (Mandatory=$true)][String] $esxiRootPassword
        
    )
    $vCenterConnection = Connect-VIServer -server $vCenterFQDN -username $vCenterAdmin -password $vCenterAdminPassword
    $clusterHosts = Get-Cluster -name $clusterName | Get-VMHost
    Disconnect-VIServer * -confirm:$false
    Foreach ($hostInstance in $clusterHosts)
    {
        Connect-VIServer -Server $hostInstance.name -User root -Password $esxiRootPassword | Out-Null
        $esxiHostName =  $hostInstance.name.Split(".")[0]
        $svcAccountName = "svc-vcf-$esxiHostName"
        Set-VMHostAccount -UserAccount $svcAccountName -Password $svcAccountPassword -confirm:$false | Out-Null
        Disconnect-VIServer $hostInstance.name -confirm:$false
    }
}

Function Set-ClusterDRSLevel 
{
    Param(
        [Parameter (Mandatory=$true)][String] $vCenterFQDN,
        [Parameter (Mandatory=$true)][String] $vCenterAdmin,
        [Parameter (Mandatory=$true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory=$true)][String] $clusterName,
        [Parameter (Mandatory=$true)][String] $DrsAutomationLevel
        
    )
    $vCenterConnection = connect-viserver $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    set-cluster -cluster $clusterName -DrsAutomationLevel $DrsAutomationLevel -confirm:$false
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
}

Function Remove-NonResponsiveHosts 
{
    Param(
        [Parameter (Mandatory=$true)][String] $vCenterFQDN,
        [Parameter (Mandatory=$true)][String] $vCenterAdmin,
        [Parameter (Mandatory=$true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory=$true)][String] $clusterName
        
    )
    $vCenterConnection = connect-viserver $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    $nonResponsiveHosts = get-cluster -name $clusterName | get-vmhost | Where-Object { $_.ConnectionState -eq "NotResponding"}
    foreach ($nonResponsiveHost in $nonResponsiveHosts) {
        Get-VMHost | Where-Object {$_.Name -eq $nonResponsiveHost.Name} | Remove-VMHost -Confirm:$false
    }
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
}

Function Add-HostsToCluster 
{
    Param(
        [Parameter (Mandatory=$true)][String] $vCenterFQDN,
        [Parameter (Mandatory=$true)][String] $vCenterAdmin,
        [Parameter (Mandatory=$true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory=$true)][String] $clusterName,
        [Parameter (Mandatory=$true)][String] $esxiRootPassword,
        [Parameter (Mandatory=$true)][String] $sddcManagerFQDN,
        [Parameter (Mandatory=$true)][String] $sddcManagerUser,
        [Parameter (Mandatory=$true)][String] $sddcManagerPassword
        )
    $tokenRequest = Request-VCFToken -fqdn $sddcManagerFQDN -username $sddcManagerUser -password $sddcManagerPassword
    $newHosts = (get-vcfhost | where-object {$_.id -in ((get-vcfcluster -name $clusterName).hosts.id)}).fqdn
    $vCenterConnection = connect-viserver $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    foreach ($newHost in $newHosts) {
        $vmHosts = (Get-cluster -name $clusterName | Get-VMHost).Name
        if ($newHost -notin $vmHosts) 
        {
            $esxiConnection = connect-viserver $newHost -user root -password $esxiRootPassword
            if ($esxiConnection) 
            {
                Write-Output "Adding $newHost to cluster $clusterName"
                Add-VMHost $newHost -username root -password $esxiRootPassword -Location $clusterName -Force -Confirm:$false | Out-Null
            }
            else 
            {
                Write-Error "Unable to connect to $newHost. Host will not be added to the cluster"
            }
        }
        else 
        {
            Write-Output "$newHost is already part of $clusterName. Skipping"
        }
    }
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
}

<# Function Add-HostsToVDS
{
    Param(
        [Parameter (Mandatory=$true)][String] $vCenterFQDN,
        [Parameter (Mandatory=$true)][String] $vCenterAdmin,
        [Parameter (Mandatory=$true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory=$true)][String] $clusterName,
        [Parameter (Mandatory=$true)][String] $sddcManagerFQDN,
        [Parameter (Mandatory=$true)][String] $sddcManagerUser,
        [Parameter (Mandatory=$true)][String] $sddcManagerPassword
        )
    $vCenterConnection = connect-viserver $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    $vmHosts = (Get-cluster -name $clusterName | Get-VMHost).Name
    $tokenRequest = Request-VCFToken -fqdn $sddcManagerFQDN -username $sddcManagerUser -password $sddcManagerPassword
    $vdsName = ((get-vcfCluster -name $clusterName -vdses) | ? {$_.portGroups.transportType -contains "MANAGEMENT"}).name
    # Put Host in Maintenance Mode
    foreach ($vmhost in $vmHosts) 
    {
    Write-Output "`nEntering Maintenance Mode for" $vmhost
    Get-VMHost -Name $vmhost | set-vmhost -State Maintenance -VsanDataMigrationMode NoDataMigration | Out-Null
    # Add host to VDS
    Write-Output "`nAdding $vmhost to $vdsName " 
    $vds = Get-VDSwitch -Name $vdsName | Add-VDSwitchVMHost -VMHost $vmhost
    $vmhostNetworkAdapter = Get-VMHost $vmhost | Get-VMHostNetworkAdapter -Physical -Name vmnic1
    $vds | Add-VDSwitchPhysicalNetworkAdapter -VMHostNetworkAdapter $vmhostNetworkAdapter -Confirm:$false
    }
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
} #>

Function Remove-StandardSwitch
{
    Param(
        [Parameter (Mandatory=$true)][String] $vCenterFQDN,
        [Parameter (Mandatory=$true)][String] $vCenterAdmin,
        [Parameter (Mandatory=$true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory=$true)][String] $clusterName
        )
    $vCenterConnection = connect-viserver $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    $vmHosts = (Get-cluster -name $clusterName | Get-VMHost).Name
    foreach ($vmhost in $vmHosts) 
    {
    Write-Output "Removing standard vSwitch from $vmhost" 
    Get-VMHost -Name $vmhost | Get-VirtualSwitch -Name "vSwitch0" | Remove-VirtualSwitch -Confirm:$false | Out-Null
    }
    Disconnect-VIServer -Server $global:DefaultVIServers -Force -Confirm:$false
}

Function Add-VMKernelsToHost
{
    Param(
        [Parameter (Mandatory=$true)][String] $vCenterFQDN,
        [Parameter (Mandatory=$true)][String] $vCenterAdmin,
        [Parameter (Mandatory=$true)][String] $vCenterAdminPassword,
        [Parameter (Mandatory=$true)][String] $clusterName,
        [Parameter (Mandatory=$true)][String] $sddcManagerFQDN,
        [Parameter (Mandatory=$true)][String] $sddcManagerUser,
        [Parameter (Mandatory=$true)][String] $sddcManagerPassword
        )
    $tokenRequest = Request-VCFToken -fqdn $sddcManagerFQDN -username $sddcManagerUser -password $sddcManagerPassword
    
    $vCenterConnection = connect-viserver $vCenterFQDN -user $vCenterAdmin -password $vCenterAdminPassword
    $vmHosts = (Get-cluster -name $clusterName | Get-VMHost).Name
    foreach ($vmhost in $vmHosts) 
    { 
        $vmotionPG = ((get-vcfCluster -name $clusterName -vdses).portGroups | ? {$_.transportType -eq "VMOTION"}).name
        $vmotionVDSName = ((get-vcfCluster -name $clusterName -vdses) | ? {$_.portGroups.transportType -contains "VMOTION"}).name
        $vmotionIP = (((Get-VCFHost | Where-Object {$_.fqdn -eq $vmhost}).ipAddresses) | ? {$_.type -eq "VMOTION"}).ipAddress
        $vmotionMask = (Get-VCFNetworkIPPool -id ((Get-VCFHost | Where-Object {$_.fqdn -eq $vmhost}).networkPool.id) | ? {$_.type -eq "VMOTION"}).mask
        $vmotionMTU = (Get-VCFNetworkIPPool -id ((Get-VCFHost | Where-Object {$_.fqdn -eq $vmhost}).networkPool.id) | ? {$_.type -eq "VMOTION"}).mtu
        $vmotionGW = (Get-VCFNetworkIPPool -id ((Get-VCFHost | Where-Object {$_.fqdn -eq $vmhost}).networkPool.id) | ? {$_.type -eq "VMOTION"}).gateway
        $vsanPG = ((get-vcfCluster -name $clusterName -vdses).portGroups | ? {$_.transportType -eq "VSAN"}).name
        $vsanVDSName = ((get-vcfCluster -name $clusterName -vdses) | ? {$_.portGroups.transportType -contains "VSAN"}).name
        $vsanIP = (((Get-VCFHost | Where-Object {$_.fqdn -eq $vmhost}).ipAddresses) | ? {$_.type -eq "VSAN"}).ipAddress
        $vsanMask = (Get-VCFNetworkIPPool -id ((Get-VCFHost | Where-Object {$_.fqdn -eq $vmhost}).networkPool.id) | ? {$_.type -eq "VSAN"}).mask
        $vsanMTU = (Get-VCFNetworkIPPool -id ((Get-VCFHost | Where-Object {$_.fqdn -eq $vmhost}).networkPool.id) | ? {$_.type -eq "VSAN"}).mtu
        $vsanGW = (Get-VCFNetworkIPPool -id ((Get-VCFHost | Where-Object {$_.fqdn -eq $vmhost}).networkPool.id) | ? {$_.type -eq "VSAN"}).gateway

        Write-Output "Creating vMotion vMK on $vmHost"
        $dvportgroup = Get-VDPortgroup -name $vmotionPG -VDSwitch $vmotionVDSName
        $vmk = New-VMHostNetworkAdapter -VMHost $vmhost -VirtualSwitch $vmotionVDSName -mtu $vmotionMTU -PortGroup $dvportgroup -ip $vmotionIP -SubnetMask $vmotionMask -NetworkStack (Get-VMHostNetworkStack -vmhost $vmhost | Where-Object {$_.id -eq "vmotion"})
        Write-Output "Setting vMotion Gateway on $vmHost"
        $vmkName = 'vmk1'
        $esx = Get-VMHost -Name $vmHost
        $esxcli = Get-EsxCli -VMHost $esx -V2
        $interface = $esxcli.network.ip.interface.ipv4.get.Invoke(@{interfacename=$vmkName})
        $interfaceArg = @{
            netmask = $interface[0].IPv4Netmask
            type    = $interface[0].AddressType.ToLower()
            ipv4    = $interface[0].IPv4Address
            interfacename = $interface[0].Name
            gateway = $vmotionGW
        }
        $esxcli.network.ip.interface.ipv4.set.Invoke($interfaceArg)

        Write-Output "Creating vSAN vMK on $vmHost"
        $dvportgroup = Get-VDPortgroup -name $vsanPG -VDSwitch $vsanVDSName
        $vmk = New-VMHostNetworkAdapter -VMHost $vmhost -VirtualSwitch $vsanVDSName -mtu $vsanMTU -PortGroup $dvportgroup -ip $vsanIP -SubnetMask $vsanMask -VsanTrafficEnabled:$true

        Write-Host "Setting vSAN Gateway on $vmHost"
        $vmkName = 'vmk2'
        $esx = Get-VMHost -Name $vmHost
        $esxcli = Get-EsxCli -VMHost $esx -V2
        $interface = $esxcli.network.ip.interface.ipv4.get.Invoke(@{interfacename=$vmkName})
        $interfaceArg = @{
            netmask = $interface[0].IPv4Netmask
            type    = $interface[0].AddressType.ToLower()
            ipv4    = $interface[0].IPv4Address
            interfacename = $interface[0].Name
            gateway = $vsanGW
        }
        $esxcli.network.ip.interface.ipv4.set.Invoke($interfaceArg)
    }
}

Function Get-ClusterVMOverrides
{   <#
    .SYNOPSIS
        Retrieves and saves configured VM Overrides.

    .DESCRIPTION
        Saves details for configured VM Overrides for the passed cluster to a JSON file

    .EXAMPLE
        Get-ClusterVMOverrides -clusterName 'sfo-m01-cl01'
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [String]$clusterName
        )
    $cluster = Get-Cluster -Name $clusterName
    $overRiddenVMs = $cluster.ExtensionData.ConfigurationEx.DrsVmConfig
    $clusterVMs = Get-Cluster | Get-VM | Select-Object Name, id
    $overRiddenData =@()
    Foreach ($overRiddenVM in $overRiddenVMs) 
    {
        $overRiddenData += @{ 
            'type' = $overRiddenVM.key.type
            'behavior' = [STRING]$overRiddenVM.Behavior
            'key' = $overRiddenVM.key.value
            'name' = ($clusterVMs | Where-Object {$_.id -eq ($overRiddenVM.key.type +"-"+$overRiddenVM.key.value)}).name
        }
    }
    $overRiddenData | ConvertTo-Json -depth 10 | Out-File "$clusterName-vmOverrides.json"
}

Function Get-ClusterVMLocations
{
    <#
    .SYNOPSIS
        Retrieves the folder and resource pool settings.

    .DESCRIPTION
        Saves the folder and resource pool settings for the passed cluster to a JSON file

    .EXAMPLE
        Get-ClusterVMLocationss -clusterName 'sfo-m01-cl01'
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [String]$clusterName
        )
    Try
    {

        $clusterVMs = Get-Cluster -Name $clusterName | Get-VM | Select-Object Name, id, folder, resourcePool    
        $allVMs = @()
        Foreach ($vm in $clusterVMs)
        {
            $vmSettings = @()
            $vmSettings += [pscustomobject]@{
                'name' = $vm.name
                'id' = $vm.id
                'folder' = $vm.folder.name
                'resourcePool' = $vm.resourcePool.name
            }
            $allVMs += $vmSettings
        }
        $allVMs | ConvertTo-Json -depth 10 | Out-File "$clusterName-vmLocations.json"
    }
    Catch
    {
        catchWriter -object $_
    }
}

Function Get-ClusterDRSGroupsAndRules
{
        <#
    .SYNOPSIS
        Retrieves the DRS Groups And Rules for a Cluster

    .DESCRIPTION
        Saves the DRS Group and Rule settings for the passed cluster to a JSON file 

    .EXAMPLE
        Get-ClusterDRSGroupsAndRules -clusterName "sfo-m01-cl01"
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [PSObject]$clusterName
        )
    Try
    {
        $retrievedVmDrsGroups = Get-DrsClusterGroup -cluster $clusterName
        $drsGroupsObject = @()
        Foreach ($drsGroup in $retrievedVmDrsGroups)
        {
            $drsGroupsObject += [pscustomobject]@{
            'name' = $drsGroup.name
            'type' = [STRING]$drsGroup.GroupType
            'vmNames' = $drsGroup.Member.name -join (",")
            }
        }
        
        #$drsGroupsObject | ConvertTo-Json -depth 10

        $retrievedDrsRules = Get-DrsRule -type VMAffinity -Cluster $clusterName
        $vmAffinityRulesObject = @()
        Foreach ($drsRule in $retrievedDrsRules)
        {
            $vmNames =@()
            Foreach ($vmId in $drsRule.vmids)
            {
                $vmName = (Get-Cluster -name $clusterName | Get-VM | Where-Object {$_.id -eq $vmId}).name
                $vmNames += $vmName    
            }
            $vmNames = $vmNames -join (",")
            $vmAffinityRulesObject += [pscustomobject]@{
                'name' = $drsrule.name
                'type' = [String]$drsRule.type
                'vmNames' = $vmNames
            }
        }
        #$vmAffinityRulesObject | ConvertTo-Json -depth 10

        $retrievedDrsRules = Get-DrsRule -type VMAntiAffinity -Cluster $clusterName
        $vmAntiAffinityRulesObject = @()
        Foreach ($drsRule in $retrievedDrsRules)
        {
            $vmNames =@()
            Foreach ($vmId in $drsRule.vmids)
            {
                $vmName = (Get-Cluster -name $clusterName | Get-VM | Where-Object {$_.id -eq $vmId}).name
                $vmNames += $vmName    
            }
            $vmNames = $vmNames -join (",")
            $vmAntiAffinityRulesObject += [pscustomobject]@{
                'name' = $drsrule.name
                'type' = [String]$drsRule.type
                'vmNames' = $vmNames
            }
        }
        #$vmAntiAffinityRulesObject | ConvertTo-Json -depth 10

        $retrievedDrsRules = Get-DrsRule -type VMHostAffinity -Cluster $clusterName
        $VMHostAffinityRulesObject = @()
        Foreach ($drsRule in $retrievedDrsRules)
        {
            $vmNames =@()
            Foreach ($vmId in $drsRule.vmids)
            {
                $vmName = (Get-Cluster -name $clusterName | Get-VM | Where-Object {$_.id -eq $vmId}).name
                $vmNames += $vmName    
            }
            $vmNames = $vmNames -join (",")
            $VMHostAffinityRulesObject += [pscustomobject]@{
                'name' = $drsrule.name
                'variant' = If ($drsRule.ExtensionData.Mandatory -eq $true){If ($drsRule.ExtensionData.AffineHostGroupName) {"Must"} else {"MustNot"}} else {If ($drsRule.ExtensionData.AffineHostGroupName) {"Should"} else {"ShouldNot"}}
                'vmGroupName' = $drsRule.ExtensionData.VmGroupName
                'hostGroupName' = If ($drsRule.ExtensionData.AffineHostGroupName) {$drsRule.ExtensionData.AffineHostGroupName} else {$drsRule.ExtensionData.AntiAffineHostGroupName}
            }
        }
        #$VMHostAffinityRulesObject | ConvertTo-Json -depth 10

        $dependencyRules = (Get-Cluster -Name $clusterName).ExtensionData.Configuration.Rule | Where-Object {$_.DependsOnVmGroup}
        $vmToVmDependencyRulesObject = @()
        Foreach ($dependencyRule in $dependencyRules)
        {
             $vmToVmDependencyRulesObject += [pscustomobject]@{
                'name' = $dependencyRule.name
                'vmGroup' = $dependencyRule.vmGroup
                'DependsOnVmGroup' = $dependencyRule.DependsOnVmGroup
            }
        }
        #$vmToVmDependencyRulesObject | ConvertTo-Json -depth 10

        $drsBackup += [pscustomobject]@{
            'vmDrsGroups' = $drsGroupsObject
            'vmAffinityRules' = $vmAffinityRulesObject
            'vmAntiAffinityRules' = $vmAntiAffinityRulesObject
            'vmHostAffinityRules' = $VMHostAffinityRulesObject
            'vmToVmDependencyRules' = $vmToVmDependencyRulesObject

        }
         $drsBackup | ConvertTo-Json -depth 10  | Out-File "$clusterName-drsConfiguration.json"
    }
    Catch
    {
        catchWriter -object $_
    }
}

#EndRegion vCenter Functions

#Region NSXT Functions
Function createHeader 
{
    Param(
    [Parameter (Mandatory=$true)]
    [String] $username,
    [Parameter (Mandatory=$true)]
    [String] $password
    )
    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $username,$password))) # Create Basic Authentication Encoded Credentials
    $headers = @{"Accept" = "application/json"}
    $headers.Add("Authorization", "Basic $base64AuthInfo")
    
    Return $headers
}

Function ResponseException
{
    #Get response from the exception
    $response = $_.exception.response
    if ($response) {
        $responseStream = $_.exception.response.GetResponseStream()
        $reader = New-Object system.io.streamreader($responseStream)
        $responseBody = $reader.readtoend()
        $errorString = "Exception occured calling invoke-restmethod. $($response.StatusCode.value__) : $($response.StatusDescription) : Response Body: $($responseBody)"
    }
    else {
        Throw $_
    }
    Return $errorString
}

Function Resolve-PhysicalHostTransportNodes
{
    Param(
    [Parameter (Mandatory=$true)][String] $vCenterFQDN,
    [Parameter (Mandatory=$true)][String] $vCenterAdmin,
    [Parameter (Mandatory=$true)][String] $vCenterAdminPassword,
    [Parameter (Mandatory=$true)][String] $clusterName,
    [Parameter (Mandatory=$true)][String] $nsxManager,
    [Parameter (Mandatory=$true)][String] $username,
    [Parameter (Mandatory=$true)][String] $password
    )
    $vCenterConnection = Connect-VIServer -server $vCenterFQDN -username $vCenterAdmin -password $vCenterAdminPassword
    Write-Output "Getting Hosts for Cluster $clusterName"
    $clusterHosts = (Get-Cluster -name $clusterName | Get-VMHost).name
    
    $headers = createHeader -username $username -password $password
    
    #Get TransportNodes
    $uri = "https://$nsxManager/api/v1/transport-nodes/"
    Write-Output "Getting Transport Nodes from $nsxManager"
    $transportNodeContents = (Invoke-WebRequest -Method GET -URI $uri -ContentType application/json -headers $headers).content | ConvertFrom-Json
    $allHostTransportNodes = ($transportNodeContents.results | Where-Object {($_.resource_type -eq "TransportNode") -and ($_.node_deployment_info.os_type -eq "ESXI")})
    Write-Output "Filtering Transport Nodes to members of cluster $clusterName"
    $hostIDs = ($allHostTransportNodes |  Where-Object {$_.display_name -in $clusterHosts}).id

    #Resolve Hosts
    Foreach ($hostID in $hostIDs)
    {
        $body = "{`"id`":5726703,`"method`":`"resolveError`",`"params`":[{`"errors`":[{`"user_metadata`":{`"user_input_list`":[]},`"error_id`":26080,`"entity_id`":`"$hostID`"}]}]}"
        $uri =  "https://$nsxManager/nsxapi/rpc/call/ErrorResolverFacade"
        Write-Output "Resolving NSX Installation on $(($allHostTransportNodes | Where-Object {$_.id -eq $hostID}).display_name) "
        $response = Invoke-WebRequest -Method POST -URI $uri -ContentType application/json -headers $headers -body $body
    }    
}
#EndRegion NSXT Functions

