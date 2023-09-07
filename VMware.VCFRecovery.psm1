#Module to Assist in VCF Full Instance Recovery
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
    Write-Output "Getting Hosts for Cluster $cluster"
    $clusterHosts = (Get-Cluster -name $cluster | Get-VMHost).name
    
    $headers = createHeader -username $username -password $password
    
    #Get TransportNodes
    $uri = "https://$nsxManager/api/v1/transport-nodes/"
    Write-Output "Getting Transport Nodes from $nsxManager"
    $transportNodeContents = (Invoke-WebRequest -Method GET -URI $uri -ContentType application/json -headers $headers).content | ConvertFrom-Json
    $allHostTransportNodes = ($transportNodeContents.results | Where-Object {($_.resource_type -eq "TransportNode") -and ($_.node_deployment_info.os_type -eq "ESXI")})
    Write-Output "Filtering Transport Nodes to members of cluster $cluster"
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

#Region Execute
$vCenterFQDN = "sfo-w02-vc01.sfo.rainpole.io"
$vCenterAdmin = "Administrator@vsphere.local"
$vCenterAdminPassword = "VMw@re1!"
$cluster = "sfo-w02-cl01"
$esxiRootPassword = "VMw@re1!"
$nsxManager = "sfo-w02-nsx01a.sfo.rainpole.io"
$nsxAdmin = "admin"
$nsxAdminPassword = "VMw@re1!VMw@re1!"
$sddcManagerFQDN = "sfo-vcf01.sfo.rainpole.io"
$sddcManagerUser = "Administrator@vsphere.local"
$sddcManagerPassword = "VMw@re1!"


Resolve-PhysicalHostServiceAccounts -vCenterFQDN $vCenterFQDN -vCenterAdmin $vCenterAdmin -vCenterAdminPassword $vCenterAdminPassword -clusterName $clusterName -esxiRootPassword $esxiRootPassword
Resolve-PhysicalHostTransportNodes -vCenterFQDN $vCenterFQDN -vCenterAdmin $vCenterAdmin -vCenterAdminPassword $vCenterAdminPassword -clusterName $clusterName -nsxManager $nsxManager -username $nsxAdmin -password $nsxAdminPassword
#EndRegion Execute