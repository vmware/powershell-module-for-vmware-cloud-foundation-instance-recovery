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
    [Parameter (Mandatory=$true)][String] $esxiRootPassword
    )
    Connect-VIServer -server $vCenterFQDN -username $vCenterAdmin -password $vCenterAdminPassword
    $clusterHosts = Get-Cluster -name $clusterName | Get-VMHost
    Disconnect-VIServer * -confirm:$false

    Foreach ($hostInstance in $clusterHosts)
        {
            Connect-VIServer -Server $hostInstance.name -User root -Password VMw@re1!
            $esxiHostName =  $hostInstance.name.Split(".")[0]
            $svcAccountName = "svc-vcf-$esxiHostName"
            $accountExists = Get-VMHostAccount -Server $hostInstance.Name -User $svcAccountName -erroraction SilentlyContinue
            If (!$accountExists)
            {
                New-VMHostAccount -Id $svcAccountName -Password VMw@re1! -Description "ESXi User"
                New-VIPermission -Entity (Get-Folder root) -Principal $svcAccountName -Role Admin
                Disconnect-VIServer $hostInstance.name -confirm:$false
            }
    }

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
        Write-Host "[$($hostInstance.name)] Password Remediation $taskStatus"
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
    Connect-VIServer -server $vCenterFQDN -username $vCenterAdmin -password $vCenterAdminPassword
    $clusterHosts = Get-Cluster -name $clusterName | Get-VMHost
    Disconnect-VIServer * -confirm:$false
    Foreach ($hostInstance in $clusterHosts)
    {
        Connect-VIServer -Server $hostInstance.name -User root -Password $esxiRootPassword
        $esxiHostName =  $hostInstance.name.Split(".")[0]
        $svcAccountName = "svc-vcf-$esxiHostName"
        Set-VMHostAccount -UserAccount $svcAccountName -Password $svcAccountPassword -confirm:$false
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
    [Parameter (Mandatory=$true)][String] $nsxManager,
    [Parameter (Mandatory=$true)][String] $username,
    [Parameter (Mandatory=$true)][String] $password
    )
    $headers = createHeader -username $username -password $password
    
    #Get TransportNodes
    $uri = "https://$nsxManager/api/v1/transport-nodes/"
    $transportNodeContents = (Invoke-WebRequest -Method GET -URI $uri -ContentType application/json -headers $headers).content | ConvertFrom-Json
    $hostIDs = ($transportNodeContents.results | Where-Object {($_.resource_type -eq "TransportNode") -and ($_.node_deployment_info.os_type -eq "ESXI")}).id

    #Resolve Hosts
    Foreach ($hostID in $hostIDs)
    {
        $body = "{`"id`":5726703,`"method`":`"resolveError`",`"params`":[{`"errors`":[{`"user_metadata`":{`"user_input_list`":[]},`"error_id`":26080,`"entity_id`":`"$hostID`"}]}]}"
        $uri =  "https://$nsxManager/nsxapi/rpc/call/ErrorResolverFacade"
        $response = Invoke-WebRequest -Method POST -URI $uri -ContentType application/json -headers $headers -body $body
    }    
}
#EndRegion NSXT Functions

#Region Execute
$vCenterFQDN = "sfo-w02-vc01.sfo.rainpole.io"
$vCenterAdmin = "Administrator@vsphere.local"
$vCenterAdminPassword = "VMw@re1!"
$nsxManager = "sfo-w02-nsx01a.sfo.rainpole.io"
$nsxAdmin = "admin"
$nsxAdminPassword = "VMw@re1!VMw@re1!"
$esxiRootPassword = "VMw@re1!"

Resolve-PhysicalHostServiceAccounts -vCenterFQDN $vCenterFQDN -vCenterAdmin $vCenterAdmin -vCenterAdminPassword $vCenterAdminPassword -clusterName $clusterName -esxiRootPassword $esxiRootPassword
Resolve-PhysicalHostTransportNodes -nsxManager $nsxManager -username $nsxAdmin -password $nsxAdminPassword
#EndRegion Execute