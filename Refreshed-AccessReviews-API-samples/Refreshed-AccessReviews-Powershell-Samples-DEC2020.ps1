function Get-GraphExampleAuthTokenServicePrincipal {
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        $ClientId,

        [Parameter(Mandatory = $true)]
        $ClientSecret,

        [Parameter(Mandatory = $true)]
        $TenantDomain
    )


    $tenant = $TenantDomain
    

    Write-Verbose "Checking for AzureAD module..."

    $AadModule = Get-Module -Name "AzureAD" -ListAvailable
    if ($AadModule -eq $null) {
        write-verbose "AzureAD PowerShell module not found, looking for AzureADPreview"
        $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable
    }

    if ($AadModule -eq $null) {
        write-output
        write-error "AzureAD Powershell module not installed..."
        write-output "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt"
        write-output "Script can't continue..."
        write-output
        return ""
    }
     # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version

    if ($AadModule.count -gt 1) {
        write-verbose "multiple module versions"
        $Latest_Version = ($AadModule | select version | Sort-Object)[-1]
        $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }
        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    }

    else {
        write-verbose "single module version"
        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    }

    Write-verbose "loading $adal and $adalforms"


    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null

    write-verbose "DLLs loaded"
  
    # $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    $resourceAppIdURI = "https://graph.microsoft.com"

    $authority = "https://login.microsoftonline.com/$Tenant"

    try {
        write-verbose "instantiating ADAL objects for $authority"
        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

        write-verbose "client $ClientId $clientSecret"

        $clientCredential = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential" -ArgumentList ($ClientId,$ClientSecret)
 
        write-verbose "acquiring token for $resourceAppIdURI"
        #   AuthenticationResult authResult = await authContext.AcquireTokenAsync(BatchResourceUri, new ClientCredential(ClientId, ClientKey));
        # if you get an error about PowerShell not being able to find this method with 2 parameters, it means there is another version of ADAL DLL already in the process space of your PowerShell environment.

        $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientCredential).Result
        # If the accesstoken is valid then create the authentication header
        if ($authResult.AccessToken) {
            write-verbose "acquired token"
            # Creating header for Authorization token
            $authHeader = @{
                'Content-Type' = 'application/json'
                'Authorization' = "Bearer " + $authResult.AccessToken
                'ExpiresOn' = $authResult.ExpiresOn
            }
            return $authHeader
        }
        else {
            write-output ""
            write-output "Authorization Access Token is null, please re-run authentication..."
            write-output ""
            break
        }
    }
    catch {
        write-output $_.Exception.Message
        write-output $_.Exception.ItemName
        write-output ""
        break
    }   
}
#endregion

$_instanceIDs = @()

# exported module member
function Connect-AzureADMSARSample { 
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true)]
    [ValidateScript({
        try {
            [System.Guid]::Parse($_) | Out-Null
            $true
        } catch {
            throw "$_ is not a valid GUID"
        }
    })]
    [string]$ClientApplicationId,

    [Parameter(Mandatory=$true)]
    [string]$ClientSecret,  # base64 client secret.  Note this as a command line parameter is for testing purposes only

    [Parameter(Mandatory=$true)]
    [string]$TenantDomain # e.g., microsoft.onmicrosoft.com
    )
   
    $script:_SampleInternalAuthNHeaders = @()


    $authHeaders = Get-GraphExampleAuthTokenServicePrincipal -ClientId $ClientApplicationId -ClientSecret $ClientSecret -TenantDomain $TenantDomain

    $script:_SampleInternalAuthNHeaders = $authHeaders

}


function Get-InternalAuthNHeaders {
  [CmdletBinding()]
  param()
  
    try {
    
        $authResult = $script:_SampleInternalAuthNHeaders
        if ($authResult.Length -eq @()) {
             Throw "Connect-AzureADMSARSample must be called first"   
        }
  
    } catch {
        Throw # "Connect-AzureADMSControls must be called first"
    }
    return $authResult
}


<#
 .Synopsis
  Gets the definition (blueprint) of an Access Review and displays its status, creation date and creator.

 .Description
  Gets the definition of an Access Review and displays its status, creation date and creator.

 .Parameter definitionID
  The ID of an Access Review, as seen from the Azure AD Portal.

 .Example
   Get-AzureADARDefinition -definitionID "a66c337b-6344-4661-a41b-a04e492baa44"
#>
function Get-AzureADARDefinition()
{
    #Parameter bindings - we expect authHeaders and definitionID.
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipelineByPropertyName)]$authHeaders,
        [Parameter(ValueFromPipelineByPropertyName)]$definitionID
    )


    #Let's build the call for Microsoft Graph.
    $definitionURL = "https://graph.microsoft.com/beta/identityGovernance/accessReviews/definitions/$definitionID"
   

    $definitionResponse = Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $definitionURL -Method Get

    #See if the response makes sense and if there's a response:
    if ($definitionResponse -eq $null -or $definitionResponse.Content -eq $null) {
        throw "ERROR: We did not get a response from $definitionURL"
     }
    
    #bring the results into a right format. We convert it to a PSObject, so we can pipe.
    $definitionResult = ConvertFrom-Json $definitionResponse.Content
    $result = New-Object PSCustomObject
    $result | Add-Member NoteProperty "definitionID" $definitionResult.id
    $result | Add-Member NoteProperty "displayName" $definitionResult.displayName
    $result | Add-Member NoteProperty "status" $definitionResult.status
    $result | Add-Member NoteProperty "createdBy" $definitionResult.createdBy.displayName
    $result | Add-Member NoteProperty "createdDateTime" $definitionResult.createdDateTime
    $result | Add-Member NoteProperty "authHeaders" $authHeaders

    $result 
}

<#
 .Synopsis
  Gets the definition for all Access Reviews, and displays their status, creation dates and creators.

 .Description
  Gets the definition for all Access Reviews, and displays their status, creation dates and creators. Will display 20 Access Reviews by default.

 .Parameter top
  The number of Access Reviews to return.

 .Example
   Get-AzureADARDefinition -top 15
#>
function Get-AzureADARAllDefinitions()
{
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipelineByPropertyName)]$authHeaders,
        [Parameter(ValueFromPipelineByPropertyName)][int]$top=20
    )

    #Let's build the call for Microsoft Graph.
    $allDefinitionsURL = "https://graph.microsoft.com/beta/identityGovernance/accessReviews/definitions"
    $allDefinitionsURL = $allDefinitionsURL + '/?$top=' + $top

    $allDefinitionResponse = Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $allDefinitionsURL -Method Get

    #See if the response makes sense and if there's a response:
    if ($allDefinitionResponse -eq $null -or $allDefinitionResponse.Content -eq $null) {
        throw "ERROR: We did not get a response from $alldefinitionsURL"
     }
    
    # Pull the result set and convert it back from the result JSON.
    $allDefinitionsResult = ConvertFrom-Json $allDefinitionResponse.Content
    $resultSet = @()
    New-Object PsCustomObject

    #bring the results into a right format. We convert it to a PSObject, so we can pipe.
    foreach($def in $allDefinitionsResult.Value)
    {
        $result = New-Object PSCustomObject
        $result | Add-Member NoteProperty "definitionID" $def.id
        $result | Add-Member NoteProperty "displayName" $def.displayName
        $resultSet += $result
    }
    $resultSet
}

<#
 .Synopsis
  Gets the instances for an Access Review.

 .Description
  Gets the instances for an Access Review. An instance could be individual reviews in a series or many reviews under one defintiion, such as "All O365 Groups with external identities".

 .Parameter top
  The number of Access Reviews to 

 .Example
   Get-AzureADARDefinition -definitionID "a66c337b-6344-4661-a41b-a04e492baa44"
#>
function Get-AzureADARInstancesFromDefinition()
{
    
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipelineByPropertyName)]$authHeaders,
        [Parameter(ValueFromPipelineByPropertyName)]$definitionID
    )

    #Let's build the call for Microsoft Graph.
    $listURL = "https://graph.microsoft.com/beta/identityGovernance/accessReviews/definitions/" + $definitionID + "/instances/"
    $listURL = $listURL + '?$top=20'
   
    $listResponse = Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $listURL -Method Get

    if ($listResponse -eq $null -or $listResponse.Content -eq $null) {
        throw "ERROR: We did not get a response from $listURL"
     }
    
    $listResult = ConvertFrom-Json $listResponse.Content
    $data = $listResult.Value

    #Let's check if Graph told us there are more results for us to fetch. If so, let's loop through the results until we have all.
    while($listResult.'@odata.nextLink')
    {
       $nextURL = $listResult.'@odata.nextLink'

        $listResponse = Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $nextURL -Method Get

        if ($listResponse -eq $null -or $listResponse.Content -eq $null) {
          #  throw "ERROR: We did not get a response from $nextURL"
        }
    
        $listResult = ConvertFrom-Json $listResponse.Content
        $data += $listResult.Value
    }

    #Let us bring the results into a format that can be used with Pipe.
    $instanceResults = @()
    foreach($inst in $listResult.Value)
    {
        $result = New-Object PSCustomObject
        $result | Add-Member NoteProperty "definitionID" $definitionID
        $result | Add-Member NoteProperty "instanceID" $inst.id
        $result | Add-Member NoteProperty "status" $inst.status
        $result | Add-Member NoteProperty "authHeaders" $authHeaders
        $instanceResults += $result
    }
    $instanceResults
}

<#
 .Synopsis
  Gets the instance details for an instance of an Access Review.

 .Description
  Gets the details of an instance of an Access Review. Details include the status and the results of the instance.

 .Parameter definitionID
  The definition ID for the Access Review as seen from the Azure AD Portal.

 .Parameter instanceID
  The instanceID for an Access Review that you are interested in inspecting deeply.

 .Example
   Get-AzureADARDefinition -definitionID "a66c337b-6344-4661-a41b-a04e492baa44" -instanceID "a66c337b-6344-4661-a41b-a04e492baa44"
#>
function Get-AzureADInstanceDetails()
{

    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipelineByPropertyName)]$authHeaders,
        [Parameter(ValueFromPipelineByPropertyName)]$definitionID,
        [Parameter(ValueFromPipelineByPropertyName)]$instanceID
    )

        
    #Let's build the call for Microsoft Graph.
    $instanceURL = "https://graph.microsoft.com/beta/identityGovernance/accessReviews/definitions/" + $definitionID + "/instances/" + $instanceID
   
    $instanceResponse = Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $instanceURL -Method Get

    if ($instanceResponse -eq $null -or $instanceResponse.Content -eq $null) {
        throw "ERROR: We did not get a response from $instanceURL"
     }
    
    #Let us bring the results into a format that can be used with Pipe.
    $instanceResult = ConvertFrom-Json $instanceResponse.Content
    $result = New-Object PSCustomObject
    $result | Add-Member NoteProperty "definitionID" $definitionID
    $result | Add-Member NoteProperty "instanceID" $instanceResult.id
    $result | Add-Member NoteProperty "status" $instanceResult.status
    $result | Add-Member NoteProperty "authHeaders" $authHeaders

    $result
}

<#
 .Synopsis
  Gets the decisions that reviews submitted for an Access Review instance.

 .Description
  Gets the decisions for an instance of an Access Review. Decision details include the decision taken, the reviewer and whent he review was recorded - and also what the system recommendation was.

 .Parameter definitionID
  The definition ID for the Access Review as seen from the Azure AD Portal.

 .Parameter instanceID
  The instanceID for an Access Review that you are interested in inspecting deeply.

 .Example
   Get-AzureADARDefinition -definitionID "a66c337b-6344-4661-a41b-a04e492baa44" -instanceID "a66c337b-6344-4661-a41b-a04e492baa44"
#>
function Get-AzureADDecisionsFromInstance()
{

    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipelineByPropertyName)]$authHeaders,
        [Parameter(ValueFromPipelineByPropertyName)]$definitionID,
        [Parameter(ValueFromPipelineByPropertyName)]$instanceID
    )

        
    #Let's build the call for Microsoft Graph.
    $listDecisionsURL = "https://graph.microsoft.com/beta/identityGovernance/accessReviews/definitions/" + $definitionID + "/instances/" + $instanceID + "/decisions/"
    $listDecisionsURL = $listDecisionsURL + '?$top=10'
   
    $listDecisionsResponse = Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $listDecisionsURL -Method Get

    if ($listDecisionsResponse -eq $null -or $listDecisionsResponse.Content -eq $null) {
        throw "ERROR: We did not get a response from $listDecisionsURL"
     }
     $listDecisionsResult = ConvertFrom-Json $listDecisionsResponse.Content
     $data = $listDecisionsResult.Value
 
     #Let's check if Graph told us there are more results for us to fetch. If so, let's loop through the results until we have all.
     while($listDecisionsResult.'@odata.nextLink')
     {
        $nextDecisionURL = $listDecisionsResult.'@odata.nextLink'
 
         $listDecisionsResponse = Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $nextDecisionsURL -Method Get
 
         if ($listDecisionsResponse -eq $null -or $listDecisionsResponse.Content -eq $null) {
           #  throw "ERROR: We did not get a response from $nextURL"
         }
     
         $listDecisionsResult = ConvertFrom-Json $listDecisionsResponse.Content
     }
    
    $instancedecisionResults = @()

    #Let us bring the results into a format that can be used with Pipe.
    New-Object PsCustomObject
    foreach($dec in $listDecisionsResult.Value)
    {
        $result = New-Object PSCustomObject
        ##$result | Add-Member NoteProperty "definitionID" $definitionID
        ##$result | Add-Member NoteProperty "instanceID" $instanceID
        $result | Add-Member NoteProperty "decisionID" $dec.id
        $result | Add-Member NoteProperty "decision" $dec.decision
        $result | Add-Member NoteProperty "recommendation" $dec.recommendation
        $result | Add-Member NoteProperty "target" $dec.target.userDisplayName
        $result | Add-Member NoteProperty "reviewedBy" $dec.reviewedBy.displayName
        $instancedecisionResults += $result
    }
    $instancedecisionResults
}

<#
 .Synopsis
  Gets a few statistics from an Access Review instance and its decisions.

 .Description
  Gets a few statistics from an Access Review instance and its decisions. It returns the accpetance/decline rate for reviewed users - and how reviewers responded.

 .Parameter definitionID
  The definition ID for the Access Review as seen from the Azure AD Portal.

 .Parameter instanceID
  The instanceID for an Access Review that you are interested in inspecting deeply.

 .Example
   Get-AzureADARDefinition -definitionID "a66c337b-6344-4661-a41b-a04e492baa44" -instanceID "a66c337b-6344-4661-a41b-a04e492baa44"
#>
function Get-AzureADInstanceStatistics($authHeaders, $definitionID, $instanceID)
{
        
    #Let's build the call for Microsoft Graph.
    $getDecisionsURL = "https://graph.microsoft.com/beta/identityGovernance/accessReviews/definitions/" + $definitionID + "/instances/" + $instanceID + "/decisions/"
    $getDecisionsURL = $getDecisionsURL + '?$top=10'
   
    $getDecisionsResponse = Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $getDecisionsURL -Method Get

    if ($getDecisionsResponse -eq $null -or $getDecisionsResponse.Content -eq $null) {
        throw "ERROR: We did not get a response from $getDecisionsURL"
     }
     $getDecisionsResult = ConvertFrom-Json $getDecisionsResponse.Content
     $data = $getDecisionsResult.Value
 
     #Let's check if Graph told us there are more results for us to fetch. If so, let's loop through the results until we have all.
     while($getDecisionsResult.'@odata.nextLink')
     {
        $nextDecisionURL = $getDecisionsResult.'@odata.nextLink'
 
         $getDecisionsResponse = Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $nextDecisionsURL -Method Get
 
         if ($getDecisionsResponse -eq $null -or $getDecisionsResponse.Content -eq $null) {
           #  throw "ERROR: We did not get a response from $nextURL"
         }
     
         $getDecisionsResult = ConvertFrom-Json $getDecisionsResponse.Content
         $data += $getDecisionsResult.Value
     }

     #collected the decision results - now let's parse them and display them.

     Write-Host "Statistics for this review:"
     Write-Host "There are $($data.Count) decisions."
     
     #declare a few variables:
     $approved = @{}
     $denied = @{}
     $dontknow = @{}
     $matchRecommendation = 0
     $justificationCount = 0
     $justificationChars = 0

     #Let's loop through the decisions - and process them into "approve/deny" buckets.
     foreach($d in $data)
     {
        switch($d.decision)
        {
            "Approve" { if($approved.Contains($d.reviewedBy.id)) { $approved[$d.reviewedBy.id]++ } else { $approved.Add($d.reviewedBy.ID, 1) }  }
            "Deny" { if($denied.Contains($d.reviewedBy.id)) { $denied[$d.reviewedBy.id]++ } else { $denied.Add($d.reviewedBy.ID, 1) } }
        }

        #in case the reviewer voted in line with the system recommendation.
        if($d.decision -eq $d.recommendation) { $matchRecommendation++ }

        #also, let's look at what the reviewer provided as a justification. What's the char number? Are they entering something sensible vs. random characters just to get past the box?
        if($d.justification -ne $null) { $justificationCount++; $justificationChars += $d.justification.Length }
     }

     
     $approvals = 0

     #Now, on to parsing, displaying the information we've gathered.
     foreach($a in $approved.Values) { $approvals = $approvals + $a }
     if($approvals -gt 0) { Write-Host "We had $approvals approvals ($($approvals/$($data.Count)*100)% approval rate)"; $approved }
     $denies = 0
     foreach($d in $denied.Values) { $denies = $denies + $d }
     if($denies -gt 0) { Write-Host "We had $denies deny decisions ($($denies/$($data.Count)*100) % denial rate)"; $denied }
     $justificationPercent = $justificationChars/$justificationCount
     Write-Host "There were $justificationCount justifications provided - with an average of $justificationPercent characters."

     ##reviewer statistics. 
}


Connect-AzureADMSARSample -ClientApplicationId "<clientID>" -ClientSecret "<client secret>" -TenantDomain "yourtenant.onmicrosoft.com"

#Get-AzureADARAllDefinitions $_SampleInternalAuthNHeaders -top 6
#Get-AzureADARInstancesFromDefinition $_SampleInternalAuthNHeaders "f255caaa-1c44-405f-870d-da4ca645db4a"
#Get-AzureADInstanceDetails $_SampleInternalAuthNHeaders "f255caaa-1c44-405f-870d-da4ca645db4a" "f56e2f4f-7fae-4852-949f-d2ef0d80dfd4"
#Get-AzureADDecisionsFromInstance $_SampleInternalAuthNHeaders "f255caaa-1c44-405f-870d-da4ca645db4a" "f56e2f4f-7fae-4852-949f-d2ef0d80dfd4"
#Get-AzureADInstanceStatistics $_SampleInternalAuthNHeaders "f255caaa-1c44-405f-870d-da4ca645db4a" "f56e2f4f-7fae-4852-949f-d2ef0d80dfd4"

#Export-ModuleMember Get-AzureADARAllDefinitions
#Export-ModuleMember Get-AzureADARDefinition
#Export-ModuleMember Get-AzureADARInstancesFromDefinition
#Export-ModuleMember Get-AzureADInstanceDetails
#Export-ModuleMember Get-AzureADDecisionsFromInstance