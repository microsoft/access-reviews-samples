# This material is provided "AS-IS" and has no warranty.
# 
# Last updated October 2020
#
# Read the Terms of Use on https://github.com/microsoft/access-reviews-samples


#region AuthToken

#This was borrowed from Mark's sample at https://techcommunity.microsoft.com/t5/azure-active-directory/example-how-to-create-azure-ad-access-reviews-using-microsoft/m-p/807241
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

#endregion

#We define two arrays that we collect the external identities in that have either never logged on, or signed in a long time ago.
$_guestsOutsideCutOff = @()
$_guestsNeverSignedIn = @()


<#
 .Synopsis
  Finds external identities (Guests) in your tenant and checks when they have last signed in to your tenant.

 .Description
  Finds external identities (Guests) in your tenant and checks when they have last signed in to your tenant. For external identities that have never signed in to your tenant or longer ago than 'staleDays', they are added as members to a newly created group. This group can then be used for an Access Review.

 .Parameter staleDays
  The number of days that external identities can not have signed in, without being found by the script. (Default 180)

 .Parameter createReviewGroups
  Indicates whether security groups will be automatically created in your tenant, that will contain the found users that have never or a long time ago signed into your tenant. (Default $false)

 .Parameter scheduleReviews
  Indicates whether Access Reviews are scheduled for the newly created groups that contain stale external identities. (Default $false)

 .Parameter JSONPath
  The literal (exact) path to a JSON file that describes how the Access Review must be created.

 .Example
   # Show a external identities that never signed in or have signed in more than 60 days ago on the console.
   Find-AzureADStaleExternals $_SampleInternalAuthNHeaders 60

 .Example
   # Find external identities that have never signed in or have signed in more than 120 days ago and put them into new security groups. Don't schedule Access Reviews.
   Find-AzureADStaleExternals $_SampleInternalAuthNHeaders 60 -createReviewGroups $true

 .Example
   # Find external identities that have never signed in or have signed in more than 120 days ago and put them into new security groups. Schedule Access Reviews - and find the definition for the Access Review in c:\AccessReviews\template.JSON.
   Find-AzureADStaleExternals $_SampleInternalAuthNHeaders 60 -createReviewGroups $true -scheduleReviews $true -JSONPath "C:\AccessReviews\template.JSON"
#>
function Find-AzureADStaleExternals($authHeaders, $staleDays=180, $createReviewGroups=$false, $scheduleReviews=$false, $JSONPath = "C:\temp\CreateJSON.json")
{
    ##Make sure $staleDays is in sensible boundaries.
    if(($staleDays >180) -or ($staleDays -eq $null))
    { $staleDays = 180 }
    else
    { $cutOffDate = (Get-Date (Get-Date).AddDays(-$staleDays) -Format s) + "Z" }

    ##This is the Graph Call for getting all external identities. 
    $listURL = 'https://graph.microsoft.com/beta/users?$select=id,displayName,userprincipalname,userType,signInActivity&$filter=userType eq ''Guest'''
   
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
    ##$data.count
    ##For every external identity that we found, let's loop through the list and check (a) if they do NOT have a lastSignInDateTime = they never signed in, (b) if the date is beyond the threshold for stale days.
    foreach($d in $data)
    {
        if(($d.signInActivity.lastSignInDateTime -eq $null) -or ($d.signInActivity.lastSignInDateTime -eq ""))
        {
            # add them to the array.
            $_guestsNeverSignedIn = $_guestsNeverSignedIn + $d.id
        }
        else
        {
            if($d.signInActivity.lastSignInDateTime -lt $cutOffDate)
            {
                ##add them to the array.
                $_guestsOutsideCutOff = $_guestsOutsideCutOff + $d.id
            }
        }
        #for debugging
        #Write-Host $d.id
        #Write-Host $d.signInActivity.lastSignInDateTime
    }

    ##If the caller wants us to create the review groups for them, we'll call the methods below.
    if($createReviewGroups)
    {
        $neverSignedInGroupObjectID = Add-NeverSignedInGroup $authHeaders
        $beyondCutOffDAysGroupObjectID = Add-BeyondCutOffDaysGroup $authHeaders $staleDays
    }
    else {
        Write-Host "External identities that have not logged on in the last $staleDays days: $($_guestsOutsideCutOff.Count)"
        Write-Host $_guestsOutsideCutOff
        Write-Host "---------------------------------"
        Write-Host "External identities that have never logged on in your tenant: $($_guestsNeverSignedIn.Count)"
        Write-Host $_guestsNeverSignedIn
    }

    #if the caller wants us to create the Access Reviews for them, we'll call the methods below.
    if($scheduleReviews)
    {
        if($_guestsNeverSignedIn.Count -gt 0) { Create-AzureADARScheduleDefinition $authHeaders $JSONPath $neverSignedInGroupObjectID "never" }
        if($_guestsOutsideCutOff.Count -gt 0) { Create-AzureADARScheduleDefinition $authHeaders $JSONPath $beyondCutOffDAysGroupObjectID "beyond" }
    }
}

function Add-NeverSignedInGroup($authHeaders)
{
        #Let's see if we even found external identities that never signed in
        if($_guestsNeverSignedIn.Count -gt 0)
        {
            #Set the name for the newly created group. We have a name and a date suffix: REVIEW_GUESTS_NEVER_SIGNED_IN_23-OCT-2020
            $groupNameNeverSignedIn = "REVIEW_GUESTS_NEVER_SIGNED_IN_$(Get-Date -Format 'dd-MMM-yyyy')"
            
            $createGroupURI = 'https://graph.microsoft.com/v1.0/groups'

            #We want to create a new group, so this will be a POST with the following group properties: security group that is not mail enabled
            $createGroupBody = "{""groupTypes"":[],""description"":""Automatically created group that contains external identities (aka Guests) that have never logged on."",""displayName"":""$groupNameNeverSignedIn"",""mailenabled"":false,""securityEnabled"":true,""mailNickName"":""$groupNameNeverSignedIn"",""members@odata.bind"": ["
            
            #we are adding all the members to the call body for Graph, so that we can commit the new group creation + all members in the same call.
            foreach($user in $_guestsNeverSignedIn)
            {
                $createGroupBody = $createGroupBody + """https://graph.microsoft.com/v1.0/users/$user"","
            }
            $createGroupBody = $createGroupBody.TrimEnd(",")
            $createGroupBody = $createGroupBody + "] }"
            #$createGroupBody = $createGroupBody | ConvertTo-Json
            
            #Create the group with its members. It's a POST this time. NOTE that the Service Principal needs Groups.Create and GroupMember.ReadWrite.All in the tenant.
            $createGroupResponse = Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $createGroupURI -Method Post -Body $createGroupBody -ContentType "application/json"
            if ($createGroupResponse -eq $null -or $createGroupResponse.Content -eq $null) {
                throw "ERROR: We did not get a response from $createGroupURI"
            }
            
            if($createGroupResponse.StatusCode -eq 201)
            {
                Write-Host "Created group with name $groupNameNeverSignedIn with $($_guestsNeverSignedIn.Count) members."
                $parsedJSON = ConvertFrom-Json $createGroupResponse.Content
                return $parsedJSON.ID
            }
            else { throw "We could not create the group."}
        }
}

function Add-BeyondCutOffDaysGroup($authHeaders, $staleDays)
{
    if($_guestsOutsideCutOff.Count -gt 0)
        {
            $groupNameOutsideCutOff = "REVIEW_GUESTS_NOT_SIGNED_IN_LAST_$($staleDays)_DAYS_$(Get-Date -Format 'dd-MMM-yyyy')"

            $createGroupURI2 = 'https://graph.microsoft.com/v1.0/groups'

            #We want to create a new group, so this will be a POST with the following group properties: security group that is not mail enabled
            $createGroupBody2 = "{""groupTypes"":[],""description"":""Automatically created group that contains external identities (aka Guests) that have never logged on."",""displayName"":""$groupNameOutsideCutOff"",""mailenabled"":false,""securityEnabled"":true,""mailNickName"":""$groupNameOutsideCutOff"",""members@odata.bind"": ["
            foreach($users in $_guestsOutsideCutOff)
            {
                $createGroupBody2 = $createGroupBody2 + """https://graph.microsoft.com/v1.0/users/$users"","
            }
            $createGroupBody2 = $createGroupBody2.TrimEnd(",")
            $createGroupBody2 = $createGroupBody2 + "] }"

            #Create the group with its members. It's a POST this time. NOTE that the Service Principal needs Groups.Create and GroupMember.ReadWrite.All in the tenant.            
            $createGroupResponse2 = Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $createGroupURI2 -Method Post -Body $createGroupBody2 -ContentType "application/json"
            if ($createGroupResponse2 -eq $null -or $createGroupResponse2.Content -eq $null) {
                throw "ERROR: We did not get a response from $createGroupURI2"
            }
            
            if($createGroupResponse2.StatusCode -eq 201)
            {
                Write-Host "Created group with name $groupNameOutsideCutOff with $($_guestsOutsideCutOff.Count) members."
                $parsedJSON = ConvertFrom-Json $createGroupResponse2.Content
                return $parsedJSON.ID
            }
            else { throw "We could not create the group."}
        }
}

function Create-AzureADARScheduleDefinition($authHeaders, $JSONPath, $groupObjectID, $groupType)
{
    #The JSON Path points us to a text file that has JSON-formatted content. It outlines a template to create an Access Review.
    #If we can't find a file in the path we were given, let's throw an error. We expect a file there and it should be JSON.
    if(-not $(Test-Path -LiteralPath $JSONPath -PathType Leaf))
    {
        throw "ERROR: File $($JSONPath) does not exist or cannot be found. Please enter a valid path to a JSON-formatted file, such as 'C:\temp\ARSamples\create-access-review.JSON'"
    }

    #Let's see if the file contents is JSON formatted. If it's not, let's throw an error and stop.
    $createJSON = Get-Content $JSONPath
    #depending on which group we're creating this review for, we want to replace variables in the template with sensible description(s)
    switch ($groupType)
    {
        "never" 
        {
            $createJSON = $createJSON.Replace("<<MYREVIEW>>", "Review of external identities that have never signed in.")
            $createJSON = $createJSON.Replace("<<MYREVIEW-ADMINDESC>>", "This review was automatically generated by a script. It reviews an also auto-created security group that contains external identities (guests) that have never logged on to your tenant.")
            $createJSON = $createJSON.Replace("<<MYREVIEW-REVIEWERDESC>>", "Please review your continued need to access this tenant.")
        }
        "beyond"
        {
            $createJSON = $createJSON.Replace("<<MYREVIEW>>", "Review of external identities that have not signed in a long time")
            $createJSON = $createJSON.Replace("<<MYREVIEW-ADMINDESC>>", "This review was automatically generated by a script. It reviews an also auto-created security group that contains external identities (guests) that have not logged on to your tenant for a long time.")
            $createJSON = $createJSON.Replace("<<MYREVIEW-REVIEWERDESC>>", "Please review your continued need to access this tenant.")
        }
    }

    ##replace start and end dates for the review. We do a 30-day review.
    $startDate = Get-Date -format "yyyy-MM-dd"
    $endDate = (Get-Date).AddDays(30).ToString("yyyy-MM-dd")
    $createJSON = $createJSON.Replace("<<START-DATE>>", $startDate)
    $createJSON = $createJSON.Replace("<<END-DATE>>", $endDate)

    ##fill in the objectID of the group we just created. We want to review that group.
    $createJSON = $createJSON.Replace("<<groupID>>", $groupObjectID)

    $createURL = 'https://graph.microsoft.com/beta/identityGovernance/accessReviews/definitions'

    $createResponse = Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Body $createJSON -Uri $createURL -Method POST

    if ($createResponse -eq $null -or $createResponse.Content -eq $null) {
        throw "ERROR: We did not get a response from $createURL"
     }

    if($createResponse.StatusCode -eq "201")
    {
        $data = ConvertFrom-JSON $createResponse
        Write-Host "Access Review $($data.ID) created. It is currently in status $($data.status)"
    }
    else
    {
        throw "ERROR: Could not create new Access Review schedule definition"
    }

} 

Connect-AzureADMSARSample -ClientApplicationId "54ed4c91-7c8a-444e-9af3-05045b8e8994" -ClientSecret "oaP1M29YDnU_i_-1p4fpl7-d6876wijZgB" -TenantDomain "frickelsoftnet.onmicrosoft.com"
Find-AzureADStaleExternals $_SampleInternalAuthNHeaders -staleDays 60 -createReviewGroups $true -scheduleReviews $true -JSONPath "C:\temp\CreateJSON.json"
