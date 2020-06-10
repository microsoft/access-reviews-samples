# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.


#region AuthToken Handling

#Authentication sample from https://techcommunity.microsoft.com/t5/azure-active-directory/example-how-to-create-azure-ad-access-reviews-using-microsoft/m-p/807241
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

$_SampleInternalAuthNHeaders = @()
$_userList = @()

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
  Retrieves decisions for a single Access Review and displays Powershell commands for Windows Active Directory to be executed to apply Access Reviews results on-premises.

 .Description
  Retrieves the decisions for a single Access Review, identified by the reviewID. Checks whether the Access Review reviews an on-premises group and if so, loads the decisions for it. If there are "deny" decisions for users, it will display a Powershell command that removes denied users from the Windows Active Directory group. This is to apply Access Reviews decisions to on-premises groups.

 .Parameter reviewID
  This is the objectID of the Access Review

 .Parameter filePath
  This is the full file path for a TXT file that Powershell commands for Windows AD are written to.

 .Example
   # Retrieve changes for on-premises group membership from the results of an Access Review - and print Powershell commands:
   Get-AzureADARSignleReviewOnPrem -reviewId 

 .Example
   # Retrieve changes for on-premises group membership from the results of an Access Review - export the Powershell commands into a TXT file:
   Get-AzureADARSingleReviewOnPrem -reviewId "20924e60-a9fb-4891-9c92-f30c47636484" -filePath "C:\temp\WindowsADCommands.txt"

#>
function Get-AzureADARSingleReviewOnPrem
{
[CmdletBinding()]
    param(
        [Parameter()]
        [ValidateScript({
            try {
                [System.Guid]::Parse($_) | Out-Null
                $true
            } catch {
                throw "$_ is not a valid GUID"
            }
        })]
        [string]$reviewId,
        [Parameter()]
        [alias("fp")]
        [ValidateScript({Test-Path $_})]
        [string]
        $filePath
    )

    $callURL = "https://graph.microsoft.com/beta/accessReviews/" + $reviewId
    $callURL += '/?$select=status,reviewedEntity'

    $response = Invoke-WebRequest -UseBasicParsing -headers $_SampleInternalAuthNHeaders -Uri $callURL -Method Get

    if ($response -eq $null -or $response.Content -eq $null) {
        throw "ERROR: We did not get a response from $callURL"
     }
    
    $result = ConvertFrom-Json $response.Content

    #Extract the status and the id from the Access Review that we've found. If the status is not "Completed", we should abort.
    if($result.Status -ne "Completed" -and $result.Status -ne "Applied")
        { throw "ERROR: The Access Review you requested is not completed. Check whether it is still running."}
    if($result.reviewedEntity.ID -eq $null -or $result.reviewedEntity.ID -eq "")
        { throw "ERROR: There's no reviewed resource." }

    #Now let's take a closer look at the group in question.
    $groupID = $result.reviewedEntity.ID
    
    $isGroupOnprem = Get-GroupByID $_SampleInternalAuthNHeaders $groupID ##if the group comes from on-premises, we are getting the SID from on-premises Windows AD back. Otherwise $null.
    if($isGroupOnprem -eq $null)
    {
        throw "The group is not from on-premises, aborting." #The group is not from on-premises. Let's stop here.
    }

    #now start building a list of users to remove from the group.
    Get-ReviewResultsToApply $_SampleInternalAuthNHeaders $reviewId
    Write-Host "We should remove $($Script:_userList.Count) users from the on-premises group $groupID"

    if($autoExecute -eq $true) { Run-GroupCleanup } else { $commandForOnPremises = Construct-CommandsToExecute $isGroupOnprem }
    
    Write-Host $commandForOnPremises
    if($filePath)
    {
            $commandForOnPremises | Out-File ($filePath)
    }
    Write-Host "." #We're done.

} 

function Construct-CommandsToExecute($onPremGroupID)
{
    $members_to_delete = ""
    foreach($u in $Script:_userList)
    {
        $members_to_delete += """$u"","
    }

    #there's a trailing "," that we need to get rid of
    $members_to_delete = $members_to_delete -replace ".$"


    #Remove-ADGroupMember -Identity "DocumentReaders" -Members administrator,DavidChew
    return "Remove-ADGroupMember -Identity $onPremGroupID -Members $members_to_delete"

}

function Get-ReviewResultsToApply($authHeaders, $reviewID)
{
    #Call Graph to find pull the decisions of the Access Review.
    #We should be getting a list of users that were denied and need removing from on-premises groups.
    #We are requesting 20 results at a time. We're using paging here.
    $decisionURL = "https://graph.microsoft.com/beta/accessReviews/" + $reviewId + "/decisions/"
    $decisionURL += '?$filter=' + "(reviewResult eq 'Deny')"
    $decisionURL += '&$top=20&$skip=0' ##&$select=userId,reviewResult ##we ask for 20 at a time.

    $applyResponse = Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $decisionURL -Method Get

    if ($applyResponse -eq $null -or $applyResponse.Content -eq $null) {
        throw "ERROR: We did not get a response from $callURL"
     }
    
    $applyResult = ConvertFrom-Json $applyResponse.Content
    $data = $applyResult.Value

    #Let's check if Graph told us there are more results for us to fetch. If so, let's loop through the results until we have all.
    while($applyResult.'@odata.nextLink')
    {
        $nextURL = $applyResult.'@odata.nextLink'

        $applyResponse = Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $nextURL -Method Get

        if ($applyResponse -eq $null -or $applyResponse.Content -eq $null) {
            throw "ERROR: We did not get a response from $nextURL"
         }
    
        $applyResult = ConvertFrom-Json $applyResponse.Content
        $data += $applyResult.Value
    }

    foreach($r in $data)
    {
        if($r.reviewResult -eq 'Deny') 
        { 
            $user_onprem = Get-UsersOnPremSIDbyID $authHeaders $r.userId
            $Script:_userList += $user_onprem 
        }
    }
}

function Get-GroupByID($authHeaders, $groupID)
{
    $groupURL = "https://graph.microsoft.com/v1.0/groups/" + $groupID
    $groupURL += '?$select=onPremisesSecurityIdentifier,onPremisesLastSyncDateTime'
    $groupResponse = Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $groupURL -Method Get

    $groupResult = ConvertFrom-Json $groupResponse.Content

    #Did we get a result?
    if ($groupResult -eq $null -and $groupResult.Content -eq $null) {
        throw "ERROR: We did not get a response from Graph, asking for the group, $groupURL"
     }
    #Qualifying the result. If the SID OR the onPremisesLastSyncDateTime are null or empty, we have reason to believe it's not an on-premises group. 
    #We can abort then.
    if($groupResult.onPremisesSecurityIdentifier -eq $null -or $groupResult.onPremisesSecurityIdentifier -eq "" -or $groupResult.onPremisesLastSyncDateTime -eq $null -or $groupResult.onPremisesLastSyncDateTime -eq "")
        { return $null; }
    
    return $groupResult.onPremisesSecurityIdentifier;
}

function Get-UsersOnPremSIDbyID($authHeaders, $userID)
{
    $usersURL = "https://graph.microsoft.com/v1.0/users/" + $userID + "/"
    $usersURL += '?$select=onPremisesSecurityIdentifier,onPremisesSyncEnabled' 

    $usersResponse = Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $usersURL -Method Get

    if ($usersResponse -eq $null -or $usersResponse.Content -eq $null) {
        throw "ERROR: We did not get a response from $usersResponse"
     }
    
    $usersResult = ConvertFrom-Json $usersResponse.Content
    if($usersResult.onPremisesSyncEnabled -ne "true") { throw "ERROR: The user is not on-premises synchronized. It may be a cloud-managed user." }
    return $usersResult.onPremisesSecurityIdentifier
}

<#
 .Synopsis
  Retrieves decisions for a multiple Access Reviews and displays Powershell commands for Windows Active Directory to be executed to apply Access Reviews results on-premises.

 .Description
  Retrieves the decisions for multiple, past Access Reviews. Will retrieve results for as many past Access Reviews as defined by "maxReviews" parameter. Checks whether the Access Review reviews an on-premises group and if so, loads the decisions for it. If there are "deny" decisions for users, it will display a Powershell command that removes denied users from the Windows Active Directory group. This is to apply Access Reviews decisions to on-premises groups.

 .Parameter maxResults
  Defines the maximum number of Access Reviews to load and inspect.

 .Parameter filePath
  This is the full file path for a TXT file that Powershell commands for Windows AD are written to.

 .Example
   # Retrieve the 50 last Access Reviews and check whether they reviewed an on-premises group. If so, display Powershell commands to execute required changes against Windows Active Directory.
   Get-AzureADARAllReviewsOnPrem

 .Example
   Retrieve the 15 last Access Reviews and check whether they reviewed an on-premises group. If so, display Powershell commands to execute required changes against Windows Active Directory.
   Get-AzureADARAllReviewsOnPrem -maxReviews 15

 .Example
   # Retrieve the 15 last Access Reviews and check whether they are reviewed an on-premises group. If so, display Powershell commands to execute required changes against Windows Active Directory. Export the Powershell commands into a TXT file:
   Get-AzureADARAllReviewsOnPrem -filePath "C:\temp\WindowsADCommands.txt" -maxReviews 15

#>
function Get-AzureADARAllReviewsOnPrem
{
[CmdletBinding()]
    param(
        [Parameter()]
        [ValidateScript({
            try {
                if($_ -gt 0 -and $_ -lt 200) { $true }
                else { $false }
            } catch {
                throw "$_ exceeds the recommended boundaries - must be 1 and 200."
            }
        })]
        [int]$maxReviews = 50,
        [Parameter()]
        [alias("fp")]
        [ValidateScript({Test-Path $_})]
        [string]
        $filePath

    )

    $allReviews = "https://graph.microsoft.com/beta/accessReviews?"
    $allReviews += '$filter=businessFlowTemplateId eq ''6e4f3d20-c5c3-407f-9695-8460952bcc68'' AND status eq ''Completed'' OR status eq ''Applied'''
    $allReviews += '&$select=id,reviewedEntity,status' 
    $allReviews += '&$top='+$maxReviews+'&$skip=0' #filtering
    $allReviews = Invoke-WebRequest -UseBasicParsing -headers $_SampleInternalAuthNHeaders -Uri $allReviews -Method Get

    if ($allReviews -eq $null -or $allReviews.Content -eq $null) {
        throw "ERROR: we couldn't get an overview of Access Reviews through Graph."
     }
    
    $allReviewResult = ConvertFrom-Json $allReviews.Content

    foreach($review in $allReviewResult.Value)
    {
        #Let's iterate through all review objects that Graph gave us.

        #some sanity checks first.
        if($review.Status -ne "Completed" -and $review.Status -ne "Applied")
            { throw "ERROR: The Access Review you requested is not completed. Check whether it is still running."} ## this shouldn't happen, if the $select is constructed correctly.
        if($review.reviewedEntity.ID -eq $null -or $review.reviewedEntity.ID -eq "")
            { throw "ERROR: There's no reviewed resource!?" }

        #Since we want to apply decisions on on-prereviewedEntity.ID)
        $currentGroup = $($review.reviewedEntity.ID)
        $isGroupOnprem = Get-GroupByID $_SampleInternalAuthNHeaders $currentGroup ##if the group comes from on-premises, we are getting the onPremises-SID back. Otherwise $null.
        if($isGroupOnprem -eq $null)
        { 
            Write-Host "$($review.id) did not review an on-premises group." 
        }
        else
        {

            #Okay, this review has a group that is on-premises - fantastic. How about we look into the Access Review's decision and collect deleted users?
            Get-ReviewResultsToApply $_SampleInternalAuthNHeaders $($review.id)

            $commandForOnPremises = Construct-CommandsToExecute $isGroupOnprem
            $Script:_userList=@()
            Write-Host $commandForOnPremises
            if($filePath)
            {
                $commandForOnPremises | Out-File $filePath -Append
            } 
        }

    }

    Write-Host "." #We're done.

}


Export-modulemember -function Connect-AzureADMSARSample
Export-modulemember -function Get-AzureADARSingleReviewOnPrem
Export-modulemember -function Get-AzureADARAllReviewsOnPrem