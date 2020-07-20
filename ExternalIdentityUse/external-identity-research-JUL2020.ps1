# azuread-sample-suggest-guest-cleanup-candidate-groups.ps1
# Copyright 2020 Microsoft Corporation
#
# Example for locating guest users to review
# Those guests from managed domains, and who have no other group memberships
# This script produces a PS1 file as output, it does not itself create or update groups.
#
# This scripts requires AzureADPreview module.
#
# This material is provided "AS-IS" and has no warranty.
#
# Last updated July 14th, 2020
#


Param(
    [Switch]$IncludeNonManagedUsers = $false,
    [Switch]$IncludeAccountBlockedUsers = $false,
    [Parameter()]
    [alias("fp")]
    [ValidateScript({Test-Path $_})]
    [string]
    $filePath
)

#region "Global Variables"

$global:CountCandidateUsers = 0

$global:CountEvaluatedUsers = 0
$global:CountSkippedBlockedUsers = 0
$global:CountSkippedDirSyncUsers = 0
$global:CountSkippedInternalUsers = 0
$global:CountSkippedInvalidUpns = 0
$global:CountSkippedUnretrievable = 0
$global:CountSkippedSocialUsers = 0
$global:CountInvalidUpns = 0

$global:CountSkippedDomains = 0

$global:CountSkippedGroups = 0
$global:CountSkippedDynamicGroups = 0
$global:CountInvalidGroupMemberCount = 0


$global:MembershipsPassed = 0

$global:GroupObjects = @{}
$global:Groups1 = @{}
$global:Domains1 = @{}
$global:Groups2 = @{}
$global:Domains2 = @{}

$global:Apps1 = @{}
$global:DirectoryRoles = @{}
$global:DirectoryRoles2 = @{}

$global:ManagedDomains = @{}
$global:ConsumerDomains = @{}

$global:UsersNotReadyForRemoval = @()
$global:UsersNotReadyForRemovalDueToApps = @()
$global:UsersReadyForRemoval = @()

$global:PShInstructions = @{}

$global:HtmlOutputFilename = "suggest-groups.htm"
$global:PSOutputFilename = "create-groups.ps1"

#endregion

function Test-Viral2 ($origupn) {

    $uri = "https://login.microsoftonline.com/common/userrealm?user=" + $origupn + "&api-version=2.1"

    try {
    $resp1 = Invoke-WebRequest -UseBasicParsing -Uri $uri -method Get
    } catch {
        return $false
    }

    $j1 = ConvertFrom-Json $resp1.Content

    $nst = $j1.NameSpaceType
    if ($nst -eq "Federated") {

        $cd = $j1.ConsumerDomain

        if ($cd -eq "true") {
            write-verbose "Adding user from consumer tenant: $origupn"
            return $true
        }

        write-verbose "Skipping user from federated tenant: $origupn"
        return $false
    } elseif ($nst -eq "Managed") {

        $isv = $j1.IsViral

        if ($isv -eq "true") {
            write-verbose "Adding user from viral tenant: $origupn"

            return $true
        } else {
           write-verbose "Skipping user from non-viral managed directory: $origupn"
            return $false
        }

    } else {
        write-verbose "Namespace type for $origupn : $nst"
    }
    return $true
}


function RecordDomain ($objectid,$upn,$oldu,$domain)
{
    $displayname = $oldu.DisplayName
    $rtvf = $oldu.RefreshTokensValidFromDateTime
    $userState = $oldu.UserState
    $usco = $oldu.UserStateChangedOn

    write-verbose "recorddomain enter"
    if ($global:Domains1.ContainsKey($domain) -eq $false) {
        $users = @()

    } else {
        $users = $global:Domains1[$domain]
    }
    $gl = [System.Collections.ArrayList]@();
    $nu = [PSCustomObject]@{
        ObjectId = $objectid;
        UPN = $upn;
        DisplayName = $displayname;
        Groups = $gl;
        RefreshTokensValidFromDateTime = $rtvf;
        UserState = $userState;
        UserStateChangedOn = $usco;
    }
    $users += $nu
    $global:CountCandidateUsers++
    $global:Domains1[$domain] = $users
    write-verbose "recorddomain exit"
    return $nu
}

function AddDomainToMemberArray ($domain,$members,$nu)
{
    if ($members.ContainsKey($domain) -eq $false) {
        $users = @()
    } else {
        $users = $members[$domain]
    }

    $users += $nu
    $members[$domain] = $users
    return $members
}

function ParseUserMemberships ($uobjectid,$upn,$msa,$domain,$nu)
{
    try {
        $gml = Get-AzureADUserMembership -ObjectId $uobjectid -All $true


    } catch {
        $global:CountSkippedUnretrievable++
        return
    }


    foreach ($m in $gml) {
        $gobjectid = $m.ObjectId
        #addres = $nu.Groups.Add($gobjectid)
        if ($global:Groups1.ContainsKey($gobjectid) -eq $false) {
            $members = @{}
        } else {
            $members = $global:Groups1[$gobjectid]
        }
        $members = AddDomainToMemberArray $domain $members $nu
        $global:Groups1[$gobjectid] = $members
        $global:GroupObjects[$gobjectId] = $m
    }

}

function GetDomainFromUpn() {
    # external user's UPNs show like this: madeline_identities.wtf#EXT#@FrickelsoftNET.onmicrosoft.com - we need to convert that to madeline@identities.wtf
    $usplit1 = $upn.Split("#")
    $lhs1 = $usplit1[0]
    if ($lhs1.Contains("_") -eq $False) {
        $CountSkippedInvalidUpns++
        return $null
    }
    $usplit2 = $lhs1.Split("_")
    $dindex = $usplit2.Count
    $dindex--
    $domain =$usplit2[$dindex].ToLower()

    if ($domain.Contains(".") -eq $false) {
        $global:CountInvalidUpns++
        return $null
    }
    return $domain
}


function findExternalsWithoutGroupMembership () {

    Write-Progress -Activity "Retrieving Guest Users..."
    
    $users = Get-AzureADUser -Filter "usertype eq 'Guest'" -All $true  
    $totalUsers = $users.Count
    
    
    Write-Progress -Activity "Retrieving Guest Users..." -Completed -Status "Done, $totalUsers retrieved"
    Write-Progress -Activity "Retrieving Group Memberships..."

    $cur = 0
    
    foreach ($u in $users) {

        #We have all users with userType "Guest" here now. However, we may have caught (a) users that are in a blocked state (accountEnabled = true) or 
        #that were synchronized from on-premises with userType=Guest (aka. "sync as guest" scenario with AADConnect. We want to count them differently).
    
            $frac = [math]::round(($cur * 100) / $totalUsers)
            $cur++
            Write-Progress -Activity "Retrieving Group Memberships..." -PercentComplete $frac -CurrentOperation "$frac% complete"
    
            if ($IncludeAccountBlockedUsers -eq $true) {
                # everyone
            } else {
                if ($u.AccountEnabled -eq $False) {  
                    $global:CountSkippedBlockedUsers++
                     continue
                }
            }

            if ($u.DirSyncEnabled -eq $true) {  # DirSyncEnabled
                $global:CountSkippedDirSyncUsers++
                continue
            }
            $objectid = $u.ObjectId
            $upn = $u.UserPrincipalName
    
            if ($upn.Contains("#EXT#@") -eq $False) {
                $CountSkippedInternalUsers++
                continue
            }

            # we have counted. Let's extract the UPN.
            $domain = GetDomainFromUpn $upn
            if ($domain -eq $null) {
                continue
            }

            $msa = $false
    
            if ($includeNonManagedUsers -eq $false) {
                        
                if (($domain -eq "gmail.com") -or ($domain -eq "outlook.com") -or ($domain -eq "live.com")) {
                    $msa = $true
                } elseif ($domain.EndsWith(".onmicrosoft.com")) {
                    $msa = $false
                } else {
                    if ($global:ConsumerDomains.ContainsKey($domain)) {
                        $msa = $true
                    } else {
                        if ($global:ManagedDomains.ContainsKey($domain)) {
                            $msa = $false
                        } else {
                            $nuser = "user@" + $domain
                            $msa =  Test-Viral2 $nuser

                            if ($msa -eq $true) {
                                $global:ConsumerDomains[$domain] = $true
                            } else {
                                $global:ManagedDomains[$domain] = $true
                            }
                        }
                    }

                }   
            }

    
            if ($msa -eq $false) {
                $global:CountEvaluatedUsers++
                $nu = RecordDomain $objectid $upn $u $domain
                ParseUserMemberships $objectid $upn $msa $domain $nu
            } else {
                $global:CountSkippedSocialUsers++
            }
    }
    Write-Progress -Activity "Retrieving Group Memberships..." -Completed -Status "Done"
    
}

function IsReviewGroup($ginfo) {

    # mail enabled,  unified groups, on-prem groups are not review groups
    if ($ginfo.SecurityEnabled -eq $false) {
        return $false
    }
    if ($ginfo.MailEnabled -eq $true) {
        return $false
    }

    foreach ($i in $ginfo.GroupTypes) {
        if ($i -eq "Unified") {
            return $false
        }
    }

    if ($ginfo.OnPremisesSecurityIdentifier -ne $null) { 
        return $false
    }

    if ($ginfo.Description -match "access review of external identities") {
        return $true
    }
    

    return $false
}

function CheckPotentialDirectoryRole($gid)
{
    try {
        $roles = Get-AzureADDirectoryRole -ObjectId $gid

        if ($roles.Count -eq 1) {
            $global:DirectoryRoles[$gid] = $roles[0]
        } else {
            # should not occur
        }
        # add to role list

    } catch {
 
        return  # not a role
    }
}

function IsDynamicOrReviewGroup($gid) {



    try {
        $ginfo = Get-AzureADMSGroup -Id $gid

    } catch {
        # group may not exist, may be a directory role
        CheckPotentialDirectoryRole $gid
        return $false
    }
        foreach ($i in $ginfo.GroupTypes) {
            if ($i -eq "DynamicMembership") {

                return $true
            }
        }

        return IsReviewGroup $ginfo


}

function ExcludeGroupFromUsers($gk)
{
    $members = $global:Groups1[$gk]

    foreach ($dm in $members.Values) {

        foreach ($nu in $dm) {
            $upn = $nu.UPN
            if ($nu.Groups.Contains($gk)) {
                $nu.Groups.Remove($gk)
                # write-verbose "user $upn removing group $gk"
            } else {
               
                }
                
            }
        }
    }



function ReduceGroup ($members) {
    $newmembers = @{}
    foreach ($ind in $members.Keys) {
        if ($global:Domains1.ContainsKey($ind) -eq $false) {
            continue  
        }

        $memberDomain = $members[$ind]

        $newmembers[$ind] = $memberDomain
        $global:MembershipsPassed++
    }

    return $newmembers
}


function RemoveDynamicGroups() {
    $keys = $global:Groups1.Keys
    $totalKeys = $keys.Count
    $cur = 0

    Write-Progress -Activity "Reducing groups..."
    

    foreach ($gk in $keys) {
        $frac = [math]::round(($cur * 100) / $totalKeys)
        $cur++
        Write-Progress -Activity "Reducing groups..." -PercentComplete $frac -CurrentOperation "$frac% complete"

        if ($global:DirectoryRoles.ContainsKey($gk)) {
            # it's a role
        } else {

           $isdyn = IsDynamicOrReviewGroup $gk

            if ($isdyn -eq $true) {
                #if($global:DynamicGroups -NotContains $gk) { $global:DynamicGroups += $gk }
                #$global:DynamicGroups.Add($gk) 
                ExcludeGroupFromUsers $gk
                $global:CountSkippedDynamicGroups++
                continue
            }
        }

        $members = $global:Groups1[$gk]

        $newmembers = ReduceGroup $members

        if ($newmembers.Count -eq 0) {
            # no domains
            $global:CountSkippedGroups++
        } else {

            if ($global:DirectoryRoles.ContainsKey($gk)) {
   
                $global:DirectoryRoles2[$gk] = $newmembers
            } else {

                $global:Groups2[$gk] = $newmembers
            }
        }

    }

    Write-Progress -Activity "Reducing groups..." -Completed -Status "Done"

}

function GetAppRoleAssignments($uobjectid)
{
    $roles = Get-AzureADUserAppRoleAssignment -ObjectId $uobjectid

    $rcount = 0

    foreach ($r in $roles) {

        $appid = $r.ResourceId
        $prevusers = @()

        if ($global:Apps1.ContainsKey($appid)) {
            $nu = $global:Apps1[$appid]
            $nu.Users += $uobjectid
        } else {
            $prevusers += $uobjectid


            $na = [PSCustomObject]@{
                ObjectId = $appid;
                DisplayName = $r.ResourceDisplayName;
                Users = $prevusers
            }

            $global:Apps1[$appid] = $na
        }

        $rcount++

    }
    
    return $rcount
}

function FindGroupsAndAppsForDomains() {

    Write-Progress -Activity "Checking app role assignments..."

    $ucount = 0
    
    foreach ($dr in $global:Domains1.Keys) {
        $users = $global:Domains1[$dr]
        $unogroups = @()
        $ugroups = @()
        $uapps = @()
        foreach ($u in $users) {
            $ucount++

            $frac = [math]::round(($ucount * 100) / $global:CountCandidateUsers)
            Write-Progress -Activity "Checking app role assignments..." -PercentComplete $frac -CurrentOperation "$frac% complete"

            $gc = $u.Groups.Count
            $uobjid = $u.ObjectId
            $upn = $u.UPN

            $arc = GetAppRoleAssignments $uobjid


            if ($gc -eq 0) {
                if ($arc -eq 0) {
                    $unogroups += $uobjid
                    $global:UsersReadyForRemoval += $upn
                } else {
                    $uapps += $upn
                }
            } else {
                $ugroups += $upn
            }
        }
    
        
        foreach ($upn in $ugroups) {
            $global:UsersNotReadyForRemoval += $upn
           
        }

        foreach ($upn in $uapps) {
            $global:UsersNotReadyForRemovalDueToApps += $upn
         
        }

    
        if ($unogroups.Count -eq 0) {
            continue
        }

        $global:Domains2[$dr] = $unogroups
    
    }

    Write-Progress -Activity "Checking app role assignments..." -Completed -Status "Done"

}

function IsUserStillNeedingReview($dr,$userid)
{
    foreach ($objid in $global:Domains2[$dr]) {
        if ($userid -eq $objid) {
            return $true
        }
    }
    return $false
}

function WasUserAlreadyReviewed($geml,$userid)
{
    foreach ($gem in $geml) {
        if ($gem.ObjectId -eq $userid) {
            return $true
        }
    }
    
    return $false
}

function FindUserForDisplayName($dr,$objectid) {

    foreach ($u in $global:Domains1[$dr]) {
        if ($u.ObjectId -eq $objectid) {
            return $u
        }
    }


    return $null
}

function CompareMemberships($gnum,$slist,$dr,$gid) {
    $geml = @()


    $emitted = @()

    if ($gid -ne $null) {
       $geml = get-azureadgroupmember -objectid $gid -All $true

        # is there a group member which is not in $global:Domains2? if so, remove them from the group
        foreach ($gem in $geml) {
            $snr = IsUserStillNeedingReview $dr $gem.ObjectId
            if ($snr -eq $false) {

            # does not yet emit removing them from the group
                $s = "# guest " + $gem.DisplayName + " " + $gem.ObjectId + " already in group, but may have other access"
                $slist += $s

            } else {
                $s = "# guest " + $gem.DisplayName + " " + $gem.ObjectId + " already in group"
                $emitted += $gem.ObjectId
                $slist += $s
            }
        }
    }

    # is there a user in $global:Domains2 which is not in $gem? if so, add them to the group

    foreach ($objid in $global:Domains2[$dr]) {
        if ($gid -eq $null) {
            $gar = $false
        } else {
            $gar = WasUserAlreadyReviewed $geml $objid
        }
        if ($gar -eq $false) {
           
            $nu =FindUserForDisplayName $dr $objid
            $displayname = $nu.DisplayName
            
            $s = "# user " + '"' + $displayname + '"' + " to be added to that new group"
            $slist += $s

            $s = "Add-AzureADGroupMember -ObjectId " + '$gid' + $gnum + ".ObjectId -RefObjectId " + '"' + $objid + '"'
            $slist += $s
        } else {

            if ($emitted -contains $objid) {
                continue
            }

            $s = "# guest " + $objid + " already in group"
            $slist += $s
        }
    }

    return $slist

}

function FindExistingReviewGroup($displayname)
{
    $gl = Get-AzureADMSGroup -SearchString $displayname -All $true

    if ($gl.Count -eq 0) {
    
        return $null
    }

    foreach ($g in $gl) {
        if ($g.DisplayName -eq $displayname) {
            $gid = $g.Id
            return $gid
        }
    }

    return $null
}


function ConstructReviewGroupAndMemberships() {


    $gnum = 0

    foreach ($dr in $global:Domains2.Keys) {

      

        $domainusercount = $global:Domains2[$dr].Count

        if ($domainusercount -eq 0) {
            continue
        }

        $gnum++

        $displayname = "external identities from " + $dr 

        # see if it already exists, if so,
        # compare the membership
        # otherwise, create it

        

        $slist = @()

    
        #   test group already exists, if not create one
        $gid = FindExistingReviewGroup $displayname

        if ($gid -eq $null) {


            $slist += "# Create a group for $domainusercount users from $dr"
        
     
            $slist += ""
           
            $desc = "access review of external identities from " + $dr
            $mn = $dr # + "-" + $datefmt
            $s = '$gid' + $gnum + ' = '
            $s += "New-AzureADGroup -DisplayName " + '"' + $displayname + '"' + " -Description " + '"' + $desc + '" -MailEnabled $false -SecurityEnabled $true -MailNickname "' + $mn + '"'
            $slist += $s

            $slist += ""

            $slist = CompareMemberships $gnum $slist $dr $null

        } else {
            #  else have gid of existing group, 

            $s = '$gid' + $gnum + ' = '
            $s += "Get-AzureADGroup -ObjectId " + '"' + $gid + '"' 
            $slist += $s

            $slist = CompareMemberships $gnum $slist $dr $gid
        }

       
        $slist += ""

        $global:PShInstructions[$dr] = $slist

    }

}


function WriteHtml($s) {
    Add-Content -Path $global:HtmlOutputFilename -Value $s
}

function WritePS($s) {
    Add-Content -Path $global:PSOutputFilename -Value $s
}

function GetInitialDomain($ctd) {
   
}

function WriteHtmlFile ($datefmt,$initialdomain) {

    Set-Content -Path $global:HtmlOutputFilename -Value "<html>" -Force
    Set-Content -Path $global:PSOutputFilename -Value "# Automatically generated on $datefmt for $initialdomain"
    WriteHtml "<head>"
    WriteHtml "<link rel='stylesheet' type='text/css' href='style.css'>"
    WriteHtml "</head><body>"

    WriteHtml "<h1>Azure AD External Identity Lookup: Summary of guest users potentially ready for review using the Azure AD Access Reviews</h1>"

    WriteHtml "<table bgcolor='#AAAAAA'><tr><td>Generated on $datefmt for $initialdomain</td></tr></table>"

    WriteHtml "<h2>External users that have no static group membership or application assignments in your tenant</h2>"
    WriteHtml "<p>The following table outlines all external identities that have no static group memberships and no applications assignments in your tenant. The external identities listed below could, however, have one of the following:<br><li>group membership in dynamic groups</li><li>access to Sharepoint Sites managed outside of Azure AD groups or assigned directly</li></p>"

    WriteHtml "<table><thead>"
   
    WriteHtml "<tr><th>Domain</th><th>UPN</th><th>Display Name</th><th>Refresh Token</th><th>User State</th><th>User State Changed</th></tr>"

    WriteHtml "</thead><tbody>"
    foreach ($dr in $global:Domains2.Keys) {


        $domainusercount = $global:Domains2[$dr].Count

        if ($domainusercount -eq 0) {
            continue
        }

        foreach ($objid in $global:Domains2[$dr]) {
            $nu = FindUserForDisplayName $dr $objid
            if ($nu -eq $null) {
                continue
            }

            WriteHtml "<tr>"

            WriteHtml "<td>$dr</td>"
            $upn = $nu.UPN
            WriteHtml "<td>$upn</td>"

            $displayName = $nu.DisplayName
            WriteHtml "<td>$displayName</td>"
           
            $rt = $nu.RefreshTokensValidFromDateTime
            WriteHtml "<td>$rt</td>"
             
            $us = $nu.UserState
            WriteHtml "<td>$us</td>"
            $usco = $nu.UserStateChangedOn
            WriteHtml "<td>$usco</td>"

            WriteHtml "</tr>"
        }

    }

   # foreach ($upn in $global:UsersReadyForRemoval) {    }
    WriteHtml "</table>"

    WriteHtml "<h2>Script suggestion: Create groups to try Azure AD Access Reviews disable-and-delete feature on</h2>"
 
    $dcount = $global:Domains2.Count
    if ($dcount -eq 0) {
        WriteHtml "<p>There are no external identities from other directories that have no group memberships. Below are Powershell code snippets that will allow you to create Azure AD groups that will include the 'group less' external identities found. Using this newly created group, you can create an Access Review with Disable and Delete.</p>"
    } else {
    WriteHtml "<p>There are $dcount domains of external identities having no other group memberships. Below are Powershell code snippets that will allow you to create Azure AD groups that will include the 'group less' external identities found. Using this newly created group, you can create an Access Review with Disable and Delete.</h3>"
    WriteHtml "<h3>First, create or update a group for each domain's external identities, using this script <tt>$global:PSOutputFilename</tt> that was also automatically created for you.</h3>"
    WriteHtml "<pre>"

  

    foreach ($dr in $global:Domains2.Keys) {


        $domainusercount = $global:Domains2[$dr].Count

        if ($domainusercount -eq 0) {
            continue
        }

        $slist = $global:PShInstructions[$dr]

        foreach ($s in $slist) {
            WriteHtml $s
            WritePS $s
        }
    
    }
    
    WriteHtml "</pre>"

    WriteHtml "<h3>Now, after you have created the respective groups, create an Access Review with disable-and-delete for them, following the instructions on DOCS.</h3>"
    } 


    $g2count = $global:Groups2.Count

    if ($g2count -ge 1) {

        WriteHtml "<hr>"

        WriteHtml "<h2>Additional Info: Other groups to review</h2>"


        WriteHtml "<p>The below groups have group members that are external identities. You may want to review these groups with Access Reviews, not to remove those external identities from the directory, but to determine if those external identities still need to be members of those groups.</p>"

        WriteHtml "<ul>"
        foreach ($gr in $global:Groups2.Keys) {
            $go = $global:GroupObjects[$gr]
            $dn = $go.DisplayName

            $membercount = 0
            if ($global:Groups1.ContainsKey($gr)) {
                $membercount = $global:Groups1[$gr].Count
            }

            WriteHtml "<li> Group Name: $dn (objectID: <tt>$gr</tt>, $membercount external identities as a member)</li>"
        }
        WriteHtml "</ul>"

    }

    $dr2count = $global:DirectoryRoles.Count
    if ($dr2count -ge 1) {
        WriteHtml "<h2>Additional Info: Directory roles to review</h2>"


        WriteHtml "<p>You may also wish to review the external identities in these directory roles, but to determine if those external identities still need to be members of those roles.</p>"

        WriteHtml "<ul>"
        foreach ($gr in $global:DirectoryRoles.Keys) {
            $go = $global:DirectoryRoles[$gr]
            $dn = $go.DisplayName


            WriteHtml "<li>$dn</li>"
        }
        WriteHtml "</ul>"


    }

    $a1count = $global:Apps1.Count
    if ($a1count -ge 1) {
        WriteHtml "<h2>Additional Info: Apps to review</h2>"


        WriteHtml "<p>You may also wish to review the external identities in these apps, not to remove those external identities from the directory, but to determine if those external identities still need access.</p>"

        WriteHtml "<ul>"
        foreach ($gr in $global:Apps1.Keys) {
            $go = $global:Apps1[$gr]
            $dn = $go.DisplayName
            $objectid = $go.ObjectId
            $ucount = $go.Users.Count
 

            WriteHtml "<li>$dn (<tt>$objectid</tt>, $ucount users)</li>"
        }
        WriteHtml "</ul>"
    }

    if ($global.$global:UsersNotReadyForRemoval.Count -ge 1) {
       WriteHtml "<h2>Additional Info:  - Guest users not ready for removal due to those external identities having other group memberships</h2>"

        WriteHtml "<ul>"
        foreach ($upn in $global:UsersNotReadyForRemoval) {
            WriteHtml "<li>$upn</li>"
        }
        WriteHtml "</ul>"

    }

    if ($global.$global:UsersNotReadyForRemovaDueToApps.Count -ge 1) {
        WriteHtml "<h2>Additional Info: - Guest users not ready for removal due to those external identities having application roles</h2>"
 
         WriteHtml "<ul>"
         foreach ($upn in $global:UsersNotReadyForRemovalDueToApps) {
             WriteHtml "<li>$upn</li>"
         }
         WriteHtml "</ul>"
 
     }

    $cdcount = $global:ConsumerDomains.Count

    if ($cdcount -ge 1) {

        WriteHtml "<h2>Additional Info: Non-Managed domains (Consumer domains) of external identities not included</h2>"


        
        WriteHtml "<p>There were $global:CountSkippedSocialUsers external identities from these domains that were not considered as candidates, as they are not from other tenants. "
        writeHtml "If you wish to include them, re-run this script with the -IncludeNonManagedUsers flag.</p>"

        WriteHtml "<ul>"
        foreach ($d in $global:ConsumerDomains.Keys) {
            WriteHtml "<li>$d</li>"
        }

        WriteHtml "</ul>"

    }

    ###if ($global:DynamicGroups.Count -gt 0)
    ##{
      #  WriteHtml "<h2>Additional Info: Dynamic Groups with external identities in them</h2>"
        
      #  WriteHtml "<p>There were $($global:DynamicGroups.Count) dynamic groups that contained external identities."

      #  WriteHtml "<ul>"
      #  foreach ($dynG in $global:DynamicGroups) {
        #    WriteHtml "<li>$dynG</li>"
      #  }

       # WriteHtml "</ul>"
    #}

    WriteHtml "</body></html>"
}

########################################################################################################
### Script starts here ###
########################################################################################################
import-module AzureADPreview

$ctd = $null


try {
    Connect-AzureAD
}
catch{
    Write-Host ""
    throw "Aborting. You need to sign in to Azure AD to continue."
}
   
#We seem to be connected. Let's try and see if we can find the initial domain of the tenant (<name>.onmicrosoft.com)
$tenantDetails = Get-AzureADTenantDetail
$initial = $tenantDetails.VerifiedDomains | ?{$_.Initial} | SELECT -ExpandProperty Name

#Which arguments was the script called with? What do we need to do?


findExternalsWithoutGroupMembership

RemoveDynamicGroups

FindGroupsAndAppsForDomains

ConstructReviewGroupAndMemberships


$now = Get-Date
$datefmt = $now.date.ToString("dd-MMM-yyyy")

# filename includes tenant name too
if(!$filepath)
{
    $global:HtmlOutputFilename = "guest-cleanup-" + $initial + "-" + $datefmt + ".htm"
    $global:PSOutputFilename = "guest-cleanup-" + $initial + "-" + $datefmt + ".ps1"
}
else
{
    $global:HtmlOutputFilename = $filePath.TrimEnd('\') + "\guest-cleanup-" + $initial + "-" + $datefmt + ".htm"
    $global:PSOutputFilename = $filePath.TrimEnd('\') + "\guest-cleanup-" + $initial + "-" + $datefmt + ".ps1"
}

WriteHtmlFile $datefmt $initial

Write-output "Done, created two output files:"
Write-Output "HTML report: $global:htmlOutputFilename "
Write-Output "Powershell group creation sample: $global:psoutputfilename "


