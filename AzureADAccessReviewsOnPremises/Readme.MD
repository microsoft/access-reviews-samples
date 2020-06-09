## Enforcing Azure AD Access Reviews decisions on on-premises-managed groups (AzureADAccessReviewsOnPremises)

## Prerequisites
This Powershell module runs in an application context, which requires that you create an application registration in Azure AD for this script, and admin-consent for the required permissions for Microsoft Graph.

The steps are as follows:
1. Log into the Azure portal as a global administrator.
2. In the Azure portal, go to Azure Active Directory, and then click App registrations on the left.
3. Click New registration. Give your app a name, and then click Register.
4. Copy and save for later the application (client) ID that appears after the app is registered.
5. On the left, click API permissions.
6. Click "Add a permission", click "Microsoft Graph", and then click "Application permissions".
7. In the Select permissions list, select the following permissions: (a) AccessReview.Read.All, (b) Group.Read.All and (c) User.Read.All.
8. Click Add permissions.
9. Click to Grant admin consent for <your tenant> and then click Yes. The status for each permission the app needs should change to a green checkmark, indicating consent was granted.
10. On the left, click Certificates & secrets.
11. Click New client secret and then for Expires select an expiry date that's a month away in the future. This will allow you to test sensibly, but not infinitely keep the credentials/secret valid. Click Add.
12. Copy and save locally the value of the secret that appears- you won’t see it again after you leave this part of the UI.

## Exported functions

This sample module exports the following Azure AD functions:

Export-modulemember -function Connect-AzureADMSARSample
Export-modulemember -function Get-AzureADARSingleReviewOnPrem
Export-modulemember -function Get-AzureADARAllReviewsOnPrem

## Exported functions
### Function Get-AzureADARSingleReviewOnPrem

Get-AzureADARSingleReviewOnPrem -reviewId "20924e60-a9fb-4891-9c92-f30c47636484" -filePath "C:\temp\WindowsADCommands.txt"

[-filePath] to define a text-based file the function writes the Windows AD Powershell command to.
[-reviewId] to define the objectID of the Access Review you want to target and pull the review decisions from.

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

### Function AzureADARAllReviewsOnPrem

Get-AzureADARAllReviewsOnPrem -filePath "C:\temp\WindowsADCommands.txt" -maxReviews 15

[-filePath] to define a text-based file the function writes the Windows AD Powershell command to.
[-maxReviews] to define how many Access Reviews to inspect and look through, to determine whether they are targeted an on-premises managed group.

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
