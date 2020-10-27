# Finding external identities ("B2B Guests") that have not never signed into your tenant, or have signed in to your tenant a long time ago
## Synopsis

This Powershell sample script is meant to enumerate the external identities in your tenant and check when their lastSignInDateTime was. When external identities have never signed in to your tenant, or have signed in a long time ago, the script can also:
* put the external identities that it found into a security group that it creates, add them as members 
* create an Access Review for that group, and request the external identities to self-attest that they still need access.

This script has two files:
1. PS1 file that is the main script. All logic is in this script file.
2. A JSON text file that contains the description for an Access Review. The script uses this JSON file to create Access Review with the settings defined in the JSON, so that the right review settings are applied.

This Powershell script can be used to get an overview of external identities that do not have any assignments in groups or applications any more, hence, should be reviewed via Access Reviews for disable&delete from the tenant.

## How to use this script and its output

This sample script intends to assist Administrators and Compliance Auditors in organizations that use Azure AD for Business-to-Business (B2B) collaobration in finding, reviewing and - should need be - clean up external identity references from their Azure AD. As with internal users and employees - you want to ensure when collaborating with external partners, vendors and supplies that 

> the right people have the right access at the right time.

This script is the first step in discovering external identities in your Azure AD tenant. It outlines what external identities in your tenant exist and when if they have not signed in recently.

This script drives awareness of external identities and prepares administrators to be able to plan their Access Reviews deployment and setup, to review external identities' access, as well as the need for continued presence for external identities in their tenant.

Learn more:

[Azure AD - Access Reviews](https://docs.microsoft.com/en-us/azure/active-directory/governance/access-reviews-overview)

[Azure AD - Identity Governance](https://docs.microsoft.com/en-us/azure/active-directory/governance/identity-governance-overview)

[Azure AD - External Collaboration](https://docs.microsoft.com/en-us/azure/active-directory/b2b/what-is-b2b)

## Prerequisites and starting the script
This Powershell module runs in application context, which requires that a Service Principal is created in Azure AD that has a clientID (application ID) and a client secret. 

If you want to learn what the script does, download the two sample output files, and get an overview of what the script generates and the style.CSS file to format the HTM output:
* sample-output-guest-cleanup-FrickelsoftNET.onmicrosoft.com-20-Jul-2020.htm
* style.CSS
* sample-output-guest-cleanup-FrickelsoftNET.onmicrosoft.com-20-Jul-2020.PS1

If you want to download the script and gather information, download the script file, as well as the .CSS style file, to format your tenant-specific output:
* style.CSS
* external-identity-research-JUL2020.ps1

## Exported functions
The script will run in the context of the executing user. An Azure AD user with reading permissions on the directory for users, groups, apps and roles is sufficient. The script, once started, will pop-up an Azure AD Sign-In dialog to sign-in into Azure AD.
```Powershell
.\external-identity-research-JUL2020.PS1 -filePath C:\temp
```


[-filePath] to define the path the two output files (HTM and PS1) are created in. Use with a full path, such as:

```Powershell
.\external-identity-research-JUL2020.PS1 -filePath C:\temp

.\external-identity-research-JUL2020.PS1 -filePath "C:\users\jennifer\Downloads\script files"
```



