# Gathering information around external identity proliferation (for Access Reviews Disable-and-Delete)
## Synopsis

This Powershell sample script is meant to create a high-level overview over external identity use in a tenant, outlining if and where external identities are used:
* group membership
* application assignment
* assignment to privileged roles
* membership through rules in a dynamic group

The script is enumerating membership and assignments in Azure AD. It does not reach out to services that keep membership or role assignments outside of Azure AD (e.g. Sharepoint Online with direct user-to-role assignment outside of group membership).

This script has two file outputs, once executed correctly:
1. an HTM file that outlines found external identities, their home domains and where they were assigned permissions and group membership in the tenant
2. a Powershell PS1 script file that allows creating new Azure AD groups to collect and group external identities for an Access Review.

This Powershell script can be used to get an overview of external identities that do not have any assignments in groups or applications any more, hence, should be reviewed via Access Reviews for disable&delete from the tenant.


## Prerequisites
This Powershell module runs in user context, which requires that the user account you run this with has privileges to read the directory.

## Exported functions
.\external-identity-enumeration-JUL2020.PS1 -filePath C:\temp

[-filePath] to define the path the two output files (HTM and PS1) are created in. Use with a full path, such as:
.\external-identity-enumeration-JUL2020.PS1 -filePath C:\temp 
.\external-identity-enumeration-JUL2020.PS1 -filePath "C:\users\jennifer\Downloads\script files"
