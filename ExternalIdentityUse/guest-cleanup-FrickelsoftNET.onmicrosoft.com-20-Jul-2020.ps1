# Automatically generated on 20-Jul-2020 for FrickelsoftNET.onmicrosoft.com
# Create a group for 2 users from identities.wtf

$gid1 = New-AzureADGroup -DisplayName "external identities from identities.wtf" -Description "access review of external identities from identities.wtf" -MailEnabled $false -SecurityEnabled $true -MailNickname "identities.wtf"

# user "Madeline Small" to be added to that new group
Add-AzureADGroupMember -ObjectId $gid1.ObjectId -RefObjectId "a1c3a6f2-756e-4230-83af-dba6c7568bf1"
# user "Elena Spinotw" to be added to that new group
Add-AzureADGroupMember -ObjectId $gid1.ObjectId -RefObjectId "bdd77c5f-eb29-4b9b-a607-d97e70f4fbb9"

# Create a group for 1 users from farrtoso.com

$gid2 = New-AzureADGroup -DisplayName "external identities from farrtoso.com" -Description "access review of external identities from farrtoso.com" -MailEnabled $false -SecurityEnabled $true -MailNickname "farrtoso.com"

# user "John Farr" to be added to that new group
Add-AzureADGroupMember -ObjectId $gid2.ObjectId -RefObjectId "06714039-45df-439c-9195-58bc01e7a852"

# Create a group for 1 users from microsoft.frickelpartners.net

$gid3 = New-AzureADGroup -DisplayName "external identities from microsoft.frickelpartners.net" -Description "access review of external identities from microsoft.frickelpartners.net" -MailEnabled $false -SecurityEnabled $true -MailNickname "microsoft.frickelpartners.net"

# user "Robert Pattinson (EXT)" to be added to that new group
Add-AzureADGroupMember -ObjectId $gid3.ObjectId -RefObjectId "f0610ab7-da71-4a4a-8ee3-94743144693d"

# Create a group for 1 users from azure-hero.com

$gid4 = New-AzureADGroup -DisplayName "external identities from azure-hero.com" -Description "access review of external identities from azure-hero.com" -MailEnabled $false -SecurityEnabled $true -MailNickname "azure-hero.com"

# user "Peter Lammert" to be added to that new group
Add-AzureADGroupMember -ObjectId $gid4.ObjectId -RefObjectId "1dfd1478-5202-4d8c-b71b-ba5afa9d3666"

# Create a group for 2 users from identitysso.onmicrosoft.com
$gid5 = New-AzureADGroup -DisplayName "external identities from identitysso.onmicrosoft.com" -Description "access review of external identities from identitysso.onmicrosoft.com" -MailEnabled $false -SecurityEnabled $true -MailNickname "identitysso.onmicrosoft.com"

# user "Customer Support Admin" to be added to that new group
Add-AzureADGroupMember -ObjectId $gid5.ObjectId -RefObjectId "9b522137-01bf-456f-ab30-cfe0e792bd2a"
# user "CSP Support Admin 2" to be added to that new group
Add-AzureADGroupMember -ObjectId $gid5.ObjectId -RefObjectId "33605554-c4a4-4fec-8da4-ed60d58400e3"

