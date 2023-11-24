# Import the Active Directory module
Import-Module ActiveDirectory

# Set the username and group name here
$Username = "YourUsername"
$GroupName = "YourGroupName"

# Get the ACL of the target group
$targetGroupAcl = Get-ADGroup -Identity $GroupName -Properties nTSecurityDescriptor | Select-Object -ExpandProperty nTSecurityDescriptor

# Get the groups that the user is a member of
$userGroups = Get-ADPrincipalGroupMembership $Username

# Check the ACL for modify rights
$hasModifyRights = $targetGroupAcl.Access | Where-Object {
    ($_.IdentityReference -eq $Username -or $userGroups.Name -contains $_.IdentityReference.Value) -and
    $_.ActiveDirectoryRights -match "WriteProperty" -and
    $_.AccessControlType -eq "Allow"
}

# Output the result
if ($hasModifyRights) {
    Write-Host "User '$Username' has permissions to modify the group: $GroupName"
} else {
    Write-Host "User '$Username' does NOT have permissions to modify the group: $GroupName"
}
