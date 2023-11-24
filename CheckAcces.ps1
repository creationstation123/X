# Get the current user SID
$currentUserSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

# Get the SIDs of the groups the current user is a member of
$currentGroupSIDs = [System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | Select-Object -ExpandProperty Value


# Replace 'TargetGroupName' with the name of the group you want to check
$targetGroupName = "TargetGroupName"
$targetGroupAcl = Get-ADGroup -Identity $targetGroupName -Properties nTSecurityDescriptor | Select-Object -ExpandProperty nTSecurityDescriptor

# Check the ACL for modify rights
$hasModifyRights = $targetGroupAcl.Access | Where-Object {
    ($_.IdentityReference -eq $currentUserSID -or $currentGroupSIDs -contains $_.IdentityReference.Value) -and
    $_.ActiveDirectoryRights -match "WriteProperty" -and
    $_.AccessControlType -eq "Allow"
}

if ($hasModifyRights) {
    Write-Host "You have permissions to modify the group: $targetGroupName"
} else {
    Write-Host "You do NOT have permissions to modify the group: $targetGroupName"
}
