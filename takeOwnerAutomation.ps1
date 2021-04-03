<#

.CONTACT
Author: Jacob Nicholas Pagano
E-mail: jacob.pagano@universalexplorer.net


.NOTES

This script was written with the purpose of taking ownership / removing non-standard permissions changes to Active Directory objects. 

First, this script will invoke Ownership Permissions so that the service account running this script can take ownership of AD objects,
without necessarily having permissions to the AD object (for unknown objects where users have denied Authenticated Users and Administrators from viewing them)
then the script will start to look for all unknown AD Objects. An unknown object can only mean one thing. That permissions on an AD Object have been modified
so that Authenticated Users, Domain Users and Administrators have been removed from the ACL and no longer have permission on the object. The only way 
to get around this is to take ownership of the object first and then reset the ACES. After, this script then finds all existing users, computers and service accounts
and sets ownership of these objects to the service account. After this it again, resets all permissions back to inheriting permissions and removes any explicit permissions
that have been added to the ACL.



.CHANGELOG

v001 - 7/14/2020 - I was born.

v001 - 7/30/2020 - I was implemeneted to run every 6 hours on Scheduled Task Server ADTHQSRV001.





#>




Try {
            [void][TokenAdjuster]
        } Catch {
            $AdjustTokenPrivileges = @"
            using System;
            using System.Runtime.InteropServices;

             public class TokenAdjuster
             {
              [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
              internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
              ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
              [DllImport("kernel32.dll", ExactSpelling = true)]
              internal static extern IntPtr GetCurrentProcess();
              [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
              internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr
              phtok);
              [DllImport("advapi32.dll", SetLastError = true)]
              internal static extern bool LookupPrivilegeValue(string host, string name,
              ref long pluid);
              [StructLayout(LayoutKind.Sequential, Pack = 1)]
              internal struct TokPriv1Luid
              {
               public int Count;
               public long Luid;
               public int Attr;
              }
              internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
              internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
              internal const int TOKEN_QUERY = 0x00000008;
              internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
              public static bool AddPrivilege(string privilege)
              {
               try
               {
                bool retVal;
                TokPriv1Luid tp;
                IntPtr hproc = GetCurrentProcess();
                IntPtr htok = IntPtr.Zero;
                retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
                tp.Count = 1;
                tp.Luid = 0;
                tp.Attr = SE_PRIVILEGE_ENABLED;
                retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
                retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                return retVal;
               }
               catch (Exception ex)
               {
                throw ex;
               }
              }
              public static bool RemovePrivilege(string privilege)
              {
               try
               {
                bool retVal;
                TokPriv1Luid tp;
                IntPtr hproc = GetCurrentProcess();
                IntPtr htok = IntPtr.Zero;
                retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
                tp.Count = 1;
                tp.Luid = 0;
                tp.Attr = SE_PRIVILEGE_DISABLED;
                retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
                retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                return retVal;
               }
               catch (Exception ex)
               {
                throw ex;
               }
              }
             }
"@
            Add-Type $AdjustTokenPrivileges
        }

        #Activate necessary admin privileges to make changes without NTFS perms
        [void][TokenAdjuster]::AddPrivilege("SeRestorePrivilege") #Necessary to set Owner Permissions
        [void][TokenAdjuster]::AddPrivilege("SeBackupPrivilege") #Necessary to bypass Traverse Checking
        [void][TokenAdjuster]::AddPrivilege("SeTakeOwnershipPrivilege") #Necessary to override FilePermissions




$NewOwner = (Get-ADServiceAccount SVC._DA001).samAccountName
$Domains = (Get-ADForest).Domains

ForEach($Domain in $Domains){

#First, get all unknown AD Objects. There should be no unknown AD objects unless read permissions have been denied to authenticated users.
$Identities1 = Get-ADObject -Filter * -Server $Domain -Properties objectClass | Where {$_.objectClass -eq $null}

#Now get all known objects and ensure that these objects have no other ACES on them but inheriting permissions from the object's parent.
$Identities2 = Get-ADComputer -Filter * -Properties samAccountName,memberOf,adminCount -Server $Domain | Where {$_.adminCount -lt 1}
$Identities3 = Get-ADGroup -Filter * -Properties samAccountName,memberOf,adminCount -Server $Domain | Where {$_.adminCount -lt 1}
$Identities4 = Get-ADServiceAccount -Filter * -Properties samAccountName,memberOf,adminCount -Server $Domain | Where {$_.adminCount -lt 1}
$Identities5 = Get-ADUser -Filter * -Properties samAccountName,memberOf,adminCount -Server $Domain | Where {$_.adminCount -lt 1}
$baseDN = (Get-ADDomain $Domain).DistinguishedName


$Server = (Get-ADDomainController -Discover -DomainName $Domain).HostName

Import-Module ActiveDirectory
New-PSDrive -Name ADDOM -PSProvider ActiveDirectory -Server $Domain -Scope Global -Root "//ROOTDSE/" | Out-Null


if (!($Identities1 -eq $null)){
Write-Host "Processing all unknown objects"
foreach ($obj in $Identities1) {

  $DN = $obj.distinguishedName
  #Members of the group "Permissions Auditor Exemption" will be exempt from this script.
  if (!($obj.memberOf -like "*Permissions Auditor Exemption*"))
  {
  Write-Host "Taking Ownership of $DN"
    #First Set the Owner to the SVC Account.
    $acl = get-acl -Path "ADDOM:CN=Users,$baseDN"
    $acl.SetOwner([Security.Principal.NTaccount]($NewOwner))
    set-acl -path ADDOM:$DN -AclObject $acl
    Start-Sleep -s 2



# get explicit permissions

$acl = Get-Acl -Path ADDOM:$DN
# Set inheritance to true
Write-Host "Removing all backdoor permissions from $DN"
$acl.SetAccessRuleProtection($false,$false)
$acl.Access |
  # ...find all not inherited permissions.
  Where-Object { $_.isInherited -eq $false } |
  # ...and remove them
  ForEach-Object { $acl.RemoveAccessRule($_) } 

# set new permissions
$acl | Set-Acl -Path ADDOM:$DN

        
}


}

}
Write-Host "Processing all computer objects"
foreach ($obj in $Identities2) {

  $DN = $obj.distinguishedName
  if (!($obj.memberOf -like "*Permissions Auditor Exemption*"))
  {
  Write-Host "Taking Ownership of $DN"
    #First Set the Owner to the SVC Account.
    $acl = get-acl -Path ADDOM:$DN
    $acl.SetOwner([Security.Principal.NTaccount]($NewOwner))
    set-acl -path ADDOM:$DN -AclObject $acl
    Start-Sleep -s 2



# get explicit permissions

$acl = Get-Acl -Path ADDOM:$DN
# Set inheritance to true
Write-Host "Removing all backdoor permissions from $DN"
$acl.SetAccessRuleProtection($false,$false)
$acl.Access |
  # ...find all not inherited permissions.
  Where-Object { $_.isInherited -eq $false } |
  # ...and remove them
  ForEach-Object { $acl.RemoveAccessRule($_) } 

# set new permissions
$acl | Set-Acl -Path ADDOM:$DN

        
}


}

Write-Host "Processing all group objects"
foreach ($obj in $Identities3) {

  $DN = $obj.distinguishedName
  if (!($obj.memberOf -like "*Permissions Auditor Exemption*"))
  {
  Write-Host "Taking Ownership of $DN"
    #First Set the Owner to the SVC Account.
    $acl = get-acl -Path ADDOM:$DN
    $acl.SetOwner([Security.Principal.NTaccount]($NewOwner))
    set-acl -path ADDOM:$DN -AclObject $acl
    Start-Sleep -s 2



# get explicit permissions

$acl = Get-Acl -Path ADDOM:$DN
# Set inheritance to true
Write-Host "Removing all backdoor permissions from $DN"
$acl.SetAccessRuleProtection($false,$false)
$acl.Access |
  # ...find all not inherited permissions.
  Where-Object { $_.isInherited -eq $false } |
  # ...and remove them
  ForEach-Object { $acl.RemoveAccessRule($_) } 

# set new permissions
$acl | Set-Acl -Path ADDOM:$DN

        
}


}

Write-Host "Processing all msDS-GroupManagedServiceAccount objects"
foreach ($obj in $Identities4) {

  $DN = $obj.distinguishedName
  if (!($obj.memberOf -like "*Permissions Auditor Exemption*"))
  {
  Write-Host "Taking Ownership of $DN"
    #First Set the Owner to the SVC Account.
    $acl = get-acl -Path ADDOM:$DN
    $acl.SetOwner([Security.Principal.NTaccount]($NewOwner))
    set-acl -path ADDOM:$DN -AclObject $acl
    Start-Sleep -s 2



# get explicit permissions

$acl = Get-Acl -Path ADDOM:$DN
# Set inheritance to true
Write-Host "Removing all backdoor permissions from $DN"
$acl.SetAccessRuleProtection($false,$false)
$acl.Access |
  # ...find all not inherited permissions.
  Where-Object { $_.isInherited -eq $false } |
  # ...and remove them
  ForEach-Object { $acl.RemoveAccessRule($_) } 

# set new permissions
$acl | Set-Acl -Path ADDOM:$DN

        
}


}

Write-Host "Processing all user objects"
foreach ($obj in $Identities5) {

  $DN = $obj.distinguishedName
  if (!($obj.memberOf -like "*Permissions Auditor Exemption*"))
  {
  Write-Host "Taking Ownership of $DN"
    #First Set the Owner to the SVC Account.
    $acl = get-acl -Path ADDOM:$DN
    $acl.SetOwner([Security.Principal.NTaccount]($NewOwner))
    set-acl -path ADDOM:$DN -AclObject $acl
    Start-Sleep -s 2



# get explicit permissions

$acl = Get-Acl -Path ADDOM:$DN
# Set inheritance to true
Write-Host "Removing all backdoor permissions from $DN"
$acl.SetAccessRuleProtection($false,$false)
$acl.Access |
  # ...find all not inherited permissions.
  Where-Object { $_.isInherited -eq $false } |
  # ...and remove them
  ForEach-Object { $acl.RemoveAccessRule($_) } 

# set new permissions
$acl | Set-Acl -Path ADDOM:$DN

        
}


}



Remove-PSDrive ADDOM
}
