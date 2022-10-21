#requires -version 2
<#
.SYNOPSIS
 

.DESCRIPTION
  Script to populate Active Directory Labs with AD Objects such as Users, Groups, Contacts, OUs.


.NOTES
  Version:        1.0
  Author:         Ben Ashlin
  Creation Date:  04/10/2022
  Purpose/Change: Initial script development

.PARAMETER Usercount
Enter the number of users that you would like to provision

.PARAMETER Groupcount
Enter the number of users that you would like to provision - This will create equal number of Security & Distribution Groups

.PARAMETER OUPath
Specify the OU Path of where user objects are to be created

.PARAMETER SECOUPath
Specify the OU Path of where Security Group objects are to be created


.PARAMETER
Specify the OU Path of where Distribution Group objects are to be created


#>

#---------------------------------------------------------[Initialisations & Declarations]--------------------------------------------------------

#Set Error Action to Silently Continue
$ErrorActionPreference = "Continue"
$logdate = 1
#Log File locations for exports, outputs and logging
#$LogFile = "$env:USERPROFILE\Desktop\AD_Lab-$LogDate.csv"
#$LogFile = $path\Outputs\AD_Lab-$LogDate.csv

$path = "C:\Scripts\Projects_Public\AD_Labs"
#Wordlist of Names
$names = Get-Content $path\Lists\Names.txt

#Password List
$passwords = Get-Content $path\Lists\500-worst-passwords.txt

#Groups List (By Cities of USA)
$Groups = Get-Content $path\Lists\Groups-By-City-USA.txt

#Wordlist value Count
$namelistcount = 1..$names.count
$pwdlistcount = 1..$passwords.count
$grpslistcount = 1..$Groups.count

[Array]$Usernames = @()
[Array]$Groups = @()
[Array]$Contacts = @()
[array]$SamNames = @()

#[String]$Domain = "Contoso.com"
[String]$Domain = Get-ADDomainController -Discover -Service adws | select -ExpandProperty Domain
[String]$Users_OU = "DistinguishedName"
[String]$Groups_OU = "DistinguishedName"
[String]$Contacts_OU = "DistinguishedName"
#[string]$MailUPN = "ashlinscott.com"



#-----------------------------------------------------------[Functions]------------------------------------------------------------


# Create Users List (Usercount)


Function Create-LabUsers {
    [cmdletbinding()]
    Param(
        $Usercount,
        [String]$OUPath
    )

  <#  
.SYNOPSIS
Creates randomized AD users

.EXAMPLE
  Create-Labusers -UserCount -OUPath
  Creates AD Users where $usercount is Amount of users to be created & $OUPath is location of Users to be created
  #>

#$usercount = 5
#$oupath = 'CN=Users,DC=adsec,DC=ashlinscott'

    for ($i = 0 ; $i -lt $Usercount) {
       $randomcount = Get-Random $namelistcount -Count 2
       # Write-Host "$($names[$randomcount])"
        $Usernames += "$($names[$randomcount])"
        ++$i
    }

    #Get SAM Account names

    foreach ($Name in $usernames) {
        $SamNames += $usernames.Replace(" ", ".")
    }


    #Create Users from Names list & Set Passwords from PWDList

    For ($i = 0; $i -lt $usernames.Count) {
        $randomcount = $pwdlistcount | Get-Random
    #    New-ADUser -SamAccountName $samnames[$i] -Name $Usernames[$i] -EmailAddress "$($samnames[$i])+ @$($Domain)" -AccountPassword (ConvertTo-SecureString -AsPlainText $passwords[$randomcount] -Force) -Path $OUPath -Verbose
         New-ADUser -Name $Usernames[$i] -EmailAddress "$($samnames[$i])@$($Domain)" -UserPrincipalName "$($samnames[$i])@$($Domain)" -Path $OUPath -Verbose
        $i++
    }
    Clear-Variable usernames
    Clear-Variable SamNames
    clear-variable oupath
}


Function Create-LabGroups {
    [cmdletbinding()]
    param(
        [int32]$groupcount,
        [String]$SECOUPath,
        [String]$DISTOUPath
    )

    #Create Group (Security & Distribution)
    for ($i = 0 ; $i -le $groupcount) {
        $randomcount = $grpslistcount | Get-Random
        New-ADGroup -SamAccountName "_$($Groups.Replace(" ","-")[$randomcount])" -GroupCategory Security -Description "$($Groups[$randomcount]) Security Group" -Path $SECOUPath -Verbose
        New-ADGroup -SamAccountName ".$($Groups.Replace(" ","-")[$randomcount])" -GroupCategory Distribution -Description "$($Groups[$randomcount]) Distribution Group" -Path $DISTOUPath -Verbose
        # Write-Host  "_$($Groups.Replace(" ","-")[$randomcount])" "$($Groups[$randomcount]) Security Group" 
        ++$i
    }

}

#>



