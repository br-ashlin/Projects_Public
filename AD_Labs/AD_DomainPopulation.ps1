#requires -version 2
<#
.SYNOPSIS
  <Overview of script>

.DESCRIPTION
  Script to populate Active Directory Labs with AD Objects such as Users, Groups, Contacts, OUs.


.NOTES
  Version:        1.0
  Author:         Ben Ashlin
  Creation Date:  04/10/2022
  Purpose/Change: Initial script development
  
.EXAMPLE
  Create-Labusers -UserCount -OUPath
  Create-LabGroups -Groupcount -SecOUPath -DistOUPath
#>

#---------------------------------------------------------[Initialisations & Declarations]--------------------------------------------------------

#Set Error Action to Silently Continue
$ErrorActionPreference = "SilentlyContinue"

#Log File locations for exports, outputs and logging
#$LogFile = "$env:USERPROFILE\Desktop\AD_Lab-$LogDate.csv"
$LogFile = ".\Outputs\AD_Lab-$LogDate.csv"


#Wordlist of Names
$names = Get-Content .\Lists\Names.txt

#Password List
$passwords = Get-Content .\Lists\500-worst-passwords.txt

#Groups List (By Cities of USA)
$Groups = Get-Content .\Lists\Groups-By-City-USA.txt

#Wordlist value Count
$namelistcount = 1..$names.count
$pwdlistcount = 1..$passwords.count
$grpslistcount = 1..$Groups.count

[Array]$Usernames = @()
[Array]$Groups = @()
[Array]$Contacts = @()
[array]$SamNames = @()

[String]$Domain = "Contoso.com"
[String]$Users_OU = "DistinguishedName"
[String]$Groups_OU = "DistinguishedName"
[String]$Contacts_OU = "DistinguishedName"



#-----------------------------------------------------------[Functions]------------------------------------------------------------

# Create Users List (Usercount)

Function Create-LabUsers {
    [cmdletbinding()]
    Param(
        [int32]$Usercount,
        [String]$OUPath
    )

    for ($i = 0 ; $i -le $Usercount) {
        $randomcount = $nameslistcount | Get-Random -Count 2
        # Write-Host "$($names[$randomcount])"
        $Usernames += "$($names[$randomcount])"
        ++$i
    }

    #Get SAM Account names

    foreach ($Name in $usernames) {
        $SamNames += $usernames.Replace(" ", ".")
    }


    #Create Users from Names list & Set Passwords from PWDList

    For ($i = 0; $i -le $usernames.Count) {
        $randomcount = $pwdlistcount | Get-Random
        New-ADUser -SamAccountName "$($samnames[$i])" -DisplayName "$($Usernames[$i])" -EmailAddress "$($samnames[$i])@$($Domain)" -AccountPassword (ConvertTo-SecureString -AsPlainText "$($passwords[$randomcount])") -Path $OUPath -Verbose
        $i++
    }
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





