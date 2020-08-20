function Get-ADuserUACIssues {
    <#
        .SYNOPSIS
            Checks current, or specified, Domain to see any UAC Flags that may be problematic
        .DESCRIPTION
            Queroes AD for all users matching specific UAC Flags and then returns them a sa combined list with a description of which flag they had
        .PARAMETER Domain
            Optional - Current Domain will be used if not specified
        .EXAMPLE
            Get-ADuserUACIssues
        .EXAMPLE
            Get-ADuserUACIssues -Domain TestDomain.com
    #>
    [CmdletBinding()]
    Param(
        [Parameter()]$Domain
    ) 
    BEGIN { 
      
        if ($NULL -eq $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }

        $ADUserUACIssues = @()

        # Check for accounts that don't have password expiry set
        $NoPWExpiry = Get-ADUser -Filter 'useraccountcontrol -band 65536' -Properties useraccountcontrol, SamAccountName -Server $Domain

        # Check for accounts that have no password requirement
        $NoPW = Get-ADUser -Filter 'useraccountcontrol -band 32' -Properties useraccountcontrol, SamAccountName -Server $Domain

        # Accounts that have the password stored in a reversibly encrypted format
        $ReversiblyEncrypted = Get-ADUser -Filter 'useraccountcontrol -band 128' -Properties useraccountcontrol, SamAccountName -Server $Domain

        # List users that are trusted for Kerberos delegation
        $TrustedDelegation = Get-ADUser -Filter 'useraccountcontrol -band 524288' -Properties useraccountcontrol, SamAccountName -Server $Domain

        # List accounts that don't require pre-authentication
        $NoPreAuthentication = Get-ADUser -Filter 'useraccountcontrol -band 4194304' -Properties useraccountcontrol, SamAccountName -Server $Domain

        # List accounts that have credentials encrypted with DES
        $DESEncryption = Get-ADUser -Filter 'useraccountcontrol -band 2097152' -Properties useraccountcontrol, SamAccountName -Server $Domain

        # List accounts that dont have the ability to change their Password
        $CannotChangePassword = Get-ADUser -Filter 'useraccountcontrol -band 64' -Properties useraccountcontrol, SamAccountName -Server $Domain

    } #BEGIN

    PROCESS {
   
        foreach ($User in $NoPWExpiry) {
            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "Identity" -Value $User.SamAccountName
            $Row | Add-Member -MemberType noteproperty -Name "Enabled" -Value $User.Enabled
            $Row | Add-Member -MemberType noteproperty -Name "UACIssue" -Value 'No Password Expiration Set'
            $Row | Add-Member -MemberType noteproperty -Name "Domain" -Value $Domain

            $ADUserUACIssues += $Row
        }

        foreach ($User1 in $NoPW) {
            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "Identity" -Value $User1.SamAccountName
            $Row | Add-Member -MemberType noteproperty -Name "Enabled" -Value $User1.Enabled
            $Row | Add-Member -MemberType noteproperty -Name "UACIssue" -Value 'No Password Required'
            $Row | Add-Member -MemberType noteproperty -Name "Domain" -Value $Domain

            $ADUserUACIssues += $Row
        }


        foreach ($User2 in $ReversiblyEncrypted) {
            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "Identity" -Value $User2.SamAccountName
            $Row | Add-Member -MemberType noteproperty -Name "Enabled" -Value $User2.Enabled
            $Row | Add-Member -MemberType noteproperty -Name "UACIssue" -Value 'Password Reversibly Encrypted'
            $Row | Add-Member -MemberType noteproperty -Name "Domain" -Value $Domain

            $ADUserUACIssues += $Row
        }

        foreach ($User3 in $TrustedDelegation) {
            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "Identity" -Value $User3.SamAccountName
            $Row | Add-Member -MemberType noteproperty -Name "Enabled" -Value $User3.Enabled
            $Row | Add-Member -MemberType noteproperty -Name "UACIssue" -Value 'Trusted for Kerberos Delegation'
            $Row | Add-Member -MemberType noteproperty -Name "Domain" -Value $Domain

            $ADUserUACIssues += $Row
        }

        foreach ($User4 in $NoPreAuthentication) {
            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "Identity" -Value $User4.SamAccountName
            $Row | Add-Member -MemberType noteproperty -Name "Enabled" -Value $User4.Enabled
            $Row | Add-Member -MemberType noteproperty -Name "UACIssue" -Value "Don't Require Pre-Authentication"
            $Row | Add-Member -MemberType noteproperty -Name "Domain" -Value $Domain

            $ADUserUACIssues += $Row
        }

        foreach ($User5 in $DESEncryption) {
            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "Identity" -Value $User5.SamAccountName
            $Row | Add-Member -MemberType noteproperty -Name "Enabled" -Value $User5.Enabled
            $Row | Add-Member -MemberType noteproperty -Name "UACIssue" -Value 'Credentials Encrypted with DES'
            $Row | Add-Member -MemberType noteproperty -Name "Domain" -Value $Domain

            $ADUserUACIssues += $Row
        }

        foreach ($User6 in $CannotChangePassword) {
            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "Identity" -Value $User6.SamAccountName
            $Row | Add-Member -MemberType noteproperty -Name "Enabled" -Value $User6.Enabled
            $Row | Add-Member -MemberType noteproperty -Name "UACIssue" -Value 'User Cannot Change Password'
            $Row | Add-Member -MemberType noteproperty -Name "Domain" -Value $Domain
            
            $ADUserUACIssues += $Row
        }
        
    } #PROCESS

    END { 
        $ADUserUACIssues
    } #END

} #FUNCTION