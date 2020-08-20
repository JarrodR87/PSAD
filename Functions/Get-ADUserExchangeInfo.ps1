function Get-ADUserExchangeInfo {
    <#
        .SYNOPSIS
            Queries AD to locate Exchange Information about Users
        .DESCRIPTION
            Queries a User or Users from AD and lists their Exchange Database and Home Server from Active Directory Attributes
        .PARAMETER Identity
            User or Users to query
        .EXAMPLE
            Get-ADUserExchangeInfo -Identity TestUser1
        .EXAMPLE
            Get-ADUserExchangeInfo -Identity TestUser1,testUser2
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]$Identity
    ) 
    BEGIN { 
        $ADUserExchangeInfo = @()
    } #BEGIN

    PROCESS {
        foreach ($User in $Identity) {
            $UserInfo = Get-ADUser -Identity $User -Properties * | Select-Object Name, @{name = 'Exchange DB'; expression = { (($_.HomeMDB).split(',')[0]).split('=')[1] } } , @{name = 'Exchange HomeServer'; expression = { ($_.msExchHomeServerName -split 'Servers/cn=')[1] } }

            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "Name" -Value $UserInfo.Name
            $Row | Add-Member -MemberType noteproperty -Name "Exchange DB" -Value $UserInfo.'Exchange DB'
            $Row | Add-Member -MemberType noteproperty -Name "Exchange HomeServer" -Value $UserInfo.'Exchange HomeServer'

            $ADUserExchangeInfo += $Row
        }
        $ADUserExchangeInfo
    } #PROCESS

    END { 

    } #END

} #FUNCTION