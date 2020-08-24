function Get-ADUserLogonWorkstations {
    <#
        .SYNOPSIS
            Gets Users with Logon Restrictions to specific Workstations
        .DESCRIPTION
            Queries Specified Domain to find users with Logon Restrictions
        .PARAMETER Domain
            Domain to search. It will use the Current Domain if none is specified
        .EXAMPLE
            Get-ADUserLogonWorkstations
        .EXAMPLE
            Get-ADUserLogonWorkstations -Domain Test.com
    #>
    [CmdletBinding()]
    Param(
        [Parameter()]$Domain
    ) 
    BEGIN { 
        if ($NULL -eq $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }
    } #BEGIN

    PROCESS {
        Get-ADUser -Filter { LogonWorkstations -ne "$NULL" } -Properties LogonWorkstations -Server $Domain | Select-Object Name, LogonWorkstations
    } #PROCESS

    END { 

    } #END

} #FUNCTION