function Get-ADOSCount {
    <#
        .SYNOPSIS
            Gets Active Directory OS Counts
        .DESCRIPTION
            Queries AD for PC's Operating Systems and then sorts them by the count and outputs a table
        .PARAMETER Domain
            Optional - Uses Current Domain if not specified
        .EXAMPLE
            Get-ADOSCount -Domain Test.com
        .EXAMPLE
            Get-ADOSCount
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
        Get-ADComputer -Filter * -Properties operatingSystem -Server $Domain | Group-Object -Property operatingSystem | Select-Object Name, Count | Sort-Object Name
    } #PROCESS

    END { 

    } #END

} #FUNCTION