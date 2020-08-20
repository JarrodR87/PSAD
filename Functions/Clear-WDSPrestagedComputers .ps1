function Clear-WDSPrestagedComputers {
    <#
        .SYNOPSIS
            Gets WDS PreStaged PC's and cleared the NetbootGUID
        .DESCRIPTION
            Queries AD for PreStaged PC's, and then cleard the NetbootGUID if it falls in the date range specified
        .PARAMETER Days
            Number of Days in the past to search for PC's with a NetbootGUID
        .EXAMPLE
            Clear-WDSPrestagedComputers -Days 7
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)][string]$Days    
    ) 
    BEGIN { 

    } #BEGIN

    PROCESS {
        Get-WDSPrestagedComputers | Where-Object { $_.Created -le ((get-date).addDays(-$Days)) } | Set-ADComputer -clear NetbootGUID
    } #PROCESS

    END { 

    } #END

} #FUNCTION