function Get-WDSPrestagedComputers {
    <#
        .SYNOPSIS
            Gtes a list of WDS Deployed PC's, or PC's that have been pre-staged for a deployment
        .DESCRIPTION
            Checked AD for PC's with a NetbootGUID and lists them our
        .EXAMPLE
            Get-WDSPrestagedComputers
    #>
    [CmdletBinding()]
    Param(
        
    ) 
    BEGIN { 

    } #BEGIN

    PROCESS {
        Get-ADComputer -Filter { NetbootGUID -like "*" } -Properties NetbootGUID, created # | Select-Object -Property name, distinguishedName, created, NetbootGUID
    } #PROCESS

    END { 

    } #END

} #FUNCTION