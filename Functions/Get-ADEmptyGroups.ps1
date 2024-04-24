function Get-ADEmptyGroups {
    <#
        .SYNOPSIS
            find empty groups 
        .DESCRIPTION
            Gets all AD Groups with zero Members
        .EXAMPLE
            Get-ADEmptyGroups
        .EXAMPLE
            $EmptyGroups = Get-ADEmptyGroups
    #>
    [CmdletBinding()]
    Param(
        
    ) 
    BEGIN { 

    } #BEGIN

    PROCESS {
        Get-ADGroup -filter * -Properties Members | Where-Object { ($_.Members).count -eq 0 }
    } #PROCESS

    END { 

    } #END

} #FUNCTION