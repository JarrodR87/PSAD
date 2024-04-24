function Get-ADUnManagedGroups {
    <#
        .SYNOPSIS
            Finds Unmanaged AD Groups
        .DESCRIPTION
            Finds AD Groups without the ManagedBy Property Set
        .EXAMPLE
            Get-ADUnManagedGroups
        .EXAMPLE
            $UnManagedGroups = Get-ADUnManagedGroups
    #>
    [CmdletBinding()]
    Param(
        
    ) 
    BEGIN { 

    } #BEGIN

    PROCESS {
        Get-ADGroup -LDAPFilter "(!ManagedBy=*)" -Properties ManagedBy, Description
    } #PROCESS

    END { 

    } #END

} #FUNCTION