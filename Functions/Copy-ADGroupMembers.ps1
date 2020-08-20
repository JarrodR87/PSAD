function Copy-ADGroupMembers {
    <#
        .SYNOPSIS
            Queries a Source AD Group and adds its members to the Target AD Group
        .DESCRIPTION
            Queries one AD Group and enumerates the Users and then adds them to the Target Group specified
        .PARAMETER ADSourceGroup
            Group to copy Users from
        .PARAMETER ADTargetGroup
            Group to copy Users to
        .EXAMPLE
            Copy-ADGroupMembers -ADSourceGroup Group1 -ADTargetGroup Group2
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)][string]$ADSourceGroup,
        [Parameter(Mandatory = $true)][string]$ADTargetGroup
    ) 
    BEGIN { 

    } #BEGIN

    PROCESS {
        $ADQuery = Get-ADGroupMember -Identity $ADSourceGroup -recursive | get-aduser -Properties * | Select-Object -ExpandProperty samaccountname

        foreach ($user in $ADQuery) {
            Add-ADGroupMember -Identity $ADTargetGroup -Members $user
        }
    } #PROCESS

    END { 

    } #END

} #FUNCTION