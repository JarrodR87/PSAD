function Get-ADUserGroupsFriendlyNames {
    <#
        .SYNOPSIS
            Gets a list of Group Names as Friendly Names instead of DN's
        .DESCRIPTION
            Pulls the Users Group List and then converts the list to Friendly Names
        .PARAMETER Identity
            User whose groups to search
        .PARAMETER Domain
            Optional - Uses Current Domain if not specified
        .EXAMPLE
            Get-ADUserGroupsFriendlyNames -Identity User1 -Domain test.com
        .EXAMPLE
            Get-ADUserGroupsFriendlyNames -Identity User2
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]$Identity,
        [Parameter()]$Domain
    ) 
    BEGIN { 
        if ($NULL -eq $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }
    } #BEGIN

    PROCESS {
        $Groups = ((Get-ADUser $Identity -Properties MemberOf -Server $Domain).MemberOf)
        $GroupFriendlyNames = foreach ($Group in $Groups) {
            (Get-ADGroup $Group -Server $Domain).name 
        }
    } #PROCESS

    END { 
        $GroupFriendlyNames
    } #END

} #FUNCTION