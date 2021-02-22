function Copy-ADUserGroups {
    <#
        .SYNOPSIS
            Copies one AD Users Groups to another User, skipping duplicates
        .DESCRIPTION
            Queries list of Users Groups and copies them to the destination user. Cannot currently copy remote-domain groups
        .PARAMETER Domain
            Domain to search. It will use the Current Domain if none is specified
        .EXAMPLE
            Copy-ADUserGroups -SourceUser User1 -DestUser User2 -Domain Test.com
        .EXAMPLE
            Copy-ADUserGroups -SourceUser User1 -DestUser User2
    #>
    [CmdletBinding()]
    Param(
        [Parameter()]$SourceUser,
        [Parameter()]$DestUser,
        [Parameter()]$Domain
    ) 
    BEGIN { 
        if ($NULL -eq $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }

        $Source = Get-ADUser -Identity $SourceUser -Properties MemberOf -Server $Domain
        $Dest = Get-ADUser -Identity $DestUser -Properties MemberOf -Server $Domain

    } #BEGIN

    PROCESS {
        $Source.MemberOf | Where-Object { $Dest.MemberOf -notcontains $_ } |  Add-ADGroupMember -Members $Dest
    } #PROCESS

    END { 

    } #END

} #FUNCTION