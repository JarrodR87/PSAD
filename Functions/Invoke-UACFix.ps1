function Invoke-UACFix {
    <#
        .SYNOPSIS
            Fixes Issues found with GET-ADUserUACIssues
        .DESCRIPTION
            Fixes Specified Issue, but currently only does No Password Required
        .PARAMETER Domain
            Optional - Current Domain will be used if not specified
        .EXAMPLE
            Invoke-UACFix
        .EXAMPLE
            Invoke-UACFix -Domain Test.com
    #>
    [CmdletBinding()]
    Param(
        [Parameter()]$Domain
    ) 
    BEGIN { 
        if ($NULL -eq $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }

        $UACIssues = Get-ADuserUACIssues -Domain $Domain
        $UACIssues = $UACIssues | where-object -filterscript { ($_.UACIssue -like 'No Password Required') -and ($_.Identity -notlike '*$') }

    } #BEGIN

    PROCESS {
        foreach ($User in $UACIssues) {
            Set-ADUser -identity $User.Identity -PasswordNotRequired $false -Server $Domain
        }
    } #PROCESS

    END { 

    } #END

} #FUNCTION