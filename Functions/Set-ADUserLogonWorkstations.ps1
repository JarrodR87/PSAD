function Set-ADUserLogonWorkstations {
    <#
        .SYNOPSIS
            Sets Approved Logon Workstations for a specified Account
        .DESCRIPTION
            Uses the ApprovedWorkstations Parameter to set the approved workstations an account can login to
        .PARAMETER Domain
            Domain to use. It will use the Current Domain if none is specified
        .PARAMETER Identity
            User Account to Modify
        .PARAMETER ApprovedWorkstations
            List of Workstations allowed to login
        .EXAMPLE
            Set-ADUserLogonWorkstations -Identity 'TESTUSER1' -ApprovedWorkstations 'test1.test.com','test2.test.com','test3.test.com'
        .EXAMPLE
            Set-ADUserLogonWorkstations -Identity 'TESTUSER1' -ApprovedWorkstations 'test1.test.com','test2.test.com','test3.test.com' -Domain Test.com
    #>
    [CmdletBinding()]
    Param(
        [Parameter()]$Domain,
        [Parameter(Mandatory = $true)]$Identity,
        [Parameter(Mandatory = $true)]$ApprovedWorkstations

    ) 
    BEGIN { 
        $WorkstationList = @()

        if ($NULL -eq $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }

        foreach ($Workstation in $ApprovedWorkstations) {
            $WorkstationList += $Workstation
        }
        $WorkstationList = $WorkstationList -join ','
    } #BEGIN

    PROCESS {
        Set-ADUser -Identity $Identity -LogonWorkstations $WorkstationList -Server $Domain
    } #PROCESS

    END { 
        $WorkstationList
    } #END

} #FUNCTION