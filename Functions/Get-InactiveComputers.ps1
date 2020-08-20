function Get-InactiveComputers {
    <#
        .SYNOPSIS
            Gets Inactive PC's from the current/specified domain
        .DESCRIPTION
            Queries AD for Inactive PC's based on the specified number of Days against the specified or current Domain
        .PARAMETER Days
            Number of Days to look in the post for PC's that have not communicated with AD
        .PARAMETER Domain
            Specifies the Domain to run against, or it will run against the current Domain
        .EXAMPLE
            Get-InactiveComputers -Days 90
        .EXAMPLE
            Get-InactiveComputers -Domain TestDomain.com -Days 90
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]$Days,
        [Parameter()]$Domain
    ) 
    BEGIN { 
        $time = (Get-Date).Adddays( - ($Days))
        $InactiveReport = @()

        if ($NULL -eq $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }
        else {
        
        }
    } #BEGIN

    PROCESS {
        $DomainReport = Get-ADComputer -Filter { LastLogonTimeStamp -lt $time } -Properties * -Server $Domain

        Foreach ($DomainPC in $DomainReport) {
            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "Name" -Value $DomainPC.CN
            $Row | Add-Member -MemberType noteproperty -Name "DN" -Value $DomainPC.DistinguishedName
            $Row | Add-Member -MemberType noteproperty -Name "Last Logon" -Value $DomainPC.LastLogonDate
            $Row | Add-Member -MemberType noteproperty -Name "Date Created" -Value $DomainPC.whenCreated
            $Row | Add-Member -MemberType noteproperty -Name "Domain" -Value $Domain
            $Row | Add-Member -MemberType noteproperty -Name "Enabled" -Value $DomainPC.Enabled

            $InactiveReport += $Row

        }
        $InactiveReport
    } #PROCESS
   
    END { 

    } #END

} #FUNCTION