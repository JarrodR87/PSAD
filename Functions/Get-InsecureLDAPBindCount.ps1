function Get-InsecureLDAPBindCount {
    <#
        .SYNOPSIS
            Gets count of Insecure LDAP Bind Events
        .DESCRIPTION
            Required Audit logging be turned up to see these Events generated
        .PARAMETER Domain
            Domain to search. It will use the Current Domain if none is specified
        .PARAMETER Days
            Specified number of Days in the past to check. Defaults to 14
        .EXAMPLE
            Get-InsecureLDAPBindCount -Domain Test.com -Days 3
        .EXAMPLE
            Get-InsecureLDAPBindCount
    #>
    [CmdletBinding()]
    Param(
        [Parameter()]$Domain,
        [Parameter()]$Days
    ) 
    BEGIN { 
        if ($NULL -eq $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }

        if ($NULL -eq $Days) {
            $Days = '14'
        }

        $DCs = (Get-ADDomainController -Filter * -Server $Domain).Name
        $InsecureLDAPBinds = @()
    } #BEGIN

    PROCESS {
        foreach ($DC in $DCs) {
            $Event2886 = Get-WinEvent -ComputerName $DC -FilterHashtable @{Logname = 'Directory Service'; Id = 2886; StartTime = (get-date).AddDays(-$Days) }
            $Event2887 = Get-WinEvent -ComputerName $DC -FilterHashtable @{Logname = 'Directory Service'; Id = 2887; StartTime = (get-date).AddDays(-$Days) }
            $Event2888 = Get-WinEvent -ComputerName $DC -FilterHashtable @{Logname = 'Directory Service'; Id = 2888; StartTime = (get-date).AddDays(-$Days) }
            $Event2889 = Get-WinEvent -ComputerName $DC -FilterHashtable @{Logname = 'Directory Service'; Id = 2889; StartTime = (get-date).AddDays(-$Days) }

            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "DC" -Value $DC
            $Row | Add-Member -MemberType noteproperty -Name "Event2886Count" -Value $Event2886.Count
            $Row | Add-Member -MemberType noteproperty -Name "Event2887Count" -Value $Event2887.Count
            $Row | Add-Member -MemberType noteproperty -Name "Event2888Count" -Value $Event2888.Count
            $Row | Add-Member -MemberType noteproperty -Name "Event2889Count" -Value $Event2889.Count

            $InsecureLDAPBinds += $Row
        }

    } #PROCESS

    END { 
        $InsecureLDAPBinds
    } #END

} #FUNCTION