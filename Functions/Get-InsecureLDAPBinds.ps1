function Get-InsecureLDAPBinds {
    <#
        .SYNOPSIS
            Queries DC's for Insecure Binds and what is doing them
        .DESCRIPTION
            Requires Directory Service Logging to be turned up for these events to be generated, but then queries them for what is doing Insecure Binds
        .PARAMETER Domain
            Domain to search. It will use the Current Domain if none is specified
        .PARAMETER Days
            Specified number of Days in the past to check. Defaults to 14
        .EXAMPLE
            C
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
        $InsecureBinds = @()
    } #BEGIN

    PROCESS {
        Foreach ($DC in $DCs) {
            $Event2889 = Get-WinEvent -ComputerName $DC -FilterHashtable @{Logname = 'Directory Service'; Id = 2889; StartTime = (get-date).AddDays(-$Days) }

            foreach ($Event in $Event2889) {

                $Row = New-Object PSObject
                $Row | Add-Member -MemberType noteproperty -Name "User" -Value $Event.Properties.Value[1]
                $Row | Add-Member -MemberType noteproperty -Name "IP" -Value $Event.Properties.Value[0]
                $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                $InsecureBinds += $Row
            }

            $DC = $Null
        }

    } #PROCESS

    END { 
        $InsecureBinds
    } #END

} #FUNCTION