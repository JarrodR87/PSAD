function Get-ADAccountLockouts {
    <#
        .SYNOPSIS
            Gathers Account Lockouts and their associated PC's for the specified days in the past
        .DESCRIPTION
            Gathers all Domain Controllers, and then queries the event log on each one to find the lockout events within the days specified and then breaks it up by User/Computer and adds it to a PS Custom Object
        .PARAMETER Days
            Days in the past to search the Event Logs - Optional. Will use 1 Day if none specified
        .EXAMPLE
            Get-ADAccountLockouts -Days 5
        .EXAMPLE
            Get-ADAccountLockouts
    #>
    [CmdletBinding()]
    Param(
        [Parameter()]$Days
    ) 
    BEGIN { 

        if ($NULL -eq $Days) {
            $Days = '1'
        }

        $ComputerName = (Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name)
        $LockedUsers = @()
    } #BEGIN

    PROCESS {
        Foreach ($Computer in $ComputerName) {
            $Events = Get-WinEvent -ComputerName $Computer -FilterHashtable @{Logname = 'Security'; ID = 4740 ; StartTime = (Get-Date).AddDays(-$Days) } -ErrorAction SilentlyContinue
            Foreach ($Event in $Events) {
                $Properties = @{DomainController = $Computer
                    Time                         = $Event.TimeCreated
                    Username                     = $Event.Properties.value[0]
                    CallerComputer               = $Event.Properties.value[1]
                }
                $LockedUsers += New-Object -TypeName PSObject -Property $Properties | Select-Object DomainController, Username, Time, CallerComputer
            }
        }
    } #PROCESS

    END { 
        $LockedUsers
    } #END

} #FUNCTION