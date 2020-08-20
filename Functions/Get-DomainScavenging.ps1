function Get-DomainScavenging {
    <#
        .SYNOPSIS
            Queries Current or specified Domain for DNS Scavenging Information
        .DESCRIPTION
            Queries AD for a list of Domain Controllers and then queries them all for their Scavenging State
        .PARAMETER Domain
            Optional - Will use the current domain if none is specified
        .EXAMPLE
            Get-DomainScavenging
        .EXAMPLE
            Get-DomainScavenging -Domain TestDomain.com
        .EXAMPLE
            Get-DomainScavenging | Format-Table
        .EXAMPLE
            Get-DomainScavenging -Domain TestDomain.com | Format-Table
    #>
    [CmdletBinding()]
    Param(
        [Parameter()]$Domain
    ) 

    BEGIN { 
        if ($NULL -eq $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }

        $Scavenging = @()

    } #BEGIN

    PROCESS {
        $DomainControllers = (get-addomain -Server $Domain).ReplicaDirectoryServers

        foreach ($DomainController in $DomainControllers) {
            $ScavengingInfo = Get-DnsServerScavenging -ComputerName $DomainController

            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "DomainController" -Value $DomainController
            $Row | Add-Member -MemberType noteproperty -Name "NoRefreshInterval" -Value $ScavengingInfo.NoRefreshInterval
            $Row | Add-Member -MemberType noteproperty -Name "RefreshInterval" -Value $ScavengingInfo.RefreshInterval
            $Row | Add-Member -MemberType noteproperty -Name "ScavengingInterval" -Value $ScavengingInfo.ScavengingInterval
            $Row | Add-Member -MemberType noteproperty -Name "ScavengingState" -Value $ScavengingInfo.ScavengingState
            $Row | Add-Member -MemberType noteproperty -Name "LastScavengeTime" -Value $ScavengingInfo.LastScavengeTime

            $Scavenging += $Row
        }

        $Scavenging
    } #PROCESS

    END { 

    } #END

} #FUNCTION