function Get-ServerList {
    <#
        .SYNOPSIS
            Queries a specified Domain for a list of Servers and associated AD Attributes
        .DESCRIPTION
            Queries for all Windows Server OS PC's in a domain and pulls their Name, Location, Description, Operating System, and Domain
        .PARAMETER Domain
            Optional - Will use the current domain if none specified
        .EXAMPLE
            Get-ServerList
        .EXAMPLE
            Get-ServerList -Domain TestDomain.com
    #>
    [CmdletBinding()]
    Param(
        [Parameter()]$Domain
    ) 
    BEGIN { 
        if ($NULL -eq $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }

        $ServerList = @()

    } #BEGIN

    PROCESS {
        $Servers = Get-ADComputer -Filter { OperatingSystem -Like '*Windows Server*' } -Property * -Server $Domain

        Foreach ($Server in $Servers) {

            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "ComputerName" -Value $Server.CN
            $Row | Add-Member -MemberType noteproperty -Name "Location" -Value $Server.Location
            $Row | Add-Member -MemberType noteproperty -Name "Description" -Value $Server.Description
            $Row | Add-Member -MemberType noteproperty -Name "OperatingSystem" -Value $Server.OperatingSystem
            $Row | Add-Member -MemberType noteproperty -Name "Domain" -Value $Domain

            $ServerList += $Row
        }
        
        $ServerList
    } #PROCESS

    END { 

    } #END

} #FUNCTION