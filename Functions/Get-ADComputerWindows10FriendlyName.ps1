function Get-ADComputerWindows10FriendlyName {
    <#
        .SYNOPSIS
            Queries Specified AD Computer and checks its OS Frienfly Name if it is Windows 10
        .DESCRIPTION
            Queries a Windows 10 PC from AD and checks its OS Version to determine the Feature Update Version of Windows 10 it is running
        .PARAMETER ComputerName
            Specified Computer/Computers to Query
        .PARAMETER Domain
            Optional - Can Query PC's in remote Domains/Forest
        .EXAMPLE
            Get-ADComputerWindows10FriendlyName -ComputerName TestPC01
        .EXAMPLE
            Get-ADComputerWindows10FriendlyName -ComputerName TestPC01 -Domain TestDomain.com
        .EXAMPLE
            Get-ADComputerWindows10FriendlyName -ComputerName TestPC01,TestPC02
        .EXAMPLE
            Get-ADComputerWindows10FriendlyName -ComputerName TestPC01,TestPC02 -Domain TestDomain.com
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]$ComputerName,    
        [Parameter()]$Domain
    ) 
    BEGIN { 

        if ($NULL -eq $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }

        $Windows10PC = @()
       
    } #BEGIN

    PROCESS {
        foreach ($Computer in $ComputerName) {
            $PCinfo = Get-ADComputer -Identity $Computer -Server $Domain -Properties OperatingSystem, OperatingSystemVersion

            $OSFriendlyName = $NULL

            if ($PCinfo.OperatingSystemVersion -eq '10.0 (18363)') {
                $OSFriendlyName = 'Windows 10 1909'
            }
            if ($PCinfo.OperatingSystemVersion -eq '10.0 (18362)') {
                $OSFriendlyName = 'Windows 10 1903'
            }
            elseif ($PCinfo.OperatingSystemVersion -eq '10.0 (17763)') {
                $OSFriendlyName = 'Windows 10 1809'
            }
            elseif ($PCinfo.OperatingSystemVersion -eq '10.0 (17134)') {
                $OSFriendlyName = 'Windows 10 1803'
            }
            elseif ($PCinfo.OperatingSystemVersion -eq '10.0 (16299)') {
                $OSFriendlyName = 'Windows 10 1709'
            }
            elseif ($PCinfo.OperatingSystemVersion -eq '10.0 (15063)') {
                $OSFriendlyName = 'Windows 10 1703'
            }
            elseif ($PCinfo.OperatingSystemVersion -eq '10.0 (14393)') {
                $OSFriendlyName = 'Windows 10 1607'
            }
            elseif ($PCinfo.OperatingSystemVersion -eq '10.0 (10586)') {
                $OSFriendlyName = 'Windows 10 1511'
            }
            else {
                $OSFriendlyName = 'UNKNOWN'
            }


            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "ComputerName" -Value $PCinfo.name
            $Row | Add-Member -MemberType noteproperty -Name "OSFriendlyName" -Value $OSFriendlyName
            $Row | Add-Member -MemberType noteproperty -Name "OperatingSystem" -Value $PCinfo.OperatingSystem
            $Row | Add-Member -MemberType noteproperty -Name "OperatingSystemVersion" -Value $PCinfo.OperatingSystemVersion

            $Windows10PC += $Row
        }

        $Windows10PC
    } #PROCESS

    END { 

    } #END

} #FUNCTION