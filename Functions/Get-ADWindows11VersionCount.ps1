function Get-ADWindows11VersionCount {
    <#
        .SYNOPSIS
            Gathers Windows 11 OS Counts
        .DESCRIPTION
            Queries AD for Windows 11 OS Counts
        .PARAMETER Domain
            Optional - Uses Current Domain if not specified
        .EXAMPLE
            Get-ADWindows11VersionCount -Domain Test.com
    #>
    [CmdletBinding()]
    Param(
        [Parameter()]$Domain
    ) 
    BEGIN { 
        if ($NULL -eq $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }
        
        $Windows11PCs = Get-ADComputer -Filter { (OperatingSystem -Like '*Windows 11*') -and (Enabled -eq $TRUE) } -Properties OperatingSystemVersion -Server $Domain

        $Windows11VersionCount = @()
    } #BEGIN

    PROCESS {

        $Row = New-Object PSObject
        $Row | Add-Member -MemberType noteproperty -Name "Windows 11 23H2" -Value @($Windows11PCs | Where-Object -filter { $_.OperatingSystemVersion -Like '10.0 (22631)' }).Count
        $Row | Add-Member -MemberType noteproperty -Name "Windows 11 22H2" -Value @($Windows11PCs | Where-Object -filter { $_.OperatingSystemVersion -Like '10.0 (22621)' }).Count
        $Row | Add-Member -MemberType noteproperty -Name "Windows 11 21H2" -Value @($Windows11PCs | Where-Object -filter { $_.OperatingSystemVersion -Like '10.0 (22000)' }).Count
        
            
        $Windows11VersionCount += $Row

    } #PROCESS

    END { 
        $Windows11VersionCount
    } #END
    
} #FUNCTION