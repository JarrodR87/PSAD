function Get-ADWindows10VersionCount {
    <#
        .SYNOPSIS
            Gathers Windows 10 OS Counts
        .DESCRIPTION
            Queries AD for Windows 10 OS Counts
        .PARAMETER Domain
            Optional - Uses Current Domain if not specified
        .EXAMPLE
            Get-ADWindows10VersionCount -Domain Test.com
    #>
    [CmdletBinding()]
    Param(
        [Parameter()]$Domain
    ) 
    BEGIN { 
        if ($NULL -eq $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }
        
        $Windows10PCs = Get-ADComputer -Filter { OperatingSystem -Like '*Windows 10*' } -Properties * -Server $Domain

        $Windows10VersionCount = @()
    } #BEGIN

    PROCESS {

        $Row = New-Object PSObject
        $Row | Add-Member -MemberType noteproperty -Name "Windows 10 20H2" -Value ($Windows10PCs | Where-Object -filter { $_.OperatingSystemVersion -Like '10.0 (19042)' }).Count
        $Row | Add-Member -MemberType noteproperty -Name "Windows 10 20H1" -Value ($Windows10PCs | Where-Object -filter { $_.OperatingSystemVersion -Like '10.0 (19041)' }).Count
        $Row | Add-Member -MemberType noteproperty -Name "Windows 10 1909" -Value ($Windows10PCs | Where-Object -filter { $_.OperatingSystemVersion -Like '10.0 (18363)' }).Count
        $Row | Add-Member -MemberType noteproperty -Name "Windows 10 1903" -Value ($Windows10PCs | Where-Object -filter { $_.OperatingSystemVersion -Like '10.0 (18362)' }).Count
        $Row | Add-Member -MemberType noteproperty -Name "Windows 10 1809" -Value ($Windows10PCs | Where-Object -filter { $_.OperatingSystemVersion -Like '10.0 (17763)' }).Count
        $Row | Add-Member -MemberType noteproperty -Name "Windows 10 1803" -Value ($Windows10PCs | Where-Object -filter { $_.OperatingSystemVersion -Like '10.0 (17134)' }).Count
        $Row | Add-Member -MemberType noteproperty -Name "Windows 10 1709" -Value ($Windows10PCs | Where-Object -filter { $_.OperatingSystemVersion -Like '10.0 (16299)' }).Count
        $Row | Add-Member -MemberType noteproperty -Name "Windows 10 1703" -Value ($Windows10PCs | Where-Object -filter { $_.OperatingSystemVersion -Like '10.0 (15063)' }).Count
        $Row | Add-Member -MemberType noteproperty -Name "Windows 10 1607" -Value ($Windows10PCs | Where-Object -filter { $_.OperatingSystemVersion -Like '10.0 (14393)' }).Count
        $Row | Add-Member -MemberType noteproperty -Name "Windows 10 1511" -Value ($Windows10PCs | Where-Object -filter { $_.OperatingSystemVersion -Like '10.0 (10586)' }).Count
            
        $Windows10VersionCount += $Row

    } #PROCESS

    END { 
        $Windows10VersionCount
    } #END

} #FUNCTION