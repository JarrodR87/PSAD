function Get-ADBitLockerStatus {
    <#
        .SYNOPSIS
            Queries AD for all BitLocked PC's
        .DESCRIPTION
            Queries AD for PC's with a BitLocker Attribute and returns a unique list with the PC, OS and OS Version. Uses current domain if none specified
        .PARAMETER Domain
            Optional - Current Domain will be used if none is specified
        .EXAMPLE
            Get-ADBitLockerStatus
        .EXAMPLE
            Get-ADBitLockerStatus -Domain TestDomain.Com
    #>
    [CmdletBinding()]
    Param(
        [Parameter()]$Domain
    ) 
    BEGIN { 
        $BitLockerStatus = @()

        if ($NULL -eq $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }

        $BitLockerObjects = Get-ADObject -Filter { ObjectClass -eq "msFVE-RecoveryInformation" } -Server $Domain

    } #BEGIN

    PROCESS {
        $BitLockerObjectParentList = foreach ($BitLockerObject in $BitLockerObjects) {
            $BitLockerObjectParent = $BitLockerObject | Select-Object *, @{l = 'Parent'; e = { (New-Object 'System.DirectoryServices.directoryEntry' "LDAP://$($_.distinguishedname)").Parent } }
            $BitLockerObjectParent = $BitLockerObjectParent.Parent
            $BitLockerObjectParent = $BitLockerObjectParent -replace 'LDAP://', ''
    
            $BitLockerObjectParent
        }

        $BitLockerObjectParentList = $BitLockerObjectParentList | Select-Object -Unique

        foreach ($BitLockerObjectParent in $BitLockerObjectParentList) {
            $ADComputerInfo = Get-ADComputer -Identity $BitLockerObjectParent -Properties Name, OperatingSystem, OperatingSystemVersion -Server $Domain

            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "ComputerName" -Value $ADComputerInfo.Name
            $Row | Add-Member -MemberType noteproperty -Name "OS Name" -Value $ADComputerInfo.OperatingSystem
            $Row | Add-Member -MemberType noteproperty -Name "OS Version" -Value $ADComputerInfo.OperatingSystemVersion

            $BitLockerStatus += $Row
            $BitLockerObjectParent = $NULL
        }

        $BitLockerStatus

    } #PROCESS

    END { 

    } #END

} #FUNCTION