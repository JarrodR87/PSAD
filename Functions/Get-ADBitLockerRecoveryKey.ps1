function Get-ADBitLockerRecoveryKey {
    <#
        .SYNOPSIS
            Gets AD BitLocker Reovery Key for a specified PC/PC's
        .DESCRIPTION
            C
        .PARAMETER ComputerName
            Computer/Computers to query AD for it's Recovery Key for BitLocker
        .EXAMPLE
            Get-ADBitLockerRecoveryKey TestPC1
        .EXAMPLE
            Get-ADBitLockerRecoveryKey TestPC1,TestPC2
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]$ComputerName
    ) 
    BEGIN { 
        $BLRecovery = @()
    } #BEGIN

    PROCESS {
        foreach ($Computer in $ComputerName) {
       
            $ADComputer = Get-ADComputer $Computer
            $Bitlocker_Object = Get-ADObject -Filter { objectclass -eq 'msFVE-RecoveryInformation' } -SearchBase $ADComputer.DistinguishedName -Properties 'msFVE-RecoveryPassword'
            
            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "ComputerName" -Value $ADComputer.Name
            $Row | Add-Member -MemberType noteproperty -Name "BitlockerRecoveryKey" -Value $Bitlocker_Object.'msFVE-RecoveryPassword'

            $BLRecovery += $Row
        }
        $BLRecovery
    } #PROCESS

    END { 

    } #END

} #FUNCTION