function Get-LAPSStatus {
    <#
        .SYNOPSIS
            Gets LAPS Information for Specified Computer
        .DESCRIPTION
            Queries LAPS Informnation from AD Computer Object via Get-ADComputer and GET-ADObject
        .PARAMETER ComputerName
            Specified Computer or Computers to retrieve LAPS Information for
        .EXAMPLE
            Get-LAPSStatus -ComputerName SERVER01
        .EXAMPLE
            Get-LAPSStatus -ComputerName SERVER01,SERVER02
    #>
    [CmdletBinding()]
    Param(
        [Parameter()]$ComputerName
    ) 
    BEGIN { 
        $ADComputerLAPSInfo = @()
    } #BEGIN

    PROCESS {
        foreach ($Computer in $ComputerName) {
            $ADObject = Get-ADObject (Get-ADComputer $Computer) -Properties ms-Mcs-AdmPwd, ms-MCS-AdmPwdExpirationTime
            $LAPSExpirationDate = $([datetime]::FromFileTime([convert]::ToInt64($ADObject.'ms-MCS-AdmPwdExpirationTime', 10)))
            $LAPSPassword = $ADObject.'ms-Mcs-AdmPwd'

            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "Computer" -Value $Computer
            $Row | Add-Member -MemberType noteproperty -Name "LAPSExpirationDate" -Value $LAPSExpirationDate
            $Row | Add-Member -MemberType noteproperty -Name "LAPSPassword" -Value $LAPSPassword
            
            $ADComputerLAPSInfo += $Row

            $NULL = $ADObject 
            $NULL = $LAPSExpirationDate
            $NULL = $LAPSPassword
        }

    } #PROCESS

    END { 
        $ADComputerLAPSInfo
    } #END

} #FUNCTION