

<#
DESCRIPTION:
Queries a Source AD Group and adds its members to the Target AD Group
#>

function Copy-ADGroupMembers {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)][string]$ADSourceGroup,
        [Parameter(Mandatory = $true)][string]$ADTargetGroup
    ) 
    BEGIN { 

    } #BEGIN

    PROCESS {
        $ADQuery = Get-ADGroupMember -Identity $ADSourceGroup -recursive | get-aduser -Properties * | Select-Object -ExpandProperty samaccountname

        foreach ($user in $ADQuery) {
            Add-ADGroupMember -Identity $ADTargetGroup -Members $user
        }
    } #PROCESS

    END { 

    } #END

} #FUNCTION





<#
DESCRIPTION:
Checks AD for a List of Servers in the current Domain and then checks DNS to see if they have Static Records
#>
function Get-ADServerNoStaticDNS {
    [CmdletBinding()]
    Param(
        
    ) 
    BEGIN { 
        $DC = (Get-ADDomainController).name
    } #BEGIN

    PROCESS {
        Get-ADComputer -Filter { OperatingSystem -Like '*Windows Server*' } | ForEach-Object {
            Get-DnsServerResourceRecord -ZoneName capacitor.knowles.com -ComputerName $DC -Name $_.Name | Where-Object { $NULL -ne $_.Timestamp }
        }
    } #PROCESS

    END { 

    } #END

} #FUNCTION




<#
DESCRIPTION:
Gets AD BitLocker Reovery Key for a specified PC/PC's
#>
function Get-ADBitLockerRecoveryKey {
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




<#
DESCRIPTION:
Gets Inactive PC's from the current/specified domain
#>
function Get-InactiveComputers {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]$Days,
        [Parameter()]$Domain
    ) 
    BEGIN { 
        $time = (Get-Date).Adddays( - ($Days))
        $InactiveReport = @()

        if ($NULL -eq $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }
        else {
        
        }
    } #BEGIN

    PROCESS {
        $DomainReport = Get-ADComputer -Filter { LastLogonTimeStamp -lt $time } -Properties * -Server $Domain

        Foreach ($DomainPC in $DomainReport) {
            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "Name" -Value $DomainPC.CN
            $Row | Add-Member -MemberType noteproperty -Name "DN" -Value $DomainPC.DistinguishedName
            $Row | Add-Member -MemberType noteproperty -Name "Last Logon" -Value $DomainPC.LastLogonDate
            $Row | Add-Member -MemberType noteproperty -Name "Date Created" -Value $DomainPC.whenCreated
            $Row | Add-Member -MemberType noteproperty -Name "Domain" -Value $Domain

            $InactiveReport += $Row

        }
        $InactiveReport
    } #PROCESS
   
    END { 

    } #END

} #FUNCTION




function Get-ADUserExchangeInfo {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]$Identity
    ) 
    BEGIN { 
        $ADUserExchangeInfo = @()
    } #BEGIN

    PROCESS {
        foreach ($User in $Identity) {
            $UserInfo = Get-ADUser -Identity $User -Properties * | Select-Object Name, @{name = 'Exchange DB'; expression = { (($_.HomeMDB).split(',')[0]).split('=')[1] } } , @{name = 'Exchange HomeServer'; expression = { ($_.msExchHomeServerName -split 'Servers/cn=')[1] } }

            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "Name" -Value $UserInfo.Name
            $Row | Add-Member -MemberType noteproperty -Name "Exchange DB" -Value $UserInfo.'Exchange DB'
            $Row | Add-Member -MemberType noteproperty -Name "Exchange HomeServer" -Value $UserInfo.'Exchange HomeServer'

            $ADUserExchangeInfo += $Row
        }
        $ADUserExchangeInfo
    } #PROCESS

    END { 

    } #END

} #FUNCTION



function Get-ADBitLockerStatus {
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




function Get-ServerList {
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




