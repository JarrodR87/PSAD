function Copy-ADGroupMembers {
    <#
        .SYNOPSIS
            Queries a Source AD Group and adds its members to the Target AD Group
        .DESCRIPTION
            Queries one AD Group and enumerates the Users and then adds them to the Target Group specified
        .PARAMETER ADSourceGroup
            Group to copy Users from
        .PARAMETER ADTargetGroup
            Group to copy Users to
        .EXAMPLE
            Copy-ADGroupMembers -ADSourceGroup Group1 -ADTargetGroup Group2
    #>
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


function Get-ADServerNoStaticDNS {
    <#
        .SYNOPSIS
            Checks AD for a List of Servers in the current Domain and then checks DNS to see if they have Static Records
        .DESCRIPTION
            Queries AD for a list of Servers and then checks DNS for Records with a Null Timestamp indicating they are not Static
        .EXAMPLE
            Get-ADServerNoStaticDNS
    #>
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


function Get-InactiveComputers {
    <#
        .SYNOPSIS
            Gets Inactive PC's from the current/specified domain
        .DESCRIPTION
            Queries AD for Inactive PC's based on the specified number of Days against the specified or current Domain
        .PARAMETER Days
            Number of Days to look in the post for PC's that have not communicated with AD
        .PARAMETER Domain
            Specifies the Domain to run against, or it will run against the current Domain
        .EXAMPLE
            Get-InactiveComputers -Days 90
        .EXAMPLE
            Get-InactiveComputers -Domain TestDomain.com -Days 90
    #>
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
    <#
        .SYNOPSIS
            Queries AD to locate Exchange Information about Users
        .DESCRIPTION
            Queries a User or Users from AD and lists their Exchange Database and Home Server from Active Directory Attributes
        .PARAMETER Identity
            User or Users to query
        .EXAMPLE
            Get-ADUserExchangeInfo -Identity TestUser1
        .EXAMPLE
            Get-ADUserExchangeInfo -Identity TestUser1,testUser2
    #>
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


function Get-FSMORoles {
    <#
        .SYNOPSIS
            Queries FSMO Roles for the current or specified Domain
        .DESCRIPTION
            Queries AD Domain/Forest to locate the FSMO Role Holders
        .PARAMETER Domain
            Optional - Will Query Current domain if not specified
        .EXAMPLE
            Get-FSMORoles
        .EXAMPLE
            Get-FSMORoles -Domain TestDomain.com
    #>
    [CmdletBinding()]
    Param(
        [Parameter()]$Domain
    ) 
    BEGIN { 
        if ($NULL -eq $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }

        $InfrastructureMaster = (Get-ADDomain -Server $Domain).InfrastructureMaster
        $RIDMaster = (Get-ADDomain -Server $Domain).RIDMaster
        $PDCEmulator = (Get-ADDomain -Server $Domain).PDCEmulator
        $DomainNamingMaster = (Get-ADForest -Server $Domain).DomainNamingMaster
        $SchemaMaster = (Get-ADForest -Server $Domain).SchemaMaster
        
        $FSMORoles = @()
    } #BEGIN

    PROCESS {
        $Row = New-Object PSObject
        $Row | Add-Member -MemberType noteproperty -Name "InfrastructureMaster" -Value $InfrastructureMaster
        $Row | Add-Member -MemberType noteproperty -Name "RIDMaster" -Value $RIDMaster
        $Row | Add-Member -MemberType noteproperty -Name "PDCEmulator" -Value $PDCEmulator
        $Row | Add-Member -MemberType noteproperty -Name "DomainNamingMaster" -Value $DomainNamingMaster
        $Row | Add-Member -MemberType noteproperty -Name "SchemaMaster" -Value $SchemaMaster

        $FSMORoles += $Row
    } #PROCESS

    END { 
        $FSMORoles 
    } #END

} #FUNCTION


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


function Invoke-AsgMSA {
    <#
        .SYNOPSIS
            Allows you to test gMSA Permissions and access by running items interactively as the gMSA
        .DESCRIPTION
            Runs a program/command as a gMSA Account installed on the PC
        .PARAMETER gMSA
            gMSA Account to run the command as. The Account needs to be installed on the PC
        .PARAMETER PSExecPath
            Full Path to PSExec.exe Executable from Sysinternals Suite
        .PARAMETER Program
            Command or Program to run as the gMSA like PowerShell.exe or cmd.exe
        .PARAMETER Domain
            Optional - Will use current domain if none entered
        .EXAMPLE
            Invoke-AsgMSA -PSExecPath <Path to PSExec.exe> -gMSA <gMSA Account> -Program cmd.exe
        .EXAMPLE
            Invoke-AsgMSA -PSExecPath <Path to PSExec.exe> -gMSA <gMSA Account> -Program cmd.exe -Domain <Remote Domain>
    #>
    [CmdletBinding()]
    Param(
        [Parameter()]$Domain,    
        [Parameter(Mandatory = $true)][string]$gMSA,
        [Parameter(Mandatory = $true)][string]$PSExecPath,
        [Parameter(Mandatory = $true)][string]$Program
    ) 
    BEGIN { 
        if ($NULL -eq $Domain) {
            $Domain = (Get-ADDomain).NetBIOSName
        }
    } #BEGIN

    PROCESS {
        Start-Process -FilePath $PSExecPath -ArgumentList "-i -u $Domain\$gMSA -p ~ $Program"
    } #PROCESS

    END { 

    } #END

} #FUNCTION