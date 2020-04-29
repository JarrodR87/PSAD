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
            $Row | Add-Member -MemberType noteproperty -Name "Enabled" -Value $DomainPC.Enabled

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


function Get-ADuserUACIssues {
    <#
        .SYNOPSIS
            Checks current, or specified, Domain to see any UAC Flags that may be problematic
        .DESCRIPTION
            Queroes AD for all users matching specific UAC Flags and then returns them a sa combined list with a description of which flag they had
        .PARAMETER Domain
            Optional - Current Domain will be used if not specified
        .EXAMPLE
            Get-ADuserUACIssues
        .EXAMPLE
            Get-ADuserUACIssues -Domain TestDomain.com
    #>
    [CmdletBinding()]
    Param(
        [Parameter()]$Domain
    ) 
    BEGIN { 
      
        if ($NULL -eq $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }

        $ADUserUACIssues = @()

        # Check for accounts that don't have password expiry set
        $NoPWExpiry = Get-ADUser -Filter 'useraccountcontrol -band 65536' -Properties useraccountcontrol, SamAccountName -Server $Domain

        # Check for accounts that have no password requirement
        $NoPW = Get-ADUser -Filter 'useraccountcontrol -band 32' -Properties useraccountcontrol, SamAccountName -Server $Domain

        # Accounts that have the password stored in a reversibly encrypted format
        $ReversiblyEncrypted = Get-ADUser -Filter 'useraccountcontrol -band 128' -Properties useraccountcontrol, SamAccountName -Server $Domain

        # List users that are trusted for Kerberos delegation
        $TrustedDelegation = Get-ADUser -Filter 'useraccountcontrol -band 524288' -Properties useraccountcontrol, SamAccountName -Server $Domain

        # List accounts that don't require pre-authentication
        $NoPreAuthentication = Get-ADUser -Filter 'useraccountcontrol -band 4194304' -Properties useraccountcontrol, SamAccountName -Server $Domain

        # List accounts that have credentials encrypted with DES
        $DESEncryption = Get-ADUser -Filter 'useraccountcontrol -band 2097152' -Properties useraccountcontrol, SamAccountName -Server $Domain

        # List accounts that dont have the ability to change their Password
        $CannotChangePassword = Get-ADUser -Filter 'useraccountcontrol -band 64' -Properties useraccountcontrol, SamAccountName -Server $Domain

    } #BEGIN

    PROCESS {
   
        foreach ($User in $NoPWExpiry) {
            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "Identity" -Value $User.SamAccountName
            $Row | Add-Member -MemberType noteproperty -Name "Enabled" -Value $User.Enabled
            $Row | Add-Member -MemberType noteproperty -Name "UACIssue" -Value 'No Password Expiration Set'

            $ADUserUACIssues += $Row
        }

        foreach ($User1 in $NoPW) {
            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "Identity" -Value $User1.SamAccountName
            $Row | Add-Member -MemberType noteproperty -Name "Enabled" -Value $User1.Enabled
            $Row | Add-Member -MemberType noteproperty -Name "UACIssue" -Value 'No Password Required'

            $ADUserUACIssues += $Row
        }


        foreach ($User2 in $ReversiblyEncrypted) {
            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "Identity" -Value $User2.SamAccountName
            $Row | Add-Member -MemberType noteproperty -Name "Enabled" -Value $User2.Enabled
            $Row | Add-Member -MemberType noteproperty -Name "UACIssue" -Value 'Password Reversibly Encrypted'

            $ADUserUACIssues += $Row
        }

        foreach ($User3 in $TrustedDelegation) {
            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "Identity" -Value $User3.SamAccountName
            $Row | Add-Member -MemberType noteproperty -Name "Enabled" -Value $User3.Enabled
            $Row | Add-Member -MemberType noteproperty -Name "UACIssue" -Value 'Trusted for Kerberos Delegation'

            $ADUserUACIssues += $Row
        }

        foreach ($User4 in $NoPreAuthentication) {
            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "Identity" -Value $User4.SamAccountName
            $Row | Add-Member -MemberType noteproperty -Name "Enabled" -Value $User4.Enabled
            $Row | Add-Member -MemberType noteproperty -Name "UACIssue" -Value "Don't Require Pre-Authentication"

            $ADUserUACIssues += $Row
        }

        foreach ($User5 in $DESEncryption) {
            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "Identity" -Value $User5.SamAccountName
            $Row | Add-Member -MemberType noteproperty -Name "Enabled" -Value $User5.Enabled
            $Row | Add-Member -MemberType noteproperty -Name "UACIssue" -Value 'Credentials Encrypted with DES'

            $ADUserUACIssues += $Row
        }

        foreach ($User6 in $CannotChangePassword) {
            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "Identity" -Value $User6.SamAccountName
            $Row | Add-Member -MemberType noteproperty -Name "Enabled" -Value $User6.Enabled
            $Row | Add-Member -MemberType noteproperty -Name "UACIssue" -Value 'User Cannot Change Password'

            $ADUserUACIssues += $Row
        }
        
    } #PROCESS

    END { 
        $ADUserUACIssues
    } #END

} #FUNCTION


function Get-ADAccountLockouts {
    <#
        .SYNOPSIS
            Gathers Account Lockouts and their associated PC's for the specified days in the past
        .DESCRIPTION
            Gathers all Domain Controllers, and then queries the event log on each one to find the lockout events within the days specified and then breaks it up by User/Computer and adds it to a PS Custom Object
        .PARAMETER Days
            Days in the past to search the Event Logs - Optional. Will use 1 Day if none specified
        .EXAMPLE
            Get-ADAccountLockouts -Days 5
        .EXAMPLE
            Get-ADAccountLockouts
    #>
    [CmdletBinding()]
    Param(
        [Parameter()]$Days
    ) 
    BEGIN { 

        if ($NULL -eq $Days) {
            $Days = '1'
        }

        $ComputerName = (Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name)
        $LockedUsers = @()
    } #BEGIN

    PROCESS {
        Foreach ($Computer in $ComputerName) {
            $Events = Get-WinEvent -ComputerName $Computer -FilterHashtable @{Logname = 'Security'; ID = 4740 ; StartTime = (Get-Date).AddDays(-$Days) } -ErrorAction SilentlyContinue
            Foreach ($Event in $Events) {
                $Properties = @{DomainController = $Computer
                    Time                         = $Event.TimeCreated
                    Username                     = $Event.Properties.value[0]
                    CallerComputer               = $Event.Properties.value[1]
                }
                $LockedUsers += New-Object -TypeName PSObject -Property $Properties | Select-Object DomainController, Username, Time, CallerComputer
            }
        }
    } #PROCESS

    END { 
        $LockedUsers
    } #END

} #FUNCTION


function Get-WDSPrestagedComputers {
    <#
        .SYNOPSIS
            Gtes a list of WDS Deployed PC's, or PC's that have been pre-staged for a deployment
        .DESCRIPTION
            Checked AD for PC's with a NetbootGUID and lists them our
        .EXAMPLE
            Get-WDSPrestagedComputers
    #>
    [CmdletBinding()]
    Param(
        
    ) 
    BEGIN { 

    } #BEGIN

    PROCESS {
        Get-ADComputer -Filter { NetbootGUID -like "*" } -Properties NetbootGUID, created # | Select-Object -Property name, distinguishedName, created, NetbootGUID
    } #PROCESS

    END { 

    } #END

} #FUNCTION


function Clear-WDSPrestagedComputers {
    <#
        .SYNOPSIS
            Gets WDS PreStaged PC's and cleared the NetbootGUID
        .DESCRIPTION
            Queries AD for PreStaged PC's, and then cleard the NetbootGUID if it falls in the date range specified
        .PARAMETER Days
            Number of Days in the past to search for PC's with a NetbootGUID
        .EXAMPLE
            Clear-WDSPrestagedComputers -Days 7
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)][string]$Days    
    ) 
    BEGIN { 

    } #BEGIN

    PROCESS {
        Get-WDSPrestagedComputers | Where-Object { $_.Created -le ((get-date).addDays(-$Days)) } | Set-ADComputer -clear NetbootGUID
    } #PROCESS

    END { 

    } #END

} #FUNCTION


function Get-ADOSCount {
    <#
        .SYNOPSIS
            Gets Active Directory OS Counts
        .DESCRIPTION
            Queries AD for PC's Operating Systems and then sorts them by the count and outputs a table
        .PARAMETER Domain
            Optional - Uses Current Domain if not specified
        .EXAMPLE
            Get-ADOSCount -Domain Test.com
        .EXAMPLE
            Get-ADOSCount
    #>
    [CmdletBinding()]
    Param(
        [Parameter()]$Domain
    ) 
    BEGIN { 
        if ($NULL -eq $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }
    } #BEGIN

    PROCESS {
        Get-ADComputer -Filter * -Properties operatingSystem -Server $Domain | Group-Object -Property operatingSystem | Select-Object Name, Count | Sort-Object Name | Format-Table -AutoSize
    } #PROCESS

    END { 

    } #END

} #FUNCTION


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