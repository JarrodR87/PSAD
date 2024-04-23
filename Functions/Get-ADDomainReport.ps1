function Get-ADDomainReport {
    <#
        .SYNOPSIS
            Gathers Domain Information
        .DESCRIPTION
            Collects Inforamtion from Specified Domain and returns it as HTML or HashTable
        .PARAMETER Domain
            Domain to run the Report against
        .PARAMETER ReportType
            Will accept either HashTable or HTML
        .EXAMPLE
            Get-ADDomainReport
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)]$Domain,
        [Parameter(Mandatory = $true)][ValidateSet("HashTable", "HTML")]$ReportType
    ) 
    BEGIN { 
        if ($NULL -eq $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }

        $DomainReport = @()
        $DomainSchemaFunctionalInfo = @()

        $HtmlHead = '<style>
    body {
        background-color: white;
        font-family:      "Calibri";
    }

    table {
        border-width:     1px;
        border-style:     solid;
        border-color:     black;
        border-collapse:  collapse;
        width:            100%;
    }

    th {
        border-width:     1px;
        padding:          5px;
        border-style:     solid;
        border-color:     black;
        background-color: #98C6F3;
    }

    td {
        border-width:     1px;
        padding:          5px;
        border-style:     solid;
        border-color:     black;
        background-color: White;
    }

    tr {
        text-align:       left;
    }
</style>'

    } #BEGIN

    PROCESS {
        $ADOSCount = Get-ADOSCount -Domain $Domain
        $ADOSCountHTML = $ADOSCount | ConvertTo-Html -Fragment

        $ADWindows10VersionCount = Get-ADWindows10VersionCount -Domain $Domain
        $ADWindows10VersionCountHTML = $ADWindows10VersionCount | ConvertTo-Html -Fragment

        $ADWindows11VersionCount = Get-ADWindows11VersionCount -Domain $Domain
        $ADWindows11VersionCountHTML = $ADWindows11VersionCount | ConvertTo-Html -Fragment
        
        $FSMORoles = Get-FSMORoles -Domain $Domain
        $FSMORolesHTML = $FSMORoles | ConvertTo-Html -Fragment

        $InactiveComputers = Get-InactiveComputers -Domain $Domain -Days 90
        $InactiveComputersHTML = $InactiveComputers | ConvertTo-Html -Fragment
        
        $ServerList = Get-ServerList -Domain $Domain
        $ServerListHTML = $ServerList | ConvertTo-Html -Fragment

        $ADBitLockerStatus = Get-ADBitLockerStatus -Domain $Domain
        $ADBitLockerStatusHTML = $ADBitLockerStatus | ConvertTo-Html -Fragment
        
        $ADUACIssues = Get-ADuserUACIssues -Domain $Domain
        $ADUACIssuesHTML = $ADUACIssues | ConvertTo-Html -Fragment

        $DomainAdmins = Get-ADGroupMember -Identity 'Domain Admins' -Server $Domain | Select-Object DistinguishedName, Name, ObjectClass, SamAccountName, SID
        $DomainAdminsHTML = $DomainAdmins | ConvertTo-Html -Fragment

        $EnterpriseAdmins = Get-ADGroupMember -Identity 'Enterprise Admins' -Server (Get-ADDomain $Domain).Forest | Select-Object DistinguishedName, Name, ObjectClass, SamAccountName, SID
        $EnterpriseAdminsHTML = $EnterpriseAdmins | ConvertTo-Html -Fragment

        $gMSAAccounts = Get-ADServiceAccount -Filter * -Server $Domain | Select-Object DistinguishedName, Name, ObjectClass, SamAccountName, SID
        $gMSAAccountsHTML = $gMSAAccounts | ConvertTo-Html -Fragment

        $ADDomainController = Get-ADDomainController -Filter * -Server $Domain | Select-Object Domain, Enabled, Forest, HostName, IPv4Address, IsGlobalCatalog, IsReadOnly, OperatingSystem, Site
        $ADDomainControllerHTML = $ADDomainController | ConvertTo-Html -Fragment


        $ForestMode = (Get-ADForest -Server $Domain).ForestMode
        $DomainMode = (Get-ADDomain -Server $Domain).DomainMode
        $SchemaVersion = (Get-ADObject (Get-ADRootDSE -Server $Domain).schemaNamingContext -Property objectVersion -Server $Domain).objectVersion


        $Row = New-Object PSObject
        $Row | Add-Member -MemberType noteproperty -Name "ForestFunctionalLevel" -Value $ForestMode
        $Row | Add-Member -MemberType noteproperty -Name "DomainFunctionalLevel" -Value $DomainMode
        $Row | Add-Member -MemberType noteproperty -Name "SchemaVersion" -Value $SchemaVersion
        
        $DomainSchemaFunctionalInfo += $Row
        $DomainSchemaFunctionalInfoHTML = $DomainSchemaFunctionalInfo | ConvertTo-Html -Fragment

        # Remote Domain Report HashTable
        $DomainReport = @{
            'ADOSCount'                  = $ADOSCount
            'ADWindows10VersionCount'    = $ADWindows10VersionCount
            'ADWindows11VersionCount'    = $ADWindows11VersionCount
            'FSMORoles'                  = $FSMORoles
            'InactiveComputers'          = $InactiveComputers
            'ServerList'                 = $ServerList
            'ADBitLockerStatus'          = $ADBitLockerStatus
            'ADUACIssues'                = $ADUACIssues
            'DomainAdmins'               = $DomainAdmins
            'EnterpriseAdmins'           = $EnterpriseAdmins
            'gMSAAccounts'               = $gMSAAccounts
            'ADDomainController'         = $ADDomainController
            'ForestMode'                 = $ForestMode
            'DomainMode'                 = $DomainMode
            'SchemaVersion'              = $SchemaVersion
            'DomainSchemaFunctionalInfo' = $DomainSchemaFunctionalInfo
        }

        # Remote Domain Report HTML
        $Head = $HtmlHead
        $DateGenerated = '<h1>' + 'Generated at ' + (Get-Date) + ' For ' + $Domain + '<h1>'
        $ADOSCountHeading = '<h2>Active Directory OS Counts</h2>'
        $ADWindows10VersionCountHeading = '<h2>Active Directory Windows 10 Version Counts</h2>'
        $ADWindows11VersionCountHeading = '<h2>Active Directory Windows 11 Version Counts</h2>'
        $FSMORolesHeading = '<h2>Active Directory FSMO Role Holders</h2>'
        $InactiveComputersHeading = '<h2>Active Directory Computers inactive for 90 Days</h2>'
        $ServerListHeading = '<h2>Active Directory Server List</h2>'
        $ADBitLockerStatusHeading = '<h2>Active Directory BitLocked Devices</h2>'
        $ADUACIssuesHeading = '<h2>Active Directory UAC Issues</h2>'
        $DomainAdminsHeading = '<h2>Active Directory Domain Admins</h2>'
        $EnterpriseAdminsHeading = '<h2>Active Directory Enterprise Admins</h2>'
        $gMSAAccountsHeading = '<h2>Active Directory gMSA Accounts</h2>'
        $ADDomainControllerHeading = '<h2>Active Directory Domain Controllers</h2>'
        $DomainSchemaFunctionalInfoHeading = '<h2>Active Directory Forest and Domain Functional Levels and Schema Version</h2>'



        $DomainReportHTML = $Head + `
            $DateGenerated + `
            $ADOSCountHeading + `
            $ADOSCountHTML + `
            $ADWindows10VersionCountHeading + `
            $ADWindows10VersionCountHTML + `
            $ADWindows11VersionCountHeading + `
            $ADWindows11VersionCountHTML + `
            $FSMORolesHeading + `
            $FSMORolesHTML + `
            $InactiveComputersHeading + `
            $InactiveComputersHTML + `
            $ServerListHeading + `
            $ServerListHTML + `
            $ADBitLockerStatusHeading + `
            $ADBitLockerStatusHTML + `
            $ADUACIssuesHeading + `
            $ADUACIssuesHTML + `
            $DomainAdminsHeading + `
            $DomainAdminsHTML + `
            $EnterpriseAdminsHeading + `
            $EnterpriseAdminsHTML + `
            $gMSAAccountsHeading + `
            $gMSAAccountsHTML + `
            $ADDomainControllerHeading + `
            $ADDomainControllerHTML + `
            $ForestModeHeading + `
            $DomainSchemaFunctionalInfoHeading + `
            $DomainSchemaFunctionalInfoHTML



    } #PROCESS

    END { 
        if ($ReportType -eq 'HTML') {
            $DomainReportHTML
        }
        elseif ($ReportType -eq 'HashTable') {
            $DomainReport
        }
    } #END

} #FUNCTION