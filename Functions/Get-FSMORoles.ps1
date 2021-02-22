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