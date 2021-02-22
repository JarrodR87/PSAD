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