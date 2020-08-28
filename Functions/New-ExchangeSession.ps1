function New-ExchangeSession {
    <#
        .SYNOPSIS
            Connects to KPD Exchange 2016 PowerShell
        .DESCRIPTION
            Connects to KPDEXCH01 to access Exchange PowerShell Cmdlets and imports the Session to the current PowerShell Session
        .PARAMETER ExchangeServers
            Exchange Servers that will accept a PowerShell Connection
        .PARAMETER Protocol
            Opti0onal - Protocol to Health Check and connect PowerShell on
        .PARAMETER Credential
            Opti0onal - Protocol to Health Check and connect PowerShell on
        .EXAMPLE
            New-ExchangeSession -ExchangeServers 'Server1.test.com' -Protocol 'HTTP'
        .EXAMPLE
            New-ExchangeSession -ExchangeServers 'Server1.test.com' -Protocol 'HTTP' -Credential (Get-Credential)
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]$ExchangeServers,
        [Parameter()]$Protocol,
        [Parameter()]$Credential
    ) 
    BEGIN { 
        if ($NULL -eq $Protocol) {
            $Protocol = 'HTTP'
        }
        $ErrorActionPreference = 'silentlycontinue'

        $HealthyExchangeServers = (Invoke-ExchangeHealthCheck -ExchangeServers $ExchangeServers -Protocol $Protocol | Where-Object -FilterScript { $_.PowerShellHealthCheck -like '*True*' })
        $ExchangePowerShellServer = (Get-Random -InputObject $HealthyExchangeServers).ExchangeServer

        $BaseURL = $Protocol + '://' + $ExchangePowerShellServer

        if ($NULL -eq $Credential) {
            $SessionArguments = @{
                ConfigurationName = 'Microsoft.Exchange'
                ConnectionUri     = "$BaseURL/PowerShell/"
                Authentication    = 'Kerberos'
            }
        }

        if ($NULL -ne $Credential) {
            $SessionArguments = @{
                ConfigurationName = 'Microsoft.Exchange'
                ConnectionUri     = "$BaseURL/PowerShell/"
                Authentication    = 'Kerberos'
                Credential        = $Credential
            }
        }

    } #BEGIN

    PROCESS {
        
        $ExchangeSession = New-PSSession @SessionArguments
        Import-Module (Import-PSSession $ExchangeSession -DisableNameChecking -AllowClobber) -Global
    } #PROCESS

    END { 

    } #END

} #FUNCTION