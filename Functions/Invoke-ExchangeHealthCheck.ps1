function Invoke-ExchangeHealthCheck {
    <#
        .SYNOPSIS
            Checks the specified Exchange Server or Servers HealthCheck URL's
        .DESCRIPTION
            Does a web request to all Exchange Healthcheck URL's to see if they come back with Status 200
        .PARAMETER ExchangeServers
            Servers to Health Check
        .PARAMETER Protocol
            Opti0onal - Protocol to Health Check on. Defaults to HTTPS
        .EXAMPLE
            Invoke-ExchangeHealthCheck -ExchangeServers 'Server1.test.com','server2.test.com'
        .EXAMPLE
            Invoke-ExchangeHealthCheck -ExchangeServers 'Server1.test.com'
        .EXAMPLE
            Invoke-ExchangeHealthCheck -ExchangeServers 'Server1.test.com' -Protocol 'HTTP'
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]$ExchangeServers,
        [Parameter()]$Protocol
    ) 
    BEGIN { 
        $ExchangeActivePowerShellServers = @()

        if ($NULL -eq $Protocol) {
            $Protocol = 'HTTPS'
        }
        
    } #BEGIN

    PROCESS {
        foreach ($ExchangeServer in $ExchangeServers) {

            $BaseURL = $Protocol + '://' + $ExchangeServer

            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "ExchangeServer" -Value $ExchangeServer
            $Row | Add-Member -MemberType noteproperty -Name "PowerShellHealthCheck" -Value ([bool]((invoke-webrequest $BaseURL/PowerShell/healthcheck.htm).statusCode -eq 200))
            $Row | Add-Member -MemberType noteproperty -Name "ActiveSyncHealthCheck" -Value ([bool]((invoke-webrequest $BaseURL/microsoft-server-activesync/healthcheck.htm).statusCode -eq 200))
            $Row | Add-Member -MemberType noteproperty -Name "AutodiscoverHealthCheck" -Value ([bool]((invoke-webrequest $BaseURL/autodiscover/healthcheck.htm).statusCode -eq 200))
            $Row | Add-Member -MemberType noteproperty -Name "ECPHealthCheck" -Value ([bool]((invoke-webrequest $BaseURL/ecp/healthcheck.htm).statusCode -eq 200))
            $Row | Add-Member -MemberType noteproperty -Name "EWSHealthCheck" -Value ([bool]((invoke-webrequest $BaseURL/ews/healthcheck.htm).statusCode -eq 200))
            $Row | Add-Member -MemberType noteproperty -Name "MAPIHealthCheck" -Value ([bool]((invoke-webrequest $BaseURL/mapi/healthcheck.htm).statusCode -eq 200))
            $Row | Add-Member -MemberType noteproperty -Name "OABHealthCheck" -Value ([bool]((invoke-webrequest $BaseURL/oab/healthcheck.htm).statusCode -eq 200))
            $Row | Add-Member -MemberType noteproperty -Name "OWAHealthCheck" -Value ([bool]((invoke-webrequest $BaseURL/owa/healthcheck.htm).statusCode -eq 200))
            $Row | Add-Member -MemberType noteproperty -Name "RPCHealthCheck" -Value ([bool]((invoke-webrequest $BaseURL/rpc/healthcheck.htm).statusCode -eq 200))


            $ExchangeActivePowerShellServers += $Row
        }
    } #PROCESS

    END { 
        $ExchangeActivePowerShellServers
    } #END

} #FUNCTION