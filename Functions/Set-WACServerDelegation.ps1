function Set-WACServerDelegation {
    <#
        .SYNOPSIS
            Sets Delegation for Windows Admin Center for Server Objects in the specified Domain
        .DESCRIPTION
            Aloows Windows Admin Center to login without always prompting users for credentials to the delegated objects
        .PARAMETER WACGateway
            Gateway Server for Windows Admin Center
        .PARAMETER WACDomain
            Domain the Windows Admin Center Server is on - Defaults to Current Domain if unset
        .PARAMETER ServerDomain
            Domain of the Servers to Allow Delegation To - Defaults to Current Domain if unset
        .EXAMPLE
            Set-WACServerDelegation -WACGateway WACServer -WACDomain Test1.com -ServerDomain test2.com
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]$WACGateway,
        [Parameter()]$WACDomain,
        [Parameter()]$ServerDomain
    ) 
    BEGIN { 
        if ($NULL -eq $WACDomain) {
            $WACDomain = (Get-ADDomain).DNSRoot
        }

        if ($NULL -eq $ServerDomain) {
            $ServerDomain = (Get-ADDomain).DNSRoot
        }

        $WACGatewayServer = Get-ADComputer -Identity $WACGateway -Server $WACDomain

    } #BEGIN

    PROCESS {
        Get-ADComputer -Filter { OperatingSystem -Like '*Windows Server*' } -Server $ServerDomain | Set-ADComputer -PrincipalsAllowedToDelegateToAccount $WACGatewayServer -Server $ServerDomain
    } #PROCESS

    END { 

    } #END

} #FUNCTION