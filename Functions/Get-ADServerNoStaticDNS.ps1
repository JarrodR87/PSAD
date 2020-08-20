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
    [Parameter()]$Domain
    ) 
    BEGIN { 
        if ($NULL -eq $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }
        else {
        
        }

        $DC = (Get-ADDomainController).name
    } #BEGIN

    PROCESS {
        Get-ADComputer -Filter { OperatingSystem -Like '*Windows Server*' } -Server $Domain | ForEach-Object {
            Get-DnsServerResourceRecord -ZoneName $Domain -ComputerName $DC -Name $_.Name | Where-Object { $NULL -ne $_.Timestamp }
        }
    } #PROCESS

    END { 

    } #END

} #FUNCTION