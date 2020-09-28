function Invoke-LocalAdminRemoval {
    <#
        .SYNOPSIS
            Removes Local Administrators Specified from the Computers Specified
        .DESCRIPTION
            Uses an Array to compare Local Admins with Local Approved Admins, and temoves those not approved
        .PARAMETER ComputerNames
            Array of Computers to prune the Local Admin Group on
        .PARAMETER UserstoRemove
            Users to remove from the Local Administrators Group
        .EXAMPLE
            Invoke-LocalAdminRemoval -ComputerNames (Get-Content "C:\Temp\TestComputers.txt") -UserstoRemove (Get-Content "C:\Temp\TestUsers.txt")
        .EXAMPLE
            Invoke-LocalAdminRemoval -ComputerNames (Get-ADGroupMember -Identity 'ComputerGroup').name -UserstoRemove (Get-ADGroupMember -Identity 'UserGroup').name
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]$ComputerNames,
        [Parameter(Mandatory = $true)]$UserstoRemove
    ) 
    BEGIN { 
        $LocalAdminRemoval = @()
    } #BEGIN

    PROCESS {
        foreach ($ComputerName in $ComputerNames) { 
            $AdminsRemovedList = @()
            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "ComputerName" -Value $ComputerName


            if ( -not(Test-Connection $ComputerName -Quiet -Count 1 -ErrorAction Continue )) { 
                $Row | Add-Member -MemberType noteproperty -Name "Pingable" -Value 'False'
            } 

            Else {
                $Row | Add-Member -MemberType noteproperty -Name "Pingable" -Value 'True'
 
                $LocalGroupName = "Administrators" 
                $Group = [ADSI]("WinNT://$computerName/$localGroupName,group") 
                $Group.Members() | 
                ForEach-Object { 
                    $AdsPath = $_.GetType().InvokeMember('Adspath', 'GetProperty', $null, $_, $null) 
                    $A = $AdsPath.split('/', [StringSplitOptions]::RemoveEmptyEntries) 
                    $Names = $a[-1]  
                    $Domain = $a[-2] 

                    foreach ($name in $names) { 
                        foreach ($Admin in $UserstoRemove) { 
                            if ($name -eq $Admin) { 
                                $Group.Remove("WinNT://$computerName/$domain/$name") 
                                $AdminsRemovedList += $name
                            }
                        }
                    } }
            }
            $Row | Add-Member -MemberType noteproperty -Name "AdminsRemoved" -Value ($AdminsRemovedList -join ',')
            $LocalAdminRemoval += $Row
            $AdminsRemovedList = $NULL
        }
    } #PROCESS

    END { 
        $LocalAdminRemoval
    } #END

} #FUNCTION