function Get-DFSStatusReport {
    <#
        .SYNOPSIS
            Checks DFS for the current, or specified Domain
        .DESCRIPTION
            Queries DFS Replication and Namespace Health for the current or Specified Domain
        .PARAMETER Domain
            Optional, will default to current domain if unspecified
        .PARAMETER ReportType
            Will Accept either HashTable or HTML
        .EXAMPLE
            Get-DFSStatusReport -Domain Test.com -ReportType HTML
        .EXAMPLE
            Get-DFSStatusReport -ReportType HashTable
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
        
        $DFSReport = @()

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
        # DFS Roots
        $DFSRoots = Get-DfsnRoot -Domain $Domain
        $DFSRoots = $DFSRoots | Select-Object State, Type, Path, TimeToLiveSec, Description, NamespacePath, TimeToLive
        $DFSRootsHTML = $DFSRoots | ConvertTo-Html -Fragment
        

        # DFS Namespace Folders
        $DFSFolders = foreach ($DFSRoot in $DFSRoots) {
            Get-DfsnFolder -Path ($DFSRoot.Path + '\*')
        }
        $DFSFolders = $DFSFolders | Select-Object State, Path, TimeToLiveSec, Description, NamespacePath, TimeToLive
        $DFSFoldersHTML = $DFSFolders | ConvertTo-Html -Fragment


        # DFS Namespace Folder Targets
        $DFSFolderTargets = foreach ($DFSFolder in $DFSFolders) {
            Get-DfsnFolderTarget $DFSFolder.Path
        }
        $DFSFolderTargets = $DFSFolderTargets | Select-Object State, ReferralPriorityClass, Path, NamespacePath, ReferralPriorityRank, TargetPath
        $DFSFolderTargetsHTML = $DFSFolderTargets | ConvertTo-Html -Fragment


        # DFS Replicated Folders
        $DFSRfolders = Get-DfsReplicatedFolder -DomainName $Domain
        $DFSRfolders = $DFSRfolders | Select-Object GroupName, FolderName, DomainName, Identifier, Description, FileNameToExclude, DirectoryNameToExclude, DfsnPath, IsDfsnPathPublished, State
        $DFSRfoldersHTML = $DFSRfolders | ConvertTo-Html -Fragment


        # DFS Replication Connections
        $DFSRConnections = Get-DfsrConnection -DomainName $Domain
        $DFSRConnections = $DFSRConnections | Select-Object GroupName, SourceComputerName, DestinationComputerName, DomainName, Identifier, Enabled, RdcEnabled, CrossFileRdcEnabled, Description, MinimumRDCFileSizeInKB, State
        $DFSRConnectionsHTML = $DFSRConnections | ConvertTo-Html -Fragment


        $DFSRSourceComputers = $DFSRConnections.SourceComputerName | Select-Object -Unique
        $DFSRDestinationComputers = $DFSRConnections.DestinationComputerName | Select-Object -Unique

        $DFSRComputers = $DFSRSourceComputers + $DFSRDestinationComputers | Select-Object -Unique


        # DFS Replication Status
        $DFSRState = foreach ($DFSRComputer in $DFSRCOmputers) {
            Get-DfsrState -ComputerName $DFSRComputer
        }
        $DFSRState = $DFSRState | Select-Object Identifier, FileName, GlobalVersionSequenceNumber, Path, ConnectionGuid, SourceComputerName, ParentIdentifier, ReplicatedFolderIdentifier, Inbound, UpdateState
        $DFSRStateHTML = $DFSRState | ConvertTo-Html -Fragment


        # DFS Report HashTable
        $DFSReport = @{
            'DFSRoots'         = $DFSRoots
            'DFSFolders'       = $DFSFolders
            'DFSFolderTargets' = $DFSFolderTargets
            'DFSRfolders'      = $DFSRfolders
            'DFSRConnections'  = $DFSRConnections
            'DFSRState'        = $DFSRState
        }

        # DFS Report HTML
        $Head = $HtmlHead
        $DateGenerated = '<h1>' + 'Generated at ' + (Get-Date) + ' For ' + $Domain + '<h1>'
        $DFSRootsHeading = '<h2>DFS Roots</h2>'
        $DFSFoldersHeading = '<h2>DFS Folders</h2>'
        $DFSFolderTargetsHeading = '<h2>DFS Folder Targets</h2>'
        $DFSRFoldersHeading = '<h2>DFS Replicated Folders</h2>'
        $DFSRConnectionsHeading = '<h2>DFS Replicated Connections</h2>'
        $DFSRStateHeading = '<h2>DFS Replication State</h2>'

        $DFSReportHTML = $Head + `
            $DateGenerated + `
            $DFSRootsHeading + `
            $DFSRootsHTML + `
            $DFSFoldersHeading + `
            $DFSFoldersHTML + `
            $DFSFolderTargetsHeading + `
            $DFSFolderTargetsHTML + `
            $DFSRFoldersHeading + `
            $DFSRfoldersHTML + `
            $DFSRConnectionsHeading + `
            $DFSRConnectionsHTML + `
            $DFSRStateHeading + `
            $DFSRStateHTML

    } #PROCESS

    END { 
        if ($ReportType -eq 'HTML') {
            $DFSReportHTML
        }
        elseif ($ReportType -eq 'HashTable') {
            $DFSReport
        }
    } #END

} #FUNCTION