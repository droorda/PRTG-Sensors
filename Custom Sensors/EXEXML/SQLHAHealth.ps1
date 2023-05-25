[CmdletBinding()]
param (
    [Parameter(Position=1)]
    [string]$ServerName = "$env:prtg_host"
    ,
    [string]$DBName
)
Begin {
    if (test-path("$(split-path $SCRIPT:MyInvocation.MyCommand.Path)\prtgshell.psm1")) {
        Import-Module "$(split-path $SCRIPT:MyInvocation.MyCommand.Path)\prtgshell.psm1" -DisableNameChecking -Verbose:$false
    } else {
        Write-output "<prtg>"
        Write-output "  <error>1</error>"
        Write-output "  <text>Unable to locate prtgshell.psm1</text>"
        Write-output "</prtg>"
        exit
    }


    Try {
        Import-Module SQLServer -ErrorAction Stop -Verbose:$false
    } Catch {
        Find-Module SQLServer | Install-Module -Force -Scope AllUsers
        Try {
            Import-Module SQLServer -ErrorAction Stop -Verbose:$false
        } Catch {
            Set-PrtgError -PrtgErrorText "Unable to locate SQLServer Module"
        }
    }

    Try {
        $AvailabilityGroups = Get-ChildItem "SQLSERVER:\SQL\$ServerName\DEFAULT\AvailabilityGroups" -ErrorAction Stop
    } Catch {
        Set-PrtgError $_.exception.Message
    }
    $DatabaseReplicaStates = $AvailabilityGroups.DatabaseReplicaStates | Where-Object {$_.AvailabilityReplicaServerName -eq $ServerName}
    if ($DBName) {
        $DatabaseReplicaStates = $DatabaseReplicaStates | Where-Object {$_.AvailabilityDatabaseName -eq $DBName}
        if (-not $DatabaseReplicaStates) {
            Set-PrtgError "Database '$DBName' not found"
        } elseif ($DatabaseReplicaStates.count -gt 5) {
            Set-PrtgError "To many databases to list all. DBName must be specified."
        }
    }

    # TODO correct time zone data from monitor. Current alerts do not have TZ Data. Force all server to be in the same TZ


    # * Possible Functions for future implimentation
    # Sourced from https://www.mssqltips.com/sqlservertip/5302/creating-a-sql-server-availability-group-dashboard-for-all-servers/

    Function Get-AvailabilityGroupStatus {
    <#
        .SYNOPSIS
            Get the status of the Availability Groups on the servers.

        .DESCRIPTION
            Displays the status for availability groups on the servers in a grid.

        .PARAMETER ServerSearchPattern
            The Search Pattern to be used for server names for the call against Get-CMSHosts.

        .PARAMETER ServerInstanceList
            The Instanace List to be used for server names for the call to Get-CMSHosts.

        .NOTES
            Tags: AvailabilityGroups
            Original Author: Tracy Boggiano (@TracyBoggiano), tracyboggiano.com
            License: GNU GPL v3 https://opensource.org/licenses/GPL-3.0

        .EXAMPLE
            Get-AvailabiliytGroupStatus -ServerInstanceList "c:\temp\servers.txt"

            Gets the status Availabiliy Groups on all servers where their name in teh specified text file..
    #>
    [CmdletBinding()]
    Param (
        [string] $ServerInstanceList
    )
        begin {
            $SQLInstance = Get-Content $ServerInstanceList
            $SQLInstance | ForEach-Object { New-PSSession -ComputerName $_ | out-null}
        }

        process {
            $sessions = Get-PSSession

            $scriptblock = {
                $sql = "
                IF SERVERPROPERTY(N'IsHadrEnabled') = 1
                BEGIN
                    DECLARE @cluster_name NVARCHAR(128)
                    DECLARE @quorum_type VARCHAR(50)
                    DECLARE @quorum_state VARCHAR(50)
                    DECLARE @Healthy INT
                    DECLARE @Primary sysname

                    SELECT @cluster_name = cluster_name ,
                            @quorum_type = quorum_type_desc ,
                            @quorum_state = quorum_state_desc
                    FROM   sys.dm_hadr_cluster

                    SELECT @Healthy = COUNT(*)
                    FROM master.sys.dm_hadr_availability_replica_states
                    WHERE recovery_health_desc <> 'ONLINE'
                        OR synchronization_health_desc <> 'HEALTHY'

                    SELECT @primary = r.replica_server_name
                    FROM master.sys.dm_hadr_availability_replica_states s
                        INNER JOIN master.sys.availability_replicas r ON s.replica_id = r.replica_id
                    WHERE role_desc = 'PRIMARY'

                    IF @Primary IS NULL
                        SELECT ISNULL(@cluster_name, '') AS [ClusterName] ,
                                ag.name,
                            CAST(SERVERPROPERTY(N'Servername') AS sysname) AS [Name] ,
                            ISNULL(@Primary, '') AS PrimaryServer ,
                            @quorum_type AS [ClusterQuorumType] ,
                            @quorum_state AS [ClusterQuorumState] ,
                            CAST(ISNULL(SERVERPROPERTY(N'instancename'), N'') AS sysname) AS [InstanceName] ,
                            CASE @Healthy
                                    WHEN 0 THEN 'Healthy'
                                    ELSE 'Unhealthly'
                            END AS AvailavaiblityGroupState
                        FROM MASTER.sys.availability_groups ag
                            INNER JOIN master.sys.dm_hadr_availability_replica_states s ON AG.group_id = s.group_id
                            INNER JOIN master.sys.availability_replicas r ON s.replica_id = r.replica_id
                    ELSE
                        SELECT ISNULL(@cluster_name, '') AS [ClusterName] ,
                                ag.name,
                            CAST(SERVERPROPERTY(N'Servername') AS sysname) AS [Name] ,
                            ISNULL(@Primary, '') AS PrimaryServer ,
                            @quorum_type AS [ClusterQuorumType] ,
                            @quorum_state AS [ClusterQuorumState] ,
                            CAST(ISNULL(SERVERPROPERTY(N'instancename'), N'') AS sysname) AS [InstanceName] ,
                            CASE @Healthy
                                    WHEN 0 THEN 'Healthy'
                                    ELSE 'Unhealthly'
                            END AS AvailavaiblityGroupState
                        FROM MASTER.sys.availability_groups ag
                            INNER JOIN master.sys.dm_hadr_availability_replica_states s ON AG.group_id = s.group_id
                            INNER JOIN master.sys.availability_replicas r ON s.replica_id = r.replica_id
                        WHERE s.role_desc = 'PRIMARY'
                END"

                Invoke-Sqlcmd -Query $sql
            }

            Invoke-Command -Session $($sessions | ? { $_.State -eq 'Opened' }) -ScriptBlock $scriptblock | Select * -ExcludeProperty RunspaceId | Out-GridView
            $sessions | Remove-PSSession
        }
    }

    Function Get-SqlAvailabilityReplicaStatus {
    <#
        .SYNOPSIS
            Get the status the availability group replicas for each server.

        .DESCRIPTION
            Displays the status for availability groups replicas on the servers in a grid.

        .PARAMETER ServerSearchPattern
            The Search Pattern to be used for server names for the call against Get-CMSHosts.

        .PARAMETER ServerInstanceList
            The Instanace List to be used for server names for the call to Get-CMSHosts.

        .NOTES
            Tags: AvailabilityGroups
            Original Author: Tracy Boggiano (@TracyBoggiano), tracyboggiano.com
            License: GNU GPL v3 https://opensource.org/licenses/GPL-3.0

        .EXAMPLE
            Get-AvailabilityGroupStatus -ServerInstanceList "c:\temp\servers.txt"

            Gets the status Availability Groups on all servers where their name in teh specified text file..
    #>
        [CmdletBinding()]
        Param (
            [string] $ServerInstanceList
        )

        begin {
            $SQLInstance = Get-Content $ServerInstanceList
            $SQLInstance | ForEach-Object { New-PSSession -ComputerName $_ | out-null}
        }

        process {
            $sessions = Get-PSSession

            $scriptblock = {
                $SQL = "
                IF SERVERPROPERTY(N'IsHadrEnabled') = 1
                BEGIN
                    SELECT  arrc.replica_server_name ,
                            COUNT(cm.member_name) AS node_count ,
                            cm.member_state_desc AS member_state_desc ,
                            SUM(cm.number_of_quorum_votes) AS quorum_vote_sum
                    INTO    #tmpar_availability_replica_cluster_info
                    FROM    (   SELECT DISTINCT replica_server_name ,
                                        node_name
                                FROM   master.sys.dm_hadr_availability_replica_cluster_nodes
                            ) AS arrc
                            LEFT OUTER JOIN master.sys.dm_hadr_cluster_members AS cm ON UPPER(arrc.node_name) = UPPER(cm.member_name)
                    GROUP BY arrc.replica_server_name,
                        cm.member_state_desc;

                    SELECT  *
                    INTO    #tmpar_ags
                    FROM    master.sys.dm_hadr_availability_group_states
                    SELECT  ar.group_id ,
                            ar.replica_id ,
                            ar.replica_server_name ,
                            ar.availability_mode ,
                            ( CASE WHEN UPPER(ags.primary_replica) = UPPER(ar.replica_server_name) THEN
                                        1
                                    ELSE 0
                                END
                            ) AS role ,
                            ars.synchronization_health
                    INTO    #tmpar_availabilty_mode
                    FROM    master.sys.availability_replicas AS ar
                            LEFT JOIN #tmpar_ags AS ags ON ags.group_id = ar.group_id
                            LEFT JOIN master.sys.dm_hadr_availability_replica_states AS ars ON ar.group_id = ars.group_id
                                                                                    AND ar.replica_id = ars.replica_id

                    SELECT  am1.replica_id ,
                            am1.role ,
                            ( CASE WHEN ( am1.synchronization_health IS NULL ) THEN 3
                                    ELSE am1.synchronization_health
                                END
                            ) AS sync_state ,
                            ( CASE WHEN ( am1.availability_mode IS NULL )
                                        OR ( am3.availability_mode IS NULL ) THEN NULL
                                    WHEN ( am1.role = 1 ) THEN 1
                                    WHEN (   am1.availability_mode = 0
                                            OR am3.availability_mode = 0
                                        ) THEN 0
                                    ELSE 1
                                END
                            ) AS effective_availability_mode
                    INTO    #tmpar_replica_rollupstate
                    FROM    #tmpar_availabilty_mode AS am1
                            LEFT JOIN   (   SELECT group_id ,
                                                role ,
                                                availability_mode
                                            FROM   #tmpar_availabilty_mode AS am2
                                            WHERE  am2.role = 1
                                        ) AS am3 ON am1.group_id = am3.group_id

                    SELECT  AR.replica_server_name AS [Name] ,
                            AR.availability_mode_desc AS [AvailabilityMode] ,
                            AR.backup_priority AS [BackupPriority] ,
                            AR.primary_role_allow_connections_desc AS [ConnectionModeInPrimaryRole] ,
                            AR.secondary_role_allow_connections_desc AS [ConnectionModeInSecondaryRole] ,
                            arstates.connected_state_desc AS [ConnectionState] ,
                            ISNULL(AR.create_date, 0) AS [CreateDate] ,
                            ISNULL(AR.modify_date, 0) AS [DateLastModified] ,
                            ISNULL(AR.endpoint_url, N'''') AS [EndpointUrl] ,
                            AR.failover_mode AS [FailoverMode] ,
                            arcs.join_state_desc AS [JoinState] ,
                            ISNULL(arstates.last_connect_error_description, N'') AS [LastConnectErrorDescription] ,
                            ISNULL(arstates.last_connect_error_number, '') AS [LastConnectErrorNumber] ,
                            ISNULL(arstates.last_connect_error_timestamp, '') AS [LastConnectErrorTimestamp] ,
                            member_state_desc AS [MemberState] ,
                            arstates.operational_state_desc AS [OperationalState] ,
                            SUSER_SNAME(AR.owner_sid) AS [Owner] ,
                            ISNULL(arci.quorum_vote_sum, -1) AS [QuorumVoteCount] ,
                            ISNULL(AR.read_only_routing_url, '') AS [ReadonlyRoutingConnectionUrl] ,
                            arstates.role_desc AS [Role] ,
                            arstates.recovery_health_desc AS [RollupRecoveryState] ,
                            ISNULL(AR.session_timeout, -1) AS [SessionTimeout] ,
                            ISNULL(AR.seeding_mode, 1) AS [SeedingMode]
                    FROM    master.sys.availability_groups AS AG
                            INNER JOIN master.sys.availability_replicas AS AR ON ( AR.replica_server_name IS NOT NULL )
                                                                            AND ( AR.group_id = AG.group_id )
                            LEFT OUTER JOIN master.sys.dm_hadr_availability_replica_states AS arstates ON AR.replica_id = arstates.replica_id
                            LEFT OUTER JOIN master.sys.dm_hadr_availability_replica_cluster_states AS arcs ON AR.replica_id = arcs.replica_id
                            LEFT OUTER JOIN #tmpar_availability_replica_cluster_info AS arci ON UPPER(AR.replica_server_name) = UPPER(arci.replica_server_name)
                            LEFT OUTER JOIN #tmpar_replica_rollupstate AS arrollupstates ON AR.replica_id = arrollupstates.replica_id
                    ORDER BY [Name] ASC

                    DROP TABLE #tmpar_availabilty_mode
                    DROP TABLE #tmpar_ags
                    DROP TABLE #tmpar_availability_replica_cluster_info
                    DROP TABLE #tmpar_replica_rollupstate
                END"

                Invoke-Sqlcmd -Query $sql
            }

            Invoke-Command -Session $($sessions | Where-Object { $_.State -eq 'Opened' }) -ScriptBlock $scriptblock | Select-Object * -ExcludeProperty RunspaceId | Out-GridView
            $sessions | Remove-PSSession
        }
    }

    Function Get-SqlDatabaseReplicaStatus {
    <#
        .SYNOPSIS
            Get the status the databases in every availability group for each servers.

        .DESCRIPTION
            Displays the status databases in every availability group on the servers in a grid.

        .PARAMETER ServerSearchPattern
            The Search Pattern to be used for server names for the call against Get-CMSHosts.

        .PARAMETER ServerInstanceList
            The Instanace List to be used for server names for the call to Get-CMSHosts.

        .NOTES
            Tags: AvailabilityGroups
            Original Author: Tracy Boggiano (@TracyBoggiano), tracyboggiano.com
            License: GNU GPL v3 https://opensource.org/licenses/GPL-3.0

        .EXAMPLE
            Get-SqlDatabaseReplicaStatus -ServerInstanceList "c:\temp\servers.txt"

            Gets the status Availability Groups on all servers where their name in teh specified text file..
    #>
        [CmdletBinding()]
        Param (
            [string] $ServerInstanceList
        )

        begin {
            $SQLInstance = Get-Content $ServerInstanceList
            $SQLInstance | ForEach-Object { New-PSSession -ComputerName $_ | out-null}
        }

        process {
            $sessions = Get-PSSession

            $scriptblock = {
                $sql = "
                    IF SERVERPROPERTY(N'IsHadrEnabled') = 1
                    BEGIN
                        SELECT ars.role ,
                            drs.database_id ,
                            drs.replica_id ,
                            drs.last_commit_time
                        INTO   #tmpdbr_database_replica_states_primary_LCT
                        FROM   master.sys.dm_hadr_database_replica_states AS drs
                            LEFT JOIN master.sys.dm_hadr_availability_replica_states ars ON drs.replica_id = ars.replica_id
                        WHERE  ars.role = 1

                        SELECT   AR.replica_server_name AS [AvailabilityReplicaServerName] ,
                                dbcs.database_name AS [AvailabilityDatabaseName] ,
                                AG.name AS [AvailabilityGroupName] ,
                                ISNULL(dbr.database_id, 0) AS [DatabaseId] ,
                                CASE dbcs.is_failover_ready
                                    WHEN 1 THEN 0
                                    ELSE
                                        ISNULL(
                                                    DATEDIFF(
                                                                ss ,
                                                                dbr.last_commit_time,
                                                                dbrp.last_commit_time
                                                            ) ,
                                                    0
                                                )
                                END AS [EstimatedDataLoss] ,
                                ISNULL(   CASE dbr.redo_rate
                                                WHEN 0 THEN -1
                                                ELSE CAST(dbr.redo_queue_size AS FLOAT) / dbr.redo_rate
                                        END ,
                                        -1
                                    ) AS [EstimatedRecoveryTime] ,
                                ISNULL(dbr.filestream_send_rate, -1) AS [FileStreamSendRate] ,
                                ISNULL(dbcs.is_failover_ready, 0) AS [IsFailoverReady] ,
                                ISNULL(dbcs.is_database_joined, 0) AS [IsJoined] ,
                                arstates.is_local AS [IsLocal] ,
                                ISNULL(dbr.is_suspended, 0) AS [IsSuspended] ,
                                ISNULL(dbr.last_commit_time, 0) AS [LastCommitTime] ,
                                ISNULL(dbr.last_hardened_time, 0) AS [LastHardenedTime] ,
                                ISNULL(dbr.last_received_time, 0) AS [LastReceivedTime] ,
                                ISNULL(dbr.last_redone_time, 0) AS [LastRedoneTime] ,
                                ISNULL(dbr.last_sent_time, 0) AS [LastSentTime] ,
                                ISNULL(dbr.log_send_queue_size, -1) AS [LogSendQueueSize] ,
                                ISNULL(dbr.log_send_rate, -1) AS [LogSendRate] ,
                                ISNULL(dbr.redo_queue_size, -1) AS [RedoQueueSize] ,
                                ISNULL(dbr.redo_rate, -1) AS [RedoRate] ,
                                ISNULL(AR.availability_mode, 2) AS [ReplicaAvailabilityMode] ,
                                arstates.role_desc AS [ReplicaRole] ,
                                dbr.suspend_reason_desc AS [SuspendReason] ,
                                ISNULL(
                                        CASE dbr.log_send_rate
                                                WHEN 0 THEN -1
                                                ELSE
                                                    CAST(dbr.log_send_queue_size AS FLOAT)
                                                    / dbr.log_send_rate
                                        END ,
                                        -1
                                    ) AS [SynchronizationPerformance] ,
                                dbr.synchronization_state_desc AS [SynchronizationState]
                        FROM     master.sys.availability_groups AS AG
                                INNER JOIN master.sys.availability_replicas AS AR ON AR.group_id = AG.group_id
                                INNER JOIN master.sys.dm_hadr_database_replica_cluster_states AS dbcs ON dbcs.replica_id = AR.replica_id
                                LEFT OUTER JOIN master.sys.dm_hadr_database_replica_states AS dbr ON dbcs.replica_id = dbr.replica_id
                                                                                        AND dbcs.group_database_id = dbr.group_database_id
                                LEFT OUTER JOIN #tmpdbr_database_replica_states_primary_LCT AS dbrp ON dbr.database_id = dbrp.database_id
                                INNER JOIN master.sys.dm_hadr_availability_replica_states AS arstates ON arstates.replica_id = AR.replica_id
                        ORDER BY [AvailabilityReplicaServerName] ASC ,
                                [AvailabilityDatabaseName] ASC;

                        DROP TABLE #tmpdbr_database_replica_states_primary_LCT
                    END"

                    Invoke-Sqlcmd -Query $sql
            }

            Invoke-Command -Session $($sessions | Where-Object { $_.State -eq 'Opened' }) -ScriptBlock $scriptblock | Select-Object * -ExcludeProperty RunspaceId | Out-GridView
            $sessions | Remove-PSSession
        }
    }

    # $DatabaseReplicaStates | Where-Object {$_.AvailabilityDatabaseName -eq 'IconicReporting'} | Format-List *

        # Select-Object AvailabilityReplicaServerName, AvailabilityDatabaseName, SynchronizationState, LogSendRate, LogSendQueueSize, RedoQueueSize |
        # LastRedoneTime, LastReceivedTime
}
Process {}
End {
    $XMLOutput = "<prtg>`n"
    Foreach ($DatabaseReplicaState in $DatabaseReplicaStates) {
        switch ($DatabaseReplicaState.SynchronizationState) {
            'not synchronizing' {$SyncState = 0}
            'synchronizing'     {$SyncState = 1}
            'synchronized'      {$SyncState = 2}
            'reverting'         {$SyncState = 3}
            'initializing'      {$SyncState = 4}
            Default {$SyncState = -1}
        }
        if (($DatabaseReplicaStates.count -gt 1)) {
            $PrtgDbName = "[$($DatabaseReplicaState.AvailabilityDatabaseName)]"
        } else {
            $PrtgDbName = ''
        }
        $XMLOutput += Set-PrtgResult -Channel "$($PrtgDbName)SyncState"         -Value $SyncState                             -Unit Count -MinError 1 -MaxError 2 -sc
        $XMLOutput += Set-PrtgResult -Channel "$($PrtgDbName)LogSendRate"       -Value $DatabaseReplicaState.LogSendRate      -Unit "KB/Sec" -sc
        $XMLOutput += Set-PrtgResult -Channel "$($PrtgDbName)LogSendQueueSize"  -Value $DatabaseReplicaState.LogSendQueueSize -Unit "KB" -MaxError 1024 -sc
        $XMLOutput += Set-PrtgResult -Channel "$($PrtgDbName)RedoQueueSize"     -Value $DatabaseReplicaState.RedoQueueSize    -Unit "KB" -MaxError 250 -sc
        if ((get-date -Date "1/1/2000") -lt $DatabaseReplicaState.LastRedoneTime) {
            $XMLOutput += Set-PrtgResult -Channel "$($PrtgDbName)LastRedoneTime"    -Value ([int]((Get-Date) - $DatabaseReplicaState.LastRedoneTime).TotalSeconds)   -Unit Seconds -MaxError 900 -sc
        }
        $XMLOutput += Set-PrtgResult -Channel "$($PrtgDbName)LastCommitTime"    -Value ([int]((Get-Date) - $DatabaseReplicaState.LastCommitTime).TotalSeconds)   -Unit Seconds -MaxError 900 -sc

        $DatabaseReplicaState | Format-List * -Force | Out-String | Write-Verbose

        Write-Verbose ("`n" +
            "SyncState                " + $DatabaseReplicaState.SynchronizationState + "`n" +
            "LogSendRate              " + $DatabaseReplicaState.LogSendRate + "`n" +
            "LogSendQueueSize         " + $DatabaseReplicaState.LogSendQueueSize + "`n" +
            "RedoQueueSize            " + $DatabaseReplicaState.RedoQueueSize + "`n" +
            "AvailabilityDatabaseName " + $DatabaseReplicaState.AvailabilityDatabaseName + "`n" +
            "LogSendQueueSize         " + $DatabaseReplicaState.LogSendQueueSize + "`n" +
            # "EstimatedDataLoss        " + $DatabaseReplicaState.EstimatedDataLoss + "`n" +
            "LastRedoneTime           " + $DatabaseReplicaState.LastRedoneTime.ToUniversalTime() + "`n" +
            "LastCommitTime           " + $DatabaseReplicaState.LastCommitTime.ToUniversalTime() + "`n" +
            "LastReceivedTime         " + $DatabaseReplicaState.LastReceivedTime.ToUniversalTime() + "`n" +
            "LastSentTime             " + $DatabaseReplicaState.LastSentTime.ToUniversalTime() + "`n" +
            "")

    }


    # $XMLOutput += "<text>StatusDescription: $($Response.StatusDescription)</text>`n"
    $XMLOutput += "</prtg>"
    $XMLOutput

}













