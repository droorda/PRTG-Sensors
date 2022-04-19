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
            Write-output "<prtg>"
            Write-output "  <error>1</error>"
            Write-output "  <text>Unable to locate SQLServer Module</text>"
            Write-output "</prtg>"
            exit
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
        $XMLOutput += Set-PrtgResult -Channel "$($PrtgDbName)LastRedoneTime"    -Value ([int]((Get-Date) - $DatabaseReplicaState.LastRedoneTime).TotalSeconds)   -Unit Seconds -MaxError 900 -sc
        $XMLOutput += Set-PrtgResult -Channel "$($PrtgDbName)LastCommitTime"    -Value ([int]((Get-Date) - $DatabaseReplicaState.LastCommitTime).TotalSeconds)   -Unit Seconds -MaxError 900 -sc

        Write-Verbose ("`n" +
            "SyncState                " + $DatabaseReplicaState.SynchronizationState + "`n" +
            "LogSendRate              " + $DatabaseReplicaState.LogSendRate + "`n" +
            "LogSendQueueSize         " + $DatabaseReplicaState.LogSendQueueSize + "`n" +
            "RedoQueueSize            " + $DatabaseReplicaState.RedoQueueSize + "`n" +
            "AvailabilityDatabaseName " + $DatabaseReplicaState.AvailabilityDatabaseName + "`n" +
            "LogSendQueueSize         " + $DatabaseReplicaState.LogSendQueueSize + "`n" +
            # "EstimatedDataLoss        " + $DatabaseReplicaState.EstimatedDataLoss + "`n" +
            "LastRedoneTime           " + $DatabaseReplicaState.LastRedoneTime + "`n" +
            "LastCommitTime           " + $DatabaseReplicaState.LastCommitTime + "`n" +
            "LastReceivedTime         " + $DatabaseReplicaState.LastReceivedTime + "`n" +
            "LastSentTime             " + $DatabaseReplicaState.LastSentTime + "`n" +
            "")


    }


    # $XMLOutput += "<text>StatusDescription: $($Response.StatusDescription)</text>`n"
    $XMLOutput += "</prtg>"
    $XMLOutput

}













