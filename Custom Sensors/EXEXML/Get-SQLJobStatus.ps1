<#
    .SYNOPSIS
        Checks information about a Sql AgentJob.
    .DESCRIPTION
        Script to check the last runtime and last run outcome of a SQL AgentJob
    .PARAMETER SqlInstance
        SQl Connection to the Server.
    .PARAMETER Agentjob
        Name of the Agentjob to Check.
    .EXAMPLE
        PS C:\> .\SQL.GetLastAgentJobRuntime.ps1 -ServerName SQL01\Instance1 -AgentJob TestJob
#>
PARAM(
    [String] $ServerName = "$env:prtg_host"
    ,
    [Parameter(Mandatory=$true)]
    [String] $AgentJob
)

# Function to return json formatted error message to PRTG

if (test-path("$(split-path $SCRIPT:MyInvocation.MyCommand.Path)\prtgshell.psm1")) {
    Import-Module "$(split-path $SCRIPT:MyInvocation.MyCommand.Path)\prtgshell.psm1" -DisableNameChecking -Verbose:$false
} else {
    Write-output "<prtg>"
    Write-output "  <error>1</error>"
    Write-output "  <text>Unable to locate prtgshell.psm1</text>"
    Write-output "</prtg>"
    exit
}

if ([string]::IsNullOrEmpty($ServerName)) {
	Set-PrtgError "ServerName or `$env:prtg_host Required"
}

Try {
    Import-Module SQLServer -ErrorAction Stop -Verbose:$false
} Catch {
    Find-Module SQLServer | Sort-Object {((Get-PSRepository -name $_.Repository).InstallationPolicy -eq 'trusted'),$_.Version} | Select-Object -Last 1 | Install-Module -Force -Scope AllUsers
    Try {
        Import-Module SQLServers -ErrorAction Stop -Verbose:$false
    } Catch {
        Set-PrtgError -PrtgErrorText "Unable to locate SQLServer Module"
    }
}



Try {
    $return = Invoke-sqlCmd -ServerInstance $ServerName -Database EPGPre -Query "EXEC msdb.dbo.sp_help_job @Job_name = '$AgentJob'" -MultiSubnetFailover -Encrypt Optional -ErrorAction Stop
} catch {
    Set-PrtgError "Invoke-sqlCmd: $($_.Exception.Message)"
}
$SQLJob = [PSCustomObject]@{
    job      = $return | Where-Object {$null -ne $_.job_id}
    step     = $return | Where-Object {$null -ne $_.step_id}
    schedule = $return | Where-Object {$null -ne $_.schedule_id} | Where-Object {$_.enabled -eq 1}
    server   = $return | Where-Object {$null -ne $_.server_id}
}



if ($SQLJob.job.current_execution_status -eq 4) {
    # Current Job not running
    $ExecutionStep = 0
    $Status = $SQLJob.server.last_run_outcome
    $Text = $SQLJob.server.last_outcome_message
    $LastRunTime = ([int]((Get-date) - [datetime]::parseexact($SQLJob.server.last_run_date.ToString() + $SQLJob.server.last_run_time.ToString().PadLeft(6,'0'), 'yyyyMMddHHmmss', $null) ).TotalMinutes)
} else {
    # Current Job Running
    $ExecutionStep = [int]($SQLJob.job.current_execution_step.Split()[0])
    $Status = 4
    $Text = "Current Step: $(($SQLJob.step | Where-Object {$_.step_id -eq $ExecutionStep}).step_name)"
    $LastRunTime = [int]((Get-date) - ($SQLJob.step | ForEach-Object { [datetime]::parseexact($_.last_run_date.ToString() + $_.last_run_time.ToString().PadLeft(6,'0'), 'yyyyMMddHHmmss', $null)} | Sort-Object | Select-Object -Last 1) ).TotalMinutes
    # msdb.sysjobstepslogs
}
$LastRunDuration = [int]([timespan]::ParseExact($SQLJob.server.last_run_duration.ToString().PadLeft(6,'0'),'hhmmss', $null).TotalMinutes )

$XMLOutput = "<prtg>`n"
$XMLOutput += Set-PrtgResult -Channel "Enabled"           -Value $SQLJob.job.enabled                  -Unit "Status"  -sc -ValueLookup "com.microsoft.sql.yesno.stateyesok"             # -minw 10 -mine 5
$XMLOutput += Set-PrtgResult -Channel "Execution Status"  -Value $SQLJob.job.current_execution_status -Unit "Status"  -sc -ValueLookup "com.microsoft.sql.job.current_execution_status" # -minw 10 -mine 5
$XMLOutput += Set-PrtgResult -Channel "Status"            -Value $Status                              -Unit "Status"  -sc -ValueLookup "com.microsoft.sql.last_run_status"              # -minw 10 -mine 5
$XMLOutput += Set-PrtgResult -Channel "Execution Step"    -Value $ExecutionStep                       -Unit "Count"   -sc                                                               # -minw 10 -mine 5
$XMLOutput += Set-PrtgResult -Channel "Last Run Time"     -Value $LastRunTime                         -Unit "Minutes" -sc                                                               # -minw 10 -mine 5
$XMLOutput += Set-PrtgResult -Channel "Last Run Duration" -Value $LastRunDuration                     -Unit "Minutes" -sc                                                               # -minw 10 -mine 5
$XMLOutput += "  <text>$Text</text>`n"



$XMLOutput += "</prtg>"

Write-Output $XMLOutput


exit



# $SQLJob.job.current_execution_status : 4
# $SQLJob.job.current_execution_step   : 0 (unknown)
# $SQLJob.job.current_retry_attempt    : 0
# 'Status' # Running, retying, last result


# $XMLOutput += Set-PrtgResult -Channel "Enabled"   -Value $SQLJob.job.enabled   -Unit "Count" -sc  #-minw 10 -mine 5
# $XMLOutput += Set-PrtgResult -Channel "Enabled"   -Value $SQLJob.job.enabled   -Unit "Count" -sc  #-minw 10 -mine 5



# $SQLJob.job.current_execution_status : 4
# $SQLJob.job.current_execution_step   : 0 (unknown)
# $SQLJob.job.current_retry_attempt    : 0

# $SQLJob.schedule.freq_type              : 4
# $SQLJob.schedule.freq_interval          : 1
# $SQLJob.schedule.freq_subday_type       : 1
# $SQLJob.schedule.freq_subday_interval   : 0
# $SQLJob.schedule.freq_relative_interval : 0
# $SQLJob.schedule.freq_recurrence_factor : 0






# Provides Last start time for a finished job
# $XMLOutput += Set-PrtgResult -Channel "Last Run Time"     -Value ([int]((Get-date) - [datetime]::parseexact($SQLJob.server.last_run_date.ToString() + $SQLJob.server.last_run_time.ToString().PadLeft(6,'0'), 'yyyyMMddHHmmss', $null) ).TotalMinutes) -Unit "Minutes" -sc # -ValueLookup "prtg.standardlookups.yesno.stateyesok" #-minw 10 -mine 5
# $XMLOutput += Set-PrtgResult -Channel "Last Run Duration" -Value ([int]([timespan]::ParseExact($SQLJob.server.last_run_duration.ToString().PadLeft(6,'0'),'hhmmss', $null).TotalMinutes ))                                                             -Unit "Minutes" -sc # -ValueLookup "prtg.standardlookups.yesno.stateyesok" #-minw 10 -mine 5

# current_execution_status
#     1 = 'Executing'
#     2 = 'Waiting For Thread'
#     3 = 'Between Retries'
#     4 = 'Idle'
#     5 = 'Suspended'
#     6 = '[Obsolete]'
#     7 = 'PerformingCompletionActions'

# last_run_outcome
#     0 = 'Failed'
#     1 = 'Succeeded'
#     2 = 'Retry'
#     3 = 'Cancelled'
#     4 = 'In Progress'
#     5 = 'Unknown'


"2023051910001",
'yyyyMMddHHmm'



#Get Current Time
$CurrentDateTime = Get-Date
#Get Timespan
$TimeSinceLastRun = New-TimeSpan -Start $DbaAgentJob.LastRunDate -End $CurrentDateTime
#Create Response for PRTG
$JSON = @{
    "prtg" = @{
        "result" = @(
            @{
                channel = ("Time since last run")
                value = $TimeSinceLastRun.TotalMinutes
                float = 1
                unit = "Custom"
                CustomUnit = "minutes"
            }
            # You clould make a PRTG lookup with all return values.
            @{
                channel = ("Last outcome")
                value = $DbaAgentJob.LastRunOutcome.value__
                unit = "Custom"
                CustomUnit = "#"
                LimitMode = 1
                LimitMinError = 0.1 #Because its not possible to alert here with 0, but its easier to work with lookups
            }
        )
    }
}
$JSON | ConvertTo-Json -Depth 3


<#

USE msdb
Go


SELECT j.Name AS 'Job Name',
    '"' + NULLIF(j.Description, 'No description available.') + '"' AS 'Description',
    SUSER_SNAME(j.owner_sid) AS 'Job Owner',
    (SELECT COUNT(step_id) FROM dbo.sysjobsteps WHERE job_id = j.job_id) AS 'Number of Steps',
    (SELECT COUNT(step_id) FROM dbo.sysjobsteps WHERE job_id = j.job_id AND command LIKE '%xp_cmdshell%') AS 'has_xpcmdshell',
    (SELECT COUNT(step_id) FROM dbo.sysjobsteps WHERE job_id = j.job_id AND command LIKE '%msdb%job%') AS 'has_jobstartstopupdate',
    (SELECT COUNT(step_id) FROM dbo.sysjobsteps WHERE job_id = j.job_id AND command LIKE '%ftp%') AS 'has_ftp',
    'Job Enabled' = CASE j.Enabled
        WHEN 1 THEN 'Yes'
        WHEN 0 THEN 'No'
    END,
    'Frequency' = CASE s.freq_type
        WHEN 1 THEN 'Once'
        WHEN 4 THEN 'Daily'
        WHEN 8 THEN 'Weekly'
        WHEN 16 THEN 'Monthly'
        WHEN 32 THEN 'Monthly relative'
        WHEN 64 THEN 'When SQLServer Agent starts'
    END,
    CASE(s.freq_subday_interval)
        WHEN 0 THEN 'Once'
        ELSE cast('Every '
                + right(s.freq_subday_interval,2)
                + ' '
                +     CASE(s.freq_subday_type)
                            WHEN 1 THEN 'Once'
                            WHEN 4 THEN 'Minutes'
                            WHEN 8 THEN 'Hours'
                        END as char(16))
    END as 'Subday Frequency',
    'Next Start Date'= CONVERT(DATETIME, RTRIM(NULLIF(js.next_run_date, 0)) + ' '
        + STUFF(STUFF(REPLACE(STR(RTRIM(js.next_run_time),6,0),
        ' ','0'),3,0,':'),6,0,':')),
    'Max Duration' = STUFF(STUFF(REPLACE(STR(maxdur.run_duration,7,0),
        ' ','0'),4,0,':'),7,0,':'),
    'Last Run Duration' = STUFF(STUFF(REPLACE(STR(lastrun.run_duration,7,0),
        ' ','0'),4,0,':'),7,0,':'),
    'Last Start Date' = CONVERT(DATETIME, RTRIM(lastrun.run_date) + ' '
        + STUFF(STUFF(REPLACE(STR(RTRIM(lastrun.run_time),6,0),
        ' ','0'),3,0,':'),6,0,':')),
    'Last Run Message' = lastrun.message
FROM dbo.sysjobs j
LEFT OUTER JOIN dbo.sysjobschedules js
    ON j.job_id = js.job_id
LEFT OUTER JOIN dbo.sysschedules s
    ON js.schedule_id = s.schedule_id
LEFT OUTER JOIN (SELECT job_id, max(run_duration) AS run_duration
        FROM dbo.sysjobhistory
        GROUP BY job_id) maxdur
ON j.job_id = maxdur.job_id
-- INNER JOIN -- Swap Join Types if you don't want to include jobs that have never run
LEFT OUTER JOIN
    (SELECT j1.job_id, j1.run_duration, j1.run_date, j1.run_time, j1.message
    FROM dbo.sysjobhistory j1
    WHERE instance_id = (SELECT MAX(instance_id)
                         FROM dbo.sysjobhistory j2
                         WHERE j2.job_id = j1.job_id)) lastrun
    ON j.job_id = lastrun.job_id
ORDER BY [Job Name]
#>