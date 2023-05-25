[CmdletBinding()]
param (
    [Parameter(Position=1)]
    [string]$ServerName = "$env:prtg_host"
)


if (test-path("$(split-path $SCRIPT:MyInvocation.MyCommand.Path)\prtgshell.psm1")) {
    Import-Module "$(split-path $SCRIPT:MyInvocation.MyCommand.Path)\prtgshell.psm1" -DisableNameChecking
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
	Import-Module -name SQLServer -DisableNameChecking -ErrorAction Stop
} Catch {
	Set-PrtgError "Invoke-sqlCmd: $($_.Exception.Message)"
}

Try {
    $return = Invoke-sqlCmd -ServerInstance $ServerName -Database EPGPre -Query "SELECT TOP (200) * FROM [EPGPre].[dbo].[Exceptions] Where [TimeStamp] >= DATEADD(minute, -5, GETDATE())" -MultiSubnetFailover -Encrypt Optional -ErrorAction Stop
} catch {
    Set-PrtgError "Invoke-sqlCmd: $($_.Exception.Message)"
}

$Timeout = ($return | Where-Object {$_.ExceptionMessage -match 'Execution Timeout Expired.*'} | Measure-Object).count
$return = $return | Where-Object {$_.ExceptionMessage -notmatch 'Execution Timeout Expired.*'}
$Execution = ($return | Where-Object {$_.ExceptionMessage -match 'An error occurred while executing the command.*'} | Measure-Object).count
$return = $return | Where-Object {$_.ExceptionMessage -notmatch 'An error occurred while executing the command.*'}
$unknown = ($return | Where-Object {$_.ExceptionMessage -eq '(null)'} | Measure-Object).count
$return = $return | Where-Object {$_.ExceptionMessage -ne '(null)'}
$other = ($return | Measure-Object).count

$XMLOutput = "<prtg>`n"
$XMLOutput += Set-PrtgResult -Channel "Timeout"   -Value $Timeout   -Unit Count -sc #-minw 10 -mine 5
$XMLOutput += Set-PrtgResult -Channel "Execution" -Value $Execution -Unit Count -sc #-minw 10 -mine 5
$XMLOutput += Set-PrtgResult -Channel "Unknown"   -Value $unknown   -Unit Count -sc #-minw 10 -mine 5
$XMLOutput += Set-PrtgResult -Channel "Other"     -Value $other     -Unit Count -sc #-minw 10 -mine 5
# $XMLOutput += "  <text>$vFlashFreeMinName</text>`n"
$XMLOutput += "</prtg>"

Write-Output $XMLOutput

