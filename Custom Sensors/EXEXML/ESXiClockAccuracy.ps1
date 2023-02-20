[CmdletBinding()]
Param(
	[Parameter(Position=1)]
	[string]$prtg_host				= "$env:prtg_host")

if (test-path("$(split-path $SCRIPT:MyInvocation.MyCommand.Path)\prtgshell.psm1")) {
	Import-Module "$(split-path $SCRIPT:MyInvocation.MyCommand.Path)\prtgshell.psm1" -DisableNameChecking
} else {
	Write-output "<prtg>"
	Write-output "  <error>1</error>"
	Write-output "  <text>Unable to locate prtgshell.psm1</text>"
	Write-output "</prtg>"
	exit
}

if (!($prtg_host)) {
    Set-PrtgError "Host Name Not specified"
}

Try {
    Import-Module VMware.PowerCLI -ErrorAction Stop
} catch {
    Set-PrtgError $_.exception.Message
}

try {
    connect-viserver $prtg_host -ErrorAction Stop | Out-Null
} catch {
    Set-PrtgError "Could not connect to `"$prtg_host`""
    return
}


$HostsView = Get-View -ViewType HostSystem -Property Name,ConfigManager.DateTimeSystem
$Hosts = $HostsView | Sort-Object Name | Select-Object Name,@{Name="TimeOffset";Expression={[math]::Abs(  ((get-date) - ((Get-View $_.ConfigManager.DateTimeSystem).QueryDateTime().ToLocalTime())).totalseconds ) }}
$Hosts = $Hosts | Select-Object Name,@{N="TimeOffset";E={[int]$_.TimeOffset}},@{N="NTPServer";E={get-VMhost $_.Name |Get-VMHostNtpServer}},@{N="ServiceRunning";E={(Get-VmHostService -VMHost $_.Name |Where-Object {$_.key-eq "ntpd"}).Running}}


$Hosts | Where-Object {$_.TimeOffset -gt 3} | ForEach-Object {
    write-verbose "Restarting ntdp on $($_.name)"
    Get-VmHostService -VMHost $_.name | Where-Object {$_.Key -eq "ntpd"} | Restart-VMHostService -confirm:$false | Out-Null
}




if ($Hosts){
    $XMLOutput = "<prtg>`n"
    $XMLOutput += Set-PrtgResult -Channel "Max Host Time Deviation" -Value "$(($Hosts | Sort-Object TimeOffset -Descending)[0].TimeOffset)" -Unit TimeSeconds   -sc -maxw 15 -maxe 30
    $XMLOutput += Set-PrtgResult -Channel "Avg Host Time Deviation" -Value "$([int](($Hosts | Sort-Object TimeOffset -Descending).TimeOffset| Measure-Object -Average ).Average)" -Unit TimeSeconds   -sc -maxw 10 -maxe 20
    $XMLOutput += "<text>$(($Hosts | Sort-Object TimeOffset -Descending)[0].Name) </text>"
    $XMLOutput += "</prtg>"
    Write-Host $XMLOutput
} else {
    Set-PrtgError "No Stats returned"
}


Disconnect-viserver $prtg_host -Confirm:$false | Out-Null



