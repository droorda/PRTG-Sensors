[CmdletBinding()]
Param(
	[Parameter(Position=1)]
	[string]$prtg_host				= "$env:prtg_host"
    # ,
	# [string]$prtg_windowsdomain		= "$env:prtg_windowsdomain"
    # ,
	# [string]$prtg_windowspassword	= "$env:prtg_windowspassword"
    # ,
	# [string]$prtg_windowsuser		= "$env:prtg_windowsuser"
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

if (!($prtg_host)) {
    Set-PrtgError "Host Name Not specified"
}
$ModuleName = "DhcpServer"
$LocalPowerCLI  = Get-Module -ListAvailable -Name $ModuleName
if (!($LocalPowerCLI)) {
    Set-PrtgError "ERROR $ModuleName Module not found"
}


try {
    $Stats = Get-DhcpServerv4ScopeStatistics -ComputerName $prtg_host -ErrorAction Stop
} catch {
    Set-PrtgError "ERROR getting stats $_"
}

#$Stats
#foreach ($Stat in $Stats) { "1 $($Stat.ScopeId)  $($Stat.Free) $($Stat.PercentageInUse) "}

if ($Stats){
    $XMLOutput = "<prtg>`n"
    foreach ($Stat in $Stats) {
        $XMLOutput += Set-PrtgResult -Channel "$($Stat.ScopeId) %" -Value $Stat.Free                         -Unit Count   -sc -minw 10 -mine 5
        $XMLOutput += Set-PrtgResult -Channel "$($Stat.ScopeId) C" -Value (100 - [int]$Stat.PercentageInUse) -Unit Percent -sc -minw 10 -mine 5
    }
    $XMLOutput += "</prtg>"
    Write-Host $XMLOutput
} else {
    Set-PrtgError "No Stats returned"
}

