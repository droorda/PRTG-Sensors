[CmdletBinding()]
param (
	[Parameter(Position=1)]
	[string]$KEMPCluster								= "",
	[Parameter(Position=2)]
	[string]$KempUserName								= "",
	[Parameter(Position=3)]
	[string]$KempPassword								= "",
	[string]$VSName

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

if (!$KEMPCluster)  {Set-PrtgError "-KEMPCluster requred"}
if (!$KempUserName) {Set-PrtgError "-KempUserName requred"}
if (!$KempPassword) {Set-PrtgError "-KempPassword requred"}

if (test-path("$(split-path $SCRIPT:MyInvocation.MyCommand.Path)\Kemp\Kemp.LoadBalancer.Powershell.psm1")) {
	Import-Module "$(split-path $SCRIPT:MyInvocation.MyCommand.Path)\Kemp\Kemp.LoadBalancer.Powershell.psm1" -DisableNameChecking
} else {
	Set-PrtgError "Unable to locate Kemp.LoadBalancer.Powershell.psm1"
}
$KempSecurePassword = ConvertTo-SecureString $KempPassword -asplaintext -force
$KempCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $script:KempUserName, $KempSecurePassword

Function Get-VirtualServiceHealth{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

    $virtualServers = Get-VirtualService -LoadBalancer $LoadBalancer -Credential $Credential | Select-Object NickName,Status,Enable,Cookie,NumberOfRSs,NumberOfRSsOnline,SubVS,Rs,Index,MasterVSID
    if ($null -eq $virtualServers) {
        Set-PrtgError "No Virtual Servers Returned"
    }

    foreach ($vs in $virtualServers)
	{
        if ($vs.MasterVSID -gt 0) {
            $vs.NickName = ($virtualServers | Where-Object {$_.Index -eq $vs.MasterVSID}).NickName + "\" + $vs.NickName
        }
#            write-host $vs.NickName
        if ($vs.Rs) {
#        write-host $vs.Rs
            $vs.NumberOfRSsOnline = 0
#            write-host $vs.Rs
            $Temp = $vs.Rs.split(",")
            $Temp = for($i=0; $i -lt $Temp.count; $i++){
                if (($i % 12) -eq 0){
                    if (($($Temp[$i]) -eq "Up") -and ($($Temp[$i+10]) -eq "Y")) {$vs.NumberOfRSsOnline += 1}
#                    write-host "$($Temp[$i+3]),$($Temp[$i]),$($Temp[$i+10])"
                    "$($Temp[$i+3]),$($Temp[$i]),$($Temp[$i+10])"
                    #00 = Health Status
                    #01 = VS [int] ID#
                    #02 = RS [int] ID#
                    #03 = RS IP Address
                    #04 = RS Port
                    #05 = RS
                    #06 = RS Forwarding method
                    #07 = RS weight
                    #08 = RS Connection Limit
                    #10 = RS [BOL] Global Enabled
                    #11 = RS [BOL]
#                } elseif (($i % 10) -eq 0){
#                    if (($($Temp[$i]) -eq "Up") -and ($($Temp[$i+10]) -eq "Y")) {$vs.NumberOfRSsOnline += 1}
#                    "$($Temp[$i+3]),$($Temp[$i]),$($Temp[$i+10])"
#                    #00 = Health Status
#                    #01 = VS [int] ID#
#                    #02 = RS [int] ID#
#                    #03 = RS IP Address
#                    #04 = RS Port
#                    #05 = RS Forwarding method
#                    #06 = RS weight
#                    #07 = RS Connection Limit
#                    #08 = RS [BOL] Global Enabled
#                    #09 = ?[BOL]
                }
            }
            #$Temp = $Temp | where {$_ -match $rs.Addr}
            $vs.Rs = $Temp
        } elseif ($vs.SubVS) {
            $vs.NumberOfRSsOnline = 0
#            write-host $vs.SubVS
            $Temp = $vs.SubVS.split(",")
            $Temp = for($i=0; $i -lt $Temp.count; $i++){
                if (($i % 12) -eq 0){
                    if ($($Temp[$i]) -eq "Up") {$vs.NumberOfRSsOnline += 1}
                    "$($Temp[$i]),$($Temp[$i+3])"
#                    write-host $vs.NumberOfRSsOnline
#                    write-host "$($Temp[$i]),$($Temp[$i+3])"
                }
            }
            #$Temp = $Temp | where {$_ -match $rs.Addr}
            $vs.SubVS = $Temp
        } else {
            $vs.NumberOfRSsOnline = 0
        }
	}
    foreach ($vs in $virtualServers)
	{
        if ($vs.MasterVSID -eq 0) {
            $vs.NickName = $vs.NickName + "\"
        }
    }
    return $virtualServers | Sort-Object NickName | Select-Object NickName,Status,Cookie,NumberOfRSs,NumberOfRSsOnline,Rs
}

#Get-VirtualService -LoadBalancer $KEMPCluster -Credential $KempCredentials |gm
#Get-VirtualService -LoadBalancer $KEMPCluster -Credential $KempCredentials |where {$_.Index -eq 21}|gm
#Get-VirtualService -LoadBalancer $KEMPCluster -Credential $KempCredentials |where {$_.Index -eq 35}|gm

# "**1**"
$VSStats = Get-VirtualServiceHealth -Credential $KempCredentials -LoadBalancer $KEMPCluster
# "**2**"

$XMLOutput = "<prtg>`n"

if ($VSName){
    foreach ($VSStat in ($VSStats | Where-Object {$_.NickName -match $VSName})){
        $XMLOutput += Set-PrtgResult $VSStat.NickName $VSStat.NumberOfRSsOnline "Count" -sc -minw $VSStat.NumberOfRSs -mine $([int](($VSStat.NumberOfRSs/2)+.1))
    }
} else {
    foreach ($VSStat in $VSStats){
        $XMLOutput += Set-PrtgResult $VSStat.NickName $VSStat.NumberOfRSsOnline "Count" -sc -minw $VSStat.NumberOfRSs -mine $([int](($VSStat.NumberOfRSs/2)+.1))
    }
}
$XMLOutput += "</prtg>"

Write-Host $XMLOutput




return
Get-VirtualServiceHealth -Credential $KempCredentials -LoadBalancer $KEMPCluster | ForEach-Object {
    if ($_.NumberOfRSs -eq $_.NumberOfRSsOnline) {
        write-host "$($_.NickName) - $($_.NumberOfRSs) - $($_.NumberOfRSsOnline)" -ForegroundColor Green
    } else {
        write-host "$($_.NickName) - $($_.NumberOfRSs) - $($_.NumberOfRSsOnline)" -ForegroundColor Yellow
    }
}
#C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass "& 'c:\Program Files (x86)\PRTG Network Monitor\Custom Sensors\EXEXML\KempVSHealth.ps1' -KEMPCluster lsd-lbc01.dmz.local -KempUserName UpdateScript -KempPassword D4RWABwWwf7X"



