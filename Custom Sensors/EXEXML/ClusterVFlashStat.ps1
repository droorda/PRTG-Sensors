[CmdletBinding()]
param (
	[Parameter(Position=1)]
	[string]$ClusterName,
    [string]$VIServer
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


if (!$ClusterName) {Set-PrtgError "ClusterName Not Specified"}

#$XMLOutput = "<prtg>`n"
#$XMLOutput += Set-PrtgResult "test" 1 "Percent"
#$XMLOutput += "</prtg>"
#Write-Host $XMLOutput
#exit



#-user $vCenterUserName -Password $vCenterPassword -ErrorAction SilentlyContinue
#write-warning "test 2"

connect-viserver $VIServer -ErrorAction SilentlyContinue |Out-Null
Update-PowerShellGalleryItem "VMware.PowerCLI" #-AllowClobber



$Stats = Get-Cluster $ClusterName |
            get-vmhost |
            Where-Object {$_.ConnectionState -eq "Connected"} |
            Select-Object Name,Version,@{N="GB vFlashFree";E={[decimal]::round((($_ | get-view).Runtime.VFlashResourceRuntimeInfo.FreeForVmCache)/(1024*1024*1024))}}, @{N="GB vFlashAval";E={[decimal]::round(($_.ExtensionData.config.VFlashConfigInfo.VFlashResourceConfigInfo.Capacity)/(1024*1024*1024))}}

#$Stats

$vFlashFreeMaxAval = ($Stats | Sort-Object "GB vFlashFree" -descending | Select-Object -first 1)."GB vFlashAval"
$vFlashFreeMaxFree = ($Stats | Sort-Object "GB vFlashFree" -descending | Select-Object -first 1)."GB vFlashFree"
# $vFlashFreeMaxName = ($Stats | Sort-Object "GB vFlashFree" -descending | Select-Object -first 1).Name
$vFlashFreeMinAval = ($Stats | Sort-Object "GB vFlashFree" | Select-Object -first 1)."GB vFlashAval"
$vFlashFreeMinFree = ($Stats | Sort-Object "GB vFlashFree" | Select-Object -first 1)."GB vFlashFree"
$vFlashFreeMinName = ($Stats | Sort-Object "GB vFlashFree" | Select-Object -first 1).Name

$vFlashFreeAval    = ($Stats | Measure-Object -property "GB vFlashFree" -Sum).Sum
$vFlashTotal       = ($Stats | Measure-Object -property "GB vFlashAval" -Sum).Sum
$vFlashUtilization = [int]((1-($vFlashFreeAval/$vFlashTotal))*100)


disconnect-viserver $VIServer -confirm:$false  |Out-Null




#"vFlashFreeMinName = $vFlashFreeMinFree/$vFlashFreeMinAval $([int](($vFlashFreeMinFree/$vFlashFreeMinAval)*100))%  $vFlashFreeMinName"
#"vFlashFreeMaxName = $vFlashFreeMaxFree/$vFlashFreeMaxAval $([int](($vFlashFreeMaxFree/$vFlashFreeMaxAval)*100))%  $vFlashFreeMaxName"
#"vFlashFreeAval    = $vFlashFreeAval"
#"vFlashTotal       = $vFlashTotal"


$XMLOutput = "<prtg>`n"
$XMLOutput += Set-PrtgResult "Min Free Gbyte"   $vFlashFreeMinFree "Gbyte" -sc
if ($vFlashFreeMinAval -gt 0){
    $XMLOutput += Set-PrtgResult "Min Free Space %" $([int](($vFlashFreeMinFree/$vFlashFreeMinAval)*100)) "Percent" -minw 30 -mine 20 -sc
} else {
    $XMLOutput += Set-PrtgResult "Min Free Space %" $([int]0) "Percent" -minw 30 -mine 20 -sc
}
$XMLOutput += Set-PrtgResult "Max Free Gbyte"   $vFlashFreeMaxFree "Gbyte" -sc
$XMLOutput += Set-PrtgResult "Max Free Space %" $([int](($vFlashFreeMaxFree/$vFlashFreeMaxAval)*100)) "Percent" -sc
$XMLOutput += Set-PrtgResult "Total Availble Gbyte"   $vFlashFreeAval "Gbyte"
$XMLOutput += Set-PrtgResult "Total Free Gbyte" $vFlashTotal "Gbyte"
$XMLOutput += Set-PrtgResult "Total Utilization" $vFlashUtilization "Percent" -me 80 -mw 70 -minw 30 -sc
$XMLOutput += "  <text>$vFlashFreeMinName</text>`n"
$XMLOutput += "</prtg>"

Write-Output $XMLOutput

exit

Write-Host "<prtg>"
Write-Host "  <result>"
Write-Host "    <channel>FreeMin</channel>"
Write-Host "    <value>$vFlashFreeMinFree</value>"
Write-Host "    <Unit>Custom</Unit>"
Write-Host "    <CustomUnit>MB</CustomUnit>"
Write-Host "    <VolumeSize>MegaByte</VolumeSize>"
Write-Host "    <float>1</float>"
Write-Host "  </result>"
Write-Host "</prtg>"
