[CmdletBinding()]
param (
	[Parameter(Position=1)]
	[String]$HostName = $env:prtg_host
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

if (-not $HostName) {
    Set-PrtgError "-HostName is Required"
}

$url = "http://$HostName/PSummary.html"


Function GetTableFromHTML {
    param(
        [Parameter(ParameterSetName='WebRequest',Mandatory = $true)]
        $WebRequest
        ,
        [Parameter(ParameterSetName='WebRequest',Mandatory = $true)]
        [int]
        $TableNumber
        ,
        [Parameter(ParameterSetName='Table',Mandatory = $true)]
        $Table
    )
#    [mshtml.HTMLDocumentClass]
    ## Extract the tables out of the web request
    if ($WebRequest) {
        $tables = @($WebRequest.getElementsByTagName("TABLE"))
        $table = $tables[$TableNumber]
    }
    $titles = @()
    $rows = @($table.Rows)
    ## Go through all of the rows in the table
    foreach($row in $rows) {
        $cells = @($row.Cells)
        ## If we've found a table header, remember its titles
        if ($cells[0].tagName -eq "TH") {
            $titles = @($cells | ForEach-Object { ("" + $_.InnerText).Trim() })
            continue
        }
        ## If we haven't found any table headers, make up names "P1", "P2", etc.
        if (-not $titles) {
            $titles = @(1..($cells.Count + 2) | ForEach-Object { "P$_" })
        }
        ## Now go through the cells in the the row. For each, try to find the
        ## title that represents that column and create a hashtable mapping those
        ## titles to content
        $resultObject = [Ordered] @{}
        for ($counter = 0; $counter -lt $cells.Count; $counter++) {
            $title = $titles[$counter]
            if (-not $title) { continue }
            $SubTable = $cells[$counter].childNodes | Where-Object {$_.nodeName -eq 'TABLE'}
            if ($SubTable) {
                $resultObject[$title] = GetTableFromHTML -Table $SubTable
            } else {
                $resultObject[$title] = ("" + $cells[$counter].InnerText).Trim()
            }
        }
        ## And finally cast that hashtable to a PSCustomObject
        if (($resultObject.count -eq 1) -and ($resultObject.GetEnumerator()[0].name -eq 'P1') -and (-not $WebRequest)) {
            $resultObject[0]
        } else {
            [PSCustomObject] $resultObject
        }
    }
}

$htmltext = (Invoke-WebRequest $url -UseBasicParsing ).Content
$htmltext = $htmltext.replace('CheckTitle(nTitle);','')
$htmltext = $htmltext.replace('<script>CheckLink ()</script>','')
$htmltext = $htmltext.replace('parent.logo.logoSetTime(sDate, sTime);','')
$h = new-object -com "HTMLFILE"
try {
    $h.IHTMLDocument2_write($htmltext)
} catch {
    try {
        $htmltext = [System.Text.Encoding]::Unicode.GetBytes($htmltext)
        $h.Write($htmltext)
    } catch {
        Set-PrtgError "$_"
        return
    }
}

$Status = @{}
$Text = @()

GetTableFromHTML -WebRequest $h -TableNumber 0 | Foreach-Object {
    if ($_.P1) {
        $Catagory = $_.P1
        $Status[$Catagory] = @{}
    } else {
        if ($_.P2) {
            $Status[$Catagory][$_.P2] = $_.P3
        }
    }
}


$Text += "Model = $($Status.Identification.'UPS Model')"
$Status.'Current Status'.'Last Logged Events' = $Status.'Current Status'.'Last Logged Events' | ForEach-Object {
    if ($_ -Match '^(\d+\/\d+\/\d+ \d+:\d+:\d+) (.*)$') {
        [PSCustomObject]@{
            'Date'  = [DateTime]$Matches[1]
            'Event' = [String]$Matches[2]
        }
    } else {
        $Text += "Event = $_"
    }
}

$Status.'Current Status'.'Last Logged Events' | Where-Object {((Get-Date) - $_.Date).TotalDays -lt 1 } | Foreach-Object {
    $Text += "Event = $($_.Event)"
}



$BypassStatus = @{
    'Unknown' = 1
    'Normal'  = 2
    'Battery' = 3
    'Recharge' = 4
    'Bypass' = 5
    'Maintenance bypass' = 6
}
$BattaryStatus = @{
    'Normal' = 2
    'Unknown' = 1
}
$ABMStatus = @{
    'Unknown'  = 1
    'Resting'  = 2
    'Floating' = 3
    'Testing'  = 4
}
$OverallStatus = @{
    'Unknown' = 1
    'UPS SUPPORTING LOAD' = 2
}
$BatteryTestStatus = @{
    'Unknown' = 1
    'Normal'  = 2  # ??
    'Warning' = 3  # ??
    'Failed' = 4
}

if ($BypassStatus[$Status.Bypass.'Bypass Status']) {
    $Status.Bypass.'Bypass Status' = $BypassStatus[$Status.Bypass.'Bypass Status']
} else {
    $Text += "Bypass Status = '$($Status.Bypass.'Bypass Status')'"
    $Status.Bypass.'Bypass Status' = 1
}

if ($BattaryStatus[$Status.Battery.'Battery Status']) {
    $Status.Battery.'Battery Status' = $BattaryStatus[$Status.Battery.'Battery Status']
} else {
    $Text += "Battery Status = '$($Status.Battery.'Battery Status')'"
    $Status.Battery.'Battery Status' = 1
}

if ($ABMStatus[$Status.Battery.'ABM Status']) {
    $Status.Battery.'ABM Status' = $ABMStatus[$Status.Battery.'ABM Status']
} else {
    $Text += "ABM Status = '$($Status.Battery.'ABM Status')'"
    $Status.Battery.'ABM Status' = 1
}

if ($OverallStatus[$Status.'Current Status'.'Overall Status']) {
    $Status.'Current Status'.'Overall Status' = $OverallStatus[$Status.'Current Status'.'Overall Status']
} else {
    $Text += "Overall Status = '$($Status.'Current Status'.'Overall Status')'"
    $Status.'Current Status'.'Overall Status' = 1
}

if ($Status.'Current Status'.'Last Battery Test Status' -match '(\d+\/\d+\/\d+) \d+:\d+:\d+ - (.*)') {
    $BatteryTestValue = $BatteryTestStatus[$Matches[2]]
    if ($BatteryTestValue) {
        if (((get-date) - [datetime]$Matches[1]).TotalDays -gt 90) {
            if ($BatteryTestValue -gt 3) {$BatteryTestValue = 3}
        }
        $Status.'Current Status'.'Last Battery Test Status' = $BatteryTestValue
    } else {
        $Text += "Last Battery Test Status = '$($Matches[2])'"
        $Status.'Current Status'.'Last Battery Test Status' = $BatteryTestStatus['Unknown']
    }
} else {
    $Text += "Last Battery Test Status = '$($Status.'Current Status'.'Last Battery Test Status')'"
    $Status.'Current Status'.'Last Battery Test Status' = $BatteryTestStatus['Unknown']
}




$XMLOutput = "<prtg>`n"
$XMLOutput += Set-PrtgResult -Channel 'Overall Status'       -Value $Status.'Current Status'.'Overall Status'                 -Unit "Status"  -sc -ValueLookup "com.eaton.overallstatus"
$XMLOutput += Set-PrtgResult -Channel 'Bypass Status'        -Value $Status.Bypass.'Bypass Status'                            -Unit "Status"  -sc -ValueLookup "com.eaton.bypassstatus"

$XMLOutput += Set-PrtgResult -Channel 'Battery Status'       -Value $Status.Battery.'Battery Status'                          -Unit "Status"  -sc -ValueLookup "com.eaton.batterystatus"
$XMLOutput += Set-PrtgResult -Channel 'Battery Test'         -Value $Status.'Current Status'.'Last Battery Test Status'       -Unit "Status"  -sc -ValueLookup "com.eaton.batteryteststatus"
$XMLOutput += Set-PrtgResult -Channel 'ABM Status'           -Value $Status.Battery.'ABM Status'                              -Unit "Status"  -sc -ValueLookup "com.eaton.abmstatus"
$XMLOutput += Set-PrtgResult -Channel 'Battery DC Amps'      -Value $Status.Battery.'Current (DC Amps)'                       -Unit "Amps"    -sc -MaxWarn 5
$XMLOutput += Set-PrtgResult -Channel 'Battery Voltage'      -Value $Status.Battery.'Voltage (VDC)'                           -Unit "VDC"     -sc -MinWarn 225
$XMLOutput += Set-PrtgResult -Channel 'Runtime'              -Value $Status.'Current Status'.'Runtime (minutes)'              -Unit "Minutes" -sc -MinErr 15

$XMLOutput += Set-PrtgResult -Channel 'Load'                 -Value (($Status.Output.'UPS Load (L) (%)'.psobject.properties | ForEach-Object {[int]$_.value } ) | Measure-Object -Average).Average -Unit "Percent" -sc -MaxWarn 70 -MaxErr 80
$XMLOutput += Set-PrtgResult -Channel 'True Power'           -Value $Status.Output.'True Power (Watts)'                       -Unit "Watt"    -sc
$XMLOutput += Set-PrtgResult -Channel 'Apparent Power'       -Value $Status.Output.'Apparent Power (VA)'                      -Unit "VA"      -sc
$XMLOutput += Set-PrtgResult -Channel 'Power Factor'         -Value $Status.Output.'Power Factor'                             -Unit "Percent" -sc

$XMLOutput += Set-PrtgResult -Channel 'Internal Temperature' -Value (([int]$Status.Statistics.'UPS Internal Temperature (Degrees C)')*9/5 + 32) -Unit "F" -sc -MaxErr 87
$XMLOutput += Set-PrtgResult -Channel 'Remote Temperature'   -Value $Status.'Current Status'.'Remote Temperature (Degrees F)' -Unit "F"       -sc -MaxErr 82
$XMLOutput += Set-PrtgResult -Channel 'Remote Humidity'      -Value $Status.'Current Status'.'Remote Humidity (%)'            -Unit "Percent" -sc -MaxErr 80

if ($Status.Statistics.'ConnectUPS Up-Time' -match '(\d+) days (\d+) hours (\d+) mins (\d+\.\d+) secs.') {
    $XMLOutput += Set-PrtgResult -Channel 'ConnectUPS Up-Time'   -Value ((($([int]$Matches[1])*24+$([int]$Matches[2]))*60+$([int]$Matches[3]))*60+$Matches[4])  -Unit "Seconds" -sc
} else {
    $Text += "ConnectUPS Up-Time = '$($Status.Statistics.'ConnectUPS Up-Time')'"
}
$XMLOutput += Set-PrtgResult -Channel 'Time Accuracy'        -Value ((get-date).ToUniversalTime() - [datetime]($Status.Statistics.'Date (mm/dd/yyyy)' + ' ' + $Status.Statistics.'Time (hh:mm:ss)')).TotalSeconds  -Unit "Seconds" -sc -MinErr -60 -MinWarn -30 -MaxWarn 30 -MaxErr 60






#$XMLOutput += Set-PrtgResult "CPU" $([int]$response.CPU.total.User + [int]$response.CPU.total.System) "Percent" -mw 50 -me 70 -sc
#$XMLOutput += Set-PrtgResult "Memory" $($response.Memory.percentmemused) "Percent" -mw 60 -me 80 -sc
#$XMLOutput += Set-PrtgResult "TPS Total" $($response.TPS.Total) "Count" -sc
#$XMLOutput += Set-PrtgResult "TPS SSL" $($response.TPS.SSL) "Count" -sc
#$response.Network | get-member -type Property | foreach-object {
#	$name=$_.Name ;
#	$value=$response.Network."$($_.Name)"
#    $XMLOutput += Set-PrtgResult "$name" $("{0:N1}" -f $((([int]$value.in + [int]$value.out)/[int]$value.speed)*100)) "Percent" -mw 60 -me 80 -sc
#}
$XMLOutput += "<text>$($Text -join ',')</text>`n"
$XMLOutput += "</prtg>"

Write-Host $XMLOutput


