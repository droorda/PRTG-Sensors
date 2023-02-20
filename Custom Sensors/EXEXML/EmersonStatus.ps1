[CmdletBinding()]
param (
	[Parameter(Position=1)]
	[string]$url								= "http://192.168.1.1/monitor/upsGeneral.htm"
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


Function GetTableFromHTML {
    param(
        [Parameter(Mandatory = $true)]
        $WebRequest,
        [Parameter(Mandatory = $true)]
        [int] $TableNumber
    )
#    [mshtml.HTMLDocumentClass]
    ## Extract the tables out of the web request
    $tables = @($WebRequest.getElementsByTagName("TABLE"))
    $table = $tables[$TableNumber]
    $titles = @()
    $rows = @($table.Rows)
    ## Go through all of the rows in the table
    foreach($row in $rows)
    {
        $cells = @($row.Cells)
        ## If we've found a table header, remember its titles
        if($cells[0].tagName -eq "TH")
        {
            $titles = @($cells | ForEach-Object { ("" + $_.InnerText).Trim() })
            continue
        }
        ## If we haven't found any table headers, make up names "P1", "P2", etc.
        if(-not $titles)
        {
            $titles = @(1..($cells.Count + 2) | ForEach-Object { "P$_" })
        }
        ## Now go through the cells in the the row. For each, try to find the
        ## title that represents that column and create a hashtable mapping those
        ## titles to content
        $resultObject = [Ordered] @{}
        for($counter = 0; $counter -lt $cells.Count; $counter++)
        {
            $title = $titles[$counter]
            if(-not $title) { continue }
            $resultObject[$title] = ("" + $cells[$counter].InnerText).Trim()
        }
        ## And finally cast that hashtable to a PSCustomObject
        [PSCustomObject] $resultObject

    }
}

$htmltext = (Invoke-WebRequest $url -UseBasicParsing ).Content
$htmltext = $htmltext.replace('<script>document.write(condensedDateTimeString(new Date()));</script>','')
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


$XMLOutput = "<prtg>`n"
GetTableFromHTML $h 1 | ForEach-Object {
    $XMLOutput += Set-PrtgResult $(($_."Supported Status").replace('Temperature','').Trim())  $($_.Value) C -sc
}
$table = GetTableFromHTML $h 2
$Table | ForEach-Object {if ($_.Status -eq "Normal"){
                            $_.Status = 1
                        } else {
                            $Text = "Unknown Status `"$($_.Status)`""
                            $_.Status = 2
                        }
                    }
$Table | ForEach-Object {
    $XMLOutput += Set-PrtgResult $_."Supported Alarms"  $_.Status "Status" -me 1 -sc -ValueLookup "com.emerson.healthlevel"
}

#$XMLOutput += Set-PrtgResult "CPU" $([int]$response.CPU.total.User + [int]$response.CPU.total.System) "Percent" -mw 50 -me 70 -sc
#$XMLOutput += Set-PrtgResult "Memory" $($response.Memory.percentmemused) "Percent" -mw 60 -me 80 -sc
#$XMLOutput += Set-PrtgResult "TPS Total" $($response.TPS.Total) "Count" -sc
#$XMLOutput += Set-PrtgResult "TPS SSL" $($response.TPS.SSL) "Count" -sc
#$response.Network | get-member -type Property | foreach-object {
#	$name=$_.Name ;
#	$value=$response.Network."$($_.Name)"
#    $XMLOutput += Set-PrtgResult "$name" $("{0:N1}" -f $((([int]$value.in + [int]$value.out)/[int]$value.speed)*100)) "Percent" -mw 60 -me 80 -sc
#}
$XMLOutput += "<text>$Text</text>`n"
$XMLOutput += "</prtg>"

Write-Host $XMLOutput


