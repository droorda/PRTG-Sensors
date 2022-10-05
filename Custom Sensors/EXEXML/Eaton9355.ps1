[CmdletBinding()]
param (
	[Parameter(Position=1)]
	[string]$url = "http://$env:prtg_host/PSummary.html"
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
    'Normal'  = 1
    'Unknown' = 2
}
$BattaryStatus = @{
    'Normal' = 1
    'Unknown' = 2
}
$ABMStatus = @{
    'Floating' = 1
    'Unknown' = 2
}
$OverallStatus = @{
    'UPS SUPPORTING LOAD' = 1
    'Unknown' = 2
}
$BatteryTestStatus = @{
    'Unknown' = 2
    'Failed' = 4
}

if ($BypassStatus[$Status.Bypass.'Bypass Status']) {
    $Status.Bypass.'Bypass Status' = $BypassStatus[$Status.Bypass.'Bypass Status']
} else {
    $Status.Bypass.'Bypass Status' = 0
    $Text += "Bypass Status = '$($Status.Bypass.'Bypass Status')'"
}

if ($BattaryStatus[$Status.Battery.'Battery Status']) {
    $Status.Battery.'Battery Status' = $BattaryStatus[$Status.Battery.'Battery Status']
} else {
    $Status.Battery.'Battery Status' = 0
    $Text += "Battery Status = '$($Status.Battery.'Battery Status')'"
}

if ($ABMStatus[$Status.Battery.'ABM Status']) {
    $Status.Battery.'ABM Status' = $ABMStatus[$Status.Battery.'ABM Status']
} else {
    $Status.Battery.'ABM Status' = 0
    $Text += "ABM Status = '$($Status.Battery.'ABM Status')'"
}

if ($OverallStatus[$Status.'Current Status'.'Overall Status']) {
    $Status.'Current Status'.'Overall Status' = $OverallStatus[$Status.'Current Status'.'Overall Status']
} else {
    $Status.'Current Status'.'Overall Status' = 0
    $Text += "Overall Status = '$($Status.'Current Status'.'Overall Status')'"
}

if ($Status.'Current Status'.'Last Battery Test Status' -match '\d+\/\d+\/\d+ \d+:\d+:\d+ - (.*)') {
    if ($BatteryTestStatus[$Matches[1]]) {
        $Status.'Current Status'.'Last Battery Test Status' = $BatteryTestStatus[$Matches[1]]
    } else {
        $Status.'Current Status'.'Last Battery Test Status' = 0
        $Text += "Last Battery Test Status = '$($Matches[1])'"
    }
} else {
    $Status.'Current Status'.'Last Battery Test Status' = 0
    $Text += "Last Battery Test Status = '$($Status.'Current Status'.'Last Battery Test Status')'"
}




$XMLOutput = "<prtg>`n"
$XMLOutput += Set-PrtgResult -Channel 'Bypass Status'        -Value $Status.Bypass.'Bypass Status'                            -Unit "Count"   -sc -ValueLookup "com.eaton.bypassstatus"
$XMLOutput += Set-PrtgResult -Channel 'Battery Status'       -Value $Status.Battery.'Battery Status'                          -Unit "Count"   -sc -ValueLookup "com.eaton.batterystatus"
$XMLOutput += Set-PrtgResult -Channel 'Battery DC Amps'      -Value $Status.Battery.'Current (DC Amps)'                       -Unit "Amps"    -sc
$XMLOutput += Set-PrtgResult -Channel 'Battery Voltage'      -Value $Status.Battery.'Voltage (VDC)'                           -Unit "VDC"     -sc
$XMLOutput += Set-PrtgResult -Channel 'ABM Status'           -Value $Status.Battery.'ABM Status'                              -Unit "Count"   -sc -ValueLookup "com.eaton.abmstatus"
$XMLOutput += Set-PrtgResult -Channel 'Remote Humidity'      -Value $Status.'Current Status'.'Remote Humidity (%)'            -Unit "Percent" -sc
$XMLOutput += Set-PrtgResult -Channel 'Overall Status'       -Value $Status.'Current Status'.'Overall Status'                 -Unit "Count"   -sc -ValueLookup "com.eaton.overallstatus"
$XMLOutput += Set-PrtgResult -Channel 'Runtime'              -Value $Status.'Current Status'.'Runtime (minutes)'              -Unit "Minutes" -sc
$XMLOutput += Set-PrtgResult -Channel 'Battery Status'       -Value $Status.'Current Status'.'Last Battery Test Status'       -Unit "Count"   -sc -ValueLookup "com.eaton.batteryteststatus"
$XMLOutput += Set-PrtgResult -Channel 'Remote Temperature'   -Value $Status.'Current Status'.'Remote Temperature (Degrees F)' -Unit "F"       -sc
$XMLOutput += Set-PrtgResult -Channel 'True Power'           -Value $Status.Output.'True Power (Watts)'                       -Unit "Watt"    -sc
$XMLOutput += Set-PrtgResult -Channel 'Apparent Power'       -Value $Status.Output.'Apparent Power (VA)'                      -Unit "VA"      -sc
$XMLOutput += Set-PrtgResult -Channel 'Power Factor'         -Value $Status.Output.'Power Factor'                             -Unit "Percent" -sc
$XMLOutput += Set-PrtgResult -Channel 'Load'                 -Value (($Status.Output.'UPS Load (L) (%)'.psobject.properties | ForEach-Object {[int]$_.value } ) | Measure-Object -Average).Average -Unit "Percent" -sc
if ($Status.Statistics.'ConnectUPS Up-Time' -match '(\d+) days (\d+) hours (\d+) mins (\d+\.\d+) secs.') {
    $XMLOutput += Set-PrtgResult -Channel 'ConnectUPS Up-Time'   -Value ((($([int]$Matches[1])*24+$([int]$Matches[2]))*60+$([int]$Matches[3]))*60+$Matches[4])  -Unit "Seconds" -sc
}
$XMLOutput += Set-PrtgResult -Channel 'Time Accuracy'        -Value ((get-date).ToUniversalTime() - [datetime]($Status.Statistics.'Date (mm/dd/yyyy)' + ' ' + $Status.Statistics.'Time (hh:mm:ss)')).TotalSeconds  -Unit "Seconds" -sc
$XMLOutput += Set-PrtgResult -Channel 'Internal Temperature' -Value (([int]$Status.Statistics.'UPS Internal Temperature (Degrees C)')*9/5 + 32) -Unit "F" -sc






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

# SIG # Begin signature block
# MIIXuwYJKoZIhvcNAQcCoIIXrDCCF6gCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUpmMMYx/bPGkWVgKeOW0mMZWR
# 2PKgghKzMIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
# AQUFADCBizELMAkGA1UEBhMCWkExFTATBgNVBAgTDFdlc3Rlcm4gQ2FwZTEUMBIG
# A1UEBxMLRHVyYmFudmlsbGUxDzANBgNVBAoTBlRoYXd0ZTEdMBsGA1UECxMUVGhh
# d3RlIENlcnRpZmljYXRpb24xHzAdBgNVBAMTFlRoYXd0ZSBUaW1lc3RhbXBpbmcg
# Q0EwHhcNMTIxMjIxMDAwMDAwWhcNMjAxMjMwMjM1OTU5WjBeMQswCQYDVQQGEwJV
# UzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFu
# dGVjIFRpbWUgU3RhbXBpbmcgU2VydmljZXMgQ0EgLSBHMjCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBALGss0lUS5ccEgrYJXmRIlcqb9y4JsRDc2vCvy5Q
# WvsUwnaOQwElQ7Sh4kX06Ld7w3TMIte0lAAC903tv7S3RCRrzV9FO9FEzkMScxeC
# i2m0K8uZHqxyGyZNcR+xMd37UWECU6aq9UksBXhFpS+JzueZ5/6M4lc/PcaS3Er4
# ezPkeQr78HWIQZz/xQNRmarXbJ+TaYdlKYOFwmAUxMjJOxTawIHwHw103pIiq8r3
# +3R8J+b3Sht/p8OeLa6K6qbmqicWfWH3mHERvOJQoUvlXfrlDqcsn6plINPYlujI
# fKVOSET/GeJEB5IL12iEgF1qeGRFzWBGflTBE3zFefHJwXECAwEAAaOB+jCB9zAd
# BgNVHQ4EFgQUX5r1blzMzHSa1N197z/b7EyALt0wMgYIKwYBBQUHAQEEJjAkMCIG
# CCsGAQUFBzABhhZodHRwOi8vb2NzcC50aGF3dGUuY29tMBIGA1UdEwEB/wQIMAYB
# Af8CAQAwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC50aGF3dGUuY29tL1Ro
# YXd0ZVRpbWVzdGFtcGluZ0NBLmNybDATBgNVHSUEDDAKBggrBgEFBQcDCDAOBgNV
# HQ8BAf8EBAMCAQYwKAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFtcC0y
# MDQ4LTEwDQYJKoZIhvcNAQEFBQADgYEAAwmbj3nvf1kwqu9otfrjCR27T4IGXTdf
# plKfFo3qHJIJRG71betYfDDo+WmNI3MLEm9Hqa45EfgqsZuwGsOO61mWAK3ODE2y
# 0DGmCFwqevzieh1XTKhlGOl5QGIllm7HxzdqgyEIjkHq3dlXPx13SYcqFgZepjhq
# IhKjURmDfrYwggSjMIIDi6ADAgECAhAOz/Q4yP6/NW4E2GqYGxpQMA0GCSqGSIb3
# DQEBBQUAMF4xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3Jh
# dGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGltZSBTdGFtcGluZyBTZXJ2aWNlcyBD
# QSAtIEcyMB4XDTEyMTAxODAwMDAwMFoXDTIwMTIyOTIzNTk1OVowYjELMAkGA1UE
# BhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTQwMgYDVQQDEytT
# eW1hbnRlYyBUaW1lIFN0YW1waW5nIFNlcnZpY2VzIFNpZ25lciAtIEc0MIIBIjAN
# BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAomMLOUS4uyOnREm7Dv+h8GEKU5Ow
# mNutLA9KxW7/hjxTVQ8VzgQ/K/2plpbZvmF5C1vJTIZ25eBDSyKV7sIrQ8Gf2Gi0
# jkBP7oU4uRHFI/JkWPAVMm9OV6GuiKQC1yoezUvh3WPVF4kyW7BemVqonShQDhfu
# ltthO0VRHc8SVguSR/yrrvZmPUescHLnkudfzRC5xINklBm9JYDh6NIipdC6Anqh
# d5NbZcPuF3S8QYYq3AhMjJKMkS2ed0QfaNaodHfbDlsyi1aLM73ZY8hJnTrFxeoz
# C9Lxoxv0i77Zs1eLO94Ep3oisiSuLsdwxb5OgyYI+wu9qU+ZCOEQKHKqzQIDAQAB
# o4IBVzCCAVMwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAO
# BgNVHQ8BAf8EBAMCB4AwcwYIKwYBBQUHAQEEZzBlMCoGCCsGAQUFBzABhh5odHRw
# Oi8vdHMtb2NzcC53cy5zeW1hbnRlYy5jb20wNwYIKwYBBQUHMAKGK2h0dHA6Ly90
# cy1haWEud3Muc3ltYW50ZWMuY29tL3Rzcy1jYS1nMi5jZXIwPAYDVR0fBDUwMzAx
# oC+gLYYraHR0cDovL3RzLWNybC53cy5zeW1hbnRlYy5jb20vdHNzLWNhLWcyLmNy
# bDAoBgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtMjAdBgNV
# HQ4EFgQURsZpow5KFB7VTNpSYxc/Xja8DeYwHwYDVR0jBBgwFoAUX5r1blzMzHSa
# 1N197z/b7EyALt0wDQYJKoZIhvcNAQEFBQADggEBAHg7tJEqAEzwj2IwN3ijhCcH
# bxiy3iXcoNSUA6qGTiWfmkADHN3O43nLIWgG2rYytG2/9CwmYzPkSWRtDebDZw73
# BaQ1bHyJFsbpst+y6d0gxnEPzZV03LZc3r03H0N45ni1zSgEIKOq8UvEiCmRDoDR
# EfzdXHZuT14ORUZBbg2w6jiasTraCXEQ/Bx5tIB7rGn0/Zy2DBYr8X9bCT2bW+IW
# yhOBbQAuOA2oKY8s4bL0WqkBrxWcLC9JG9siu8P+eJRRw4axgohd8D20UaF5Mysu
# e7ncIAkTcetqGVvP6KUwVyyJST+5z3/Jvz4iaGNTmr1pdKzFHTx/kuDDvBzYBHUw
# ggTQMIIDuKADAgECAgEHMA0GCSqGSIb3DQEBCwUAMIGDMQswCQYDVQQGEwJVUzEQ
# MA4GA1UECBMHQXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTEaMBgGA1UEChMR
# R29EYWRkeS5jb20sIEluYy4xMTAvBgNVBAMTKEdvIERhZGR5IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IC0gRzIwHhcNMTEwNTAzMDcwMDAwWhcNMzEwNTAzMDcw
# MDAwWjCBtDELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcT
# ClNjb3R0c2RhbGUxGjAYBgNVBAoTEUdvRGFkZHkuY29tLCBJbmMuMS0wKwYDVQQL
# EyRodHRwOi8vY2VydHMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeS8xMzAxBgNVBAMT
# KkdvIERhZGR5IFNlY3VyZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgLSBHMjCCASIw
# DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALngyxDUr3a91JNi6zBkuIEIbMME
# 2WIXji//PmXPj85i5jxSHNoWRUtVq3hrY4NikM4PaWyZyBoUi0zMRTPqiNyeo68r
# /oBhnXlXxM8u9D8wPF1H/JoWvMM3lkFRjhFLVPgovtCMvvAwOB7zsCb4Zkdjbd5x
# JkePOEdT0UYdtOPcAOpFrL28cdmqbwDb280wOnlPX0xH+B3vW8LEnWA7sbJDkdik
# M07qs9YnT60liqXG9NXQpq50BWRXiLVEVdQtKjo++Li96TIKApRkxBY6UPFKrud5
# M68MIAd/6N8EOcJpAmxjUvp3wRvIdIfIuZMYUFQ1S2lOvDvTSS4f3MHSUvsCAwEA
# AaOCARowggEWMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1Ud
# DgQWBBRAwr0njsw0gzCiM9f7bLPwtCyAzjAfBgNVHSMEGDAWgBQ6moUHEGcotu/2
# vQVBbiDBlNoP3jA0BggrBgEFBQcBAQQoMCYwJAYIKwYBBQUHMAGGGGh0dHA6Ly9v
# Y3NwLmdvZGFkZHkuY29tLzA1BgNVHR8ELjAsMCqgKKAmhiRodHRwOi8vY3JsLmdv
# ZGFkZHkuY29tL2dkcm9vdC1nMi5jcmwwRgYDVR0gBD8wPTA7BgRVHSAAMDMwMQYI
# KwYBBQUHAgEWJWh0dHBzOi8vY2VydHMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeS8w
# DQYJKoZIhvcNAQELBQADggEBAAh+bJMQyDi4lqmQS/+hX08E72w+nIgGyVCPpnP3
# VzEbvrzkL9v4utNb4LTn5nliDgyi12pjczG19ahIpDsILaJdkNe0fCVPEVYwxLZE
# nXssneVe5u8MYaq/5Cob7oSeuIN9wUPORKcTcA2RH/TIE62DYNnYcqhzJB61rCIO
# yheJYlhEG6uJJQEAD83EG2LbUbTTD1Eqm/S8c/x2zjakzdnYLOqum/UqspDRTXUY
# ij+KQZAjfVtL/qQDWJtGssNgYIP4fVBBzsKhkMO77wIv0hVU7kQV2Qqup4oz7bEt
# djYm3ATrn/dhHxXch2/uRpYoraEmfQoJpy4Eo428+LwEMAEwggVCMIIEKqADAgEC
# AggFH/2DzeEySTANBgkqhkiG9w0BAQsFADCBtDELMAkGA1UEBhMCVVMxEDAOBgNV
# BAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAYBgNVBAoTEUdvRGFk
# ZHkuY29tLCBJbmMuMS0wKwYDVQQLEyRodHRwOi8vY2VydHMuZ29kYWRkeS5jb20v
# cmVwb3NpdG9yeS8xMzAxBgNVBAMTKkdvIERhZGR5IFNlY3VyZSBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgLSBHMjAeFw0xNzAxMTAxNDM4MDBaFw0yMDAyMTEyMDI3MjJa
# MIGDMQswCQYDVQQGEwJVUzEQMA4GA1UECBMHRmxvcmlkYTEUMBIGA1UEBxMLVGFs
# bGFoYXNzZWUxJTAjBgNVBAoTHEVWRU5UIFBIT1RPR1JBUEhZIEdST1VQLCBJTkMx
# JTAjBgNVBAMTHEVWRU5UIFBIT1RPR1JBUEhZIEdST1VQLCBJTkMwggEiMA0GCSqG
# SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDOOPPNzkLxi9hXM7BbsldN3OWUtE9XSPdR
# mRvhEc+ICwW4eFvWEhXSkuVlTBkrCoMDsD2YnuOTesmMNw7qHK/6OU65ZL2hSggJ
# mhnxtFY1BPfItzPurzaCNaYIZYUaZlhI3f8+07/9TiKEsb9cezolAlWD59pZuKCb
# RiNuUlXeqbDhbIotqdhu1UEWSUddcJ2HgIOM3qDfzKIECmPw23Bxa+X9tMbLOpt2
# jZ8xCnEvF7FT0BcmdVJOVQcYGr1HAE3jeI2JqOpxSfciC0q7xAM9mhvNlPApvgzb
# P1VXxpCuu97HljDHzZp5syzcs5Ry9NSJfywSX8bRGBKvAoEDxODpAgMBAAGjggGF
# MIIBgTAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA4GA1UdDwEB
# /wQEAwIHgDA1BgNVHR8ELjAsMCqgKKAmhiRodHRwOi8vY3JsLmdvZGFkZHkuY29t
# L2dkaWcyczUtMi5jcmwwXQYDVR0gBFYwVDBIBgtghkgBhv1tAQcXAjA5MDcGCCsG
# AQUFBwIBFitodHRwOi8vY2VydGlmaWNhdGVzLmdvZGFkZHkuY29tL3JlcG9zaXRv
# cnkvMAgGBmeBDAEEATB2BggrBgEFBQcBAQRqMGgwJAYIKwYBBQUHMAGGGGh0dHA6
# Ly9vY3NwLmdvZGFkZHkuY29tLzBABggrBgEFBQcwAoY0aHR0cDovL2NlcnRpZmlj
# YXRlcy5nb2RhZGR5LmNvbS9yZXBvc2l0b3J5L2dkaWcyLmNydDAfBgNVHSMEGDAW
# gBRAwr0njsw0gzCiM9f7bLPwtCyAzjAdBgNVHQ4EFgQU97SPwQlA65NWm/9nnrsb
# tZ2zvXIwDQYJKoZIhvcNAQELBQADggEBAJ36ckoxUB2DxpdK+3JJIrBqhRpaPVi6
# sNgKUdudmqAu/pi1jfTgyk/cLEoG1Xsc++LvngVhouczWxHH7QetxXE/zo4xVYuJ
# SYEw5ydgJnEADAdaWVq7itID5TGsHgT1BkxYc64rrfXPfRjaNxxEgSK+MLTn1I0a
# 9brYIprSss/KixPVi1vcU4O4u8poTwc6wpARuWE470d2kjfxip0asG5nqfCkPo9i
# ltvKR411GEUP1wNijiirCQUl+YyD3iFmJGYY7qw2/kNoVif0wQqgjxS3Rn647jFy
# ikLMLE/vynzd7gfzwAbOcNZAXsuD8wXf+gAThc/lm4c+o2/QLq94WMkxggRyMIIE
# bgIBATCBwTCBtDELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNV
# BAcTClNjb3R0c2RhbGUxGjAYBgNVBAoTEUdvRGFkZHkuY29tLCBJbmMuMS0wKwYD
# VQQLEyRodHRwOi8vY2VydHMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeS8xMzAxBgNV
# BAMTKkdvIERhZGR5IFNlY3VyZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgLSBHMgII
# BR/9g83hMkkwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAw
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFA25oqKWJE3lKkXCF5mZFc2D3P8HMA0G
# CSqGSIb3DQEBAQUABIIBAIQclEsctea+AbtOHM1IfHkvZstOlgprk2+xKjceDkip
# tF75EPW5XhTiZ8xyVrM87a0p3fPKJt+4m51LxKOUMsfi/6V+WEcYWMFw9FqjN5ym
# T8OR0m7TJC232lCe9s9lrxaeUwTsbjvMpFNlpkVkhkhTH1MsuuSGi9MykE0Y/lQ2
# 1IqpqE6+yWQ0gDlA/IiZTrheFshUr1WXzGpnf+8y3Ni9e/C8vbVeWg4mmzL432xS
# a/mAiy8hbl8BntdNF7pTvvtpybNBEHNiHePiN4BJAzEcKn5S9ITivYIj96r474UW
# 1PL1npXWeF0r1otO94pzLOapmrLpAzq2viownaj40s+hggILMIICBwYJKoZIhvcN
# AQkGMYIB+DCCAfQCAQEwcjBeMQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50
# ZWMgQ29ycG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFudGVjIFRpbWUgU3RhbXBpbmcg
# U2VydmljZXMgQ0EgLSBHMgIQDs/0OMj+vzVuBNhqmBsaUDAJBgUrDgMCGgUAoF0w
# GAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTkxMjAy
# MjE1OTM0WjAjBgkqhkiG9w0BCQQxFgQU6XeKme8WPEhJWI/iAy1ol2WsQQMwDQYJ
# KoZIhvcNAQEBBQAEggEAgekg0loYwcWXiBpH5HlZsqNrjZgDScDOgILMOfoKwcFt
# 1RXgY4OVEubf1ZtJiIn4PGqRFgO8UIoZHawbrjgQG9FqCeZ89ex9aFXsLV8KiwwT
# rcOd1d2byGaaWb0Jrp4ciDwVi1T3HaizalE425D3VlvCgzCDxXkKEqTW7KrqiX+b
# FmT+34nDYu4UXz7W8R2eZN1nJnMzwXC2zuJ47RvzH1G+u98gOBIy3jm7tE5P7Yph
# H7kesk5qm8sJihsNmQb+O5hVHbUBCiOmBrmK6PTfBt0slr+WlrjxcAvr8P+QxzwE
# hBk+Eq/uBU5KVbiC1sgn/jgs/BSyoljIdAdsL4rdeA==
# SIG # End signature block
