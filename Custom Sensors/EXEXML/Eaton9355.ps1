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

if ($Status.'Current Status'.'Last Battery Test Status' -match '\d+\/\d+\/\d+ \d+:\d+:\d+ - (.*)') {
    if ($BatteryTestStatus[$Matches[1]]) {
        $Status.'Current Status'.'Last Battery Test Status' = $BatteryTestStatus[$Matches[1]]
    } else {
        $Text += "Last Battery Test Status = '$($Matches[1])'"
        $Status.'Current Status'.'Last Battery Test Status' = 1
    }
} else {
    $Text += "Last Battery Test Status = '$($Status.'Current Status'.'Last Battery Test Status')'"
    $Status.'Current Status'.'Last Battery Test Status' = 1
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

# SIG # Begin signature block
# MIIM/gYJKoZIhvcNAQcCoIIM7zCCDOsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU0Swo4qzzBRvIY9Q+RP+3vHnx
# 7+ygggoFMIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UE
# BhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAY
# BgNVBAoTEUdvRGFkZHkuY29tLCBJbmMuMTEwLwYDVQQDEyhHbyBEYWRkeSBSb290
# IENlcnRpZmljYXRlIEF1dGhvcml0eSAtIEcyMB4XDTExMDUwMzA3MDAwMFoXDTMx
# MDUwMzA3MDAwMFowgbQxCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMw
# EQYDVQQHEwpTY290dHNkYWxlMRowGAYDVQQKExFHb0RhZGR5LmNvbSwgSW5jLjEt
# MCsGA1UECxMkaHR0cDovL2NlcnRzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMTMw
# MQYDVQQDEypHbyBEYWRkeSBTZWN1cmUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0g
# RzIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC54MsQ1K92vdSTYusw
# ZLiBCGzDBNliF44v/z5lz4/OYuY8UhzaFkVLVat4a2ODYpDOD2lsmcgaFItMzEUz
# 6ojcnqOvK/6AYZ15V8TPLvQ/MDxdR/yaFrzDN5ZBUY4RS1T4KL7QjL7wMDge87Am
# +GZHY23ecSZHjzhHU9FGHbTj3ADqRay9vHHZqm8A29vNMDp5T19MR/gd71vCxJ1g
# O7GyQ5HYpDNO6rPWJ0+tJYqlxvTV0KaudAVkV4i1RFXULSo6Pvi4vekyCgKUZMQW
# OlDxSq7neTOvDCAHf+jfBDnCaQJsY1L6d8EbyHSHyLmTGFBUNUtpTrw700kuH9zB
# 0lL7AgMBAAGjggEaMIIBFjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIB
# BjAdBgNVHQ4EFgQUQMK9J47MNIMwojPX+2yz8LQsgM4wHwYDVR0jBBgwFoAUOpqF
# BxBnKLbv9r0FQW4gwZTaD94wNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5nb2RhZGR5LmNvbS8wNQYDVR0fBC4wLDAqoCigJoYkaHR0cDov
# L2NybC5nb2RhZGR5LmNvbS9nZHJvb3QtZzIuY3JsMEYGA1UdIAQ/MD0wOwYEVR0g
# ADAzMDEGCCsGAQUFBwIBFiVodHRwczovL2NlcnRzLmdvZGFkZHkuY29tL3JlcG9z
# aXRvcnkvMA0GCSqGSIb3DQEBCwUAA4IBAQAIfmyTEMg4uJapkEv/oV9PBO9sPpyI
# BslQj6Zz91cxG7685C/b+LrTW+C05+Z5Yg4MotdqY3MxtfWoSKQ7CC2iXZDXtHwl
# TxFWMMS2RJ17LJ3lXubvDGGqv+QqG+6EnriDfcFDzkSnE3ANkR/0yBOtg2DZ2HKo
# cyQetawiDsoXiWJYRBuriSUBAA/NxBti21G00w9RKpv0vHP8ds42pM3Z2Czqrpv1
# KrKQ0U11GIo/ikGQI31bS/6kA1ibRrLDYGCD+H1QQc7CoZDDu+8CL9IVVO5EFdkK
# rqeKM+2xLXY2JtwE65/3YR8V3Idv7kaWKK2hJn0KCacuBKONvPi8BDABMIIFLTCC
# BBWgAwIBAgIICFNsLoGX5IQwDQYJKoZIhvcNAQELBQAwgbQxCzAJBgNVBAYTAlVT
# MRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMRowGAYDVQQK
# ExFHb0RhZGR5LmNvbSwgSW5jLjEtMCsGA1UECxMkaHR0cDovL2NlcnRzLmdvZGFk
# ZHkuY29tL3JlcG9zaXRvcnkvMTMwMQYDVQQDEypHbyBEYWRkeSBTZWN1cmUgQ2Vy
# dGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIwHhcNMjAwMjE4MjExMjUyWhcNMjMwMjE4
# MjExMjUyWjBvMQswCQYDVQQGEwJVUzEQMA4GA1UECBMHRmxvcmlkYTEUMBIGA1UE
# BxMLVGFsbGFoYXNzZWUxGzAZBgNVBAoTEklDT05JQyBHUk9VUCwgSU5DLjEbMBkG
# A1UEAxMSSUNPTklDIEdST1VQLCBJTkMuMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
# MIIBCgKCAQEAzjjzzc5C8YvYVzOwW7JXTdzllLRPV0j3UZkb4RHPiAsFuHhb1hIV
# 0pLlZUwZKwqDA7A9mJ7jk3rJjDcO6hyv+jlOuWS9oUoICZoZ8bRWNQT3yLcz7q82
# gjWmCGWFGmZYSN3/PtO//U4ihLG/XHs6JQJVg+faWbigm0YjblJV3qmw4WyKLanY
# btVBFklHXXCdh4CDjN6g38yiBApj8NtwcWvl/bTGyzqbdo2fMQpxLxexU9AXJnVS
# TlUHGBq9RwBN43iNiajqcUn3IgtKu8QDPZobzZTwKb4M2z9VV8aQrrvex5Ywx82a
# ebMs3LOUcvTUiX8sEl/G0RgSrwKBA8Tg6QIDAQABo4IBhTCCAYEwDAYDVR0TAQH/
# BAIwADATBgNVHSUEDDAKBggrBgEFBQcDAzAOBgNVHQ8BAf8EBAMCB4AwNQYDVR0f
# BC4wLDAqoCigJoYkaHR0cDovL2NybC5nb2RhZGR5LmNvbS9nZGlnMnM1LTUuY3Js
# MF0GA1UdIARWMFQwSAYLYIZIAYb9bQEHFwIwOTA3BggrBgEFBQcCARYraHR0cDov
# L2NlcnRpZmljYXRlcy5nb2RhZGR5LmNvbS9yZXBvc2l0b3J5LzAIBgZngQwBBAEw
# dgYIKwYBBQUHAQEEajBoMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5nb2RhZGR5
# LmNvbS8wQAYIKwYBBQUHMAKGNGh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5j
# b20vcmVwb3NpdG9yeS9nZGlnMi5jcnQwHwYDVR0jBBgwFoAUQMK9J47MNIMwojPX
# +2yz8LQsgM4wHQYDVR0OBBYEFPe0j8EJQOuTVpv/Z567G7Wds71yMA0GCSqGSIb3
# DQEBCwUAA4IBAQCrubpxo95D5MNNN0668ADnsLam4A/WyzCHHtRL8dzU5TM1iw+F
# PwcIdWcnWyJWYNwgeCGfquhiYyzwA6BErKHLd0vke8NN2djwX48/pNUOmhT1ke5K
# PfX+xsBlD3MPfC6b1kBLhNr/IliXlrGOxO6pp/DknEoxNDsAWOU0A209hO/MKANe
# INFhyz63LvMAKzu8p1we2qC1rwkdzYSygxE0iCbko5wOvvfCXjE1osKzzE3KSuq9
# +BMfthKjLGlEd6rFShaipBH/PCCXF0NeP4DHTC4+IzfSqpeUXpZA+pRMfdDRgBUS
# TwPEOWBGRc1p0UmsnVEl9O6ykKDQEqEOtzMcMYICYzCCAl8CAQEwgcEwgbQxCzAJ
# BgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxl
# MRowGAYDVQQKExFHb0RhZGR5LmNvbSwgSW5jLjEtMCsGA1UECxMkaHR0cDovL2Nl
# cnRzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMTMwMQYDVQQDEypHbyBEYWRkeSBT
# ZWN1cmUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0gRzICCAhTbC6Bl+SEMAkGBSsO
# AwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEM
# BgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqG
# SIb3DQEJBDEWBBQH4Y6bJ6ONfMd8ErbSWlXFV+crqDANBgkqhkiG9w0BAQEFAASC
# AQBdjyGDTf8G4DPsAXprYPfSMfCXUch6oGl/DRgzpSx3fq+YVEN13i2wyM2+C279
# lIRy2Mob9kT/eN4K1u6vsEEofK84+I2t2pO8CYxStLNeBiOixhd70pKDEFdPD3ts
# LWoSj8L6jFD31TdBFXw/L6Xmn+zhWgHR6GDhcxOgdBWNjT8TBAGVy7lbh7GNByRe
# akPN9fu57NKYTTUxg8nWXDdS1z+smkDgVmmRzeSGsE3l9a2EwEita9GfIgvdt+Gr
# 4U/vDLxDrRbeKl2srntxXBtcP9DNYJyCijfFPQ0LOamM5LheBVSkJgH8BAN554QF
# 901f1z6Dg46Ear5Rf+o+Gse7
# SIG # End signature block
