
[CmdletBinding()]
PARAM(
    [String]
    $CName = "$env:prtg_windowsdomain"
    ,
    [String]
    $User  = "$env:prtg_windowsuser"
    ,
    [String]
    $PWD   = "$env:prtg_windowspassword"
    ,
    [Int]
    $mid
)

$ExecutionTime = [System.Diagnostics.Stopwatch]::StartNew()

Function Import-ModuleList {
    PARAM(
        [String[]]$Name,
        [String]$Repository,
        [String]$InstallationPolicy = "Trusted"
    )
    if (-not (get-PSRepository | Where-Object {$_.Name -eq $Repository})){
        Throw " NuGet Repository '$Repository' Missing"
    }
    Foreach ($Module in $Name) {
        Try {
            Import-Module $Module -ErrorAction Stop
        } catch {
            Write-Verbose "Installing $($Module)" -Verbose
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop
            install-Module -Name $Module -Repository $Repository -Scope AllUsers -Force -ErrorAction Stop
            Try {
                Import-Module $Module -ErrorAction Stop
            } catch {
                $PSCmdlet.ThrowTerminatingError($PSItem)
            }
        }
    }
}
Function Get-StringHash {
    PARAM(
        [String]
        $String
        ,
        [String]
        $HashName = "SHA512"
    )
    $StringBuilder = New-Object System.Text.StringBuilder
    [System.Security.Cryptography.HashAlgorithm]::Create($HashName).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String)) | ForEach-Object{
        [Void]$StringBuilder.Append($_.ToString("x2"))
    }
    $StringBuilder.ToString()
}
Function ConvertTo-LocalTime {
    Param(
        [Parameter(Position = 0, Mandatory, HelpMessage = "Specify the date and time from the other time zone. ")]
        [ValidateNotNullorEmpty()]
        [alias("dt")]
        [string]$Time
        ,
        [Parameter(Position = 1, HelpMessage = "Select the corresponding time zone.")]
        [alias("tz")]
        [System.TimeZoneInfo]$TimeZone = (Get-TimeZone -ID UTC)
    )
    #parsing date from a string to accommodate cultural variations
    $ParsedDateTime = Get-Date $time
    $datetime = "{0:f}" -f $parsedDateTime

    Write-Verbose "Converting $datetime [$($TimeZone.id) $($TimeZone.BaseUTCOffSet) UTC] to local time."

    $ParsedDateTime.AddHours(-($TimeZone.BaseUtcOffset.totalhours)).ToLocalTime()
}

$StatusDictionaryRG = @{
    'green' = 1
    'red'   = 2
}
$StatusDictionaryYN = @{
    'No'    = 1
    'Yes'   = 2
}
$StatusDictionaryNY = @{
    'No'    = 2
    'Yes'   = 1
}


if (test-path("$(split-path $SCRIPT:MyInvocation.MyCommand.Path)\prtgshell.psm1")) {
    Import-Module "$(split-path $SCRIPT:MyInvocation.MyCommand.Path)\prtgshell.psm1" -DisableNameChecking -Verbose:$False
} else {
    Write-output "<prtg>"
    Write-output "  <error>1</error>"
    Write-output "  <text>Unable to locate prtgshell.psm1</text>"
    Write-output "</prtg>"
    exit
}

if ("" -eq $CName) {
    Set-PrtgError "-CName is a required Parameter"
}
if ("" -eq $User) {
    Set-PrtgError "-User is a required Parameter"
}
if ("" -eq $PWD) {
    Set-PrtgError "-PWD is a required Parameter"
}
if ("" -eq $mid) {
    Set-PrtgError "-mid is a required Parameter"
}

Try {
    # Import-Module DellPEWSManTools -ErrorAction Stop -Verbose:$false
    Import-ModuleList -Name "PowerHTML" -Repository "PSGallery"
} catch {
    Set-PrtgError $_.exception.Message
}

if (test-Path -Path "$env:temp\OmnimetrixSession.dat") {
    $Return = Import-Clixml $env:temp\OmnimetrixSession.dat
    $Headers = $Return.Headers
    $session = New-Object -TypeName Microsoft.PowerShell.Commands.WebRequestSession
    $Return.cookies | Foreach-Object {
        $cookie = New-Object System.Net.Cookie
        $cookie.Name   = $_.Name
        $cookie.Path   = $_.Path
        $cookie.Value  = $_.Value
        $cookie.Domain = $_.Domain
        $session.Cookies.Add($cookie)
    }
    $LoginTime = 0
}

if ($session) {
    # Get Unit Page
    $url = "https://webdata.omnimetrix.net/omxphp/refreshSingleUnit.php?&mid=$mid"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $DataPoints = Invoke-RestMethod -Uri $url -WebSession $session
    Write-Verbose "Data Page Load Time $($Stopwatch.Elapsed)"
    If ($DataPoints.company_id) {
        Write-Verbose "Company ID : $($DataPoints.company_id)"
    } else {
        Remove-Variable session
    }
    $DataPoints | Format-List | Out-String | Write-Verbose
}

if (-not $session) {
    # Create Web Session
    $url = 'https://webdata.omnimetrix.net/omxphp/omxLogin_APIRoute.php?Action=Logon'
    $Fields = @{
        'CName' = $CName
        'User'  = $User
        'PWD'   = Get-StringHash -String $PWD
    }
    Try {
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $WebRequest = Invoke-WebRequest -Uri $url -SessionVariable session -Body $Fields -UseBasicParsing
        $LoginTime = [int]$Stopwatch.Elapsed.TotalMilliseconds
        Write-Verbose "Login Page Load Time $LoginTime"
    } Catch {
        Set-PrtgError "Login Page: $($_.exception.message)"
    }
    if ($WebRequest.StatusCode -ne 200) {
        Set-PrtgError "Login Page Returned Code: $($WebRequest.StatusCode)"
    }
    if ($WebRequest.Links.href -contains 'forgot_pass.php') {
        Set-PrtgError "Login Failed"
    }

    # Parse Data From Unit Page
    $HTML = $WebRequest.Content | ConvertFrom-Html
    $Table = $HTML.SelectNodes("//table") | Where-Object {$_.id -eq 'machinelist'}
    $Headers = $Table.SelectNodes("thead").SelectNodes("tr").SelectNodes("th|td") | Foreach-Object {"$($_.InnerText.trim().Split("`n")[0])"}
    Write-Verbose "Headers `n$($Headers | Format-Table | Out-String)"
    $Headers = $Headers | Select-Object -Skip ([array]::indexof($Headers,'Supply Voltage'))

    # Get Unit Page
    $url = "https://webdata.omnimetrix.net/omxphp/refreshSingleUnit.php?&mid=$mid"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $DataPoints = Invoke-RestMethod -Uri $url -WebSession $session
    Write-Verbose "Data Page Load Time $($Stopwatch.Elapsed)"
    If ($DataPoints.company_id) {
        Write-Verbose "Company ID : $($DataPoints.company_id)"
    } else {
        Set-PrtgError "Company ID : 'Not Found' - Verify MID is correct"
    }
    $DataPoints | Format-List | Out-String | Write-Verbose
    @{
        Headers = $Headers
        Cookies = $session.cookies.GetCookies("https:\\$(([uri]$url).host)")
    } | Export-Clixml $env:temp\OmnimetrixSession.dat
}

Write-Verbose "Headers`n$($Headers | Format-Table | Out-String)"

# Get DateTime of Last event
$url = "https://webdata.omnimetrix.net/omxphp/omxMachineData.php?MID=$mid&ViewDate=10"
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$WebRequest2 = Invoke-WebRequest -Uri $url -WebSession $session -UseBasicParsing
Write-Verbose "Event Page Load Time $($Stopwatch.Elapsed)"

$HTML2 = $WebRequest2.Content | ConvertFrom-Html
$Table2 = $HTML2.SelectNodes("//table")[1]

$objTable = @()
$Headers2 = $Table2.SelectNodes("tr") | Select-Object -First 1 | ForEach-Object {$_.SelectNodes("th|td").InnerText.trim()}
$Table2.SelectNodes("tr") | Select-Object -Skip 1 | ForEach-Object {
    $Node = $_.SelectNodes("th|td").InnerText
    if ($Node.Count -ne $Headers2.Count) {
        Write-Warning "Error parsing tr`n    $($test.InnerHtml)"
    }
    $Row = @{}
    for ($i = 0; $i -lt $Node.Count; $i++) {
        $Row[$Headers2[$i]] = $Node[$i]
    }
    $Row['Date'    ] = (ConvertTo-LocalTime -Time $Row['Date'])
    $Row['Type'    ] = [Int]$Row['Type'    ]
    $Row['Count'   ] = [Int]$Row['Count'   ]
    $Row['Sequence'] = [Int]$Row['Sequence']
    $Row['Data'    ] = @($Row['Data'].Split(':') | Where-Object {$_})

    $objTable += [PSCustomObject]$Row
}
$objTable = $objTable | Where-Object {$_.Type -eq 1} | Select-Object -first 1

# Try {
#     $LastEventDateTime = Get-Date (get-itemPropertyValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Paessler\PRTG Network Monitor' -Name OmniMetrixLastEvent -ErrorAction Stop)
# } catch {
#     $LastEventDateTime = (Get-Date).AddDays(-1)
# }


# Correct Names of extra Parameters
$Return = [ordered]@{}
$Return['DateTime'] = $objTable.Date
# Get Normal Names
$DataPoints.PSObject.Properties.name | Where-Object {$_ -notmatch 'Param(\d+)'} | ForEach-Object {$Return[$_] = $DataPoints.$_}
# Get Generic names Params
$DataPoints.PSObject.Properties.name | Where-Object {$_ -match 'Param(\d+)'} | ForEach-Object {$Return[$Headers[$Matches[1]]] = $DataPoints.$_}


# Clear HTML in Data
$Return.keys.Clone() | Foreach-Object {
    $key = $_
    if ($Return[$key] -match '^<\S+>(.+)<\/\S+>$') {
        $Return[$key] = $Matches[1]
    } elseif ($Return[$key] -match "^<a.*src='?\S+\/([^ ']+)'? .*$") {
        $Return[$key] = $Matches[1]
        switch ($Return[$key]) {
            'green-check-small.png' { $Return[$key] = 'green' }
            'red-x-small.png'       { $Return[$key] = 'red' }
            # Default {}
        }
    } elseif ($Return[$key] -eq '--') {
        $Return[$key] = 0
    }
}

# $Return.test = $Return.age_in_minutes
# if ($Return.age_in_minutes -eq '') {
#     $Return.age_in_minutes = 0
# } elseif ($Return.age_in_minutes -match '^(\d+) hours? (\d+) minutes? ago$') {
#     $Return.age_in_minutes = ([timespan]"$($Matches[1]):$($Matches[2])").TotalMinutes
# } elseif ($Return.age_in_minutes -match '^(\d+) minutes? ago$') {
#     $Return.age_in_minutes = ([timespan]"0:$($Matches[1])").TotalMinutes
# } elseif ($Return.age_in_minutes -match '^(\d+) hours? ago$') {
#     $Return.age_in_minutes = ([timespan]"$($Matches[1]):00").TotalMinutes
# }
$Return.age_in_minutes = [int]((Get-Date)-$objTable.Date).TotalMinutes

$Return.Remove('company_id')
$Return.Remove('Engine Hours')
$Return.Remove('messaging_enabled')
$Return.Remove('service_mode')

# $Return['DateTime'] = $Return['DateTime'].addMinutes(-1 * $Return['age_in_minutes'])
[PSCustomObject]$Return | Out-String | Write-Verbose

# if ($Return['DateTime'] -le $LastEventDateTime) {
#     Write-Verbose "No New event"
#     $XMLOutput  = "<prtg>`n"
#     $XMLOutput += Set-PrtgResult -Channel "Last Checkin"    -Value $Return."age_in_minutes"  -Unit "Min"      -sc
#     $XMLOutput += "  <text>Unit $($Return.machine_description)</text>`n"
#     $XMLOutput += "</prtg>"
#     Write-Host $XMLOutput
# } else {
#     Write-Verbose "New event"
    # $null = new-itemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Paessler\PRTG Network Monitor' -Name OmniMetrixLastEvent -PropertyType String -Value (Get-Date) -Force

    $XMLOutput  = "<prtg>`n"
    $XMLOutput += Set-PrtgResult -Channel "Status"          -Value $StatusDictionaryRG[$Return.Status]             -Unit "Status"  -sc -ValueLookup "OmniMetrix.yesno.stateyeswarn"
    $XMLOutput += Set-PrtgResult -Channel "Faulted"         -Value $StatusDictionaryRG[$Return.machine_faulted]    -Unit "Status"  -sc -ValueLookup "prtg.standardlookups.yesno.statenook"
    $XMLOutput += Set-PrtgResult -Channel "Alarms"          -Value $Return.persisted_alarm                         -Unit "Count"   -sc -MaxError 0
    $XMLOutput += Set-PrtgResult -Channel "Running"         -Value $StatusDictionaryYN[$Return.Running]            -Unit "Status"  -sc -ValueLookup "OmniMetrix.yesno.stateyeswarn"
    $XMLOutput += Set-PrtgResult -Channel "On Utility"      -Value $StatusDictionaryYN[$Return.NotOnUtility]       -Unit "Status"  -sc -ValueLookup "prtg.standardlookups.yesno.stateyesok"
    $XMLOutput += Set-PrtgResult -Channel "On Generator"    -Value $StatusDictionaryYN[$Return.OnGenerator]        -Unit "Status"  -sc -ValueLookup "prtg.standardlookups.yesno.statenook"
    $XMLOutput += Set-PrtgResult -Channel "In Auto"         -Value $StatusDictionaryYN[$Return.NotInAuto]          -Unit "Status"  -sc -ValueLookup "prtg.standardlookups.yesno.stateyesok"
    $XMLOutput += Set-PrtgResult -Channel "Engine Run Time" -Value ([int](([single]$Return.Acc0)*60))              -Unit "Min"     -sc -MaxError 35
    $XMLOutput += Set-PrtgResult -Channel "Supply Voltage"  -Value $Return."Supply Voltage"                        -Unit "Volt"    -sc -MinError 25 -MaxError 30
    $XMLOutput += Set-PrtgResult -Channel "Fuel Level"      -Value $Return."Fuel Level"                            -Unit "Percent" -sc -MinError 15 -MinWarn 20
    $XMLOutput += Set-PrtgResult -Channel "Signal Strength" -Value $Return."Signal Strength"                       -Unit "Db"      -sc
    $XMLOutput += Set-PrtgResult -Channel "Last Checkin"    -Value $Return."age_in_minutes"                        -Unit "Min"     -sc -MaxError 220
    $XMLOutput += Set-PrtgResult -Channel "Page Login Time" -Value (([int]($LoginTime/100))/10)                    -Unit "Seconds"     -MaxWarn 5
    $XMLOutput += Set-PrtgResult -Channel "ExecutionTime"   -Value ([int]$ExecutionTime.Elapsed.TotalSeconds)      -Unit "Seconds"     -MaxWarn 15
    $XMLOutput += "  <text>Unit $($Return.machine_description)</text>`n"
    $XMLOutput += "</prtg>"
    Write-Host $XMLOutput
# }




# SIG # Begin signature block
# MIIM/gYJKoZIhvcNAQcCoIIM7zCCDOsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU40uN+y5Ig+VG99aNjhwjnm7s
# KI6gggoFMIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UE
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
# SIb3DQEJBDEWBBSYVWAnGPI9f+1g7ebzlUJYAk07UDANBgkqhkiG9w0BAQEFAASC
# AQCmO10EHy8x/LZyPj3oZRw4ce/5DFtQ1ghvNQFjZ4qOidtJgDqWJ8tiLCqA2o/r
# Ga47CCWIpuCY6vkZlcwbzy+BmV5ekI3/yEgN91ucQwINcig7iDTq775ttjHF474W
# 7Ei+KWza418d4kGvsebgILN8O672cTJj8nWzOjsnR93jB01jgarAHvyb0QUJUg5t
# wNnpqITOkHxcPtx9+l6AVyqWgOVfJCtRHjQ+acDdkeItWNX7ZKLx3UbHUQi6ZeWO
# G/+3jFGmtf1U5SC7ZJTTya/M3jnAGa2Nobh8rjQ9m2OvZ6DkZVwz6xGAk712HYIY
# 2/RE9VWcbBuFCC2YiII5/uO3
# SIG # End signature block
