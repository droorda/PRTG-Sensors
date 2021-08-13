#Requires -Modules PowerShellLogging

[CmdletBinding(
    SupportsShouldProcess=$True,
    ConfirmImpact='Low'
)]
param (
    [System.URI]
    $URI
    ,
    [String]
    $IPaddress
    ,
    # [string]
    # $DomainName
    # ,
    [string]
    $PageTitle
    ,
    [string]
    $Method = "GET"
    ,
    [string]
    $UserAgent = 'Mozilla/5.0 (compatible; PRTG Network Monitor (www.paessler.com); Windows)'
    ,
    [string]
    $RequireKeyword
    ,
    [string]
    $ExcludeKeyword
    ,
    # [int]
    # $DownloadLimit
    # ,
    [ValidateRange(0,999)]
    [int[]]
    $ReturnCode = @(200..299)
    ,
    [ValidateRange(0,20)]
    [int]
    $MaximumRedirection = 0
    ,
    [ValidateRange(0,60000)]
    [int]
    $TimeoutSec = 30
    ,
    $Header
    # ,
    # [switch]
    # $Raw
    # [ValidateSet("Ssl3","Tls","Tls11","Tls12")]
    # [string[]]
    # $SecurityProtocolType = @("Tls11","Tls12")

)
begin {
    $ExecutionTimer = [System.Diagnostics.Stopwatch]::StartNew()
    $script:ScriptPath = split-path $SCRIPT:MyInvocation.MyCommand.Path -parent
    $script:ScriptName =            $SCRIPT:MyInvocation.MyCommand.Name.split(".")[0]
    $host.privatedata.VerboseForegroundColor  = 'DarkYellow'

    Write-Verbose "-------------Start $($myInvocation.InvocationName) IN '$((Get-MyFunctionLocation).ScriptName)' : $($ExecutionTimer.Elapsed.ToString()) -----------------"
    Write-Verbose "  From Script:'$($myInvocation.ScriptName)' - At Line:$($myInvocation.ScriptLineNumber) char:$($myInvocation.OffsetInLine)"
    Write-Verbose "  Line '$($myInvocation.Line.Trim())'"
    $myInvocation.BoundParameters.GetEnumerator()  | ForEach-Object { Write-Verbose "  BoundParameter   : '$($_.key)' = '$($_.Value)'" }
    $myInvocation.UnboundArguments | ForEach-Object { Write-Verbose "  UnboundArguments : '$_'" }

    if (test-path("$(split-path $SCRIPT:MyInvocation.MyCommand.Path)\prtgshell.psm1")) {
        Import-Module "$(split-path $SCRIPT:MyInvocation.MyCommand.Path)\prtgshell.psm1" -DisableNameChecking -Verbose:$False
    } else {
        Write-output "<prtg>"
        Write-output "  <error>1</error>"
        Write-output "  <text>Unable to locate prtgshell.psm1</text>"
        Write-output "</prtg>"
        exit
    }

    if (!$DomainName -and !$URI)  {Set-PrtgError "-DomainName or -URI requred"}
    if (!$IPaddress)  {Set-PrtgError "-IPaddress requred"}
    if ($null -eq $URI.AbsoluteURI) {{Set-PrtgError "invalid URL '$URI' : Should be like https://site.com"}}

    if ($Header) {
        If ($Header -is [System.Collections.Hashtable]) {
            # This is Ideal
        } ElseIf ($Header -is [System.String]) {
            try {
                [System.Collections.Hashtable]$Header = $Header | ConvertFrom-StringData
            } catch {
                Set-PrtgError "invalid header value '$header'"
            }
        } else {
            Set-PrtgError "invalid header type '$($header | Get-Member | Select-Object -ExpandProperty TypeName -Unique)'"
        }
    }



    if ([System.Net.IPAddress]::TryParse($IPaddress,[ref][ipaddress]::Loopback)) {
        [System.Net.IPAddress]$IPaddress = $IPaddress
    } else {
        [System.Net.IPAddress]$IPaddress = (Resolve-DnsName -Name $IPaddress).IPAddress | Get-Random
    }

    [System.UriBuilder]$WebRequestURI = $URI
    $WebRequestURI.Host = $IPaddress
    [System.URI]$WebRequestURI = $WebRequestURI.Uri

    $WebRequest = [Net.WebRequest]::Create($WebRequestURI)
    # $WebRequest.Proxy = $Proxy
    # $WebRequest.Credentials = $null
    $WebRequest.Timeout = ($TimeoutSec * 1000)
    $WebRequest.Host = $URI.Host
    # $WebRequest.RequestUri =
    $WebRequest.UserAgent = $UserAgent
    $WebRequest.AllowAutoRedirect = $true
    if ($MaximumRedirection -eq 0) {
        $WebRequest.AllowAutoRedirect =  $false
    } else {
        $WebRequest.AllowAutoRedirect =  $true
        $WebRequest.MaximumAutomaticRedirections = $MaximumRedirection
    }
    $WebRequest.Method = $Method

    Try {
        $LoadTime = Measure-Command {
            $Response = $WebRequest.GetResponse()
            $reqstream = $Response.GetResponseStream()
        }
    } catch {
        Set-PrtgError "Error Connecting to Site $($_.exception.message)"
    }
    $sr = new-object System.IO.StreamReader $reqstream
    $Return = $sr.ReadToEnd()

    Write-Verbose "------------ Response ------------"
    Write-Verbose "StatusCode = $([int]$Response.StatusCode)"
    $Response | out-string | write-Verbose
    $Headers = @{}
    $Response.Headers | ForEach-Object {
        $Headers[$_] = $Response.GetResponseHeader($_)
    }
    Write-Verbose "------------ Headers ------------"
    [pscustomobject]$Headers | Out-String | Write-Verbose

    if ($ReturnCode -notcontains $Response.StatusCode) {
        if (@(301,302) -contains $Response.StatusCode) {
            Set-PrtgError "Returned StatusCode : $($Response.StatusCode) => '$($Response.GetResponseHeader('location'))'"
        } else {
            Set-PrtgError "Returned StatusCode : $($Response.StatusCode)"
        }
    }

    if ($Return.IndexOf("<title>") -gt 0) {
        $title = [regex]::Replace($Return.replace("`n"," "), '.*<title>(.*)<\/title>.*', '$1', 'IgnoreCase').trim() -replace '[^a-zA-Z0-9 ]', ''
        Write-Verbose "Page Title: '$title'"
    }

    if ($PageTitle){
        if ($title -ne $PageTitle) {
            Set-PrtgError "Incorect page Title : '$title'"
        }
    }

    if ($RequireKeyword) {
        if ($Return.IndexOf($RequireKeyword) -lt 0) {
            Set-PrtgError "Could not Find : '$RequireKeyword'"
        }
    }
    if ($ExcludeKeyword) {
        if ($Return.IndexOf($ExcludeKeyword) -ge 0) {
            Set-PrtgError "Found : '$ExcludeKeyword'"
        }
    }
    if ($Header) {
        Foreach ($Name in $Header.Keys) {
            if ($Header[$Name] -ne $Response.GetResponseHeader($Name)) {
                Set-PrtgError "Incorrect Header : [$Name='$($Response.GetResponseHeader($Name))']"
            }
        }
    }


    $XMLOutput = "<prtg>`n"
    $XMLOutput += Set-PrtgResult -Channel "LoadTime"         -Value ([int]$LoadTime.TotalMilliseconds)      -Unit "msec" -sc -MaxWarn 600 -MaxError 1200
    $StatusCode = @{
        MinError = 200
        MaxError = 299
    }
    if ($ReturnCode) {
        $StatusCode.MinError = $ReturnCode | Sort-Object | Select-Object -First 1
        $StatusCode.MaxError = $ReturnCode | Sort-Object | Select-Object -Last 1
    }
    $XMLOutput += Set-PrtgResult -Channel "StatusCode"       -Value ([int]$Response.StatusCode)             -Unit "Count" -sc @StatusCode
    $XMLOutput += Set-PrtgResult -Channel "RawContentLength" -Value ([int]$Return.Length)                   -Unit "Count" -sc
    $XMLOutput += "<text>StatusDescription: $($Response.StatusDescription)</text>`n"
    $XMLOutput += "</prtg>"
    $XMLOutput

}
process {
}
End {
    Write-Verbose "--------------END- $($myInvocation.InvocationName) : $($ExecutionTimer.Elapsed.ToString()) -----------------"
}



# SIG # Begin signature block
# MIIM/gYJKoZIhvcNAQcCoIIM7zCCDOsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU+q9bZvkAIMGZUmP0FzWcVZQN
# UgmgggoFMIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UE
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
# SIb3DQEJBDEWBBR/v9JHe19h5FYW5+sZTiiN9OpE2jANBgkqhkiG9w0BAQEFAASC
# AQBiDqjwrZNSgrT6Ex9HMTDFkiCgv8gL5SAXFMB6w+dOtRtRWuGYQREdB0yni/oD
# 1erqDNidfSgb+GSzFcCs+fWiQpS0UXfvxMdHwBGmJ7f4CxVd4gjV5q+Xd+08adQi
# mikvteFxTs+2or1t34sLA718t9MoC4AYIY4Mic7RbPN0LhXUNXtwH6nCDlbpzYRi
# hn6y7XO3h7ZDWzX7breLSFAFYXGPbbPB2vm0NSTT4T6AMGgGULWB4O+/vrQoFxKi
# tH8mo14WxIJE6lWbhe2lHHWmUBkK4ODUalX0zbpiWufX4D0d431M5zP6BhUHxhBS
# IG5xsoNnymMKt6aq4zTCuQGq
# SIG # End signature block
