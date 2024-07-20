param (
	[Parameter(Position=1)]
	[string]$URI = "http://www.gradimages.com/health"
)
$error.Clear()
try {
    $BuildVersion=$(((Invoke-WebRequest -Uri $URI -UseBasicParsing).Content.split("`r`n") | Where-Object {$_ -like "Build:*"}).split()[1])
}
catch {
    Write-host " <prtg>"
    Write-host "    <Error>1</Error>"
    Write-host "    <Text>$URI Not Found $error</Text>"
    Write-host " </prtg>"
    exit 1
}

Write-host " <prtg>"
Write-host "    <result>"
Write-host "        <channel>BuildYear</channel>"
Write-host "        <unit>Custom</unit>"
Write-host "        <mode>Absolute</mode>"
Write-host "        <showChart>1</showChart>"
Write-host "        <showTable>1</showTable>"
Write-host "        <value>$($BuildVersion.Split(".")[0])</value>"
Write-host "    </result>"
Write-host "    <result>"
Write-host "        <channel>BuildMonth</channel>"
Write-host "        <unit>Custom</unit>"
Write-host "        <mode>Absolute</mode>"
Write-host "        <showChart>1</showChart>"
Write-host "        <showTable>1</showTable>"
Write-host "        <value>$($BuildVersion.Split(".")[1])</value>"
Write-host "    </result>"
Write-host "    <result>"
Write-host "        <channel>BuildDay</channel>"
Write-host "        <unit>Custom</unit>"
Write-host "        <mode>Absolute</mode>"
Write-host "        <showChart>1</showChart>"
Write-host "        <showTable>1</showTable>"
Write-host "        <value>$($BuildVersion.Split(".")[2])</value>"
Write-host "    </result>"
Write-host "    <result>"
Write-host "        <channel>BuildNumber</channel>"
Write-host "        <unit>Custom</unit>"
Write-host "        <mode>Absolute</mode>"
Write-host "        <showChart>1</showChart>"
Write-host "        <showTable>1</showTable>"
Write-host "        <value>$($BuildVersion.Split(".")[3])</value>"
Write-host "    </result>"
    Write-host "    <Text>$BuildVersion</Text>"
Write-host " </prtg>"
#write-host "$(((Invoke-WebRequest -Uri $URI).Content.split("`r`n") | where{$_ -like "Build:*"}).split()[1])"
# SIG # Begin signature block
# MIIXuwYJKoZIhvcNAQcCoIIXrDCCF6gCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUvlfXTVhzTAd500wXd1g/lhvR
# lqGgghKzMIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
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
# AQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFGZtbo0xt6jtgDI8cIfLSENZRsyeMA0G
# CSqGSIb3DQEBAQUABIIBAI6+/uBgpXPmYa7voJiTf0cQrcOGnHj0fqIhgm9+o9XC
# QDKgOqdwaURFYgxiQgn0YEwvDk1Bw+rHTwXufI6AU8UJ3dXOhc55KP9XO3qv4Wdm
# Q65e8pb+ISysERfpYhxu64lOnlt136dhs30sKj+9jO8Jq0KKQBC74XschOsI9KEP
# O+Q29Ulb7rByXoFoPbLbur2I4fzqvBtL6AD5zyp6h6j+3sdehnDjHrsFviglp1xE
# s0elQEKQ8fpBcT9rUSGo/xLIX+YNkqSeFwf5ucRmTGJX8Kryyx+6QVN/phWuYAM4
# 32OqA4ohuoILJC4fzAvtpri/P00F8qX3uUhxtNs8taihggILMIICBwYJKoZIhvcN
# AQkGMYIB+DCCAfQCAQEwcjBeMQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50
# ZWMgQ29ycG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFudGVjIFRpbWUgU3RhbXBpbmcg
# U2VydmljZXMgQ0EgLSBHMgIQDs/0OMj+vzVuBNhqmBsaUDAJBgUrDgMCGgUAoF0w
# GAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTkxMjAy
# MjIwMjI3WjAjBgkqhkiG9w0BCQQxFgQUtSxjxXX2UB/O2roGsp4iRZNZwkIwDQYJ
# KoZIhvcNAQEBBQAEggEACDQqFHqBqxqQ9cuR5WQQ/I8gtMFVwhyT6qfHTQbzXX8S
# tqnKEzvtE9D7k0at5QejoYbmGnn+td/WYxcGYLRMF8vEiyFw3q1Vm6NO1/HGh5mY
# etpxsshylloKngIU/WiSZ0iEVv3KLtdd02pU6T2lYoWo7GdTGWorm1fMvbBXNwPC
# YKEZsPfJsjyWCvGhE8K56W/Tb7egcgTg4wlfKQoE/5pzk7s1KFBndFzxS/9nfBZ4
# 8u9uqz7VSDXlI/P+UW8vew4EgXoW1sd+UqIeLA0aN1m9dtxHNM1W2TIsEgb8AiQS
# zdxT9G4+CHe4DTZJDcezPYYh5/HxZWJLgDY0cW9HCw==
# SIG # End signature block
