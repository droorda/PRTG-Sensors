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


# SIG # Begin signature block
# MIIXuwYJKoZIhvcNAQcCoIIXrDCCF6gCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUCds8VhJ5M8tjhpdXAFFmKp8p
# fSagghKzMIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
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
# AQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFIRw2JseLYOptomiERfuhYOHox1pMA0G
# CSqGSIb3DQEBAQUABIIBAAE74uskERtsup6bC/GZZDYI0UVZz+NjDPJ71Q7CWwxZ
# UmYr7w+w73idOeAvDMtGT9WZ6UJO44+JcEAuQcP3QUQObPV++6aIYMRjofD6JvrB
# OjPq2xdlZUDu+DSUZukxad26+v/gsNAXRH3usk1xwThGvfRwThj38Up3y7Ux8FRm
# Boz8lEwbXAsWu8gQvG069KQWZqd0oGMqXC5Yde0+iqC30hFwex26NdG7315MVafm
# BnJMfNCPouA1tfrfpkmghg+X546iUadYUiZi9JoM4mYBo0YpplVUjPCbsmruzhWf
# F3aevAYoaChlKJxOnWbm1sodSTYD9ODVQG+jz+gZGrqhggILMIICBwYJKoZIhvcN
# AQkGMYIB+DCCAfQCAQEwcjBeMQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50
# ZWMgQ29ycG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFudGVjIFRpbWUgU3RhbXBpbmcg
# U2VydmljZXMgQ0EgLSBHMgIQDs/0OMj+vzVuBNhqmBsaUDAJBgUrDgMCGgUAoF0w
# GAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTkxMjAy
# MjIxMDQzWjAjBgkqhkiG9w0BCQQxFgQUa+CHFI1/fd6Ks402E2+6sEiVSS0wDQYJ
# KoZIhvcNAQEBBQAEggEAk101SSPO7KeDgqhKCkQRoKR5mHYMCoxdVtovUJSNfwOh
# fMXYJ/zyZOBYu8mX1wEvTVMe/pcjJf6aVWArjMCBbglo7OhS6NzXHtjS657mfdI7
# e/csDxdnU8J2osoG1xwHHl9I6SNCLp6kgx2w6eNH31sbYt53XN4lALA3poULTuNf
# YdtfTblivoieeueNoEvU39lMomAtpz29QjmcmtcjWd2zTyETSclxQQcsTR2n3wAA
# iaSmSOzRLCBmkXQFsIyplJ1+WOBqWRBuIIm6vRqBAGLznntW7Vl2buZU3ujCrasm
# 0h1niJtek8ZHiIfDUhvMiM7IlISOS+ELGbn1eWJ/2w==
# SIG # End signature block
