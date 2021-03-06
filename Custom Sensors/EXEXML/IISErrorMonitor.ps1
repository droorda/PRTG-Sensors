Param(
	[Parameter(Position=1)]
	[string]$LogPath				,
	[string]$prtg_host				= "$env:prtg_host",
	[string]$prtg_windowsdomain		= "$env:prtg_windowsdomain",
	[string]$prtg_windowspassword	= "$env:prtg_windowspassword",
	[string]$prtg_windowsuser		= "$env:prtg_windowsuser"
)

# if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
    if (!$LogPath)              {
        Write-host " <prtg>"
        Write-host "    <error>"
        Write-host "       <text>LogPath Not Specified EG: -LogPath 'c$\inetpub\logs\LogFiles\W3SVC1'</text>"
        Write-host "    </error>"
        Write-host " </prtg>"
        exit 1
    }
    if (!$prtg_host)            {
        Write-host " <prtg>"
        Write-host "    <error>"
        Write-host "       <text>-prtg_host Not Specified</text>"
        Write-host "    </error>"
        Write-host " </prtg>"
        exit 1
    }
    if (!$prtg_windowsdomain)   {
        Write-host " <prtg>"
        Write-host "    <error>"
        Write-host "       <text>-prtg_windowsdomain Not Specified</text>"
        Write-host "    </error>"
        Write-host " </prtg>"
        exit 1
    }
    if (!$prtg_windowsuser)     {
        Write-host " <prtg>"
        Write-host "    <error>"
        Write-host "       <text>-prtg_windowsuser Not Specified</text>"
        Write-host "    </error>"
        Write-host " </prtg>"
        exit 1
    }
    if (!$prtg_windowspassword) {
        Write-host " <prtg>"
        Write-host "    <error>"
        Write-host "       <text>-prtg_windowspassword Not Specified</text>"
        Write-host "    </error>"
        Write-host " </prtg>"
        exit 1
    }
# }


<#
	This file will grab the latest IIS log file, extract the last 50MB and scan it for page errors.
	It will then return a prtg formated XML doc to stdout

#>
#region User-Variables
# File Output path and filename
# $ScriptVersion = "0.0.1"

###############################
#endregion



#region Functions
    function Copy-File
    {
        param( [string]$from, [string]$to, [int]$MaxSizeEnd)
        if (!(test-path $from -ErrorAction SilentlyContinue)) {
            Write-Warning "Unable to access source file"
            return $False
        }
        if (test-path $to) {
            Remove-Item $to -ErrorAction SilentlyContinue
            if (test-path $to) {
                Write-Warning "Copy-File - Error removing existing Destination file"
                return $false
            }
        } else {
            if ($(test-path -path $(split-path $to -Parent) -pathType container) -ne $true) {
                Write-Host "Copy-File - Making directory $(split-path $to -Parent)"
                New-Item -ItemType directory -Path $(split-path $to -Parent) -ErrorAction SilentlyContinue
                if ($(test-path -path $(split-path $to -Parent) -pathType container) -ne $true) {
                    Write-Warning "Copy-File - Error creating destination Path"
                    return $false
                }
            }
        }
        $toFreeSpace = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType = 3"| Where-Object { $_.DeviceID -eq $(split-path $to -qualifier) } | ForEach-Object {$_.FreeSpace}
        if ($MaxSizeEnd) {
            if ( $MaxSizeEnd -gt $toFreeSpace) {
                Write-Warning "Copy-File - Not Enough free space for file"
                return $false
            }
        } else {
            if ( $(Get-Item $from).length -gt $toFreeSpace) {
                Write-Warning "Copy-File - Not Enough free space for file"
                return $false
            }
        }

        Write-Progress -Activity "Copying file" -status "$from -> $to" -PercentComplete 0
        if ($(test-path $from) -ne $true) {
            write-warning "Copy-File - Source File Not Found"
            return $false
        }

        $error.clear()
        try {
            $ffile = [io.file]::OpenRead($from)
        } catch {
                #write-warning "Could not lock file, Attempting to open in shared mode"
        }
        if (!$ffile) {
            try {
                $ffile = [io.file]::Open($from, [io.filemode]::Open, [io.fileaccess]::Read, [io.fileshare]::ReadWrite)
            } catch {
                write-warning "Error Opening the File $from"
                ##write-host $error
                return $false
            }
        }
        #$ffile.Length
        $tofile = [io.file]::OpenWrite($to)
        try {
            [byte[]]$buff = new-object byte[] 4096
            [long]$total = [long]$count = 0
            $StartTime = Get-Date
#                Write-Verbose " File Length $($ffile.Length)"
#                Write-Verbose " Skip Length $($MaxSizeEnd)"

            if ($MaxSizeEnd -lt $ffile.Length) {$ffile.seek(-$MaxSizeEnd, [System.IO.SeekOrigin]::End)}
            do {
                $count = $ffile.Read($buff, 0, $buff.Length)
                #write-host $count
                $tofile.Write($buff, 0, $count)
                $total += $count
                if ($total % 10mb -eq 0) {
                    $FileETA = ($(New-TimeSpan $StartTime (Get-Date)).TotalSeconds/$($total/$ffile.Length* 100))*(100-($total/$ffile.Length* 100))
                    $FileETA = $((get-date).addSeconds($FileETA)).ToShortTimeString()
                    if ($CopyPercent -ne $([int]($total/$ffile.Length* 100))) {
                        $CopyPercent=([int]($total/$ffile.Length* 100))
                    }
                    Write-Progress  -Activity "Copying file" `
                                    -status "$from -> $to" `
                                    -PercentComplete $CopyPercent `
                                    -currentOperation "$($total/1048576) MB Transfered $CopyPercent%   ETA $FileETA"
                }
            } while ($count -gt 0)

        }
        Catch {
            Write-Warning "Copy-File - Error copying file `n$_"
            $ffile.Close()
            $tofile.Close()
            Remove-Item $to
            return $false
        }
        finally {
            $ffile.Close()
            $tofile.Close()
        }
        if (test-path $to) {
            return $true
        }
    }
#endregion


#[string]$LogFile="u_ex150504.log"
#[string]$LogFile="u_ex150504.log"
$LogSearch = (Get-Date).ToUniversalTime().AddMinutes(-2).ToString("yyyy-MM-dd HH:mm")
if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
$LogSearch
}
$LogSearch="^"+$LogSearch+":.* [45][01][0123458] \d+ \d+ \d+"
if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
$LogSearch
}
$LogFile = "u_ex$((Get-Date).ToUniversalTime().AddMinutes(-2).ToString("yyMMdd")).log"
#write-host "copy \\$prtg_host\$LogPath$LogFile to $($env:temp)$LogFile"
#exit
$results  = net use \\$prtg_host /user:$prtg_windowsdomain\$prtg_windowsuser $prtg_windowspassword 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-host " <prtg>"
    Write-host "    <error>"
    Write-host "       <text>Error $LASTEXITCODE Authenticating to Server  $results</text>"
    Write-host "    </error>"
    Write-host " </prtg>"
    exit 1
}
$results = Copy-File "\\$prtg_host\$LogPath\$LogFile" "$($env:temp)\$prtg_host$LogFile" 5000000
if ($results -eq $false) {
    Write-host " <prtg>"
    Write-host "    <error>"
    Write-host "       <text>Could Not access Log file on server</text>"
    Write-host "    </error>"
    Write-host " </prtg>"
    exit 1
}
$results = net use \\$prtg_host /delete 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-host " <prtg>"
    Write-host "    <error>"
    Write-host "       <text>Error $LASTEXITCODE Authenticating to Server  $results</text>"
    Write-host "    </error>"
    Write-host " </prtg>"
    exit 1
}


$LogArray = @()
get-content "$($env:temp)\$prtg_host$LogFile" | Where-Object {($_ -match $LogSearch) } | ForEach-Object {$LogArray += $_}
Remove-Item "$($env:temp)\$prtg_host$LogFile" -ErrorAction SilentlyContinue
if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
($LogArray| Where-Object {($_ -match ' 502 ') })
}
[int]$ErrorCount404=($LogArray| Where-Object {($_ -match ' 404 ') }).count
[int]$ErrorCount405=($LogArray| Where-Object {($_ -match ' 405 ') }).count
[int]$ErrorCount408=($LogArray| Where-Object {($_ -match ' 408 ') }).count
[int]$ErrorCount412=($LogArray| Where-Object {($_ -match ' 412 ') }).count
[int]$ErrorCount500=($LogArray| Where-Object {($_ -match ' 500 ') }).count
[int]$ErrorCount501=($LogArray| Where-Object {($_ -match ' 501 ') }).count
[int]$ErrorCount502=($LogArray| Where-Object {($_ -match ' 502 ') }).count
[int]$ErrorCount503=($LogArray| Where-Object {($_ -match ' 503 ') }).count
#group | sort -desc Count
#get-content $LogPath"u_ex150504x.txt" | select -first 5 | % {if($_ -match '2015-05-04*') {$_}} #| group | sort -desc Count
write-verbose "ErrorCount404 $ErrorCount404"
write-verbose "ErrorCount405 $ErrorCount405"
write-verbose "ErrorCount408 $ErrorCount408"
write-verbose "ErrorCount412 $ErrorCount412"
write-verbose "ErrorCount500 $ErrorCount500"
write-verbose "ErrorCount501 $ErrorCount501"
write-verbose "ErrorCount502 $ErrorCount502"
write-verbose "ErrorCount503 $ErrorCount503"

if (!($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent)) {


Write-host " <prtg>"
Write-host "    <result>"
Write-host "        <channel>Error 404</channel>"
Write-host "        <unit>Count</unit>"
Write-host "        <mode>Absolute</mode>"
Write-host "        <showChart>1</showChart>"
Write-host "        <showTable>1</showTable>"
Write-host "        <value>$ErrorCount404</value>"
Write-host "    </result>"
Write-host "    <result>"
Write-host "        <channel>Error 405</channel>"
Write-host "        <unit>Count</unit>"
Write-host "        <mode>Absolute</mode>"
Write-host "        <showChart>1</showChart>"
Write-host "        <showTable>1</showTable>"
Write-host "        <value>$ErrorCount405</value>"
Write-host "    </result>"
Write-host "    <result>"
Write-host "        <channel>Error 408</channel>"
Write-host "        <unit>Count</unit>"
Write-host "        <mode>Absolute</mode>"
Write-host "        <showChart>1</showChart>"
Write-host "        <showTable>1</showTable>"
Write-host "        <value>$ErrorCount408</value>"
Write-host "    </result>"
Write-host "    <result>"
Write-host "        <channel>Error 412</channel>"
Write-host "        <unit>Count</unit>"
Write-host "        <mode>Absolute</mode>"
Write-host "        <showChart>1</showChart>"
Write-host "        <showTable>1</showTable>"
Write-host "        <value>$ErrorCount412</value>"
Write-host "    </result>"
Write-host "    <result>"
Write-host "        <channel>Error 500</channel>"
Write-host "        <unit>Count</unit>"
Write-host "        <mode>Absolute</mode>"
Write-host "        <showChart>1</showChart>"
Write-host "        <showTable>1</showTable>"
Write-host "        <value>$ErrorCount500</value>"
Write-host "    </result>"
Write-host "    <result>"
Write-host "        <channel>Error 501</channel>"
Write-host "        <unit>Count</unit>"
Write-host "        <mode>Absolute</mode>"
Write-host "        <showChart>1</showChart>"
Write-host "        <showTable>1</showTable>"
Write-host "        <value>$ErrorCount501</value>"
Write-host "    </result>"
Write-host "    <result>"
Write-host "        <channel>Error 502</channel>"
Write-host "        <unit>Count</unit>"
Write-host "        <mode>Absolute</mode>"
Write-host "        <showChart>1</showChart>"
Write-host "        <showTable>1</showTable>"
Write-host "        <value>$ErrorCount502</value>"
Write-host "    </result>"
Write-host "    <result>"
Write-host "        <channel>Error 503</channel>"
Write-host "        <unit>Count</unit>"
Write-host "        <mode>Absolute</mode>"
Write-host "        <showChart>1</showChart>"
Write-host "        <showTable>1</showTable>"
Write-host "        <value>$ErrorCount503</value>"
Write-host "    </result>"
#Write-host " <text>findstr /r /C:"%CurrentDate% %CurrentHour%:%CurrentMin%:.*- [45][01][0123458] " "c:\inetpub\logs\LogFiles\W3SVC1\%LAST%"</text>"
Write-host " </prtg>"
}
# SIG # Begin signature block
# MIIXpgYJKoZIhvcNAQcCoIIXlzCCF5MCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUH3aJublxJKLi/GPr+kjn+TKO
# FgSgghKeMIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
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
# djYm3ATrn/dhHxXch2/uRpYoraEmfQoJpy4Eo428+LwEMAEwggUtMIIEFaADAgEC
# AggIU2wugZfkhDANBgkqhkiG9w0BAQsFADCBtDELMAkGA1UEBhMCVVMxEDAOBgNV
# BAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAYBgNVBAoTEUdvRGFk
# ZHkuY29tLCBJbmMuMS0wKwYDVQQLEyRodHRwOi8vY2VydHMuZ29kYWRkeS5jb20v
# cmVwb3NpdG9yeS8xMzAxBgNVBAMTKkdvIERhZGR5IFNlY3VyZSBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgLSBHMjAeFw0yMDAyMTgyMTEyNTJaFw0yMzAyMTgyMTEyNTJa
# MG8xCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdGbG9yaWRhMRQwEgYDVQQHEwtUYWxs
# YWhhc3NlZTEbMBkGA1UEChMSSUNPTklDIEdST1VQLCBJTkMuMRswGQYDVQQDExJJ
# Q09OSUMgR1JPVVAsIElOQy4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDOOPPNzkLxi9hXM7BbsldN3OWUtE9XSPdRmRvhEc+ICwW4eFvWEhXSkuVlTBkr
# CoMDsD2YnuOTesmMNw7qHK/6OU65ZL2hSggJmhnxtFY1BPfItzPurzaCNaYIZYUa
# ZlhI3f8+07/9TiKEsb9cezolAlWD59pZuKCbRiNuUlXeqbDhbIotqdhu1UEWSUdd
# cJ2HgIOM3qDfzKIECmPw23Bxa+X9tMbLOpt2jZ8xCnEvF7FT0BcmdVJOVQcYGr1H
# AE3jeI2JqOpxSfciC0q7xAM9mhvNlPApvgzbP1VXxpCuu97HljDHzZp5syzcs5Ry
# 9NSJfywSX8bRGBKvAoEDxODpAgMBAAGjggGFMIIBgTAMBgNVHRMBAf8EAjAAMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMA4GA1UdDwEB/wQEAwIHgDA1BgNVHR8ELjAsMCqg
# KKAmhiRodHRwOi8vY3JsLmdvZGFkZHkuY29tL2dkaWcyczUtNS5jcmwwXQYDVR0g
# BFYwVDBIBgtghkgBhv1tAQcXAjA5MDcGCCsGAQUFBwIBFitodHRwOi8vY2VydGlm
# aWNhdGVzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMAgGBmeBDAEEATB2BggrBgEF
# BQcBAQRqMGgwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmdvZGFkZHkuY29tLzBA
# BggrBgEFBQcwAoY0aHR0cDovL2NlcnRpZmljYXRlcy5nb2RhZGR5LmNvbS9yZXBv
# c2l0b3J5L2dkaWcyLmNydDAfBgNVHSMEGDAWgBRAwr0njsw0gzCiM9f7bLPwtCyA
# zjAdBgNVHQ4EFgQU97SPwQlA65NWm/9nnrsbtZ2zvXIwDQYJKoZIhvcNAQELBQAD
# ggEBAKu5unGj3kPkw003TrrwAOewtqbgD9bLMIce1Evx3NTlMzWLD4U/Bwh1Zydb
# IlZg3CB4IZ+q6GJjLPADoESsoct3S+R7w03Z2PBfjz+k1Q6aFPWR7ko99f7GwGUP
# cw98LpvWQEuE2v8iWJeWsY7E7qmn8OScSjE0OwBY5TQDbT2E78woA14g0WHLPrcu
# 8wArO7ynXB7aoLWvCR3NhLKDETSIJuSjnA6+98JeMTWiwrPMTcpK6r34Ex+2EqMs
# aUR3qsVKFqKkEf88IJcXQ14/gMdMLj4jN9Kql5RelkD6lEx90NGAFRJPA8Q5YEZF
# zWnRSaydUSX07rKQoNASoQ63MxwxggRyMIIEbgIBATCBwTCBtDELMAkGA1UEBhMC
# VVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAYBgNV
# BAoTEUdvRGFkZHkuY29tLCBJbmMuMS0wKwYDVQQLEyRodHRwOi8vY2VydHMuZ29k
# YWRkeS5jb20vcmVwb3NpdG9yeS8xMzAxBgNVBAMTKkdvIERhZGR5IFNlY3VyZSBD
# ZXJ0aWZpY2F0ZSBBdXRob3JpdHkgLSBHMgIICFNsLoGX5IQwCQYFKw4DAhoFAKB4
# MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQB
# gjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkE
# MRYEFB8flFcVkafTjN4654M6VRik/hhZMA0GCSqGSIb3DQEBAQUABIIBAGdz5kpd
# 7gg7vqRmFpD9E9uBAjfdsZ5mRZuKDW5rSpSJiwrMPODzQ4REFB1jp79bAlfWl4NI
# Z9PqL5SKHZpUQRTT30RQAq9Zcy4/9EUnLDim5G7Ntxk0Xf9/402qbnGE/9mY3CeB
# cqD77O1drCv+Rp8MBk58/M834DtOe43Viutswd1OmuzAJV+ZrouwsYpZrkxcIpwp
# 1qu87LOp4+PpCO7kqVLb9WX8Qlv3jxuxMiZyet8C91s4D56Zp8FgGTkCVUoYm07R
# v3s3Spp2fpcbomxoq/iqYqRSJenBVmymZwhHFqxftshXO5/ZY+bxGSp3iuJ0Jr7Q
# 3eCtmWK9/G8L1EWhggILMIICBwYJKoZIhvcNAQkGMYIB+DCCAfQCAQEwcjBeMQsw
# CQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xMDAuBgNV
# BAMTJ1N5bWFudGVjIFRpbWUgU3RhbXBpbmcgU2VydmljZXMgQ0EgLSBHMgIQDs/0
# OMj+vzVuBNhqmBsaUDAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3
# DQEHATAcBgkqhkiG9w0BCQUxDxcNMjAwNzE0MjAwODQ3WjAjBgkqhkiG9w0BCQQx
# FgQU0YpEWEqgZcIlot6j0DIlDAmSkF0wDQYJKoZIhvcNAQEBBQAEggEAVSDkTSEv
# MiumjSRE4MugQ7dwgqBIZQ8O1+CoHg/d+qbTAY5Td70YXJJ8kD1fsI9p5zlCx5ax
# fs5IUEWm8Huc5GiVH+TYiXvfQj3NOhi8YB7IIMq5Y8xxkhtcQa+oyzcS4go+XRmd
# x1NeYGChtYcKoJ2XgRGGpMs2pTmC1jx+WHkVgRBNAZwYi+NyxnGZHmjGhoMYQJzK
# qDrbsU72fM9wzkLkzP3yhQkvYHAMz0YGe4MjWNRwFWDKQEamJKNVUyGP9yIIRdmw
# OMS2LUR4f3Gi+J5dQqjnenfg0lzjJTFc8u8KmlPVwrtQbwjDd34O8N3Vl/TqvCYD
# HFmazuhGq87zpA==
# SIG # End signature block
