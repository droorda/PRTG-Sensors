[CmdletBinding()]
param (
[string]$VMServer,
[string]$VMUser  ,
[string]$VMPass

)

#-VMServer "xxxxx" -VMUser 'xxxxx' -VMPass 'xxxxx'

trap {
#    Write-Warning ('We Have an issue: "{0}" : {1} in "{2}"' -f $currentcomputer, `      $_.Exception.Message, $_.InvocationInfo.ScriptName)
    Write-warning "We Have an issue:"
    if ($_.Exception.ItemName){
        Write-warning "Exception - $($_.Exception.ItemName)"
    } else {
        Write-warning "InvocationInfo - $($_.InvocationInfo.PositionMessage)"
    }
    Write-warning "$($_.Exception.Message)"
    Write-warning "$($_.InvocationInfo.ScriptName) - $($MyInvocation.ScriptLineNumber) "
    Write-warning "----------------------------------------------------------------------------"
    $_

    return
}




if (test-path("$(split-path $SCRIPT:MyInvocation.MyCommand.Path)\prtgshell.psm1")) {
	Import-Module "$(split-path $SCRIPT:MyInvocation.MyCommand.Path)\prtgshell.psm1" -DisableNameChecking
} else {
	Write-output "<prtg>"
	Write-output "  <error>1</error>"
	Write-output "  <text>Unable to locate prtgshell.psm1</text>"
	Write-output "</prtg>"
	exit
}
<#
    Install-PackageProvider -Name NuGet -Force
    Find-Module -Name VMware.PowerCLI | Install-Module -force
#>
Try {
    Import-Module VMware.PowerCLI -ErrorAction Stop
} catch {
    Set-PrtgError $_.exception.Message
}

#Update-PowerShellGalleryItem "VMware.PowerCLI" #-AllowClobber

Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -confirm:$false | Out-Null

try {
    Connect-CisServer -Server $VMServer -User $VMUser -Password $VMPass -ErrorAction Stop | Write-Verbose
} catch {
    Set-PrtgError "Unable to connect to CisService $_"
}


$summaryResult = [pscustomobject] @{}


Try {
    $systemVersionAPI = Get-CisService -Name 'com.vmware.appliance.system.version' -ErrorAction Stop
} catch {
    Set-PrtgError "Unable to query to CisService $_"
}
$results = $systemVersionAPI.get() | Select-Object product, type, version, build, install_time

$systemUptimeAPI = Get-CisService -Name 'com.vmware.appliance.system.uptime'
$ts = [timespan]::fromseconds($systemUptimeAPI.get().toString())
$uptime = $ts.ToString("hh\:mm\:ss")


$healthOverall          = (Get-CisService -Name 'com.vmware.appliance.health.system'          ).get()
$healthLastCheck        = (Get-CisService -Name 'com.vmware.appliance.health.system'          ).lastcheck()
$healthCPU              = (Get-CisService -Name 'com.vmware.appliance.health.load'            ).get()

$healthapplmgmt         = (Get-CisService -Name 'com.vmware.appliance.health.applmgmt'        ).get()
$healthdatabasestorage  = (Get-CisService -Name 'com.vmware.appliance.health.databasestorage' ).get()
#$healthmonitoring       = (Get-CisService -Name 'com.vmware.appliance.monitoring'             ).get()
$healthsoftwarepackages = (Get-CisService -Name 'com.vmware.appliance.health.softwarepackages').get()
$healthapplianceupdate  = (Get-CisService -Name 'com.vmware.appliance.update'                 ).get()

$healthMem              = (Get-CisService -Name 'com.vmware.appliance.health.mem'             ).get()
$healthSwap             = (Get-CisService -Name 'com.vmware.appliance.health.swap'            ).get()
$healthStorage          = (Get-CisService -Name 'com.vmware.appliance.health.storage'         ).get()
try {
    $systemUpdatepolicy       = (Get-CisService -Name 'com.vmware.appliance.update.policy' -ErrorAction Stop).get()
} catch {
    Write-Verbose $_.Exception.Message
}
write-Verbose "---Testing----------------------------------------------------"
Write-verbose "Checking for Version Update"
Write-Verbose "Downloading $($systemUpdatepolicy.default_URL)manifest/manifest-latest.xml"
#[xml]$LatestManifest = (New-Object System.Net.WebClient).DownloadString("https://vapp-updates.vmware.com/vai-catalog/valm/vmw/8d167796-34d5-4899-be0a-6daade4005a3/6.5.0.14000.latest/manifest/manifest-latest.xml")
if ($systemUpdatepolicy.default_URL){
    [xml]$LatestManifest = (New-Object System.Net.WebClient).DownloadString("$($systemUpdatepolicy.default_URL)manifest/manifest-latest.xml")
    Write-Verbose "Current   Version $([version]$results.version)"
    Write-Verbose "Available Version $([version]$LatestManifest.update.version)"
    if ([version]$LatestManifest.update.version -gt [version]$results.version){
        $UpdateNeeded = "yellow"
    } else {
        $UpdateNeeded = "green"
    }
} else {
        $UpdateNeeded = "gray"
}

write-verbose "UpdateNeeded: $UpdateNeeded"

write-Verbose "---Testing----------------------------------------------------"

# DB health only applicable for Embedded/External VCSA Node
$vami = (Get-CisService -Name 'com.vmware.appliance.system.version').get()

if($vami.type -eq "vCenter Server with an embedded Platform Services Controller" -or $vami.type -eq "vCenter Server with an external Platform Services Controller") {
    $healthVCDB = (Get-CisService -Name 'com.vmware.appliance.health.databasestorage').get()
    Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "HealthVCDB"      -Value $healthVCDB
#} else {
#    $healthVCDB = "N/A"
}
$healthSoftwareUpdates = (Get-CisService -Name 'com.vmware.appliance.health.softwarepackages').get()
$consoleAccess         = (Get-CisService -Name 'com.vmware.appliance.access.consolecli'      ).get()
$dcuiAccess            = (Get-CisService -Name 'com.vmware.appliance.access.dcui'            ).get()
$shellAccess           = (Get-CisService -Name 'com.vmware.appliance.access.shell'           ).get()
$sshAccess             = (Get-CisService -Name 'com.vmware.appliance.access.ssh'             ).get()
$timeResults           = (Get-CisService -Name 'com.vmware.appliance.system.time'            ).get()
$timeSyncMode          = (Get-CisService -Name 'com.vmware.appliance.timesync'               ).get()

#$systemTimeAPI         = Get-CisService -Name 'com.vmware.appliance.system.time'
#$timeResults = $systemTimeAPI.get()

#try {
#    $timeSync = (Get-CisService -Name 'com.vmware.appliance.timesync' -ErrorAction Stop).get()
#} catch {
#    Write-Verbose $_.Exception.Message
#}
#$timeSyncMode = $timeSync.mode

$VCSAzone = [System.TimeZoneInfo]::FindSystemTimeZoneById($timeResults.timezone)
$HostTimeInVCSATimeZone = [System.TimeZoneInfo]::ConvertTimeFromUtc((Get-Date).ToUniversalTime(), $VCSAzone)
$VCSAtimeDelta = ([int](((get-date -date "$($timeResults.date) $($timeResults.time)") - $HostTimeInVCSATimeZone).TotalSeconds *10))/10

$healthLastCheck = [int]((get-date) - $healthLastCheck).TotalHours
$hash = @{
    "green"  = 1;
    "gray"   = 2;
    "yellow" = 4;
    "orange" = 5;
    "red"    = 6
}




#https://code.vmware.com/apis/4726/vcenter-server-appliance-management#!/health%2Fsoftwarepackages_/get_appliance_health_software_packages
#http://www.virtuallyghetto.com/2017/01/exploring-new-vcsa-vami-api-wpowercli-part-1.html
Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "Product"         -Value $results.product
Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "Type"            -Value $results.type
Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "Version"         -Value $results.version
Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "Build"           -Value $results.build
#Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "InstallTime"     -Value $results.install_time
Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "Uptime"          -Value $([int]$ts.Totalhours)
Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "HealthOverall"   -Value $healthOverall
Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "HealthLastCheck" -Value $healthLastCheck
Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "HealthCPU"       -Value $healthCPU
Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "HealthMem"       -Value $healthMem
Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "HealthSwap"      -Value $healthSwap
Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "HealthStorage"   -Value $healthStorage
Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "HealthSoftware"  -Value $healthSoftwareUpdates
#    Get information on available software updates available in remote VUM repository.
#    red indicates that security updates are available.
#    orange indicates that non security updates are available.
#    green indicates that there are no updates available.
#    gray indicates that there was an error retreiving information on software updates.

#Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "Console"         -Value $consoleAccess
#Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "DCUI"            -Value $dcuiAccess
#Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "BashShell"       -Value $shellAccess.enabled
#Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "SSH"             -Value $sshAccess
#Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "Timezone"        -Value $timeResults.timezone
#Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "Date"            -Value $timeResults.date
#Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "CurrentTime"     -Value $timeResults.time
Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "TimeDelta"              -Value $VCSAtimeDelta
Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "Mode"                   -Value $timeSyncMode

Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "HealthApplMgmt"         -Value $healthapplmgmt
Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "HealthSoftwarePackages" -Value $healthsoftwarepackages
Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "HealthDatabaseStorage"  -Value $healthdatabasestorage

Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "healthApplianceUpdate"  -Value $healthapplianceupdate

if($timeSyncMode -eq "NTP") {
    $ntpServers = (Get-CisService -Name 'com.vmware.appliance.ntp').get()
    Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "NTPServers"      -Value $ntpServers
#    Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "NTPStatus"       -Value $ntpServers.status
} else {
    Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "NTPServers"      -Value "N/A";
    Add-Member -InputObject $summaryResult -MemberType NoteProperty -Name "NTPStatus"       -Value "N/A";
}

if ($summaryResult.Product -eq "VMware vCenter Server Appliance"    ) {$summaryResult.Product = "vCSA"      }
if ($summaryResult.Type    -eq "VMware Platform Services Controller") {$summaryResult.Type    = "PSC"}

$XMLOutput = "<prtg>`n"
#$XMLOutput += Set-PrtgResult "Product"         $summaryResult.Product                "Name"
#$XMLOutput += Set-PrtgResult "Type"            $summaryResult.Type                   "Type"
#$XMLOutput += Set-PrtgResult "Version"         $summaryResult.Version                "Version"
$XMLOutput += Set-PrtgResult "HealthOverall"   $hash[$summaryResult.HealthOverall]   "Status" -sc -ValueLookup "Com.Vmware.Appliance.Health.System.HealthLevel"
$XMLOutput += Set-PrtgResult "Build"           $summaryResult.Build                  "Build"
$XMLOutput += Set-PrtgResult "Uptime"          ($summaryResult.Uptime/60)            "TimeHours" -sc
$XMLOutput += Set-PrtgResult "HealthLastCheck" $summaryResult.HealthLastCheck        "TimeHours" -sc -me 1440 -mw 720
$XMLOutput += Set-PrtgResult "HealthCPU"       $hash[$summaryResult.HealthCPU]       "Status" -sc -ValueLookup "Com.Vmware.Appliance.Health.System.HealthLevel"
$XMLOutput += Set-PrtgResult "HealthMem"       $hash[$summaryResult.HealthMem]       "Status" -sc -ValueLookup "Com.Vmware.Appliance.Health.System.HealthLevel"
$XMLOutput += Set-PrtgResult "HealthSwap"      $hash[$summaryResult.HealthSwap]      "Status" -sc -ValueLookup "Com.Vmware.Appliance.Health.System.HealthLevel"
$XMLOutput += Set-PrtgResult "HealthStorage"   $hash[$summaryResult.HealthStorage]   "Status" -sc -ValueLookup "Com.Vmware.Appliance.Health.System.HealthLevel"
$XMLOutput += Set-PrtgResult "HealthSoftware"  $hash[$summaryResult.HealthSoftware]  "Status" -sc -ValueLookup "Com.Vmware.Appliance.Health.System.HealthLevel"

# Todo: Migrate to $healthapplianceupdate
$XMLOutput += Set-PrtgResult "UpdateAvailible" $hash[$UpdateNeeded]                  "Status" -sc -ValueLookup "Com.Vmware.Appliance.Health.System.HealthLevel"

$XMLOutput += Set-PrtgResult "HealthApplMgmt"         $hash[$summaryResult.HealthApplMgmt]         "Status" -sc -ValueLookup "Com.Vmware.Appliance.Health.System.HealthLevel"
$XMLOutput += Set-PrtgResult "HealthSoftwarePackages" $hash[$summaryResult.HealthSoftwarePackages] "Status" -sc -ValueLookup "Com.Vmware.Appliance.Health.System.HealthLevel"
$XMLOutput += Set-PrtgResult "HealthDatabaseStorage"  $hash[$summaryResult.HealthDatabaseStorage]  "Status" -sc -ValueLookup "Com.Vmware.Appliance.Health.System.HealthLevel"

$XMLOutput += Set-PrtgResult "TimeDelta"       $summaryResult.TimeDelta              "TimeSeconds" -me 10 -mine -10 -sc
#$XMLOutput += Set-PrtgResult "Mode"            $summaryResult.Mode                   "NTPMode"
#$XMLOutput += Set-PrtgResult "NTPServers"      $summaryResult.NTPServers             "NTPServers"
#$XMLOutput += Set-PrtgResult "NTPStatus"       $summaryResult.NTPStatus              "NTPStatus"
$XMLOutput += "<text>$($summaryResult.Product) $($summaryResult.Type) $($summaryResult.Version)</text>"
$XMLOutput += "</prtg>"

Write-Host $XMLOutput


$summaryResult | Format-List | Out-String | write-verbose

DisConnect-CisServer -Server $VMServer -Confirm:$false


# SIG # Begin signature block
# MIIXuwYJKoZIhvcNAQcCoIIXrDCCF6gCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUHcV2XF2VXVVx3Y1/whwBwsjC
# RF+gghKzMIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
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
# AQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFHxjTT3+xtUjLlJ0XHoFBmfgXWidMA0G
# CSqGSIb3DQEBAQUABIIBACTQ00FiuX2fN7VvDyY45BD16nDBdDPdIQssusFds/Er
# t/cBs93X98qJ4vQMxqoR4OciClOjvN+A0Zke0YvSrZivTJERVYfK/PXCX6CclP+j
# V3iOqY9mllCQbda/3MlnsbwTEOQ05NKXQ11xewPFrtCzMa0yWVDjAgKXK1M8WLau
# E9v8906NTWuDWES1DjBWS8CBWu2W81Z92GGTrekCEXNkxTuJYh2hGGoxkaH5H8IB
# 8AaOumdONkN1j6Ne0UDMSHXZ2RuXzDFqK2n7SYuInLHSHEi2etTAbe6TlZCX6BLR
# pqnspRDau2cjUrrwDdZHAWou4W2yz2gCT6SLyRDqOOGhggILMIICBwYJKoZIhvcN
# AQkGMYIB+DCCAfQCAQEwcjBeMQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50
# ZWMgQ29ycG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFudGVjIFRpbWUgU3RhbXBpbmcg
# U2VydmljZXMgQ0EgLSBHMgIQDs/0OMj+vzVuBNhqmBsaUDAJBgUrDgMCGgUAoF0w
# GAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTkxMjAy
# MjIxMjAxWjAjBgkqhkiG9w0BCQQxFgQUlz0AnIizYE7sglwSdqErFxhAg8owDQYJ
# KoZIhvcNAQEBBQAEggEAOhHBADsqQRKG7VvL/3OBS196fixPrGNiW9kszsihImvr
# rqD9YxojoJ6eLphkTFyPAkfGcQ7cbEyi+ckQB84C5jlXJBPUzigGg/Utcqj+doK4
# btmcmxk8gA+wB/g4dM4Jbkt0lYY9ODek+cQ8hYgICtPMloNfDStfMjhSWky/moYQ
# 5aD+odT2lV1/kE8K1nXb0R9kYhF3QNZ5QF6QXbzZgMtHHV7NHOHgjUUmOgjtz1Hn
# 8QGtm9jHN7Ns1mxAkP9liqhnTheQwK74ru0mQFWZTLXjFmnIFfEAuG6zvrDSUPQD
# R9wGyHNgQwlgjxtnJkzh1B30Zcgiivs6VRYpI1bO5Q==
# SIG # End signature block
