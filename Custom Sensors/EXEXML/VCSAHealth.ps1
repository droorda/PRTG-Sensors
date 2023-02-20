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



