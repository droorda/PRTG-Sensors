<#


    Copyright 2012-2012 Amazon.com, Inc. or its affiliates. All Rights Reserved.

    Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at

        http://aws.amazon.com/apache2.0/

    or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.


.SYNOPSIS
Collects memory, and Pagefile utilization on an Amazon Windows EC2 instance and sends this data as custom metrics to Amazon CloudWatch.

.DESCRIPTION
Queries Amazon CloudWatch for statistics on CPU, memory, swap, and disk space utilization within a given time interval. This data is provided for the Amazon EC2 instance on which this script is executed.

.PARAMETER period
		The granularity, in seconds, of the returned data points. For metrics with regular resolution, a period can be as short as one minute (60 seconds) and must be a multiple of 60.
		For high-resolution metrics that are collected at intervals of less than one minute, the period can be 1, 5, 10, 30, 60, or any multiple of 6
.PARAMETER InstanceID
		Specifies the AWS instance ID number. if not provided, the script will attempt to find the ID of the machine running the script
.PARAMETER recent_minutess
		Specifies the number of minutes to go back when collecting stats

.NOTES
    PREREQUISITES:
    1) Run on machine with AWS powershell module



.EXAMPLE

    powershell.exe .\mon-get-instance-stats.ps1
.EXAMPLE
    powershell.exe .\mon-get-instance-stats.ps1 -InstanceID i-00000000000000000 -recent_minutess 30 -period 60

#>

[CmdletBinding(DefaultParametersetName="credsfromfile", supportsshouldprocess = $true) ]
param(
    [Parameter(mandatory = $false)]
    [validaterange(1,360 )]
    [int]$recent_minutess = 10
    ,
    [Parameter(mandatory = $false)]
    [string]$InstanceID
    ,
    [Parameter(mandatory = $false)]
    [validaterange(1,86400 )]
    [int]$period = 600

    #[Parameter(Parametersetname ="credsinline",mandatory=$false)]
    #[string]$aws_access_id,
    #[Parameter(Parametersetname ="credsinline",mandatory=$false)]
    #[string]$aws_secret_key,
    #[Parameter(Parametersetname ="credsfromfile")]
    #[string]$aws_credential_file = [Environment]::GetEnvironmentVariable("AWS_CREDENTIAL_FILE"),

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

$ErrorActionPreference = 'Stop'

$env:AWS_EC2_METADATA_DISABLED='false'

### Initliaze common variables ###
#$accountinfo = New-Object psobject
$WebClient = New-Object Net.WebClient
$time = Get-Date
#[string]$aaid =""
#[string]$ask =""
#$invoc = (Get-Variable myinvocation -Scope 0).value
#$scriptname = $invoc.mycommand.Name
#$ver = '1.0.0'

$starttime = ($time.AddMinutes(-$recent_minutess)).ToUniversalTime()
#$starttime = ($time.AddHours(-$recent_hours)).ToUniversalTime()
$endtime = $time.ToUniversalTime()

$statistics = New-Object Collections.Generic.List[String]
$statistics.add("Average")
$statistics.add("Maximum")
$statistics.add("Minimum")



### Global trap for all excpetions for this script. All exceptions will exit the script.###
trap [Exception] {
	Set-PrtgError ($_.Exception.Message)
}

# Install-Module -Name AWS.Tools.Installer -Force -AllowClobber -Scope AllUsers

try {
    import-module -Name AWS.Tools.CloudWatch -verbose:$false
} catch {
    try {
        Install-Module -Name PowerShellGet -Repository PSGallery -Force -AllowClobber
        Install-Module -Name AWS.Tools.CloudWatch -confirm:$false -AllowClobber -Scope AllUsers
        import-module -Name AWS.Tools.CloudWatch -verbose:$false
    } catch {
        Set-PrtgError "Unable to load Module AWS.Tools.CloudWatch"
    }
}


####Test and load AWS sdk # POS locks CPU at 100% for 30-60 seconds
# try {
#     import-module -Name AWSPowerShell -verbose:$false
# } catch {
#     Set-PrtgError "Unable to load Module AWSPowerShell"
# }

### Process parameterset for credentials and adds them to a powershell object ###
#switch ($PSCmdlet.Parametersetname) {
#	"credsinline" {
#		    Write-Verbose "Using credentials passed as arguments"
#		    if (!($aws_access_id.Length -eq 0 )) {
#			    $aaid = $aws_access_id
#			    }
#		    else {
#			    throw ("Value of AWS access key id is not specified.")
#			    }

#		    if (!($aws_secret_key.Length -eq 0 )) {
#			    $ask = $aws_secret_key
#			    }
#		    else {
#			    throw "Value of AWS secret key is not specified."
#			    }
#		    }
#	"credsfromfile" {
#		    if ( Test-Path $aws_credential_file) {
#			    Write-Verbose "Using AWS credentials file $aws_credential_file"
#			    Get-Content $aws_credential_file | ForEach-Object { if($_ -match '.*=.*'){$text = $_.split("="); switch ($text[0].trim()){"AWSAccessKeyId" {$aaid= $text[1].trim()} "AWSSecretKey" { $ask = $text[1].trim()}}}}
#			    }
#		    else {
#			    throw "Failed to open AWS credentials file $aws_credential_file"
#			    }
#		    }
#}

#if (($aaid.length -eq 0) -or ($ask.length -eq 0)) {
#	throw "Provided incomplete AWS credential set"
#} else {
#	Add-Member -membertype noteproperty -inputobject $accountinfo -name "AWSSecretKey" -value $ask
#	Add-Member -membertype noteproperty -inputobject $accountinfo -name "AWSAccessKeyId" -value $aaid
#	Remove-Variable ask; Remove-Variable aaid
#}

### Functions that interact with metadata to get data required for dimenstion calculation and endpoint for cloudwatch api. ###
function get-metadata {
	$extendurl = $args
	$baseurl = "http://169.254.169.254/latest/meta-data"
	$fullurl = $baseurl + $extendurl
	return ($WebClient.DownloadString($fullurl))
}

function get-region {
	$az = get-metadata ("/placement/availability-zone")
	return ($az.Substring(0, ($az.Length -1)))
}

function get-endpoint {
	$region = get-region
	return "https://monitoring." + $region + ".amazonaws.com/"
}






if (-not $InstanceID) {
    $InstanceID = get-metadata ("/instance-id")
    Write-verbose "Detected Instance-ID '$InstanceID'"
}



$Metrics = @(
    'CPUUtilization'
    'CPUCreditUsage'
    'CPUCreditBalance'
    'CPUSurplusCreditBalance'
    'CPUSurplusCreditsCharged'
#    'DiskReadBytes'
#    'DiskReadOps'
#    'DiskWriteBytes'
#    'DiskWriteOps'
#    'NetworkIn'
#    'NetworkOut'
#    'NetworkPacketsIn'
#    'NetworkPacketsOut'
    'StatusCheckFailed'
    'StatusCheckFailed_Instance'
    'StatusCheckFailed_System'
)


$XMLOutput = "<prtg>`n"

$Dimension       = New-Object Amazon.CloudWatch.Model.Dimension
$Dimension.set_Name('InstanceId')
$Dimension.set_Value($InstanceID)

Foreach ($Metric in $Metrics){
    $Params = @{
        Dimension    = $Dimension
        MetricName   = $Metric
        Statistic    = $statistics
        UtcStartTime = $starttime
        UtcEndTime   = $endtime
        Period       = $period
        Namespace    = 'AWS/EC2'
        # Region       = (get-region)
        # StartTime    = $starttime
        # EndTime      = $endtime
        # ProfileName  = $AWSProfileName
        # Dimension    = @{'Name'='InstanceId';'Value'= $InstanceID}
    }
    Write-Debug "Params"
    $Params           | out-string | Write-Debug
    Write-Debug "Params.Dimension"
    $Params.Dimension | out-string | Write-Debug

    Try {
        $stat = Get-CWMetricStatistic @Params
        #$stat.Datapoints | Select Timestamp, Average,Maximum, Minimum | Sort-object Timestamp

        $XMLOutput += Set-PrtgResult $Metric $stat.Datapoints.Average "Count"  -sc
    } catch {
        Write-Warning $_.exception.message
        Set-PrtgError "Unable to get Metric for $($Params.MetricName)"
    }
}


#if ($response -isnot [System.Xml.XmlElement]) {
#	Set-PrtgError $response
#}

#$XMLOutput += Set-PrtgResult "Memory" $($response.Memory.percentmemused) "Percent" -mw 60 -me 80 -sc
#$XMLOutput += Set-PrtgResult "TPS Total" $($response.TPS.Total) "Count" -sc
#$XMLOutput += Set-PrtgResult "TPS SSL" $($response.TPS.SSL) "Count" -sc
#$response.Network | get-member -type Property | foreach-object {
#	$name=$_.Name ;
#	$value=$response.Network."$($_.Name)"
#    $XMLOutput += Set-PrtgResult "$name" $("{0:N1}" -f $((([int]$value.in + [int]$value.out)/[int]$value.speed)*100)) "Percent" -mw 60 -me 80 -sc
#}
$XMLOutput += "</prtg>"

Write-Host $XMLOutput


#$metricName = 'CPUCreditBalance'
#$stat = Get-CWMetricStatistic `
#            -ProfileName $AWSProfileName `
#            -Dimension  @{'Name'='InstanceId';'Value'= $instance} `
#            -MetricName $metricName `
#            -Statistic $statistics `
#            -StartTime $starttime `
#            -EndTime $endtime `
#            -Period $period `
#            -Namespace 'AWS/EC2'
#$stat.Datapoints | Select Timestamp, Average,Maximum, Minimum | Sort-object Timestamp


