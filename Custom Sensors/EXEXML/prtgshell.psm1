﻿###############################################################################
## API Functions
###############################################################################

function Get-PrtgServer {
	<#
	.SYNOPSIS
		Establishes initial connection to PRTG API.

	.DESCRIPTION
		The Get-PrtgServer cmdlet establishes and validates connection parameters to allow further communications to the PRTG API. The cmdlet needs at least three parameters:
			- The server name (without the protocol)
			- An authenticated username
			- A passhash that can be retrieved from the PRTG user's "My Account" page.


		The cmdlet returns an object containing details of the connection, but this can be discarded or saved as desired; the returned object is not necessary to provide to further calls to the API.

	.EXAMPLE
		Get-PrtgServer "prtg.company.com" "jsmith" 1234567890

		Connects to PRTG using the default port (443) over SSL (HTTPS) using the username "jsmith" and the passhash 1234567890.

	.EXAMPLE
		Get-PrtgServer "prtg.company.com" "jsmith" 1234567890 -HttpOnly

		Connects to PRTG using the default port (80) over SSL (HTTP) using the username "jsmith" and the passhash 1234567890.

	.EXAMPLE
		Get-PrtgServer -Server "monitoring.domain.local" -UserName "prtgadmin" -PassHash 1234567890 -Port 8080 -HttpOnly

		Connects to PRTG using port 8080 over HTTP using the username "prtgadmin" and the passhash 1234567890.

	.PARAMETER Server
		Fully-qualified domain name for the PRTG server. Don't include the protocol part ("https://" or "http://").

	.PARAMETER UserName
		PRTG username to use for authentication to the API.

	.PARAMETER PassHash
		PassHash for the PRTG username. This can be retrieved from the PRTG user's "My Account" page.

	.PARAMETER Port
		The port that PRTG is running on. This defaults to port 443 over HTTPS, and port 80 over HTTP.

	.PARAMETER HttpOnly
		When specified, configures the API connection to run over HTTP rather than the default HTTPS.
	#>

	Param (
		[Parameter(Mandatory=$True,Position=0)]
		[ValidatePattern("\d+\.\d+\.\d+\.\d+|(\w\.)+\w")]
		[string]$Server,

		[Parameter(Mandatory=$True,Position=1)]
		[string]$UserName,

		[Parameter(Mandatory=$True,Position=2)]
		[string]$PassHash,

		[Parameter(Mandatory=$False,Position=3)]
		[int]$Port = $null,

		[Parameter(Mandatory=$False)]
		[alias('http')]
		[switch]$HttpOnly
	)

    BEGIN {
		if ($HttpOnly) {
			$Protocol = "http"
			if (!$Port) { $Port = 80 }
		} else {
			$Protocol = "https"
			if (!$Port) { $Port = 443 }

			HelperSSLConfig
		}
    }

    PROCESS {
		$url = HelperURLBuilder "getstatus.xml" -Protocol $Protocol -Server $Server -Port $Port -UserName $UserName -PassHash $PassHash

        $global:lasturl = $url

		$QueryObject = HelperHTTPQuery $url -AsXML
		$Data = $QueryObject.Data

		$Return = "" | Select-Object Server,Port,UserName,Protocol,Version,Clock,IsCluster,IsAdminUser,ReadOnlyUser
		$Return.Server       = $Server
		$Return.Port         = $Port
		$Return.UserName     = $UserName
		$Return.Protocol     = $Protocol
		$Return.Version      = $Data.status.Version
		$Return.Clock        = $Data.status.Clock
		$Return.IsCluster    = $Data.status.IsCluster
		$Return.IsAdminUser  = $Data.status.IsAdminUser
		$Return.ReadOnlyUser = $Data.status.ReadOnlyUser

		$StoredConfiguration = $Return | Select-Object *,PassHash
        $StoredConfiguration.PassHash = $PassHash

        $global:PrtgServerObject = $StoredConfiguration

		HelperFormatTest

		# this is just to be pretty; doesn't contain the passhash
        return $Return
    }
}

###############################################################################

function Get-PrtgObjectDetails {
	<#
	.SYNOPSIS
		Provides details for the specified object.

	.DESCRIPTION
		The Get-PrtgObjectDetails provides metadata about a given object in PRTG. This includes the object name and type, information about the parent device and the probe, last status information, and uptime summaries.

		For objects other than sensors, this will only report around half of the listed values. Sensor objects will return all of the values.

		The Value parameter can be used to return a single named value rather than the complete hash table.

	.EXAMPLE
		Get-PrtgObjectDetails 1002

		Returns details for object 1002, which is typically the Core Server's Probe Device Core Health sensor.

	.EXAMPLE
		Get-PrtgObjectDetails -ObjectId 40 -Value sensortype

		Returns the sensortype of object 40, which is typically the Core Server Prove Device.

	.PARAMETER ObjectId
		An object ID from PRTG. Objects include probes, groups, devices, and sensors, as well as reports, maps, and todos.

	.PARAMETER Value
		If the Value parameter is specified, the cmdlet will return a simple string containing the named value specified.
	#>

    Param (
        [Parameter(Mandatory=$True,Position=0)]
        [int]$ObjectId,

        [Parameter(Mandatory=$False,Position=1)]
        [string]$Value
    )

    BEGIN {
		$PRTG = $Global:PrtgServerObject
		if ($PRTG.Protocol -eq "https") { HelperSSLConfig }
    }

    PROCESS {
		$url = HelperURLBuilder "getsensordetails.xml" (
			"&id=$ObjectId"
		)

        $global:lasturl = $url

		$QueryObject = HelperHTTPQuery $url -AsXML
		$Data = $QueryObject.Data.sensordata.psobject.properties | ? { $_.TypeNameOfValue -eq "System.Xml.XmlElement" }

		$ListOfNames = $Data | ForEach-Object { $_.Name }
		$ListOfValues = $Data | ForEach-Object { $_.Value."#cdata-section" }

		$i = 0

		while ($i -lt $ListOfNames.Count) {
			$Return += @{$ListOfNames[$i]=$ListOfValues[$i]}
			$i++
		}

		if ($Value) {
			$Return.$Value
		} else {
			[Collections.SortedList]$Return
		}
    }
}

###############################################################################

function Get-PrtgObjectType {
	<#
	.SYNOPSIS
		Returns the object of a given object ID.
	.DESCRIPTION
		This cmdlet simply returns a string value identifying the object type of the requested object. It can return "group", "probenode", "device", or "sensor", as well as other object types such as reports and maps. If the -Detailed switch is used, it will also report additional details about sensor types.
	.EXAMPLE
		Get-PrtgObjectType 40

		Reports "device", as object 40 refers to the Core Server device.

	.EXAMPLE
		Get-PrtgObjectType 1002

		Reports "sensor", referring to the Core State sensor on the Core Server device.

	.EXAMPLE
		Get-PrtgObjectType 1002 -Detailed

		Reports "sensor: corestate", referring to the Core State sensor on the Core Server device.

	.PARAMETER ObjectId
		An object ID from PRTG. Objects include probes, groups, devices, and sensors, as well as reports, maps, and todos.

	.PARAMETER Detailed
		If the Detailed switch is set, the cmdlet will return additional details about sensor types (but not group, device, probenode, or other object types).
	#>

    Param (
        [Parameter(Mandatory=$True,Position=0)]
        [int]$ObjectId,

        [Parameter(Mandatory=$False)]
        [switch]$Detailed
    )

	$ObjectDetails = Get-PrtgObjectDetails $ObjectId

	if ($ObjectDetails.interval) {
		if ($ObjectDetails.interval -eq "(Object not found)") {
			# well, why didn't you just say so
			return $ObjectDetails.sensortype
		} else {
			# if it reports an interval, it's a sensor
			if ($Detailed) {
				return ("sensor: " + $ObjectDetails.sensortype)
			} else {
				return "sensor"
			}
		}
	} else {
		# if it doesn't, the sensortype says what it is
		return $ObjectDetails.sensortype
	}
}

###############################################################################

function Get-PrtgTableData {
	<#
		.SYNOPSIS
			Returns a PowerShell object containing data from the specified object in PRTG.

		.DESCRIPTION
			The Get-PrtgTableData cmdlet can return data of various different content types using the specified parent object, as well as specify the return columns or filtering options. The input formats generally coincide with the Live Data demo from the PRTG API documentation, but there are some content types that the cmdlet does not yet support, such as "sensortree".

		.PARAMETER Content
			The type of data to return about the specified object. Valid values are "devices", "groups", "sensors", "todos", "messages", "values", "channels", and "history". Note that all content types are not valid for all object types; for example, a device object can contain no groups or channels.

		.PARAMETER ObjectId
			An object ID from PRTG. Objects include probes, groups, devices, and sensors, as well as reports, maps, and todos.

		.PARAMETER Columns
			A string array of named column values to return. In general the default return values for a given content type will return all of the available columns; this parameter can be used to change the order of columns or specify which columns to include or ignore.

		.PARAMETER FilterTags
			A string array of sensor tags. This parameter only has any effect if the content type is "sensor". Output will only include sensors with the specified tags. Note that specifying multiple tags performs a logical OR of tags.

		.PARAMETER Count
			Number of records to return. PRTG's internal default for this is 500. Valid values are 1-50000.

		.PARAMETER Raw
			If this switch is set, the cmdlet will return the raw XML data rather than a PowerShell object.

		.EXAMPLE
			Get-PrtgTableData groups 1

			Returns the groups under the object ID 1, which is typically the Core Server's Local Probe.

		.EXAMPLE
			Get-PrtgTableData sensors -FilterTags corestatesensor,probesensor

			Returns a filtered list of sensors tagged with "corestatesensor" or "probesensor".

		.EXAMPLE
			Get-PrtgTableData messages 1002

			Returns the messages log for device 1002.
	#>

	Param (
		[Parameter(Mandatory=$True,Position=0)]
		[ValidateSet("devices","groups","sensors","todos","messages","values","channels","history")]
		[string]$Content,

		[Parameter(Mandatory=$false,Position=1)]
		[int]$ObjectId = 0,

		[Parameter(Mandatory=$False)]
		[string[]]$Columns,

		[Parameter(Mandatory=$False)]
		[string[]]$FilterTags,

		[Parameter(Mandatory=$False)]
		[int]$Count,

		[Parameter(Mandatory=$False)]
		[switch]$Raw
	)

	<# things to add

		filter_drel (content = messages only) today, yesterday, 7days, 30days, 12months, 6months - filters messages by timespan
		filter_status (content = sensors only) Unknown=1, Collecting=2, Up=3, Warning=4, Down=5, NoProbe=6, PausedbyUser=7, PausedbyDependency=8, PausedbySchedule=9, Unusual=10, PausedbyLicense=11, PausedUntil=12, DownAcknowledged=13, DownPartial=14 - filters messages by status
		sortby = sorts on named column, ascending (or decending with a leading "-")
		filter_xyz - fulltext filtering. this is a feature in its own right

	#>

	BEGIN {
		$PRTG = $Global:PrtgServerObject
		if ($PRTG.Protocol -eq "https") { HelperSSLConfig }

		if ($Count) {
			$CountString = "&count=$Count"
		}


		if ($Content -eq "sensors" -and $FilterTags) {
			$FilterString = ""

			foreach ($tag in $FilterTags) {
				$FilterString += "&filter_tags=" + $tag
			}
		}

		if (!$Columns) {

			# this was pulled mostly from the API doc, with some minor adjustments
			# this function currently doesn't work with "sensortree" or any of the nonspecific values: "reports","maps","storedreports"

			$TableValues = "devices","groups","sensors","todos","messages","values","channels","history"
			$TableColumns =
				@("objid","probe","group","device","host","downsens","partialdownsens","downacksens","upsens","warnsens","pausedsens","unusualsens","undefinedsens"),
				@("objid","probe","group","name","downsens","partialdownsens","downacksens","upsens","warnsens","pausedsens","unusualsens","undefinedsens"),
				@("objid","probe","group","device","sensor","status","message","lastvalue","lastvalue_raw","priority","favorite"),
				@("objid","datetime","name","status","priority","message"),
				@("objid","datetime","parent","type","name","status","message"),
				@("datetime","value_","coverage"),
				@("name","lastvalue","lastvalue_raw"),
				@("dateonly","timeonly","user","message")

			$PRTGTableBuilder = @()

			for ($i = 0; $i -le $TableValues.Count; $i++) {
				$ThisRow = "" | Select-Object @{ n='content'; e={ $TableValues[$i] } },@{ n='columns'; e={ $TableColumns[$i] } }
				$PRTGTableBuilder += $ThisRow
			}

			$SelectedColumns = ($PRTGTableBuilder | ? { $_.content -eq $Content }).columns
		} else {
			$SelectedColumns = $Columns
		}

		$SelectedColumnsString = $SelectedColumns -join ","

		$HTMLColumns = @("downsens","partialdownsens","downacksens","upsens","warnsens","pausedsens","unusualsens","undefinedsens","message","favorite")
	}

	PROCESS {

		$url = HelperURLBuilder "table.xml" (
			"&content=$Content",
			"&columns=$SelectedColumnsString",
			"&id=$ObjectId",
			$FilterString,
			$CountString
		)

		$Global:LastUrl = $Url

		if ($Raw) {
			$QueryObject = HelperHTTPQuery $url
			return $QueryObject.Data
		}

		$QueryObject = HelperHTTPQuery $url -AsXML
		$Data = $QueryObject.Data

		$ReturnData = @()

		foreach ($item in $Data.$Content.item) {
			$ThisRow = "" | Select-Object $SelectedColumns
			foreach ($Prop in $SelectedColumns) {
				if ($Content -eq "channels" -and $Prop -eq "lastvalue_raw") {
					# fix a bizarre formatting bug
					$ThisRow.$Prop = HelperFormatHandler $item.$Prop
				} elseif ($HTMLColumns -contains $Prop) {
					# strip HTML, leave bare text
					$ThisRow.$Prop =  $item.$Prop -replace "<[^>]*?>|<[^>]*>", ""
				} else {
					$ThisRow.$Prop = $item.$Prop
				}
			}
			$ReturnData += $ThisRow
		}

		if ($ReturnData.name -eq "Item" -or (!($ReturnData.ToString()))) {
			$DeterminedObjectType = Get-PrtgObjectType $ObjectId

			$ValidQueriesTable = @{
				group=@("devices","groups","sensors","todos","messages","values","history")
				probenode=@("devices","groups","sensors","todos","messages","values","history")
				device=@("sensors","todos","messages","values","history")
				sensor=@("messages","values","channels","history")
				report=@("Currently unsupported")
				map=@("Currently unsupported")
				storedreport=@("Currently unsupported")
			}

			Write-Host "No $Content; Object $ObjectId is type $DeterminedObjectType"
			Write-Host (" Valid query types: " + ($ValidQueriesTable.$DeterminedObjectType -join ", "))
		} else {
			return $ReturnData
		}
	}
}

###############################################################################

function Set-PrtgObjectProperty {
        <#
        .SYNOPSIS

        .DESCRIPTION

        .EXAMPLE

        #>

    Param (
        [Parameter(Mandatory=$True,Position=0)]
        [int]$ObjectId,

        [Parameter(Mandatory=$True,Position=1)]
        [string]$Property,

        [Parameter(Mandatory=$True,Position=2)]
        [string]$Value
    )

    BEGIN {
                $PRTG = $Global:PrtgServerObject
                if ($PRTG.Protocol -eq "https") { HelperSSLConfig }
                $WebClient = New-Object System.Net.WebClient
    }

    PROCESS {
                $url = HelperURLBuilder "setobjectproperty.htm" (
                        "&id=$ObjectId",
                        "&name=$Property",
                        "&value=$Value"
                )

        $global:lasturl = $url
        $global:Response = ($WebClient.DownloadString($url)) -replace "<[^>]*?>|<[^>]*>", ""

        return "" | select @{n='ObjectID';e={$ObjectId}},@{n='Property';e={$Property}},@{n='Value';e={$Value}},@{n='Response';e={$global:Response}}
    }
}


###############################################################################

function Get-PrtgObjectProperty {
	<#
	.SYNOPSIS

	.DESCRIPTION

	.EXAMPLE

	#>

    Param (
        [Parameter(Mandatory=$True,Position=0)]
		[alias('DeviceId')]
        [int]$ObjectId,

        [Parameter(Mandatory=$True,Position=1)]
        [string]$Property
    )

    BEGIN {
		$PRTG = $Global:PrtgServerObject
		if ($PRTG.Protocol -eq "https") { HelperSSLConfig }
    }

    PROCESS {
		$url = HelperURLBuilder "getobjectproperty.htm" (
			"&id=$ObjectId",
			"&name=$Property",
			"&show=text"
		)

        $global:lasturl = $url

		$QueryObject = HelperHTTPQuery $url -AsXML
		$Data = $QueryObject.Data

        return $Data.prtg.result
    }
}

###############################################################################

function Move-PrtgObject {
	<#
	.SYNOPSIS

	.DESCRIPTION

	.EXAMPLE

	#>

    Param (
        [Parameter(Mandatory=$True,Position=0)]
		[alias('SensorId')]
        [int]$ObjectId,

        [Parameter(Mandatory=$True,Position=1)]
        [ValidateSet("up","down","top","bottom")]
        [string]$Position
    )

    BEGIN {
		$PRTG = $Global:PrtgServerObject
		if ($PRTG.Protocol -eq "https") { HelperSSLConfig }
		$WebClient = New-Object System.Net.WebClient
    }

    PROCESS {
		$url = HelperURLBuilder "setposition.htm" (
			"&id=$ObjectId",
			"&newpos=$Position"
		)

        $global:lasturl = $url
        $global:Response = $WebClient.DownloadString($url)

        return $global:Response
    }
}

###############################################################################

function Copy-PrtgObject {
	<#
	.SYNOPSIS

	.DESCRIPTION

	.EXAMPLE

	#>

    Param (
        [Parameter(Mandatory=$True,Position=0)]
		[alias('SensorId')]
        [int]$ObjectId,

        [Parameter(Mandatory=$True,Position=1)]
        [string]$Name,

        [Parameter(Mandatory=$True,Position=2)]
        [string]$TargetId
    )

    BEGIN {
		$PRTG = $Global:PrtgServerObject
		if ($PRTG.Protocol -eq "https") { HelperSSLConfig }
		$WebClient = New-Object System.Net.WebClient
    }

    PROCESS {
		$url = HelperURLBuilder "duplicateobject.htm" (
			"&id=$ObjectId",
			"&name=$Name",
			"&targetid=$TargetId"
		)

        $global:lasturl = $url

        $NewIdRx = [regex] '(?<=id%3D)\d+'

		###########################################
		# can we let the http function handle this?

        $Req = [system.net.httpwebrequest]::create($url)
        $Res = $Req.GetResponse()
        if ($Res.StatusCode -eq "OK") {
            return $NewIDRx.Match($Res.ResponseUri.PathAndQuery).value
        } else {
            Throw "Error Accessing Page $WebPage"
        }
    }
}

###############################################################################

function Remove-PrtgObject {
	<#
	.SYNOPSIS

	.DESCRIPTION

	.EXAMPLE

	#>

    Param (
        [Parameter(Mandatory=$True,Position=0)]
        $ObjectId
        #TODO: document this; $ObjectID for this cmdlet can either be a single integer or a comma-separated string of integers to handle multiples
    )

    BEGIN {
		$PRTG = $Global:PrtgServerObject
		if ($PRTG.Protocol -eq "https") { HelperSSLConfig }
		$WebClient = New-Object System.Net.WebClient
    }

    PROCESS {
		$url = HelperURLBuilder "deleteobject.htm" (
			"&id=$ObjectId",
			"&approve=1"
		)

        $global:lasturl = $url
        $global:Response = $WebClient.DownloadString($url)

        return $global:Response
    }
}

###############################################################################

function Resume-PrtgObject {
	<#
	.SYNOPSIS

	.DESCRIPTION

	.EXAMPLE

	#>

    Param (
        [Parameter(Mandatory=$True,Position=0)]
        [int]$ObjectId
    )

    BEGIN {
		$PRTG = $Global:PrtgServerObject
		if ($PRTG.Protocol -eq "https") { HelperSSLConfig }
		$WebClient = New-Object System.Net.WebClient
    }

    PROCESS {
		$url = HelperURLBuilder "pause.htm" (
			"&id=$ObjectId",
			"&action=1"
		)

        $global:lasturl = $url
        $global:Response = $WebClient.DownloadString($url)

		###########################################
		# this needs a handler; the output is silly
        return $global:Response
    }
}


###############################################################################


function Suspend-PrtgObject {
	<#
	.SYNOPSIS

	.DESCRIPTION

	.EXAMPLE

	#>

    Param (
        [Parameter(Mandatory=$True,Position=0)]
        [int]$ObjectId,
	    [Parameter(Mandatory=$False,Position=1)]
        [string]$PauseMessage = ""
    )

    BEGIN {
		$PRTG = $Global:PrtgServerObject
		if ($PRTG.Protocol -eq "https") { HelperSSLConfig }
		$WebClient = New-Object System.Net.WebClient
    }

    PROCESS {
		$url = HelperURLBuilder "pause.htm" (
			"&id=$ObjectId",
			"&pausemsg=$PauseMessage",
			"&action=0"
		)

        $global:lasturl = $url
        $global:Response = $WebClient.DownloadString($url)

		###########################################
		# this needs a handler; the output is silly
        return $global:Response
    }
}




###############################################################################
# This is definitely incomplete but works in extremely limited use cases
# todo:
#   adjust "avg" value, which sets the interval of data returned

function Get-PrtgSensorHistoricData {
	<#
	.SYNOPSIS

	.DESCRIPTION

	.EXAMPLE

	#>

    Param (
        [Parameter(Mandatory=$True,Position=0)]
        [int]$SensorId,

		# really, this should be a (negative) timespan
        [Parameter(Mandatory=$True,Position=1)]
        [int]$HistoryInDays,

		[Parameter(Mandatory=$false,Position=2)]
        [string]$ChannelName
    )

    BEGIN {
		$PRTG = $Global:PrtgServerObject
		if ($PRTG.Protocol -eq "https") { HelperSSLConfig }

		$HistoryTimeStart = ((Get-Date).AddDays([System.Math]::Abs($HistoryInDays) * (-1))).ToString("yyyy-MM-dd-HH-mm-ss")
		$HistoryTimeEnd = (Get-Date).ToString("yyyy-MM-dd-HH-mm-ss")

		# /api/historicdata.xml?id=objectid&avg=0&sdate=2009-01-20-00-00-00&edate=2009-01-21-00-00-00
    }

    PROCESS {
		$url = HelperURLBuilder "historicdata.xml" (
			"&id=$SensorId",
			"&sdate=$HistoryTimeStart",
			"&edate=$HistoryTimeEnd"
		)

        $Global:LastUrl = $Url

		$QueryObject = HelperHTTPQuery $url -AsXML
		$Data = $QueryObject.Data

		$ValidData = $Data.histdata.item | ? { $_.coverage_raw -ne '0000000000' }

		$DataPoints = @()

		foreach ($v in $ValidData) {
			$Channels = @()
			foreach ($val in $v.value) {
				$NewChannel          = "" | Select Channel,Value
				$NewChannel.Channel  = $val.channel
				$NewChannel.Value    = $val.'#text'
				$Channels           += $NewChannel
			}

			$ChannelsRaw = @()
			foreach ($vr in $v.value_raw) {
				$NewChannel          = "" | Select Channel,Value
				$NewChannel.Channel  = $vr.channel
				$NewChannel.Value    = [double]$vr.'#text'
				$ChannelsRaw        += $NewChannel
			}

			$New             = "" | Select DateTime,Channels,ChannelsRaw
			$New.Datetime    = [DateTime]::Parse(($v.datetime.split("-"))[0]) # need to do a datetime conversion here
			$New.Channels    = $Channels
			$New.ChannelsRaw = $ChannelsRaw

			$DataPoints += $New
		}

	}

	END {
		return $DataPoints
    }
}


function Measure-PRTGStorage {

    Param (
        [Parameter(Mandatory=$True,Position=0)]
        [int]$HistorySensorObjectId,

        [Parameter(Mandatory=$False,Position=1)]
        [int]$HistoryInDays = 30
    )

	$ObjectDetails = Get-PrtgObjectDetails $HistorySensorObjectId

	if ($ObjectDetails.sensortype -ne "exexml") {
		return " Selected sensor object (" + $HistorySensorObjectId + ": " + $ObjectDetails.name + ") is not the proper type."
	}

	$HistorySensorData = Get-PrtgSensorHistoricData $HistorySensorObjectId $HistoryInDays

	$OldestDataPointDate = $HistorySensorData[0].DateTime
	$OldestDataPointSize = ($HistorySensorData[0].ChannelsRaw | ? { $_.Channel -match "History Size$" }).Value

	$NewestDataPointDate = $HistorySensorData[$HistorySensorData.Count-1].DateTime
	$NewestDataPointSize = ($HistorySensorData[$HistorySensorData.Count-1].ChannelsRaw | ? { $_.Channel -match "History Size$" }).Value

	$HistorySizeGain = $NewestDataPointSize - $OldestDataPointSize
	$MeasuredPeriod = $NewestDataPointDate - $OldestDataPointDate

	$DailyGrowthRate = $HistorySizeGain / $MeasuredPeriod.TotalDays
	$RemainingDiskFree = ($HistorySensorData[$HistorySensorData.Count-1].ChannelsRaw | ? { $_.Channel -match "Disk Free$" }).Value
	$MonitorableDaysAtCurrentGrowthRate = $RemainingDiskFree / $DailyGrowthRate

	if ($MonitorableDaysAtCurrentGrowthRate) {
		Write-Host " PRTG has" ("{0:N}" -f $RemainingDiskFree) "GB remaining disk available and" ("{0:N}" -f $NewestDataPointSize) "GB of monitoring data stored."
		Write-Host " The history size monitor reports an average daily growth rate of" ("{0:N}" -f $DailyGrowthRate) "GB over a period of" ("{0:N}" -f $MeasuredPeriod.TotalDays) "days."
		Write-Host " There is enough space available to store monitoring data for" ("{0:N}" -f $MonitorableDaysAtCurrentGrowthRate) "days."
	} else {
		Write-Host " Sensor does not appear to be a history database size monitor sensor."
	}
}


###############################################################################
# this needs to be combined somehow with "Move-PrtgObject" from above
# if you want positional changes, you give the string nouns
# if you want group changes, you give an integer for the target objectid

function Move-PrtgObject2 {
	<#
	.SYNOPSIS

	.DESCRIPTION

	.EXAMPLE

	#>

    Param (
        [Parameter(Mandatory=$True,Position=0)]
		[alias('SensorId')]
        [int]$ObjectId,

        [Parameter(Mandatory=$True,Position=1)]
        [string]$TargetId
    )

    BEGIN {
		$PRTG = $Global:PrtgServerObject
		if ($PRTG.Protocol -eq "https") { HelperSSLConfig }
		$WebClient = New-Object System.Net.WebClient
    }

    PROCESS {
		$url = HelperURLBuilder "moveobject.htm" (
			"&id=$ObjectId",
			"&targetid=$TargetId"
		)

        $global:lasturl = $url

        $NewIdRx = [regex] '(?<=id%3D)\d+'

		###########################################
		# can we let the http function handle this?

        $Req = [system.net.httpwebrequest]::create($url)
        $Res = $Req.GetResponse()
        if ($Res.StatusCode -eq "OK") {
            return $NewIDRx.Match($Res.ResponseUri.PathAndQuery).value
        } else {
            Throw "Error Accessing Page $WebPage"
        }
    }
}


###############################################################################
# custom exe/xml functions

function Set-PrtgResult {
    Param (
    [Parameter(mandatory=$True,Position=0)]
    [string]$Channel,

    [Parameter(mandatory=$True,Position=1)]
    $Value,

    [Parameter(mandatory=$True,Position=2)]
    [string]$Unit,

    [Parameter(mandatory=$False)]
    [alias('mw')]
    [string]$MaxWarn,

    [Parameter(mandatory=$False)]
    [alias('minw')]
    [string]$MinWarn,

    [Parameter(mandatory=$False)]
    [alias('me')]
    [string]$MaxError,

    [Parameter(mandatory=$False)]
    [alias('mine')]
    [string]$MinError,

    [Parameter(mandatory=$False)]
    [alias('wm')]
    [string]$WarnMsg,

    [Parameter(mandatory=$False)]
    [alias('em')]
    [string]$ErrorMsg,

    [Parameter(mandatory=$False)]
    [alias('mo')]
    [string]$Mode,

    [Parameter(mandatory=$False)]
    [alias('sc')]
    [switch]$ShowChart,

    [Parameter(mandatory=$False)]
    [alias('ss')]
    [ValidateSet("One","Kilo","Mega","Giga","Tera","Byte","KiloByte","MegaByte","GigaByte","TeraByte","Bit","KiloBit","MegaBit","GigaBit","TeraBit")]
    [string]$SpeedSize,

	[Parameter(mandatory=$False)]
    [ValidateSet("One","Kilo","Mega","Giga","Tera","Byte","KiloByte","MegaByte","GigaByte","TeraByte","Bit","KiloBit","MegaBit","GigaBit","TeraBit")]
    [string]$VolumeSize,

    [Parameter(mandatory=$False)]
    [alias('dm')]
    [ValidateSet("Auto","All")]
    [string]$DecimalMode,

    [Parameter(mandatory=$False)]
    [alias('w')]
    [switch]$Warning,

    [Parameter(mandatory=$False)]
    [string]$ValueLookup
    )

    $StandardUnits = @("BytesBandwidth","BytesMemory","BytesDisk","Temperature","Percent","TimeResponse","TimeSeconds","Custom","Count","CPU","BytesFile","SpeedDisk","SpeedNet","TimeHours")
    $LimitMode = $false

    $Result  = "  <result>`n"
    $Result += "    <channel>$Channel</channel>`n"
    $Result += "    <value>$Value</value>`n"

    if ($StandardUnits -contains $Unit) {
        $Result += "    <unit>$Unit</unit>`n"
    } elseif ($Unit) {
        $Result += "    <unit>custom</unit>`n"
        $Result += "    <customunit>$Unit</customunit>`n"
    }

	if (!($Value -is [int])) { $Result += "    <float>1</float>`n" }
    if ($Mode)        { $Result += "    <mode>$Mode</mode>`n" }
    if ($MaxWarn)     { $Result += "    <limitmaxwarning>$MaxWarn</limitmaxwarning>`n"; $LimitMode = $true }
    if ($MinWarn)     { $Result += "    <limitminwarning>$MinWarn</limitminwarning>`n"; $LimitMode = $true }
    if ($MaxError)    { $Result += "    <limitmaxerror>$MaxError</limitmaxerror>`n"   ; $LimitMode = $true }
    if ($MinError)    { $Result += "    <limitMinError>$MinError</limitMinError>`n"   ; $LimitMode = $true }
    if ($WarnMsg)     { $Result += "    <limitwarningmsg>$WarnMsg</limitwarningmsg>`n"; $LimitMode = $true }
    if ($ErrorMsg)    { $Result += "    <limiterrormsg>$ErrorMsg</limiterrormsg>`n"   ; $LimitMode = $true }
    if ($LimitMode)   { $Result += "    <limitmode>1</limitmode>`n" }
    if ($SpeedSize)   { $Result += "    <speedsize>$SpeedSize</speedsize>`n" }
    if ($VolumeSize)  { $Result += "    <volumesize>$VolumeSize</volumesize>`n" }
    if ($DecimalMode) { $Result += "    <decimalmode>$DecimalMode</decimalmode>`n" }
    if ($Warning)     { $Result += "    <warning>1</warning>`n" }
    if ($ValueLookup) { $Result += "    <ValueLookup>$ValueLookup</ValueLookup>`n" }

    if (!($ShowChart)) { $Result += "    <showchart>0</showchart>`n" }

    $Result += "  </result>`n"

    return $Result
}



function Set-PrtgError {
	Param (
		[Parameter(Position=0)]
		[string]$PrtgErrorText
	)

	@"
<prtg>
	<error>1</error>
	<text>$PrtgErrorText</text>
</prtg>
"@

exit
}

function New-PrtgSnmpTrafficSensor {
    Param (
        [Parameter(Mandatory=$True)]
        [string]$Name,

        [Parameter(Mandatory=$True)]
        [int]$InterfaceNumber,

        [Parameter(Mandatory=$True)]
        [int]$ParentId,

        [Parameter(Mandatory=$False)]
        [string]$Tags,

        [Parameter(Mandatory=$False)]
        [ValidateRange(1,5)]
        [int]$Priority = 3,

        [Parameter(Mandatory=$False)]
        [int]$Interval = 60,

        [Parameter(Mandatory=$False)]
        [ValidateSet("Independent","Stacked","PosNeg")]
        [String]$ChartType = "Independent",

        [Parameter(Mandatory=$False)]
        [switch]$ErrorOnDown = $True,

        [Parameter(Mandatory=$False)]
        [switch]$ShowErrors,

        [Parameter(Mandatory=$False)]
        [switch]$ShowDiscards,

        [Parameter(Mandatory=$False)]
        [switch]$ShowUnicast,

        [Parameter(Mandatory=$False)]
        [switch]$ShowNonUnicast,

        [Parameter(Mandatory=$False)]
        [switch]$ShowMulticast,

        [Parameter(Mandatory=$False)]
        [switch]$ShowBroadcast,

        [Parameter(Mandatory=$False)]
        [switch]$ShowUnknown
    )

    BEGIN {
        Add-Type -AssemblyName System.Web # Needed for System.Web.HttpUtility
        $PRTG = $Global:PrtgServerObject
		if ($PRTG.Protocol -eq "https") { HelperSSLConfig }
    }

    PROCESS {


        ###############################################################################
        # build the post data payload/query string
        # note that "$QueryString.ToString()" actually builds this

        $QueryStringTable = @{
			"name_"                  = $Name
			"tags_"                  = "prtgshell snmptrafficsensor bandwidthsensor $Tags"
			"priority_"              = $Priority
            "interfacenumber_"       = 1
            "interfacenumber__check" = "$InterfaceNumber`:$Name|$Name|Connected|1 GBit/s|Ethernet|1|$Name|1000000000|3|2|" # don't know what the 3|2 are, or if the other bits matter
            "namein_"                = "Traffic In"
            "nameout_"               = "Traffic Out"
            "namesum_"               = "Traffic Total"
            "stack_"                 = 0
			"intervalgroup"          = 1
			"interval_"              = "$Interval|$Interval seconds"
			"inherittriggers"        = 1
			"id"                     = $ParentId
			"sensortype"             = "snmptraffic"
        }

        # create a blank, writable HttpValueCollection object
        $QueryString = [System.Web.httputility]::ParseQueryString("")

        # iterate through the hashtable and add the values to the HttpValueCollection
        foreach ($Pair in $QueryStringTable.GetEnumerator()) {
			$QueryString[$($Pair.Name)] = $($Pair.Value)
        }

        ###############################################################################
        # Add TrafficMode

        $TrafficMode = @()
        if ($ShowErrors)     { $TrafficMode += "errors"     }
        if ($ShowDiscards)   { $TrafficMode += "discards"   }
        if ($ShowUnicast)    { $TrafficMode += "unicast"    }
        if ($ShowNonUnicast) { $TrafficMode += "nonunicast" }
        if ($ShowMulticast)  { $TrafficMode += "multicast"  }
        if ($ShowBroadcast)  { $TrafficMode += "broadcast"  }
        if ($ShowUnknown)    { $TrafficMode += "unknown"    }

        foreach ($t in $TrafficMode) {
            $QueryString.Add("trafficmode_",$t)
        }

        ###############################################################################
        # fire the api call

        $Url  = "https://$($PRTG.Server)"
        $Url += "/addsensor5.htm?"
        $Url += "username=$($PRTG.UserName)&"
        $Url += "passhash=$($PRTG.PassHash)"

        HelperHTTPPostCommand $Url $QueryString.ToString() | Out-Null
    }
}


###############################################################################
## Alias Defintions and Alias-Only Functions
###############################################################################

# all of these aliases are in place for backwards compatibility with Brian's scripts
# once he fixes them, these can be removed
Set-Alias Get-PrtgObjectProp Get-PrtgObjectProperty
Set-Alias Copy-PrtgSensor Copy-PrtgObject
Set-Alias Rename-PrtgSensor Rename-PrtgObject
Set-Alias Move-PrtgSensor Move-PrtgObject

function Get-PrtgSensorChannels {
	<#
		.SYNOPSIS

		.DESCRIPTION

		.EXAMPLE
	#>

	Param (
		[Parameter(Mandatory=$True,Position=0)]
		[int]$SensorId
	)

	Get-PrtgTableData channels $SensorId
}

###############################################################################

function Get-PrtgParentProbe {
	<#
	.SYNOPSIS

	.DESCRIPTION

	.EXAMPLE

	#>

    Param (
        [Parameter(Mandatory=$True,Position=0)]
        [int]$DeviceId
    )

	Get-PrtgObjectDetails $DeviceId -Value probename
}

###############################################################################

function Get-PrtgDeviceSensors {
	<#
	.SYNOPSIS

	.DESCRIPTION

	.EXAMPLE

	#>

    Param (
        [Parameter(Mandatory=$True,Position=0)]
        [int]$DeviceId
    )

	Get-PrtgTableData sensors $DeviceId
}

###############################################################################

function Get-PrtgDeviceSensorsByTag {
	<#
	.SYNOPSIS

	.DESCRIPTION

	.EXAMPLE

	#>

    Param (
        [Parameter(Mandatory=$True,Position=0)]
        [string[]]$FilterTags,

        [Parameter(Mandatory=$False,Position=1)]
        [int]$SensorId
    )

    Get-PrtgTableData sensors -FilterTags $FilterTags
}

###############################################################################

function Rename-PrtgObject {
	<#
	.SYNOPSIS

	.DESCRIPTION

	.EXAMPLE

	#>

    Param (
        [Parameter(Mandatory=$True,Position=0)]
		[alias('SensorId')]
        [int]$ObjectId,

        [Parameter(Mandatory=$True,Position=1)]
        [string]$NewName
    )

    PROCESS {
		return Set-PrtgObjectProperty $ObjectId "name" $NewName
    }
}

###############################################################################
# these have also not been extensively tested



function Get-PrtgSensorTree {
    Param (
        [Parameter(Mandatory=$False,Position=0)]
        [int]$ObjectId,

        [Parameter(Mandatory=$False,Position=1)]
        [string]$Value
    )

    BEGIN {
		$PRTG = $Global:PrtgServerObject
		if ($PRTG.Protocol -eq "https") { HelperSSLConfig }
    }

    PROCESS {
		$url = HelperURLBuilder "table.xml" (
			"&content=sensortree"
		)

        $global:lasturl = $url

		$QueryObject = HelperHTTPQuery $url -AsXML

		return $QueryObject
    }
}


function Get-PRTGProbes {
	$data = Get-PrtgSensorTree
	foreach ($node in $data.data.prtg.sensortree.nodes.group.probenode) {
		$node | Select-Object @{n='objid';e={ $_.id[0] }},name
	}
}



function Remove-PrtgSensorNumbers {
    Param (
        [Parameter(Mandatory=$True,Position=0)]
        [int]$ObjectId
	)

	$ObjectType = (Get-PrtgObjectDetails $ObjectId).sensortype

	if ($ObjectType -eq "device") {

		$ObjectSensors = Get-PrtgTableData sensors $ObjectId | select objid,sensor
		$regex = [regex]"\s\d+$"

		foreach ($Sensor in $ObjectSensors) {
			$SensorName = $Sensor.sensor -replace $regex

			$ReturnName = $Sensor.sensor + " -> " + $SensorName
			$ReturnValue = $(Set-PrtgObjectProperty -ObjectId $Sensor.objid -Property name -Value $SensorName) -replace "<[^>]*?>|<[^>]*>", ""

			"" | Select @{n='Name Change';e={$ReturnName}},@{n='Return Code';e={$ReturnValue}}
		}
	} else {
		Write-Error "Object must be a device; provided object is type $ObjectType."
	}
}



function Invoke-PrtgObjectDiscovery {
        <#
        .SYNOPSIS

        .DESCRIPTION

        .EXAMPLE

        #>

    Param (
        [Parameter(Mandatory=$True,Position=0)]
        [int]$ObjectId
    )

    BEGIN {
                $PRTG = $Global:PrtgServerObject
                if ($PRTG.Protocol -eq "https") { HelperSSLConfig }
                $WebClient = New-Object System.Net.WebClient
    }

    PROCESS {
                $url = HelperURLBuilder "discovernow.htm" (
                        "&id=$ObjectId"
                )

        $global:lasturl = $url
        $global:Response = $WebClient.DownloadString($url)

        return $global:Response -replace "<[^>]*?>|<[^>]*>", ""
    }
}

function New-PrtgSensor {
    Param (
        [Parameter(Mandatory=$True,Position=0)]
        [psobject]$PrtgObject
    )

    BEGIN {
        Add-Type -AssemblyName System.Web # Needed for System.Web.HttpUtility
        $PRTG = $Global:PrtgServerObject
		if ($PRTG.Protocol -eq "https") { HelperSSLConfig }
    }

    PROCESS {

    ###############################################################################
    # Tediously inspect the Object, needs more c#, maybe?

    $PropertyTypes = @{
						Name            = "String"
						Tags            = "String"
						Priority        = "Int32"
						Script          = "String"
						ExeParams       = "String"
						Environment     = "Int32"
						SecurityContext = "Int32"
						Mutex           = "String"
						ExeResult       = "Int32"
						ParentId        = "Int32"}

    foreach ($p in $PropertyTypes.GetEnumerator()) {
        $PropName  = $p.Name
        $PropValue = $PrtgObject."$PropName"
        $Type      = $PrtgObject."$PropName".GetType().Name

        if ($Type -eq $p.Value) {
            switch ($PropName) {
                priority {
                    if (($PropValue -lt 1) -or ($PropValue -gt 5)) {
                        $ErrorMessage = "Error creating Sensor $($Prtgobject.Name). $PropName is $PropValue, must be a integer from 1 to 5."
                    }
                }
                { ($_ -eq "environment") -or ($_ -eq "securitycontext") } {
                    if (($PropValue -lt 0) -or ($PropValue -gt 1)) {
                        $ErrorMessage = "Error creating Sensor $($Prtgobject.Name). $PropName is $PropValue, must be a integer from 0 to 1."
                    }
                }
                exeresult {
                    if (($PropValue -lt 0) -or ($PropValue -gt 2)) {
                        $ErrorMessage = "Error creating Sensor $($Prtgobject.Name). $PropName is $PropValue, must be a integer from 0 to 1."
                    }
                }
            }
        } else {
            $ErrorMessage = "Error creating Sensor $($Prtgobject.Name), $($p.Name) is $Type, should be $($p.Value)"
        }
        if ($ErrorMessage) { return $ErrorMessage }
    }

    ###############################################################################
    # build the post data payload/query string
    # note that "$QueryString.ToString()" actually builds this

    $QueryStringTable = @{
		"name_" = $PrtgObject.Name
		"tags_" = $PrtgObject.Tags
		"priority_" = $PrtgObject.Priority
		"exefile_" = "$($PrtgObject.Script)|$$(PrtgObject.Script)||" # WHAT THE FUCK
		"exefilelabel" = ""
		"exeparams_" = $PrtgObject.ExeParams
		"environment_" = $PrtgObject.Environment
		"usewindowsauthentication_" = $PrtgObject.SecurityContext
		"mutexname_" = $PrtgObject.Mutex
		"timeout_" = 60
		"writeresult_" = $PrtgObject.ExeResult
		"intervalgroup" = 1
		"interval_" = "60|60 seconds"
		"inherittriggers" = 1
		"id" = $PrtgObject.ParentId
		"sensortype" = "exexml"
    }

    # create a blank, writable HttpValueCollection object
    $QueryString = [System.Web.httputility]::ParseQueryString("")

    # iterate through the hashtable and add the values to the HttpValueCollection
    foreach ($Pair in $QueryStringTable.GetEnumerator()) {
		$QueryString[$($Pair.Name)] = $($Pair.Value)
    }

    ###############################################################################
    # fire the api call

    $Url  = "https://$($PRTG.Server)"
    $Url += "/addsensor5.htm?"
    $Url += "username=$($PRTG.UserName)&"
    $Url += "passhash=$($PRTG.PassHash)"
    #$Url

    HelperHTTPPostCommand $Url $QueryString.ToString() | Out-Null

    }
}

###############################################################################

function New-PrtgSnmpCpuLoadSensor {
    Param (
        [Parameter(Mandatory=$True)]
        [string]$Name,

        [Parameter(Mandatory=$True)]
        [int]$ParentId,

        [Parameter(Mandatory=$False)]
        [string]$Tags,

        [Parameter(Mandatory=$False)]
        [ValidateRange(1,5)]
        [int]$Priority = 3,

        [Parameter(Mandatory=$False)]
        [int]$Interval = 60
    )

    BEGIN {
        Add-Type -AssemblyName System.Web # Needed for System.Web.HttpUtility
        $PRTG = $Global:PrtgServerObject
		if ($PRTG.Protocol -eq "https") { HelperSSLConfig }
    }

    PROCESS {


        ###############################################################################
        # build the post data payload/query string
        # note that "$QueryString.ToString()" actually builds this

        if ($Tags) { $Tags = "$Tags snmp cpu cpuloadsensor" } `
		else { $Tags = "snmp cpu cpuloadsensor"       }

        $QueryStringTable = @{
			"name_"                  = $Name
			"tags_"                  = $Tags
			"priority_"              = $Priority
			"intervalgroup"          = 1
			"interval_"              = "$Interval|$Interval seconds"
			"inherittriggers"        = 1
			"id"                     = $ParentId
			"sensortype"             = "snmpcpu"
        }

        # create a blank, writable HttpValueCollection object
        $QueryString = [System.Web.httputility]::ParseQueryString("")

        # iterate through the hashtable and add the values to the HttpValueCollection
        foreach ($Pair in $QueryStringTable.GetEnumerator()) {
			$QueryString[$($Pair.Name)] = $($Pair.Value)
        }

        ###############################################################################
        # fire the api call

        $Url  = "https://$($PRTG.Server)"
        $Url += "/addsensor5.htm?"
        $Url += "username=$($PRTG.UserName)&"
        $Url += "passhash=$($PRTG.PassHash)"

        HelperHTTPPostCommand $Url $QueryString.ToString() | Out-Null
    }
}


###############################################################################
## Helper Functions
###############################################################################
# http://stackoverflow.com/questions/6032344/how-to-hide-helper-functions-in-powershell-modules
# make sure none of these have a dash in their name

function HelperSSLConfig {
	[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
	[System.Net.ServicePointManager]::Expect100Continue = {$true}
	[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls
}

function HelperHTTPQuery {
	Param (
		[Parameter(Mandatory=$True,Position=0)]
		[string]$URL,

		[Parameter(Mandatory=$False)]
		[alias('xml')]
		[switch]$AsXML
	)

	try {
		$Response = $null
		$Request = [System.Net.HttpWebRequest]::Create($URL)
		$Response = $Request.GetResponse()
		if ($Response) {
			$StatusCode = $Response.StatusCode.value__
			$DetailedError = $Response.GetResponseHeader("X-Detailed-Error")
		}
	}
	catch {
		$ErrorMessage = $Error[0].Exception.ErrorRecord.Exception.Message
		$Matched = ($ErrorMessage -match '[0-9]{3}')
		if ($Matched) {
			throw ('HTTP status code was {0} ({1})' -f $HttpStatusCode, $matches[0])
		}
		else {
			throw $ErrorMessage
		}

		#$Response = $Error[0].Exception.InnerException.Response
		#$Response.GetResponseHeader("X-Detailed-Error")
	}

	if ($Response.StatusCode -eq "OK") {
		$Stream    = $Response.GetResponseStream()
		$Reader    = New-Object IO.StreamReader($Stream)
		$FullPage  = $Reader.ReadToEnd()

		if ($AsXML) {
			$Data = [xml]$FullPage
		} else {
			$Data = $FullPage
		}

		$Global:LastResponse = $Data

		$Reader.Close()
		$Stream.Close()
		$Response.Close()
	} else {
		Throw "Error Accessing Page $FullPage"
	}

	$ReturnObject = "" | Select-Object StatusCode,DetailedError,Data
	$ReturnObject.StatusCode = $StatusCode
	$ReturnObject.DetailedError = $DetailedError
	$ReturnObject.Data = $Data

	return $ReturnObject
}

function HelperURLBuilder {
	Param (
		[Parameter(Mandatory=$True,Position=0)]
		[string]$Action,

		[Parameter(Mandatory=$false,Position=1)]
		[string[]]$QueryParameters,

		[Parameter(Mandatory=$false,Position=2)]
		[string]$Protocol = $Global:PrtgServerObject.Protocol,

		[Parameter(Mandatory=$false,Position=3)]
		[string]$Server = $Global:PrtgServerObject.Server,

		[Parameter(Mandatory=$false,Position=4)]
		[int]$Port = $Global:PrtgServerObject.Port,

		[Parameter(Mandatory=$false,Position=5)]
		[string]$UserName = $Global:PrtgServerObject.UserName,

		[Parameter(Mandatory=$false,Position=6)]
		[string]$PassHash = $Global:PrtgServerObject.PassHash
	)

	$PortString = (":" + ($Port))

	$Return =
		$Protocol, "://", $Server, $PortString,
		"/api/",$Action,"?",
		"username=$UserName",
		"&passhash=$PassHash" -join ""

	$Return += $QueryParameters -join ""

	return $Return
}

function HelperFormatTest {
	$URLKeeper = $global:lasturl

	$CoreHealthChannels = Get-PrtgSensorChannels 1002
	$HealthPercentage = $CoreHealthChannels | ? {$_.name -eq "Health" }
	$ValuePretty = [int]$HealthPercentage.lastvalue.Replace("%","")
	$ValueRaw = [int]$HealthPercentage.lastvalue_raw

	if ($ValueRaw -eq $ValuePretty) {
		$RawFormatError = $false
	} else {
		$RawFormatError = $true
	}

	$global:lasturl = $URLKeeper

	$StoredConfiguration = $Global:PrtgServerObject | Select-Object *,RawFormatError
	$StoredConfiguration.RawFormatError = $RawFormatError

	$global:PrtgServerObject = $StoredConfiguration
}

function HelperFormatHandler {
    Param (
        [Parameter(Mandatory=$False,Position=0)]
        $InputData
	)

	if (!$InputData) { return }

	if ($Global:PrtgServerObject.RawFormatError) {
		# format includes the quirk
		return [double]$InputData.Replace("0.",".")
	} else {
		# format doesn't include the quirk, pass it back
		return [double]$InputData
	}
}

function HelperHTTPPostCommand() {
	param(
		[string] $url = $null,
		[string] $data = $null,
		[System.Net.NetworkCredential]$credentials = $null,
		[string] $contentType = "application/x-www-form-urlencoded",
		[string] $codePageName = "UTF-8",
		[string] $userAgent = $null
	);

	if ( $url -and $data ) {
		[System.Net.WebRequest]$webRequest = [System.Net.WebRequest]::Create($url);
		$webRequest.ServicePoint.Expect100Continue = $false;
		if ( $credentials ) {
			$webRequest.Credentials = $credentials;
			$webRequest.PreAuthenticate = $true;
		}
		$webRequest.ContentType = $contentType;
		$webRequest.Method = "POST";
		if ( $userAgent ) {
			$webRequest.UserAgent = $userAgent;
		}

		$enc = [System.Text.Encoding]::GetEncoding($codePageName);
		[byte[]]$bytes = $enc.GetBytes($data);
		$webRequest.ContentLength = $bytes.Length;
		[System.IO.Stream]$reqStream = $webRequest.GetRequestStream();
		$reqStream.Write($bytes, 0, $bytes.Length);
		$reqStream.Flush();

		$resp = $webRequest.GetResponse();
		$rs = $resp.GetResponseStream();
		[System.IO.StreamReader]$sr = New-Object System.IO.StreamReader -argumentList $rs;
		$sr.ReadToEnd();
	}
}

###############################################################################
## PowerShell Module Functions
###############################################################################

Export-ModuleMember *-*


# SIG # Begin signature block
# MIIXuwYJKoZIhvcNAQcCoIIXrDCCF6gCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUZ0ESOPq/vdMiHRDWWKdjpkjn
# YoqgghKzMIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
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
# AQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFB16IZiPKAg1Owe8HofdM73Y4G+CMA0G
# CSqGSIb3DQEBAQUABIIBACIDFn/4GI4laTUkKQAWm8hf3IVIlqVlGbwOn+aPPN4/
# gTQVHjaRcnpY6GhQZDEU3cezJQvpedXftXI3o5LxXPflQjLygCGUETv4fGsovaeP
# t8EF3o7RskjZYMCocQFprIpAw0k+vnLqz1KsbPEMOIECGtiinnkfbjl+HHRmRd5A
# N2aZ9t6bVRO2XGEQyT0YwpiLssgMiXtSkLgDzBNpJ5sw/a1tgGN6ydrbCXPfC1Wl
# d3A/FzF7Q6d96DwtyCx8Fesa+jV55fOv24VfX1FJnyUYDJ4b6P9kd7m4KwpZ4BEd
# VWQQ7dqEQlln4ei01+Thz96/1QVA1P90qksfJH2SolmhggILMIICBwYJKoZIhvcN
# AQkGMYIB+DCCAfQCAQEwcjBeMQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50
# ZWMgQ29ycG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFudGVjIFRpbWUgU3RhbXBpbmcg
# U2VydmljZXMgQ0EgLSBHMgIQDs/0OMj+vzVuBNhqmBsaUDAJBgUrDgMCGgUAoF0w
# GAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTkxMjAy
# MjIxNjA1WjAjBgkqhkiG9w0BCQQxFgQUJpHi10nxn12uO/hT9RQ0makzZD8wDQYJ
# KoZIhvcNAQEBBQAEggEAZ6Njze+OZ4zlInkvx+gSX5uCjYmvQ/hh0hI6xN/RNbtH
# yf8iZjxKG/jIKohaFBCK6sS8ezKyJYc86rlz8kvXHIdVr0FIO2FnfKy9xyDCnJ6P
# Cde2wq7zC5n6cecX+sOD3f2zBFl2MeQk9o54wApZNcBUwHFz6EzHtB4y0ctjGze4
# fle7nGXsDPlkquC5MSQ+6+mxSfaUVBCMdtOfrMl9jkonkZ9gSM5ESmivLuYIvPbg
# l5+hlklBv/vTm/qHicPslAGZVNRQtlbnhqJ4aRilHUYeepn/7hcgkUEcut3KVKmr
# tqa1aNkJ0h/EUML5qQkFSeB2wtCyeM5tvsWUYnoVOQ==
# SIG # End signature block
