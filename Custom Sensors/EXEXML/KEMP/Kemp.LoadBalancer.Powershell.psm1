#region Originating script: 'C:\devhome\Powershell\KempTechPowershellModule\Kemp.LoadBalancer.Powershell.ps1'
#
# $Id: Kemp.LoadBalancer.Powershell.psm1 13186 2016-07-08 09:08:13Z rkelemanskis $
#
####################
# MODULE VARIABLES #
####################
[System.Reflection.Assembly]::LoadWithPartialName("system.web") | Out-Null
New-Variable -Name LoadBalancerAddress -Scope Script -Force
New-Variable -Name Cred -Scope Script -Force
New-Variable -Name LBAccessPort -Scope Script -Force -Value 443
$IgnoredParameters = @("Verbose","Debug","WarningAction","WarningVariable","ErrorAction",
	"ErrorVariable","OutVariable","OutBuffer","WhatIf","Confirm","RuleType","LoadBalancer")

$ParamReplacement = @{VSIndex = "vs";VirtualService = "vs";Protocol = "prot";
	RSIndex = "rs";RealServer = "rs";RealServerPort = "rsport";
	RuleName = "rule";InterfaceID = "iface";IPAddress = "addr";
	NameServer="nameserver";NamServer="namserver";HAMode="hamode";Partner='partner';Hcp="hcp";Location="location";
	GeoTraffic="geotraffic";Mapaddress="mapaddress";Mapport="mapport";Cluster="clust";
	KempId="kempid";Password="password";OrderId="orderid";}

$SystemRuleType = @{MatchContentRule=0;AddHeaderRule=1;DeleteHeaderRule=2;ReplaceHeaderRule=3;ModifyUrlRule=4}
$RestoreType = @{Base=1;VS=2;Geo=3}

#region - LBCommunication

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Send-LBMessage
{
 	[CmdletBinding(DefaultParameterSetName="SingleParam")]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[string]$Command,
		[Parameter(Position=1,ParameterSetName="SingleParam")]
		[string]$ParameterName,
		[Parameter(Position=2,ParameterSetName="SingleParam")]
		[string]$ParameterValue,
		[Parameter(Position=1,ParameterSetName="MultiParam")]
		[hashtable]$ParameterValuePair,
		[Parameter(Position=2,ParameterSetName="MultiParam")]
		[string]$File,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.PSCredential]$Credential = $script:cred,
		[int]$LBPort = $LBAccessPort,
		[switch]$Output
	)
	Write-Verbose "Entering Send-LBMessage"
	$sb = New-Object Text.StringBuilder

	if($Command -eq 'enableapi')
	{
		$sb.Append("https://$LoadBalancer`:$LBPort/progs/doconfig/enableapi/set/yes") | out-null
	}
	Elseif($Command -eq 'disableapi')
	{
		$sb.Append("https://$LoadBalancer`:$LBPort/progs/doconfig/enableapi/set/no") | out-null
	}
	Elseif($Command -eq 'isapienabled')
	{
		$sb.Append("https://$LoadBalancer`:$LBPort/access/get?param=version") | out-null
	}
	Elseif($Command -eq 'isapienabled2')
	{
		$Command = 'isapienabled'
		$orig_command = 'isapienabled2'
		$sb.Append("https://$LoadBalancer`:$LBPort/access/get?param=version") | out-null
	}
	Elseif($Command -eq 'set_initial_passwd2')
	{
		$Command = 'set_initial_passwd'
		$orig_command = 'set_initial_passwd2'
		$sb.Append("https://$LoadBalancer`:$LBPort/access/$Command`?") | out-null
	}
	else {
		if ($Command -eq 'alsilicense2')
		{
			$Command = 'alsilicense'
			$orig_command = 'alsilicense2'
		}
		$sb.Append("https://$LoadBalancer`:$LBPort/access/$Command`?") | out-null
	}
	switch ($PsCmdlet.ParameterSetName)
	{
		"SingleParam"
		{
			if($ParameterValue)
			{
				$sb.Append("param=$ParameterName&value=$ParameterValue") | out-null
			}
			Elseif($Command -eq "get")
			{
				# The "get" commands require "param=Name".
				$sb.Append("param=$ParameterName") | out-null
			}
			else {
				# No value and omit the "param=".
				$sb.Append("$ParameterName") | out-null
			}
			break
		}
		"MultiParam"
		{
			if ($Command -eq "isapienabled" -or $Command -eq "isapienabled")
			{
				break
			}
			foreach ($key in $ParameterValuePair.keys)
			{
				Write-Verbose "key=`"$key`" - value=`"$($ParameterValuePair[$key])`""
				$sb.Append("$key=$($ParameterValuePair[$key])&") | out-null
			}
			break
		}
		default
		{
		}
	}
	$uri = $sb.ToString() -replace "\&$"
	Write-Verbose "Uri = $uri"
	$response = $null
	try {
		Write-Verbose "Creating request"
		[System.Net.ServicePointManager]::Expect100Continue = $true
		[System.Net.ServicePointManager]::MaxServicePointIdleTime = 10000
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
		[System.Net.ServicePointManager]::SecurityProtocol = 'Tls11','Tls12'
		$request = [System.Net.HttpWebRequest]::Create($uri)
		$request.UserAgent = "KempLoadBalancerPowershellModule"
		$request.Credentials = $Credential
		if (($File) -and (-not ($Output)))
		{
			if ((-not (Test-Path -Path $file)) -and (-not ($Output)))
			{
				Write-Error -Message "You have specified an input file that does not exist." -RecommendedAction "Make sure the path is correct and that the file exists." -TargetObject $file
			}
			Write-Verbose "There is a file to upload."
			$datalength = (Get-Item -Path $File).Length
			Write-Verbose "File length: $datalength"
			$request.SendChunked = $true
			$request.KeepAlive = $false
			#$request.protocolversion = [System.Net.HttpVersion]::Version10
			Write-Verbose "Send Chunked: $($request.SendChunked)"
			$request.method = "POST"
			$request.ContentType = "application/x-www-form-urlencoded"
			Write-Verbose "Reading file..."
			$fileStream = New-Object IO.FileStream($File, "Open", "Read")
			$binaryReader = New-Object IO.BinaryReader($fileStream)
			$data = $binaryReader.ReadBytes([int]$datalength)
			Write-Verbose "Cleaning up readers."
			$binaryReader.close()
			Write-Verbose "Getting request stream"
			$stream = $request.GetRequestStream()
			$binaryWriter = New-Object IO.BinaryWriter($stream)
			Write-Verbose "Writing the data to the stream"
			$binaryWriter.Write($data, 0, $data.length)
			$binaryWriter.Flush()
			$binaryWriter.Close()
		}
		Write-Verbose "Trying to get response"
		$response = $request.GetResponse()
		Write-Verbose "Response received."
		Write-Verbose $response

		if ($Command -eq 'isapienabled')
		{
			if ($orig_command -eq 'isapienabled2')
			{
				if ($response.StatusCode -eq 404 -or $response.StatusCode -eq 401)
				{
					Write-Verbose "API is Disabled"
				}
				else {
					Write-Verbose "API is Enabled"
				}
			}
			else {
				if ($response.StatusCode -eq 404 -or $response.StatusCode -eq 401)
				{
					Write-Output "API is Disabled"
				}
				else {
					Write-Output "API is Enabled"
				}
			}
		}
	}
	catch [Exception]
	{
		#if ($Command -eq "isapienabled")
		#{
		#	Write-Verbose $_.Exception.Message
		#}
		#else {
		#	Write-Host $_.Exception.Message
		#}
		$response = $_.Exception.InnerException.Response
		if ($orig_command -eq 'isapienabled2')
		{
			Write-Verbose "Exception catched [$_.Exception.Message]"
		}
		else {
			Write-Host $_.Exception.Message
		}
		if (!$response)
		{
			if ($Command -eq 'isapienabled' -and $orig_command -ne 'isapienabled2')
			{
				Write-Output "API is disabled"
			}
			$response = $_.Exception.Response
		}
		if ($orig_command -eq 'isapienabled2')
		{
			# (1) The remote server returned an error: (404) Not Found
			# (2) Unable to connect to the remote server.
			$errorMsg = [string]$($_.Exception.Message)
			Write-Verbose "Error Message [$errorMsg]"

			if ($errorMsg -eq "The remote server returned an error: (404) Not Found.")
			{
				throw "API is disabled."
			}
			else {
				throw "Unable to connect to the remote server: check username/password and/or LM IP/PORT."
			}
		}
		#$result.response
	}
	finally
	{
		try {
			$stream = $response.GetResponseStream()
		}
		catch {
		}
		if($response.contenttype -eq "text/xml")
		{
			$Encoding = [System.Text.Encoding]::GetEncoding("utf-8")
			$reader = New-Object system.io.StreamReader($stream, $Encoding)

			if($Command -eq 'readeula' -or $Command -eq 'accepteula')
			{
				Write-Verbose "Skip XML processing in the case of eula commands."
				$result = $reader.REadToEnd()
				Write-Output $result
			}
			Else {
				Write-Verbose "Converting response to XML."
				[xml]$result = $reader.REadToEnd()
				Write-Verbose "Checking for success."
				if ($result.response.success)
				{
					Write-Verbose "This is a success response."
					if ([string]::IsNullOrEmpty($result.response.success.data))
					{
						Write-Verbose "There is no data, so just write the code."
						if ($Command -eq "DownloadWafRules" -or $Command -eq "Update-WafRulesDatabase")
						{
							Write-Verbose "No writing response code"
						}
						elseif ($Command -eq "ManInstallWafRules" -or $Command -eq "Install-WafRulesDatabase")
						{
							Write-Verbose "No writing response code"
						}
						elseif ($Command -like "set?param=enableapi&value=no&")
						{
							Write-Verbose "No writing response code"
						}
						elseif ($Command -eq "resolvenow")
						{
							Write-Verbose "No writing response code"
						}
						else {
							if ($orig_command -eq "alsilicense2")
							{
								Write-Verbose "No writing response code"
							}
							else {
								Write-Output $result.response.code
							}
						}
					}
					else {
						Write-Verbose "There is data to return."
						write-output $result.response.success.data
					}
				}
				else {
					Write-Verbose "This is a failure response, and here is the response."
					if ($Command -eq "set_initial_passwd" -and $orig_command -eq "set_initial_passwd2")
					{
						throw "Method Not Allowed."
					}
					if ($Command -eq "geoacl/getsettings")
					{
						throw "$($result.response.error)"
					}
					if ($Command -eq "geoacl/setautoupdate" -or $Command -eq "geoacl/setautoinstall" -or $Command -eq "geoacl/setinstalltime" -or $Command -eq "geoacl/installnow" -or $Command -eq "geoacl/updatenow" -or $Command -eq "geoacl/downloadlist" -or $Command -eq "geoacl/downloadchanges")
					{
						$errorMsg = $($result.response.error)
						if ($errorMsg -eq "Command not available.")
						{
							throw "operation not permitted."
						}
						else {
							throw "$($result.response.error)"
						}
					}
					if ($Command -eq "geoacl/addcustom")
					{
						$errorMsg = $($result.response.error)
						if ($errorMsg -eq "addr: CIDR format out of range" -or $errorMsg -eq "addr: Invalid address format")
						{
							throw "$errorMsg"
						}
						elseif ($errorMsg -like "* is already present in the white list")
						{
							$smp = $errorMsg.IndexOf(":")
							$errMsg  = $errorMsg.substring($smp + 2)
							throw "$errMsg"	#the address/network is already present in the white list."
						}
						else {
							throw "Internal error."
						}
					}
					if ($Command -eq "geoacl/removecustom")
					{
						throw "the address/network is NOT present in the whitelist."
					}
					Write-Output $result.response.Error
					Write-Output $result.response
				}
			}
		}
		if ($response.ContentType -eq "application/octet-stream" -or $response.ContentType -eq "application/x509-cert" -or $Command -eq "exportvstmplt" -or $response.ContentType -eq "application/vnd.tcpdump.pcap")
		{
			if ($response.StatusCode -eq 200)
			{
				if ((Test-Path -Path $file) -and (-not ($Force)))
				{
					Write-Error -Message "The specified file already exists." -RecommendedAction "To use the same filename, either delete the file or use the -Force switch" -TargetObject $file
				}
				$datalength = $response.ContentLength
				$reader = $response.GetResponseStream()
				$writer = New-Object io.FileStream $file, "Create"
				$buffer = New-Object byte[] 4096
				do
				{
					$count = $reader.Read($buffer, 0, $buffer.length)
					$writer.Write($buffer, 0, $count)

				} while ($count -gt 0)
				$writer.Flush()
				$writer.Close()
			}
		}
		if ($reader)
		{
			$reader.Close()
			$reader.Dispose()
		}
		if ($stream)
		{
			$stream.Close()
			$stream.Dispose()
		}
		if ($fileStream)
		{
			$fileStream.Close()
			$fileStream.Dispose()
		}
		if ($response)
		{
			$response.Close()
			$response.Dispose()
		}
	}
}
Export-ModuleMember -function Send-LBMessage

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Initialize-LoadBalancer
Function Initialize-Lm
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Address,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort
	)

	$netAssembly = [Reflection.Assembly]::GetAssembly([System.Net.Configuration.SettingsSection])

	if($netAssembly)
	{
		$bindingFlags = [Reflection.BindingFlags] "Static,GetProperty,NonPublic"
		$settingsType = $netAssembly.GetType("System.Net.Configuration.SettingsSectionInternal")

		$instance = $settingsType.InvokeMember("Section", $bindingFlags, $null, $null, @())

		if($instance)
		{
			$bindingFlags = "NonPublic","Instance"
			$useUnsafeHeaderParsingField = $settingsType.GetField("useUnsafeHeaderParsing", $bindingFlags)

			if($useUnsafeHeaderParsingField)
			{
				$useUnsafeHeaderParsingField.SetValue($instance, $true)
			}
		}
	}

	if ($LBPort)
	{
		Write-Host "Unless overridden using a local -Port parameter, all commands will now use Port $LBPort."
		$script:LBAccessPort = $LBPort;
	}

	if ($Address)
	{
		if (-not (Test-ServerConnection -ComputerName $Address -Port $script:LBAccessPort))
		{
			Write-Host "Unable to resolve or connect to $Address"
			return
		}
		$script:LoadBalancerAddress = $Address
	}
	$tempCredential = $script:cred
	$script:cred = $Credential

	if (-not ([String]::IsNullOrEmpty($LoadBalancerAddress)))
	{
		Write-Host "Unless overridden using a local -LoadBalancer parameter, all commands will now be directed to $LoadBalancerAddress."
	}

	if ($LBPort -eq "")
	{
		$en = Enable-SecAPIAccess -LoadBalancer $Address -Credential $Credential
	}
	else {
		$en = Enable-SecAPIAccess -LoadBalancer $Address -Credential $Credential -port $LBPort
	}

	if ($Credential -ne [System.Management.Automation.PSCredential]::Empty)
	{
		Write-Host "Unless overridden using a local -Credential parameter, all commands will now use $($Credential.Username)."
	}
	else {
		$script:cred = $tempCredential
		Write-Host "No changes made to stored credentials."
	}
}
New-Alias -Name Initialize-LoadBalancer -value Initialize-Lm -Description "Alias for Initialize-LoadBalancer command"
Export-ModuleMember -function Initialize-Lm -Alias Initialize-LoadBalancer

#Function Test-ServerConnection
Function Test-LmServerConnection
{
	[CmdletBinding()]
	Param(
		[string]$ComputerName,
		[Int32]$Port
	)
	$connection = New-Object Net.Sockets.TcpClient
	try
	{
		Write-Verbose -Message "Connecting to $ComputerName on $Port..."
		$connection.connect($ComputerName, $Port)
		Write-Verbose -Message "Connection Status: $($connection.Connected)"
		if ($connection.Connected)
		{
			Write-Verbose "Returning true."
			return $true
		}
	}
	catch [System.Management.Automation.MethodInvocationException]
	{
		Write-Verbose "Exception thrown."
	}
	Write-Verbose "Returning false."
	return $false
}
New-Alias -Name Test-ServerConnection -value Test-LmServerConnection -Description "Alias for Test-ServerConnection command"
Export-ModuleMember -function Test-LmServerConnection -Alias Test-ServerConnection

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
# Function Set-LoadBalancerAddress
# {
# 	[CmdletBinding()]
# 	Param(
# 		[Parameter(Mandatory=$true)]
# 		[ValidateNotNullOrEmpty()]
# 		[string]$Address
# 	)
# 	$script:LoadBalancerAddress = $Address
#
# 	if (-not ([String]::IsNullOrEmpty($LoadBalancerAddress)))
# 	{
# 		Write-Host "Unless overridden using a local -LoadBalancer parameter, all commands will now be directed to $LoadBalancerAddress."
# 	}
# }
#
# #.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
# Function Set-Credentials
# {
# 	[CmdletBinding()]
# 	Param(
# 		[ValidateNotNullOrEmpty()]
# 		[System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty
# 	)
#
# 	$script:cred = $Credential
#
# 	if ($Credential -ne [System.Management.Automation.PSCredential]::Empty)
# 	{
# 		Write-Host "Unless overridden using a local -Credential parameter, all commands will now use $($Credential.Username)."
# 	}
# 	else
# 	{
# 		Write-Host "No changes made to stored credentials."
# 	}
# }

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Convert-XMLToPSObject
{
	[CmdletBinding()]
	Param(
		[Parameter(ValueFromPipeline=$true)]
		[System.Xml.XmlElement[]]$Element
	)

	BEGIN
	{
		$objectProperties = @{}
	}

	PROCESS
	{
		if($_)
		{
			$Element | ForEach-Object {
				Write-Verbose "Element = $($_.Name)"
				foreach ($child in $_.get_ChildNodes())
				{
					$property = $child.get_Name()
					$value = ""
					Write-Verbose "Child Type = $($child.GetType().Name)"
					if ($child -is [System.Xml.XmlElement])
					{
						Write-Verbose "Trying to get child nodes."
						$value = @($child.get_ChildNodes() | ForEach-Object {$_.InnerText}) -join ","
					}
					else
					{
						Write-Verbose "Caught exception."
						$value = $child.InnerText
					}
					Write-Verbose "Property: $property; Value: $value"
					if ($value -ne "-")
					{
						if ($objectProperties.ContainsKey($property))
						{
							$objectProperties[$property] += ",$value"
						}
						else
						{
							$objectProperties[$property] = $value
						}
					}
				}
				$objectProperties.Remove("#whitespace")
				New-Object -TypeName PSObject -Property $objectProperties
				$objectProperties.Clear()
			}
		}
	}
}

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Convert-BoundParameters
{
	[CmdletBinding()]
	Param(
		[hashtable]$hashtable
	)

	$propertyTable = @{}

	foreach ($param in $IgnoredParameters)
	{
		$hashtable.Remove($param)
	}

	foreach ($param in $hashtable.keys)
	{
		if ($hashtable[$param] -is [bool])
		{
			#$propertyTable.Add(($param -replace "_","."), $hashtable[$param] -as [int])
			$propertyTable.Add(($param), $hashtable[$param] -as [int])
		}
		else {
			#$value = [System.Web.HttpUtility]::UrlEncode($hashtable[$param] -split ",")
			$value = [System.Web.HttpUtility]::UrlEncode($hashtable[$param])
			#Write-Verbose "URLEncoded value: $value"
			Write-Verbose "param name [$param], param value [$value]"
			if ($param -eq "BondMode")
			{
				if ($hashtable[$param].ToLowerInvariant() -eq "802.3ad") {$value = 4}
				if ($hashtable[$param].ToLowerInvariant() -eq "active-backup") {$value = 1}
			}

			if ($ParamReplacement.Keys -contains $param)
			{
				# Special case: Add the "!" prefix to the RSIndex value.
				if ($param -eq "RSIndex")
				{
					$value = "!" + $value
				}
				$param = $ParamReplacement[$param]
			}
			$propertyTable.Add($param, $value)
		}
	}
	return $propertyTable
}

#Function EnableAPI
Function Enable-SecAPIAccess
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[ValidateRange(1,65535)]
		[int]$port,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$ErrorActionPreference = "Stop"
	$response = $null
	try {
		if ($port -eq "") {
			$port = 443
		}
		$isApiEn = Test-SecAPIAccess -LoadBalancer $LoadBalancer -Credential $Credential -port $port
		if ($isApiEn.ReturnCode -eq 200) {
			$tempApiRetObj = @{}
			$tempApiRetObj.PSTypeName = "KempAPI"
			$tempApiRetObj.ReturnCode = 200
			$tempApiRetObj.Response = "API already enabled"
			$tempApiRetObj.Data = $null

			$apiRetObject = New-Object -TypeName PSObject -Prop $tempApiRetObj
			$apiRetObject
		}
		else {
			$sb = New-Object Text.StringBuilder
			if ($port -eq "") {
				[void]$sb.Append("https://$LoadBalancer/progs/doconfig/enableapi/set/yes")
			}
			else {
				[void]$sb.Append("https://$LoadBalancer`:$port/progs/doconfig/enableapi/set/yes")
			}
			$uri = $sb.ToString() -replace "\&$"

			[System.Net.ServicePointManager]::Expect100Continue = $true
			[System.Net.ServicePointManager]::MaxServicePointIdleTime = 10000
			[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}	# ignore cert problems
			[System.Net.ServicePointManager]::SecurityProtocol = 'Tls11','Tls12'

			$request = [System.Net.HttpWebRequest]::Create($uri)
			$request.UserAgent = "KempLoadBalancerPowershellModule"
			$request.Method = "GET"

			$username = $Credential.UserName
			$temp = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
			$password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($temp)

			$b = [System.Text.Encoding]::UTF8.GetBytes($username + ":" + $password)

			$p = [System.Convert]::ToBase64String($b)
			$creds = "Basic " + $p
			$request.Headers.Add("Authorization: " + $creds)
			$response = $request.GetResponse()

			if ($response -ne $null) {
				try {
					$stream = $response.GetResponseStream()
					$Encoding = [System.Text.Encoding]::GetEncoding("utf-8")
					$reader = New-Object system.io.StreamReader($stream, $Encoding)
					$result = $reader.REadToEnd()
				}
				catch {
					write-host "Caught an exception" -ForegroundColor Red
					write-host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
					write-host "Exception Message: $($_.Exception.Message)" -ForegroundColor Red
				}
			}
			$tempApiRetObj = @{}
			$tempApiRetObj.PSTypeName = "KempAPI"
			$tempApiRetObj.ReturnCode = 200
			$tempApiRetObj.Response = "API successfully enabled"
			$tempApiRetObj.Data = $null

			$apiRetObject = New-Object -TypeName PSObject -Prop $tempApiRetObj
			$apiRetObject
		}
	}
	catch [Exception] {
		$err = [string]$_
		$response = $_.Exception.InnerException.Response
		if (!$response) {
			$response = $_.Exception.Response
		}
		$tempApiRetObj = @{}
		$tempApiRetObj.PSTypeName = "KempAPI"
		$tempApiRetObj.ReturnCode = 404
		$tempApiRetObj.Response = $err
		$tempApiRetObj.Data = $null

		$apiRetObject = New-Object -TypeName PSObject -Prop $tempApiRetObj
		$apiRetObject
	}
	finally {
		if ($reader) {
			$reader.Close()
			$reader.Dispose()
		}
		if ($stream) {
			$stream.Close()
			$stream.Dispose()
		}
		if ($response) {
			$response.Close()
			$response.Dispose()
		}
	}
}
New-Alias -Name EnableAPI -value Enable-SecAPIAccess -Description "Alias for EnableAPI command"
Export-ModuleMember -function Enable-SecAPIAccess -Alias EnableAPI

#Function DisableAPI
Function Disable-SecAPIAccess
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[ValidateRange(1,65535)]
		[int]$port,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	try {
		if ($port -eq "")
		{
			$port = 443
		}
		$isApiEn = Test-SecAPIAccess -LoadBalancer $LoadBalancer -Credential $Credential -port $port
		if ($isApiEn.ReturnCode -eq 404)
		{
			if ($isApiEn.Response -eq "API is disabled.")
			{
				$msg = "API already disabled"
			}
			else {
				$msg = $isApiEn.Response
			}
			$tempApiRetObj = @{}
			$tempApiRetObj.PSTypeName = "KempAPI"
			$tempApiRetObj.ReturnCode = 200
			$tempApiRetObj.Response = $msg
			$tempApiRetObj.Data = $null

			$apiRetObject = New-Object -TypeName PSObject -Prop $tempApiRetObj
			$apiRetObject
		}
		else {
			$cmdToExec = "set?param=enableapi&value=no&"
			Send-LBMessage -Command $cmdToExec -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

			$tempApiRetObj = @{}
			$tempApiRetObj.PSTypeName = "KempAPI"
			$tempApiRetObj.ReturnCode = 200
			$tempApiRetObj.Response = "API successfully disabled"
			$tempApiRetObj.Data = $null

			$apiRetObject = New-Object -TypeName PSObject -Prop $tempApiRetObj
			$apiRetObject
		}
	}
	catch {
		write-host "Caught an exception" -ForegroundColor Red
		write-host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
		write-host "Exception Message: $($_.Exception.Message)" -ForegroundColor Red
	}
}
New-Alias -Name DisableAPI -value Disable-SecAPIAccess -Description "Alias for DisableAPI command"
Export-ModuleMember -function Disable-SecAPIAccess -Alias DisableAPI

Function IsAPIEnabled
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command isapienabled -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
Export-ModuleMember -function IsAPIEnabled

Function Test-SecApiAccess
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[ValidateRange(1,65535)]
		[int]$port,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	if ($port -eq "")
	{
		$port = 443
	}

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	try {
		$response = Send-LBMessage -Command isapienabled2 -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -LBPort $port -Credential $Credential

		[string]$r_string = $response | Convert-XmlToPSObject

		$eqp = $r_string.IndexOf("=")
		$lbp = $r_string.IndexOf("}")

		$version = $r_string.substring($eqp + 1, $lbp - $eqp - 1)

		$tempApiVs = @{}
		$tempApiVs.PSTypeName = "Version"
		$tempApiVs.ApiVersion = $version

		$apiVers = New-Object -TypeName PSObject -Prop $tempApiVs

		$tempApiRetObj = @{}
		$tempApiRetObj.PSTypeName = "KempAPI"
		$tempApiRetObj.ReturnCode = 200
		$tempApiRetObj.Response = "API are enabled"
		$tempApiRetObj.Data = $apiVers
	}
	catch [Exception] {
		$exceptionMsg = [string]$($_.Exception.Message)
		if ($exceptionMsg -eq "The remote server returned an error: (404) Not Found.")
		{
			$errMsg = "API are disabled"
		}
		else {
			$errMsg = $exceptionMsg
		}

		$tempApiRetObj = @{}
		$tempApiRetObj.PSTypeName = "KempAPI"
		$tempApiRetObj.ReturnCode = 404
		$tempApiRetObj.Response = $errMsg	# "API are disabled"
		$tempApiRetObj.Data = $null
	}
	finally {
		$apiRetObject = New-Object -TypeName PSObject -Prop $tempApiRetObj
		$apiRetObject
	}
}
Export-ModuleMember -function Test-SecApiAccess

#endregion - LBCommunication

#region - Virtual Service

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-AllParameters
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$propertyTable = @{}

	Send-LBMessage -Command getall -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
}

#Function Get-Parameter
Function Get-LmParameter
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$Param,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command get -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name Get-Parameter -value Get-LmParameter -Description "Alias for Get-Parameter command"
Export-ModuleMember -function Get-LmParameter -Alias Get-Parameter

#Function Set-Parameter
Function Set-LmParameter
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$Param,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullOrEmpty()]
		[String]$Value,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command set -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name Set-Parameter -value Set-LmParameter -Description "Alias for Set-Parameter command"
Export-ModuleMember -function Set-LmParameter -Alias Set-Parameter

Function ListIfconfig
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$propertyTable = @{}

	$response = Send-LBMessage -Command listifconfig -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response | Convert-XmlToPSObject
}

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function New-VirtualService
Function New-AdcVirtualService
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[string]$VirtualService,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateRange(3,65530)]
		[Int32]$Port,
		[Parameter(Mandatory=$true,Position=2)]
		[ValidateSet("tcp","udp")]
		[string]$Protocol,
		[ValidateRange(0,6)]
		[Int16]$AddVia,
		[string]$Template,
		[bool]$Cache = $false,
		[string]$CertFile,
		[ValidateSet("tcp","icmp","https","http","smtp","nntp","ftp","telnet","pop3","imap","rdp","none")]
		[string]$CheckType = "tcp",
		[string]$CheckHost,
		[string]$CheckPattern,
		[string]$CheckUrl,
		[string]$CheckHeaders,
		[string]$MatchLen,
		[bool]$CheckUse1_1 = $false,
		[ValidateRange(3,65530)]
		[Int32]$CheckPort,
		[bool]$EnhancedHealthChecks,
		[Int32]$RsMinimum,
		[ValidateRange(0,2)]
		[Int16]$ClientCert = 0,
		[bool]$Compress = $false,
		[string]$Cookie,
		[ValidateRange(0,100)]
		[Int16]$CachePercent = 0,
		[string]$DefaultGW,
		[bool]$Enable = $true,
		[string]$ErrorCode = 0,
		[string]$ErrorUrl,
		[ValidateRange(3,65530)]
		[Int32]$PortFollow,
		[bool]$ForceL7 = $true,
		[ValidateRange(0,86400)]
		[Int32]$Idletime,
		[String[]]$LocalBindAddresses,
		[ValidateSet("gen","http","tls","ts")]
		[string]$VSType,
		[string]$Nickname,
		[ValidateSet("ssl","cookie","active-cookie","cookie-src","active-cook-src","cookie-hash",
		            "url","query-hash","host","header","super","super-src","src","rdp","rdp-src",
		            "rdp-sb","udpsip")]
		[string]$Persist,
		[ValidateRange(0, 604800)]
		[Int32]$PersistTimeout,
		[string]$QueryTag,
		[string]$CipherSet,
		[bool]$SSLReencrypt,
		[bool]$SSLReverse,
		[ValidateSet("","http","https")]
		[string]$SSLRewrite,
		[string]$ReverseSNIHostname,
		[ValidateSet("rr","wrr","lc","wlc","fixed","adaptive","sh")]
		[string]$Schedule,
		[ValidateRange(0,5)]
		[Int16]$ServerInit,
		[bool]$SSLAcceleration,
		[string]$StandByAddr,
		[string]$StandByPort,
		[Int32]$TransactionLimit,
		[bool]$Transparent,
		[bool]$SubnetOriginating,
		[bool]$UseforSnat,
		[ValidateSet("0","1","2","4","8")]
		[string]$QoS,
		[int32]$CheckUseGet,
		[ValidateRange(0,7)]
		[Int16]$Verify,
		[string]$ExtraHdrKey,
		[string]$ExtraHdrValue,
		[string]$AllowedHosts,
		[string]$AllowedDirectories,
		[string]$AllowedGroups,
		[bool]$IncludeNestedGroups,
		[bool]$DisplayPubPriv,
		[bool]$DisablePasswordForm,
		[string]$Domain,
		[string]$AltDomains,
		[string]$Logoff,
		[ValidateRange(0,7)]
		[Int16]$ESPLogs,
		[string]$SMTPAllowedDomains,
		[bool]$ESPEnabled,
		[ValidateRange(0,5)]
		[Int16]$InputAuthMode,
		[ValidateRange(0,2)]
		[Int16]$OutputAuthMode,
		[ValidateRange(0,1)]
		[Int16]$StartTLSMode,
		[string]$ExtraPorts,
		[string]$AltAddress,
		[bool]$MultiConnect,
		[string]$SingleSignOnDir,
		[string]$OCSPVerify,
		[Int32]$FollowVSID,
		[bool]$TlsType = $false,
		[string]$CheckPostData,
		[string]$CheckCodes,
		[string]$PreProcPrecedence,
		[Int16]$PreProcPrecedencePos,
		[string]$RequestPrecedence,
		[Int16]$RequestPrecedencePos,
		[string]$ResponsePrecedence,
		[Int16]$ResponsePrecedencePos,
		[string]$RsRulePrecedence,
		[Int16]$RsRulePrecedencePos,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command addvs -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
}
New-Alias -Name New-VirtualService -value New-AdcVirtualService -Description "Alias for New-VirtualService command"
Export-ModuleMember -function New-AdcVirtualService -Alias New-VirtualService

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function New-SubVirtualService
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[string]$VirtualService,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateRange(3,65530)]
		[Int32]$Port,
		[Parameter(Mandatory=$true,Position=2)]
		[ValidateSet("tcp","udp")]
		[string]$Protocol,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$propertyTable = @{}
	$propertyTable.Add("vs", $VirtualService)
	$propertyTable.Add("port", $Port)
	$propertyTable.Add("prot", $Protocol)
	$propertyTable.Add("createsubvs", "")

	Send-LBMessage -Command modvs -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
}

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function New-SubVirtualServiceByID
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[Int32]$VSIndex,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$propertyTable = @{}
	$propertyTable.Add("vs", $VSIndex)
	$propertyTable.Add("createsubvs", "")

	Send-LBMessage -Command modvs -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
}

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Remove-VirtualService
Function Remove-AdcVirtualService
{
	[CmdletBinding(SupportsShouldProcess=$true)]
	Param(
		[Parameter(Position=0,Mandatory=$true,ParameterSetName="IPAddress",ValueFromPipelineByPropertyName=$true)]
		[Alias("VSAddress")]
		[string]$VirtualService,
		[Parameter(Position=1,Mandatory=$true,ParameterSetName="IPAddress",ValueFromPipelineByPropertyName=$true)]
		[ValidateRange(3,65530)]
		[Int32]$Port,
		[Parameter(Position=2,Mandatory=$true,ParameterSetName="IPAddress",ValueFromPipelineByPropertyName=$true)]
		[ValidateSet("tcp","udp")]
		[string]$Protocol,
		[Parameter(Position=0,Mandatory=$true,ParameterSetName="Index",ValueFromPipelineByPropertyName=$true)]
		[Int32]$VSIndex,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred,
		[switch]$Force
	)

	PROCESS
	{
		Write-Verbose "Starting to process VirtualService"
		switch ($PsCmdlet.ParameterSetName)
		{
			"IPAddress"
			{
				Write-Verbose "IPAddress parameter set"
				$service = Get-VirtualService -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort | Where-Object{(($_.VSAddress -eq $VirtualService) -and ($_.VSPort -eq $Port) -and ($_.Protocol -eq $Protocol))}
			}
			"Index"
			{
				Write-Verbose "Index parameter set"
				$service = Get-VirtualService -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort | Where-Object{$_.Index -eq $VSIndex}
			}

		}

		if ($service)
		{
			Write-Verbose "Working with $($service.VSAddress)"
			$propertyTable = @{
				vs=$($service.VSAddress)
				port=$($service.VSPort)
				prot=$($service.Protocol)
			}

			if (($Force) -or ($PsCmdlet.ShouldProcess("$($VirtualService)/$($Port)/$($Protocol)", "Remove Virtual Service")))
			{
				Write-Verbose "Committing change."
				$response = Send-LBMessage -Command delvs -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
				$response
			}
		}
		else
		{
			switch ($PsCmdlet.ParameterSetName)
			{
				"IPAddress"
				{
					Write-Error "The Virtual Service at `"$($propertyTable.vs)`" using $($propertyTable.prot)/$($propertyTable.port) could not be found. Has it already been deleted?"
					break
				}
				"Index"
				{
					Write-Error "The Virtual Service with index `"$VSIndex`" could not be found."
				}

			}
		}
	}
}
New-Alias -Name Remove-VirtualService -value Remove-AdcVirtualService -Description "Alias for Remove-VirtualService command"
Export-ModuleMember -function Remove-AdcVirtualService -Alias Remove-VirtualService

#Function Remove-VirtualServiceByID
Function Remove-AdcVirtualServiceByID
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[Alias("Vs")]
		[Int32]$VSIndex,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command delvs -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name Remove-VirtualServiceByID -value Remove-AdcVirtualServiceByID -Description "Alias for Remove-VirtualServiceByID command"
Export-ModuleMember -function Remove-AdcVirtualServiceByID -Alias Remove-VirtualServiceByID

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Get-VirtualService
Function Get-AdcVirtualService
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[String]$VirtualService,
		[ValidateRange(3,65530)]
		[Int32]$Port,
		[ValidateSet("tcp","udp")]
		[String]$Protocol,
		[Int32]$VSIndex,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	if ($VSIndex) {
		if ($VirtualService) {
			Throw "The VSIndex and VirtualService parameters are mutually exclusive."
		}
		if ($Port) {
			Throw "The VSIndex and Port parameters are mutually exclusive."
		}
		if ($Protocol) {
			Throw "The VSIndex and Protocol parameters are mutually exclusive."
		}
	} Elseif ($VirtualService) {
		if (!$Port -or !$Protocol) {
			Throw "The VirtualService, Port and Protocol parameters must be used together."
		}
	} else {
		if ($Port -or $Protocol) {
			Throw "The VirtualService, Port and Protocol parameters must be used together."
		}
	}

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	if ($VirtualService -or $VSIndex) {
		$response = Send-LBMessage -command showvs -parametervaluepair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort

		if($response -is "String") {
			$response
		} else {
			$response | Convert-XmlToPSObject
		}
	} else {

		$response = Send-LBMessage -command listvs -parametervaluepair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort

		$response.VS | Convert-XmlToPSObject
	}
}
New-Alias -Name Get-VirtualService -value Get-AdcVirtualService -Description "Alias for Get-VirtualService command"
Export-ModuleMember -function Get-AdcVirtualService -Alias Get-VirtualService

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Set-VirtualService
Function Set-AdcVirtualService
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$VirtualService,
		[ValidateRange(3,65530)]
		[Int32]$Port,
		[ValidateSet("tcp","udp")]
		[string]$Protocol,
		[Int32]$VSIndex,
		[Int16]$AddVia,
		[bool]$Cache,
		[string]$CertFile,
		[ValidateSet("tcp","icmp","https","http","smtp","nntp","ftp","telnet","pop3","imap","rdp","none")]
		[string]$CheckType,
		[string]$CheckHost,
		[string]$CheckPattern,
		[string]$CheckUrl,
		[string]$CheckHeaders,
		[string]$MatchLen,
		[bool]$CheckUse1_1,
		[ValidateRange(3,65530)]
		[Int32]$CheckPort,
		[bool]$EnhancedHealthChecks,
		[Int32]$RsMinimum,
		[ValidateRange(0,2)]
		[Int16]$ClientCert,
		[bool]$Compress,
		[string]$Cookie,
		[ValidateRange(0,100)]
		[Int16]$CachePercent,
		[string]$DefaultGW,
		[bool]$Enable,
		[string]$ErrorCode,
		[string]$ErrorUrl,
		[ValidateRange(3,65530)]
		[Int32]$PortFollow,
		[bool]$ForceL7,
		[ValidateRange(0,86400)]
		[Int32]$Idletime,
		[String[]]$LocalBindAddresses,
		[ValidateSet("gen","http","tls","ts")]
		[string]$VSType,
		[string]$Nickname,
		[ValidateSet("ssl","cookie","active-cookie","cookie-src","active-cook-src","cookie-hash",
		             "url","query-hash","host","header","super","super-src","src","rdp","rdp-src",
		             "rdp-sb","udpsip")]
		[string]$Persist,
		[ValidateRange(0, 604800)]
		[Int32]$PersistTimeout,
		[string]$QueryTag,
		[string]$CipherSet,
		[bool]$SSLReencrypt,
		[bool]$SSLReverse,
		[ValidateSet("","http","https")]
		[string]$SSLRewrite,
		[string]$ReverseSNIHostname,
		[ValidateSet("rr","wrr","lc","wlc","fixed","adaptive","sh")]
		[string]$Schedule,
		[ValidateRange(0,5)]
		[Int16]$ServerInit,
		[bool]$SSLAcceleration,
		[string]$StandByAddr,
		[string]$StandByPort,
		[Int32]$TransactionLimit,
		[bool]$Transparent,
		[bool]$SubnetOriginating,
		[bool]$UseforSnat,
		[ValidateSet("0","1","2","4","8")]
		[string]$QoS,
		[int32]$CheckUseGet,
		[ValidateRange(0,7)]
		[Int16]$Verify,
		[string]$ExtraHdrKey,
		[string]$ExtraHdrValue,
		[string]$AllowedHosts,
		[string]$AllowedDirectories,
		[string]$AllowedGroups,
		[bool]$IncludeNestedGroups,
		[bool]$DisplayPubPriv,
		[bool]$DisablePasswordForm,
		[string]$Domain,
		[string]$AltDomains,
		[string]$Logoff,
		[ValidateRange(0,7)]
		[Int16]$ESPLogs,
		[string]$SMTPAllowedDomains,
		[bool]$ESPEnabled,
		[ValidateRange(0,5)]
		[Int16]$InputAuthMode,
		[ValidateRange(0,1)]
		[Int16]$OutputAuthMode,
		[ValidateRange(0,1)]
		[Int16]$StartTLSMode,
		[string]$ExtraPorts,
		[string]$AltAddress,
		[bool]$MultiConnect,
		[string]$SingleSignOnDir,
		[string]$OCSPVerify,
		[Int32]$FollowVSID,
		[bool]$TlsType = $false,
		[string]$CheckPostData,
		[string]$CheckCodes,
		[string]$PreProcPrecedence,
		[Int16]$PreProcPrecedencePos,
		[string]$RequestPrecedence,
		[Int16]$RequestPrecedencePos,
		[string]$ResponsePrecedence,
		[Int16]$ResponsePrecedencePos,
		[string]$RsRulePrecedence,
		[Int16]$RsRulePrecedencePos,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[bool]$Intercept,
		[ValidateNotNullOrEmpty()]
		[string]$InterceptOpts,
		[ValidateNotNullOrEmpty()]
		[string]$InterceptRules,
		[ValidateRange(0, 100000)]
		[int32]$AlertThreshold,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	if ($VSIndex) {
		if ($VirtualService) {
			Throw "The VSIndex and VirtualService parameters are mutually exclusive."
		}
		if ($Port) {
			Throw "The VSIndex and Port parameters are mutually exclusive."
		}
		if ($Protocol) {
			Throw "The VSIndex and Protocol parameters are mutually exclusive."
		}
	} Elseif ($VirtualService) {
		if (!$Port -or !$Protocol) {
			Throw "The VirtualService, Port and Protocol parameters must be used together."
		}
	} else {
		Throw "Either the VirtualService or VSIndex parameter is required."
	}

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command modvs -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
}
New-Alias -Name Set-VirtualService -value Set-AdcVirtualService -Description "Alias for Set-VirtualService command"
Export-ModuleMember -function Set-AdcVirtualService -Alias Set-VirtualService

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-VSTotals
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$propertyTable = @{}

	$response = Send-LBMessage -Command vstotals -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort

	if ($response.code -eq "fail") {
		$response.Error
	} else {
		$response.VSTotals | Add-Member -MemberType NoteProperty -Name Type -Value "VSTotals"
		$response.SUBVSTotals | Add-Member -MemberType NoteProperty -Name Type -Value "SubVSTotals"
		$response.RSTotals | Add-Member -MemberType NoteProperty -Name Type -Value "RSTotals"
		Write-Output $response.VSTotals
		Write-Output $response.SUBVSTotals
		Write-Output $response.RSTotals
	}
}

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-VSPacketFilterACL
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[string]$VirtualService,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateRange(3,65530)]
		[Int32]$Port,
		[Parameter(Mandatory=$true,Position=2)]
		[ValidateSet("tcp","udp")]
		[string]$Protocol,
		[Parameter(Mandatory=$true,Position=3)]
		[ValidateSet("black","white")]
		[String]$Type,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$propertyTable = @{}
	$propertyTable.Add("listvs", $Type)
	$propertyTable.Add("vsip", $VirtualService)
	$propertyTable.Add("vsport", $Port)
	$propertyTable.Add("vsprot", $Protocol)

	$response = Send-LBMessage -Command aclcontrol -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	if ($response.code -eq "fail")
	{
		$response.Error
	}
	else
	{
		$response.VS | Convert-XmlToPSObject
	}
}

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Add-VSPacketFilterAddr
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[string]$VirtualService,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateRange(3,65530)]
		[Int32]$Port,
		[Parameter(Mandatory=$true,Position=2)]
		[ValidateSet("tcp","udp")]
		[string]$Protocol,
		[Parameter(Mandatory=$true,Position=3)]
		[ValidateSet("black","white")]
		[String]$Type,
		[Parameter(Mandatory=$true,Position=4)]
		[ValidateNotNullOrEmpty()]
		[String]$Address,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$propertyTable = @{}
	$propertyTable.Add("addvs", $Type)
	$propertyTable.Add("vsip", $VirtualService)
	$propertyTable.Add("vsport", $Port)
	$propertyTable.Add("vsprot", $Protocol)
	$propertyTable.Add("addr", $Address)

	Send-LBMessage -Command aclcontrol -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
}

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-VSPacketFilterAddr
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[string]$VirtualService,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateRange(3,65530)]
		[Int32]$Port,
		[Parameter(Mandatory=$true,Position=2)]
		[ValidateSet("tcp","udp")]
		[string]$Protocol,
		[Parameter(Mandatory=$true,Position=3)]
		[ValidateSet("black","white")]
		[String]$Type,
		[Parameter(Mandatory=$true,Position=4)]
		[ValidateNotNullOrEmpty()]
		[String]$Address,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$propertyTable = @{}
	$propertyTable.Add("delvs", $Type)
	$propertyTable.Add("vsip", $VirtualService)
	$propertyTable.Add("vsport", $Port)
	$propertyTable.Add("vsprot", $Protocol)
	$propertyTable.Add("addr", $Address)

	Send-LBMessage -Command aclcontrol -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
}

Function ExportVSTemplate
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$VirtualService,
		[Parameter(Mandatory=$true)]
		[ValidateRange(3,65530)]
		[Int32]$Port,
		[Parameter(Mandatory=$true)]
		[ValidateSet("tcp","udp")]
		[string]$Protocol,
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Path,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$params = @{}
	$params.Add("vs", $VirtualService)
	$params.Add("port", $Port)
	$params.Add("prot", $Protocol)

	Send-LBMessage -Command exportvstmplt -ParameterValuePair $params -File $Path -Output -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
}

#Function UploadTemplate
Function Install-Template
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[string]$Path,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$params = @{}

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command uploadtemplate -ParameterValuePair $propertyTable -File $Path -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response
}
New-Alias -Name UploadTemplate -value Install-Template -Description "Alias for UploadTemplate command"
Export-ModuleMember -function Install-Template -Alias UploadTemplate

#Function DeleteTemplate
Function Remove-Template
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command deltemplate -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name DeleteTemplate -value Remove-Template -Description "Alias for DeleteTemplate command"
Export-ModuleMember -function Remove-Template -Alias DeleteTemplate

#Function ListTemplates
Function Get-Template
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command listtemplates -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
	$response.template | Convert-XmlToPSObject
}
New-Alias -Name ListTemplates -value Get-Template -Description "Alias for ListTemplates command"
Export-ModuleMember -function Get-Template -Alias ListTemplates

#endregion - Virtual Service

#region - SSO Domains

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function New-SSODomain
{
	[CmdletBinding()]
	Param(
		[Parameter(Position=0,ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[Alias("Name")]
		[string]$Domain,
		[Parameter(Position=1,ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[ValidateSet("Unencrypted","StartTLS","LDAPS")]
		[string]$TLS,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[ValidateSet("LDAP-Unencrypted","LDAP-StartTLS","LDAP-LDAPS", "RADIUS", "RSA-SECURID", "Certificate", "KCD", "RADIUS and LDAP-Unencrypted", "RADIUS and LDAP-StartTLS", "RADIUS and LDAP-LDAPS", "RSA-SECURID and LDAP-Unencrypted", "RSA-SECURID and LDAP-StartTLS", "RSA-SECURID and LDAP-LDAPS")]
		[string]$auth_type,
		[Parameter(Position=2,ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[String[]]$Server,
		[Parameter(Position=0,ParameterSetName="Multiple",ValueFromPipeline=$true)]
		[PSCustomObject[]]$DomainObject,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[Alias("KerberosDomain")]
		[string]$kerberos_domain,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[Alias("KerberosKDC")]
		[string]$kerberos_kdc,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[Alias("KCDUsername")]
		[string]$kcd_username,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[Alias("KCDPassword")]
		[string]$kcd_password,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[Alias("LDAPAdmin")]
		[string]$ldap_admin,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[Alias("LDAPPassword")]
		[string]$ldap_password,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[Alias("ServerSide")]
		[string]$server_side,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[Alias("CertCheck")]
		[string]$cert_check_asi,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[Alias("CertCheckCn")]
		[string]$cert_check_cn,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[Alias("LogonTranscode")]
		[bool]$Logon_Transcode,
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	PROCESS
	{
		switch ($PsCmdlet.ParameterSetName)
		{
			"Single"
			{
				Write-Verbose "Domain = $Domain"
				if (-not (Get-SSODomain -LoadBalancer $LoadBalancer | Where-Object{$_.Name -eq $Domain}))
				{
					$propertytable = Convert-BoundParameters $psboundparameters
					$response = Send-LBMessage -command adddomain -parametervaluepair $propertytable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
					if ($response -eq "ok")
					{
						$response = Send-LBMessage -command moddomain -parametervaluepair $propertytable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
						if ($response.haschildnodes)
						{
							$response.domain | Where-Object{$_.Name -eq $Domain}
						}
					}
				}
				else
				{
					Write-Error "The domain name already exists."
				}
				break
			}
			"Multiple"
			{
				foreach ($object in $DomainObject)
				{
					New-SSODomain -Domain $DomainObject.Domain -TLS $DomainObject.TLS -Server $DomainObject.Server -LoadBalancer $LoadBalancer -Credential $Credential
				}
				break
			}
		}
	}
}
Export-ModuleMember -function New-SSODomain

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-SSODomain
{
	[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact="High")]
	Param(
		[Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
		[Alias("Name")]
		[string[]]$Domain,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred,
		[switch]$Force
	)
	PROCESS
	{
		foreach ($name in $Domain)
		{
			if (Get-SSODomain -LoadBalancer $LoadBalancer -Credential $Credential | Where-Object{$_.Name -eq $name})
			{
				if (($Force) -or ($PsCmdlet.ShouldProcess($name, "Remove SSO Domain")))
				{
					$response = Send-LBMessage -command deldomain -parametervaluepair @{domain=$name} -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
					if ($response = "ok")
					{
						Write-Host "The SSO Domain `"$name`" has been removed."
					}
				}
			}
			else
			{
				Write-Error "The SSO Domain `"$name`" does not exist. Have you already deleted it?"
			}
		}
	}
}
Export-ModuleMember -function Remove-SSODomain

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Set-SSODomain
{
	[CmdletBinding()]
	Param(
		[Parameter(Position=0,ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[Alias("Name")]
		[string]$Domain,
		[Parameter(Position=1,ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[ValidateSet("Unencrypted","StartTLS","LDAPS")]
		[string]$TLS,
		[Parameter(Position=2,ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[String[]]$Server,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[String[]]$Server2,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[ValidateSet("LDAP-Unencrypted","LDAP-StartTLS","LDAP-LDAPS", "RADIUS", "RSA-SECURID", "Certificate", "KCD", "RADIUS and LDAP-Unencrypted", "RADIUS and LDAP-StartTLS", "RADIUS and LDAP-LDAPS", "RSA-SECURID and LDAP-Unencrypted", "RSA-SECURID and LDAP-StartTLS", "RSA-SECURID and LDAP-LDAPS")]
		[string]$auth_type,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[ValidateRange(0,999)]
		[int]$max_failed_auths,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[ValidateRange(60,86400)]
		[int]$reset_fail_tout,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[ValidateRange(60,86400)]
		[int]$unblock_tout,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[ValidateSet("Notspecified","Not specified","Principalname","Username","Usernameonly","Username only")]
		[string]$logon_fmt,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[ValidateSet("Notspecified","Not specified","Principalname","Username")]
		[string]$logon_fmt2,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[string]$logon_domain,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[Alias("stt")][ValidateSet("idle time","max duration")]
		[string]$sess_tout_type,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[Alias("stipub")][ValidateRange(60,86400)]
		[int]$sess_tout_idle_pub,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[Alias("stdpub")][ValidateRange(60,86400)]
		[int]$sess_tout_duration_pub,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[Alias("stipriv")][ValidateRange(60,86400)]
		[int]$sess_tout_idle_priv,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[Alias("stdpriv")][ValidateRange(60,86400)]
		[int]$sess_tout_duration_priv,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[string]$testuser,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[string]$testpass,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[Alias("Secret")]
		[string]$radius_shared_secret,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[Alias("KerberosDomain")]
		[string]$kerberos_domain,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[Alias("SKerberosKDC")]
		[string]$kerberos_kdc,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[Alias("KCDUsername")]
		[string]$kcd_username,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[Alias("KCDPassword")]
		[string]$kcd_password,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[Alias("LDAPAdmin")]
		[string]$ldap_admin,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[Alias("LDAPPassword")]
		[string]$ldap_password,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[Alias("ServerSide")]
		[string]$server_side,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[Alias("CertCheck")]
		[string]$cert_check_asi,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[Alias("CertCheckCn")]
		[string]$cert_check_cn,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[Alias("LogonTranscode")]
		[bool]$Logon_Transcode,
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[PSCustomObject[]]$DomainObject,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	BEGIN
	{
		# We allow logon_fmt values with or without a space, but the
		# RESTful API requires a space character for each of these.
		if ($logon_fmt -eq "Notspecified")
		{
			$psboundparameters.Remove("logon_fmt")
			$psboundparameters.Add("logon_fmt", "Not specified")
		}
		Elseif ($logon_fmt -eq "Usernameonly")
		{
			$psboundparameters.Remove("logon_fmt")
			$psboundparameters.Add("logon_fmt", "Username only")
		}

		if ($logon_fmt2 -eq "Notspecified")
		{
			$psboundparameters.Remove("logon_fmt2")
			$psboundparameters.Add("logon_fmt2", "Not specified")
		}
	}

	PROCESS
	{
		switch ($PsCmdlet.ParameterSetName)
		{
			"Single"
			{
				Write-Verbose "Domain = $Domain"
				if (Get-SSODomain -LoadBalancer $LoadBalancer -Credential $Credential | Where-Object{$_.Name -eq $Domain})
				{
					$propertytable = Convert-BoundParameters $psboundparameters
					$response = Send-LBMessage -command moddomain -parametervaluepair $propertytable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
					if ($response.haschildnodes)
					{
						$response.domain | Where-Object{$_.Name -eq $Domain}
					}
				}
				else
				{
					Write-Error "The domain name doesn't exist.  Did you mean to execute New-SSODomain instead?"
				}
				break
			}
			"Multiple"
			{
				foreach ($object in $DomainObject)
				{
					Set-SSODomain $DomainObject.Domain -TLS $DomainObject.TLS -Server $DomainObject.Server -LoadBalancer $LoadBalancer -Credential $Credential
				}
				break
			}
		}
	}
}
Export-ModuleMember -function Set-SSODomain

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-SSODomain
{
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

	$response = Send-LBMessage -command showdomain -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	if ($response.hasChildNodes)
	{
		$response.Domain | Convert-XmlToPSObject
	}
}
Export-ModuleMember -function Get-SSODomain

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Get-SSODomainLockedUsers
Function Get-SSODomainLockedUser
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$false,Position=0,ValueFromPipeline=$true)]
		[Alias("Name")]
		[string]$Domain,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	PROCESS
	{
		$propertytable = Convert-BoundParameters $psboundparameters
		$response = Send-LBMessage -command showdomainlockedusers -parametervaluepair $propertytable -LoadBalancer $LoadBalancer -Credential $Credential
		if ($response.hasChildNodes)
		{
			$response.LockedUsers | Convert-XmlToPSObject
		}
	}
}
New-Alias -Name Get-SSODomainLockedUsers -value Get-SSODomainLockedUser -Description "Alias for Get-SSODomainLockedUsers command"
Export-ModuleMember -function Get-SSODomainLockedUser -Alias Get-SSODomainLockedUsers

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Set-SSODomainUnlockUsers
Function Set-SSODomainUnlockUser
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
		[Alias("Name")]
		[string]$Domain,
		[Parameter(Mandatory=$true,Position=1,ValueFromPipeline=$true)]
		[string]$Users,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	PROCESS
	{
		$propertytable = Convert-BoundParameters $psboundparameters
		$response = Send-LBMessage -command unlockdomainusers -parametervaluepair $propertytable -LoadBalancer $LoadBalancer -Credential $Credential
		if ($response.hasChildNodes)
		{
			$response.UnlockedUsers | Convert-XmlToPSObject
		}
	}
}
New-Alias -Name Set-SSODomainUnlockUsers -value Set-SSODomainUnlockUser -Description "Alias for Set-SSODomainUnlockUsers command"
Export-ModuleMember -function Set-SSODomainUnlockUser -Alias Set-SSODomainUnlockUsers

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function UploadRSAConfigurationFile
Function Install-SSORSAConfigurationFile
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[string]$Path,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$params = @{}
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters
	$response = Send-LBMessage -Command setrsaconfig -ParameterValuePair $propertyTable -File $Path -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response
}
New-Alias -Name UploadRSAConfigurationFile -value Install-SSORSAConfigurationFile -Description "Alias for UploadRSAConfigurationFile command"
Export-ModuleMember -function Install-SSORSAConfigurationFile -Alias UploadRSAConfigurationFile

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function UploadRSANodeSecretAndPassword
Function Install-SSORSANodeSecretAndPassword
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[string]$Password,
		[Parameter(Mandatory=$true)]
		[string]$Path,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$params = @{}
	$params.Add("rsanspwd",[System.Web.HttpUtility]::UrlEncode($Password))
	$response = Send-LBMessage -Command setrsanodesecret -ParameterValuePair $params -File $Path -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response
}
New-Alias -Name UploadRSANodeSecretAndPassword -value Install-SSORSANodeSecretAndPassword -Description "Alias for UploadRSANodeSecretAndPassword command"
Export-ModuleMember -function Install-SSORSANodeSecretAndPassword -Alias UploadRSANodeSecretAndPassword

#endregion - SSO Domains

#region - Statistics

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Get-Statistics
Function Get-LogStatistics
{
	[CmdletBinding()]
	Param(
		[switch]$VirtualService,
		[switch]$Totals,
		[switch]$RealServer,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	if ((!$VirtualService) -and (!$Totals) -and (!$RealServer))
	{
		$VirtualService = $true
		$Totals = $true
		$RealServer = $true
	}

	$response = Send-LBMessage -command stats -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort

	if (($VirtualService) -and ($response.Vs))
	{
		$response.Vs | Convert-XmlToPSObject
	}

	if (($Totals) -and ($response.VStotals))
	{
		$response.VStotals | Convert-XmlToPsObject
		$response.CPU | Convert-XmlToPsObject
		$response.Network | Convert-XmlToPsObject
		$response.Memory | Convert-XmlToPsObject
		$response.TPS | Convert-XmlToPsObject
	}

	if (($RealServer) -and ($response.rs))
	{
		$response.rs | Convert-XmlToPSObject
	}
}
New-Alias -Name Get-Statistics -value Get-LogStatistics -Description "Alias for Get-Statistics command"
Export-ModuleMember -function Get-LogStatistics -Alias Get-Statistics

#Function LicenseInfo
Function Get-LicenseInfo
{
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
	$response = Send-LBMessage -command licenseinfo -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response
}
New-Alias -Name LicenseInfo -value Get-LicenseInfo -Description "Alias for LicenseInfo command"
Export-ModuleMember -function Get-LicenseInfo -Alias LicenseInfo

#endregion - Statistics

#region - Real Servers

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function New-RealServer
Function New-AdcRealServer
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$VirtualService,
		[ValidateRange(3,65530)]
		[Int32]$Port,
		[ValidateSet("tcp","udp")]
		[string]$Protocol,
		[Int32]$VSIndex,
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$RealServer,
		[Parameter(Mandatory=$true)]
		[ValidateRange(3,65530)]
		[Int32]$RealServerPort,
		[ValidateRange(1,65530)]
		[Int32]$Weight,
		[ValidateSet("nat","route")]
		[string]$Forward = "nat",
		[bool]$Enable = $true,
		[bool]$Non_Local = $false,
		[ValidateRange(0,100000)]
		[Int64]$Limit = 0,
		[bool]$Critical,
		[ValidateRange(0,65535)]
		[Int32]$Follow,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	if ($VSIndex) {
		if ($VirtualService) {
			Throw "The VSIndex and VirtualService parameters are mutually exclusive."
		}
		if ($Port) {
			Throw "The VSIndex and Port parameters are mutually exclusive."
		}
		if ($Protocol) {
			Throw "The VSIndex and Protocol parameters are mutually exclusive."
		}
	} Elseif ($VirtualService) {
		if (!$Port -or !$Protocol) {
			Throw "The VirtualService, Port and Protocol parameters must be used together."
		}
	} else {
		Throw "Either the VirtualService or VSIndex parameter is required."
	}

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command addrs -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort

	if ($response.code -eq "fail") {
		$response.Error
	} else {
		$response.RS | Convert-XmlToPSObject
	}
}
New-Alias -Name New-RealServer -value New-AdcRealServer -Description "Alias for New-RealServer command"
Export-ModuleMember -function New-AdcRealServer -Alias New-RealServer

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Remove-RealServer
Function Remove-AdcRealServer
{
	[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact="High")]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$VirtualService,
		[ValidateRange(3,65530)]
		[Int32]$Port,
		[ValidateSet("tcp","udp")]
		[string]$Protocol,
		[Int32]$VSIndex,
		[ValidateNotNullOrEmpty()]
		[string]$RealServer,
		[ValidateRange(3,65530)]
		[Int32]$RealServerPort,
		[Int32]$RSIndex,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred,
		[switch]$Force
	)

	if ($VSIndex) {
		if ($VirtualService) {
			Throw "The VSIndex and VirtualService parameters are mutually exclusive."
		}
		if ($Port) {
			Throw "The VSIndex and Port parameters are mutually exclusive."
		}
		if ($Protocol) {
			Throw "The VSIndex and Protocol parameters are mutually exclusive."
		}
	}
	Elseif ($VirtualService) {
		if (!$Port -or !$Protocol) {
			Throw "The VirtualService, Port and Protocol parameters must be used together."
		}
	}
	else {
		Throw "Either the VirtualService or VSIndex parameter is required."
	}

	if ($RSIndex) {
		if ($RealServer) {
			Throw "The RSIndex and RealServer parameters are mutually exclusive."
		}
		if ($RealServerPort) {
			Throw "The RSIndex and RealServerPort parameters are mutually exclusive."
		}
	}
	Elseif ($RealServer) {
		if (!$RealServerPort) {
			Throw "The RealServer and RealServerPort parameters must be used together."
		}
	}
	else {
		Throw "Either the RealServer or RSIndex parameter is required."
	}

	$propertytable = Convert-BoundParameters -hashtable $psboundparameters

	if (($Force) -or ($PsCmdlet.ShouldProcess($RealServer, "Remove Real Server")))
	{
		Send-LBMessage -Command delrs -ParameterValuePair $propertytable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	}
}
New-Alias -Name Remove-RealServer -value Remove-AdcRealServer -Description "Alias for Remove-RealServer command"
Export-ModuleMember -function Remove-AdcRealServer -Alias Remove-RealServer

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Get-RealServer
Function Get-AdcRealServer
{
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

	$realServers = Get-Statistics -RealServer -LoadBalancer $LoadBalancer -Credential $Credential
	foreach ($rs in $realServers)
	{
		$vs = Get-VirtualService -LoadBalancer $LoadBalancer -Credential $Credential | Where-Object {$_.Index -eq $rs.VSIndex}
		$rs | Add-Member -MemberType NoteProperty -Name VirtualService -Value $vs.VSAddress
		$rs | Add-Member -MemberType NoteProperty -Name VSPort -Value $vs.VSPort
		$rs | Add-Member -MemberType NoteProperty -Name Protocol -Value $vs.Protocol
		Write-Output $rs
	}
}
New-Alias -Name Get-RealServer -value Get-AdcRealServer -Description "Alias for Get-RealServer command"
Export-ModuleMember -function Get-AdcRealServer -Alias Get-RealServer

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Set-RealServer
Function Set-AdcRealServer
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$VirtualService,
		[ValidateRange(3,65530)]
		[Int32]$Port,
		[ValidateSet("tcp","udp")]
		[string]$Protocol,
		[Int32]$VSIndex,
		[ValidateNotNullOrEmpty()]
		[string]$RealServer,
		[ValidateRange(3,65530)]
		[Int32]$RealServerPort,
		[Int32]$RSIndex,
		[ValidateRange(3,65530)]
		[Int32]$NewPort,
		[ValidateRange(1,65530)]
		[Int32]$Weight,
		[ValidateSet("nat","route")]
		[string]$Forward = "nat",
		[bool]$Enable = $true,
		[ValidateRange(0,100000)]
		[Int64]$Limit = 0,
		[bool]$Critical,
		[ValidateRange(0,65535)]
		[Int32]$Follow,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	if ($VSIndex) {
		if ($VirtualService) {
			Throw "The VSIndex and VirtualService parameters are mutually exclusive."
		}
		if ($Port) {
			Throw "The VSIndex and Port parameters are mutually exclusive."
		}
		if ($Protocol) {
			Throw "The VSIndex and Protocol parameters are mutually exclusive."
		}
	}
	Elseif ($VirtualService) {
		if (!$Port -or !$Protocol) {
			Throw "The VirtualService, Port and Protocol parameters must be used together."
		}
	}
	else {
		Throw "Either the VirtualService or VSIndex parameter is required."
	}

	if ($RSIndex) {
		if ($RealServer) {
			Throw "The RSIndex and RealServer parameters are mutually exclusive."
		}
		if ($RealServerPort) {
			Throw "The RSIndex and RealServerPort parameters are mutually exclusive."
		}
	}
	Elseif ($RealServer) {
		if (!$RealServerPort) {
			Throw "The RealServer and RealServerPort parameters must be used together."
		}
	}
	else {
		Throw "Either the RealServer or RSIndex parameter is required."
	}

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command modrs -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
}
New-Alias -Name Set-RealServer -value Set-AdcRealServer -Description "Alias for Set-RealServer command"
Export-ModuleMember -function Set-AdcRealServer -Alias Set-RealServer

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Enable-RealServer
Function Enable-AdcRealServer
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[Parameter(Position=0,Mandatory=$true)]
		[string]$IPAddress,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	Send-LBMessage -Command enablers -ParameterValuePair @{rs=$IPAddress} -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
}
New-Alias -Name Enable-RealServer -value Enable-AdcRealServer -Description "Alias for Enable-RealServer command"
Export-ModuleMember -function Enable-AdcRealServer -Alias Enable-RealServer

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Disable-RealServer
Function Disable-AdcRealServer
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[Parameter(Position=0,Mandatory=$true)]
		[string]$IPAddress,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	Send-LBMessage -Command disablers -ParameterValuePair @{rs=$IPAddress} -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
}
New-Alias -Name Disable-RealServer -value Disable-AdcRealServer -Description "Alias for Disable-RealServer command"
Export-ModuleMember -function Disable-AdcRealServer -Alias Disable-RealServer

#endregion - Real Servers

#region - Rules

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml

#Function New-Rule
Function New-AdcContentRule
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$true,Position=0)]
		[string]$Name,
		[ValidateSet("regex","prefix","postfix")]
		[string]$MatchType = "regex",
		[bool]$IncHost = $false,
		[bool]$NoCase = $false,
		[bool]$Negate = $false,
		[bool]$IncQuery = $false,
		[string]$Header,
		[string]$Pattern,
		[string]$Replacement,
		[Int32]$Type,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters
	$response = Send-LBMessage -Command addrule -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response.childnodes
}
New-Alias -Name New-Rule -value New-AdcContentRule -Description "Alias for New-Rule command"
Export-ModuleMember -function New-AdcContentRule -Alias New-Rule

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Remove-Rule
Function Remove-AdcContentRule
{
	[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact="High")]
	Param(
		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
		[string]$Name,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred,
		[switch]$Force
	)

	if (($Force) -or ($PsCmdlet.ShouldProcess($Name, "Remove Rule")))
	{
		$response = Send-LBMessage -Command delrule -ParameterValuePair @{name=$name} -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	}
}
New-Alias -Name Remove-Rule -value Remove-AdcContentRule -Description "Alias for Remove-Rule command"
Export-ModuleMember -function Remove-AdcContentRule -Alias Remove-Rule

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Set-Rule
Function Set-AdcContentRule
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$true,Position=0)]
		[string]$Name,
		[ValidateSet("regex","prefix","postfix")]
		[string]$MatchType = "regex",
		[bool]$IncHost,
		[bool]$NoCase,
		[bool]$Negate,
		[bool]$IncQuery,
		[string]$Header,
		[string]$Pattern,
		[string]$Replacement,
		[Int32]$Type,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters
	$response = Send-LBMessage -Command modrule -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response.childnodes
}
New-Alias -Name Set-Rule -value Set-AdcContentRule -Description "Alias for Set-Rule command"
Export-ModuleMember -function Set-AdcContentRule -Alias Set-Rule

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Get-Rule
Function Get-AdcContentRule
{
	[CmdletBinding(DefaultParameterSetName="All")]
	Param(
		[Parameter(ParameterSetName="Name")]
		[string]$name,
		[Parameter(ParameterSetName="Type")]
		[ValidateSet("MatchContentRule","AddHeaderRule","DeleteHeaderRule","ReplaceHeaderRule","ModifyUrlRule")]
		[string]$Type,
		[Parameter(ParameterSetName="All")]
		[switch]$All,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$ht = @{}
	switch ($PsCmdlet.parametersetname)
	{
		"Name"
		{
			$ht.Add("name",$Name)
			break
		}
		"Type"
		{
			$TypeNumber = $null
			$TypeNumber = $SystemRuleType[$Type]
			$ht.Add("type",$TypeNumber)
			break
		}
	}
	$response = Send-LBMessage -command showrule -ParameterValuePair $ht -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	if ($response.code -eq "fail")
	{
		$response.Error
	}
	else {
		foreach ($ruletype in $SystemRuleType.Keys)
		{
			if ($response.$ruletype)
			{
				$response.$ruletype | Add-Member -MemberType NoteProperty -Name RuleType -Value $ruletype
			}
		}
		$response.childnodes | Sort-Object -Property RuleType | Format-List
	}
}
New-Alias -Name Get-Rule -value Get-AdcContentRule -Description "Alias for Get-Rule command"
Export-ModuleMember -function Get-AdcContentRule -Alias Get-Rule

#endregion - Rules

#region - Real Server Rule

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function New-RealServerRule
Function New-AdcRealServerRule
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$VirtualService,
		[ValidateRange(3,65530)]
		[Int32]$Port,
		[ValidateSet("tcp","udp")]
		[string]$Protocol,
		[Int32]$VSIndex,
		[ValidateNotNullOrEmpty()]
		[string]$RealServer,
		[ValidateRange(3,65530)]
		[Int32]$RSPort,
		[Int32]$RSIndex,
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$RuleName,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	if ($VSIndex) {
		if ($VirtualService) {
			Throw "The VSIndex and VirtualService parameters are mutually exclusive."
		}
		if ($Port) {
			Throw "The VSIndex and Port parameters are mutually exclusive."
		}
		if ($Protocol) {
			Throw "The VSIndex and Protocol parameters are mutually exclusive."
		}
	} Elseif ($VirtualService) {
		if (!$Port -or !$Protocol) {
			Throw "The VirtualService, Port and Protocol parameters must be used together."
		}
	} else {
		Throw "Either the VirtualService or VSIndex parameter is required."
	}

	if ($RSIndex) {
		if ($RealServer) {
			Throw "The RSIndex and RealServer parameters are mutually exclusive."
		}
		if ($RSPort) {
			Throw "The RSIndex and RSPort parameters are mutually exclusive."
		}
	} Elseif ($RealServer) {
		if (!$RSPort) {
			Throw "The RealServer and RSPort parameters must be used together."
		}
	} else {
		Throw "Either the RealServer or RSIndex parameter is required."
	}

	$propertytable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -command addrsrule -ParameterValuePair $propertytable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
}
New-Alias -Name New-RealServerRule -value New-AdcRealServerRule -Description "Alias for New-RealServerRule command"
Export-ModuleMember -function New-AdcRealServerRule -Alias New-RealServerRule

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Remove-RealServerRule
Function Remove-AdcRealServerRule
{
	[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact="High")]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$VirtualService,
		[ValidateRange(3,65530)]
		[Int32]$Port,
		[ValidateSet("tcp","udp")]
		[string]$Protocol,
		[Int32]$VSIndex,
		[ValidateNotNullOrEmpty()]
		[string]$RealServer,
		[ValidateRange(3,65530)]
		[Int32]$RSPort,
		[Int32]$RSIndex,
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$RuleName,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred,
		[switch]$Force
	)

	if ($VSIndex) {
		if ($VirtualService) {
			Throw "The VSIndex and VirtualService parameters are mutually exclusive."
		}
		if ($Port) {
			Throw "The VSIndex and Port parameters are mutually exclusive."
		}
		if ($Protocol) {
			Throw "The VSIndex and Protocol parameters are mutually exclusive."
		}
	} Elseif ($VirtualService) {
		if (!$Port -or !$Protocol) {
			Throw "The VirtualService, Port and Protocol parameters must be used together."
		}
	} else {
		Throw "Either the VirtualService or VSIndex parameter is required."
	}

	if ($RSIndex) {
		if ($RealServer) {
			Throw "The RSIndex and RealServer parameters are mutually exclusive."
		}
		if ($RSPort) {
			Throw "The RSIndex and RSPort parameters are mutually exclusive."
		}
	} Elseif ($RealServer) {
		if (!$RSPort) {
			Throw "The RealServer and RSPort parameters must be used together."
		}
	} else {
		Throw "Either the RealServer or RSIndex parameter is required."
	}

	$propertytable = Convert-BoundParameters -hashtable $psboundparameters

	if (($Force) -or ($PsCmdlet.ShouldProcess($RuleName, "Remove Real Server Rule")))
	{
		Send-LBMessage -command delrsrule -ParameterValuePair $propertytable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	}
}
New-Alias -Name Remove-RealServerRule -value Remove-AdcRealServerRule -Description "Alias for Remove-RealServerRule command"
Export-ModuleMember -function Remove-AdcRealServerRule -Alias Remove-RealServerRule

#endregion - Real Server Rule

#region - Virtual Server Rules

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function New-VirtualServerRule
Function New-AdcVirtualServerRule
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateSet("pre","response","request")]
		[string]$RuleType,
		[ValidateNotNullOrEmpty()]
		[string]$VirtualService,
		[ValidateRange(3,65530)]
		[Int32]$Port,
		[ValidateSet("tcp","udp")]
		[string]$Protocol,
		[Int32]$VSIndex,
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$RuleName,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	if ($VSIndex) {
		if ($VirtualService) {
			Throw "The VSIndex and VirtualService parameters are mutually exclusive."
		}
		if ($Port) {
			Throw "The VSIndex and Port parameters are mutually exclusive."
		}
		if ($Protocol) {
			Throw "The VSIndex and Protocol parameters are mutually exclusive."
		}
	} Elseif ($VirtualService) {
		if (!$Port -or !$Protocol) {
			Throw "The VirtualService, Port and Protocol parameters must be used together."
		}
	} else {
		Throw "Either the VirtualService or VSIndex parameter is required."
	}

	$Command = ""
	switch ($RuleType)
	{
		"pre" {$Command = "addprerule"}
		"response" {$Command = "addresponserule"}
		"request" {$Command = "addrequestrule"}
	}

	$propertytable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command $Command -ParameterValuePair $propertytable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
}
New-Alias -Name New-VirtualServerRule -value New-AdcVirtualServerRule -Description "Alias for New-VirtualServerRule command"
Export-ModuleMember -function New-AdcVirtualServerRule -Alias New-VirtualServerRule

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Remove-VirtualServerRule
Function Remove-AdcVirtualServerRule
{
	[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact="High")]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateSet("pre","response","request")]
		[string]$RuleType,
		[ValidateNotNullOrEmpty()]
		[string]$VirtualService,
		[ValidateRange(3,65530)]
		[Int32]$Port,
		[ValidateSet("tcp","udp")]
		[string]$Protocol,
		[Int32]$VSIndex,
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$RuleName,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred,
		[switch]$Force
	)

	if ($VSIndex) {
		if ($VirtualService) {
			Throw "The VSIndex and VirtualService parameters are mutually exclusive."
		}
		if ($Port) {
			Throw "The VSIndex and Port parameters are mutually exclusive."
		}
		if ($Protocol) {
			Throw "The VSIndex and Protocol parameters are mutually exclusive."
		}
	} Elseif ($VirtualService) {
		if (!$Port -or !$Protocol) {
			Throw "The VirtualService, Port and Protocol parameters must be used together."
		}
	} else {
		Throw "Either the VirtualService or VSIndex parameter is required."
	}

	$Command = ""
	switch ($RuleType)
	{
		"pre" {$Command = "delprerule"}
		"response" {$Command = "delresponserule"}
		"request" {$Command = "delrequestrule"}
	}

	$propertytable = Convert-BoundParameters -hashtable $psboundparameters

	if (($Force) -or ($PsCmdlet.ShouldProcess($RuleName, "Remove Virtual Server Rule")))
	{
		Send-LBMessage -Command $Command -ParameterValuePair $propertytable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	}
}
New-Alias -Name Remove-VirtualServerRule -value Remove-AdcVirtualServerRule -Description "Alias for Remove-VirtualServerRule command"
Export-ModuleMember -function Remove-AdcVirtualServerRule -Alias Remove-VirtualServerRule

#endregion - Virtual Server Rules

#region - Service Check Parameters

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Get-ServiceHealth
Function Get-AdcServiceHealth
{
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
	$response = Send-LBMessage -command showhealth -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response | Convert-XmlToPSObject
}
New-Alias -Name Get-ServiceHealth -value Get-AdcServiceHealth -Description "Alias for Get-ServiceHealth command"
Export-ModuleMember -function Get-AdcServiceHealth -Alias Get-ServiceHealth

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Set-ServiceHealth
Function Set-AdcServiceHealth
{
	[CmdletBinding()]
	Param(
		[Int16]$RetryInterval,
		[Int16]$RetryCount,
		[Int16]$Timeout,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters $psboundparameters
	$response = Send-LBMessage -command modhealth -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response | Convert-XmlToPSObject
}
New-Alias -Name Set-ServiceHealth -value Set-AdcServiceHealth -Description "Alias for Set-ServiceHealth command"
Export-ModuleMember -function Set-AdcServiceHealth -Alias Set-ServiceHealth

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Get-AdaptiveCheck
Function Get-AdcAdaptiveHealthCheck
{
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
	$response = Send-LBMessage -command showadaptive -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response | Convert-XmlToPSObject
}
New-Alias -Name Get-AdaptiveCheck -value Get-AdcAdaptiveHealthCheck -Description "Alias for Get-AdaptiveCheck command"
Export-ModuleMember -function Get-AdcAdaptiveHealthCheck -Alias Get-AdaptiveCheck

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Set-AdaptiveCheck
Function Set-AdcAdaptiveHealthCheck
{
	[CmdletBinding()]
	Param(
		[string]$AdaptiveURL,
		[Int32]$AdaptivePort,
		[Int32]$AdaptiveInterval,
		[Int16]$MinPercent,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters $psboundparameters
	$response = Send-LBMessage -command modadaptive -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response | Convert-XMLToPSObject
}
New-Alias -Name Set-AdaptiveCheck -value Set-AdcAdaptiveHealthCheck -Description "Alias for Set-AdaptiveCheck command"
Export-ModuleMember -function Set-AdcAdaptiveHealthCheck -Alias Set-AdaptiveCheck

#endregion - Service Check Parameters

#region - Certificates

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function New-Certificate
Function New-TlsCertificate
{
	[CmdletBinding()]
	Param(
		[string]$Name,
		[string]$Password,
		[switch]$Replace,
		[string]$Path,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$params = @{cert=$name;replace="0"}

	if ($Replace)
	{
		$params["replace"]="1"
	}
	if ($Password)
	{
		$params.Add("password",[System.Web.HttpUtility]::UrlEncode($Password))
	}

	$response = Send-LBMessage -command addcert -ParameterValuePair $params -File $Path -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	if ($response.code -eq "fail")
	{
		$response.Error
	}
	else {
		$response
	}
}
New-Alias -Name New-Certificate -value New-TlsCertificate -Description "Alias for New-Certificate command"
Export-ModuleMember -function New-TlsCertificate -Alias New-Certificate

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Remove-Certificate
Function Remove-TlsCertificate
{
	[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact="High")]
	Param(
		[string]$Name,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred,
		[switch]$Force
	)

	$param = @{cert=$name}

	if (($Force) -or ($PsCmdlet.ShouldProcess($Name, "Remove Certificate")))
	{
		$response = Send-LBMessage -Command delcert -ParameterValuePair $param -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		if ($response.code -eq "fail")
		{
			$response.Error
		}
		else {
			$response
		}
	}
}
New-Alias -Name Remove-Certificate -value Remove-TlsCertificate -Description "Alias for Remove-Certificate command"
Export-ModuleMember -function Remove-TlsCertificate -Alias Remove-Certificate

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function New-IntermediateCertificate
Function New-TlsIntermediateCertificate
{
	[CmdletBinding()]
	Param(
		[string]$Name,
		[string]$Password,
		[switch]$Replace,
		[string]$Path,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$params = @{cert=$name;replace="0"}

	if ($Replace)
	{
		$params["replace"]="1"
	}
	if ($Password)
	{
		$params.Add("password",[System.Web.HttpUtility]::UrlEncode($Password))
	}

	$response = Send-LBMessage -command addintermediate -ParameterValuePair $params -File $Path -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	if ($response.code -eq "fail")
	{
		$response.Error
	}
	else {
		$response
	}
}
New-Alias -Name New-IntermediateCertificate -value New-TlsIntermediateCertificate -Description "Alias for New-IntermediateCertificate command"
Export-ModuleMember -function New-TlsIntermediateCertificate -Alias New-IntermediateCertificate

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Remove-IntermediateCertificate
Function Remove-TlsIntermediateCertificate
{
	[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact="High")]
	Param(
		[string]$Name,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred,
		[switch]$Force
	)

	$param = @{cert=$name}

	if (($Force) -or ($PsCmdlet.ShouldProcess($Name, "Remove Intermediate Certificate")))
	{
		$response = Send-LBMessage -Command delintermediate -ParameterValuePair $param -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		if ($response.code -eq "fail")
		{
			$response.Error
		}
		else {
			$response
		}
	}
}
New-Alias -Name Remove-IntermediateCertificate -value Remove-TlsIntermediateCertificate -Description "Alias for Remove-IntermediateCertificate command"
Export-ModuleMember -function Remove-TlsIntermediateCertificate -Alias Remove-IntermediateCertificate

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Backup-Certificate
Function Backup-TlsCertificate
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateScript({$_.length -gt 6})]
		[string]$Password,
		[string]$Path,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$params = @{}
	$params.Add("password",[System.Web.HttpUtility]::UrlEncode($Password))
	if (-not ($Path))
	{
		$Path = "$($Env:SystemRoot)\Temp\CertificateBackup_$(Get-Date -format yyyy-MM-dd_HH-mm-ss)"
	}
	Write-Verbose "Path = $Path"
	$response = Send-LBMessage -command backupcert -ParameterValuePair $params -File $Path -Output -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response
}
New-Alias -Name Backup-Certificate -value Backup-TlsCertificate -Description "Alias for Backup-Certificate command"
Export-ModuleMember -function Backup-TlsCertificate -Alias Backup-Certificate


#Function ListCert
Function Get-TlsCertificate
{
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
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command listcert -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
}
New-Alias -Name ListCert -value Get-TlsCertificate -Description "Alias for ListCert command"
Export-ModuleMember -function Get-TlsCertificate -Alias ListCert

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Restore-Certificate
Function Restore-TlsCertificate
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateScript({$_.length -gt 6})]
		[string]$Password,
		[string]$Path,
		[Parameter(Mandatory=$true)]
		[ValidateSet("Full","VS","Third")]
		[string]$Type,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$params = @{}
	$params.Add("password",[System.Web.HttpUtility]::UrlEncode($Password))
	$params.Add("Type", $Type)
	$response = Send-LBMessage -Command restorecert -ParameterValuePair $params -File $Path -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response
}
New-Alias -Name Restore-Certificate -value Restore-TlsCertificate -Description "Alias for Restore-Certificate command"
Export-ModuleMember -function Restore-TlsCertificate -Alias Restore-Certificate

#endregion - Certificates

#region - Cipherset

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function ModifyCipherset
Function Set-TlsCipherSet
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullOrEmpty()]
		[String]$Value,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command modifycipherset -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
}
New-Alias -Name ModifyCipherset -value Set-TlsCipherSet -Description "Alias for ModifyCipherset command"
Export-ModuleMember -function Set-TlsCipherSet -Alias ModifyCipherset

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function GetCipherset
Function Get-TlsCipherSet
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command getcipherset -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
}
New-Alias -Name GetCipherset -value Get-TlsCipherSet -Description "Alias for GetCipherset command"
Export-ModuleMember -function Get-TlsCipherSet -Alias GetCipherset

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function DelCipherset
Function Remove-TlsCipherSet
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command delcipherset -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
}
New-Alias -Name DelCipherset -value Remove-TlsCipherSet -Description "Alias for DelCipherset command"
Export-ModuleMember -function Remove-TlsCipherSet -Alias DelCipherset

#endregion - Cipherset

#region - Interfaces

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Get-Interface
Function Get-NetworkInterface
{
	[CmdletBinding()]
	Param(
		[Int16]$InterfaceID,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$response = Send-LBMessage -Command showiface -ParameterValuePair @{iface=$InterfaceID} -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	if ($response.Interface)
	{
		$response.Interface | Convert-XmlToPSObject
	}

	if ($response.code -eq "fail")
	{
		Write-Error $response.Error
	}
}
New-Alias -Name Get-Interface -value Get-NetworkInterface -Description "Alias for Get-Interface command"
Export-ModuleMember -function Get-NetworkInterface -Alias Get-Interface

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Set-Interface
Function Set-NetworkInterface
{
	[CmdletBinding()]
	Param(
		[Int16]$InterfaceID,
		[string]$IPAddress,
		[Int32]$MTU,
		[bool]$HACheck,
		[bool]$GWIface,
		[bool]$GeoTraffic,
		[ValidateSet("802.3ad","Active-backup")]
		[string]$BondMode,
		[string]$Partner,
		[string]$Shared,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	if (Get-Interface -InterfaceID $InterfaceID -LoadBalancer $LoadBalancer -Credential $Credential)
	{
		$propertyTable = Convert-BoundParameters $psboundparameters
		$propertytable.Remove("iface")
		$response = ""
		Foreach ($property in $propertytable.keys)
		{
			$params = @{iface=$InterfaceID}
			Write-Verbose "Property = $property and Value = $($propertytable[$property])"
			$params.Add($property, $propertytable[$property])
			$response = Send-LBMessage -command modiface -ParameterValuePair $params -ErrorAction SilentlyContinue -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
			if ($property -eq "addr")
			{
				$SystemIP = [System.Web.HttpUtility]::UrlEncode((Get-Interface -InterfaceID $InterfaceID).IPAddress)
				Write-Verbose "System value: $SystemIP"
				Write-Verbose "Given IP: $($propertytable[$property])"
				if ($SystemIP -ne $($propertytable[$property]))
				{
					Write-Error "IP Address could not be bound to interface."
					break
				}
			}
			else
			{
				if ($response -ne "ok")
				{
					Write-Error $response.Error
					break
				}
			}
		}
		if ($response -eq "ok")
		{
			Get-Interface -InterfaceID $InterfaceID
		}

	}
}
New-Alias -Name Set-Interface -value Set-NetworkInterface -Description "Alias for Set-Interface command"
Export-ModuleMember -function Set-NetworkInterface -Alias Set-Interface


#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Add-InterfaceAddress
Function Add-NetworkInterfaceAddress
{
	[CmdletBinding()]
	Param(
		[Int16]$InterfaceID,
		[string]$Address,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	if (Get-Interface -InterfaceID $InterfaceID)
	{
		$response = Send-LBMessage -Command addadditional -ParameterValuePair @{iface=$InterfaceID;addr=$Address} -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		if ($response -eq "ok")
		{
			Get-Interface -InterfaceID $InterfaceID
		}
		else
		{
			Write-Error $response.Error
		}
	}
}
New-Alias -Name Add-InterfaceAddress -value Add-NetworkInterfaceAddress -Description "Alias for Add-InterfaceAddress command"
Export-ModuleMember -function Add-NetworkInterfaceAddress -Alias Add-InterfaceAddress

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Remove-InterfaceAddress
Function Remove-NetworkInterfaceAddress
{
	[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact="High")]
	Param(
		[Int16]$InterfaceID,
		[string]$Address,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred,
		[switch]$Force
	)

	if (Get-Interface -InterfaceID $InterfaceID)
	{
		if (($Force) -or ($PsCmdlet.ShouldProcess($InterfaceID, "Remove Interface Address")))
		{
			$response = Send-LBMessage -Command deladditional -ParameterValuePair @{iface=$InterfaceID;addr=$Address} -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
			if ($response -eq "ok")
			{
				Get-Interface -InterfaceID $InterfaceID -LoadBalancer $LoadBalancer -Credential $Credential
			}
			else
			{
				Write-Error $response.Error
			}
		}
	}
}
New-Alias -Name Remove-InterfaceAddress -value Remove-NetworkInterfaceAddress -Description "Alias for Remove-InterfaceAddress command"
Export-ModuleMember -function Remove-NetworkInterfaceAddress -Alias Remove-InterfaceAddress

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Register-BondedInterface
Function Register-NetworkBondedInterface
{
	[CmdletBinding()]
	Param(
		[Int16]$InterfaceID,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	if (Get-Interface -InterfaceID $InterfaceID -LoadBalancer $LoadBalancer -Credential $Credential)
	{
		$response = Send-LBMessage -Command createbond -ParameterValuePair @{iface=$InterfaceID} -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		if ($response -eq "ok")
		{
			Get-Interface -InterfaceID $InterfaceID -LoadBalancer $LoadBalancer -Credential $Credential
		}
		else
		{
			Write-Error $response.Error
		}
	}
}
New-Alias -Name Register-BondedInterface -value Register-NetworkBondedInterface -Description "Alias for Register-BondedInterface command"
Export-ModuleMember -function Register-NetworkBondedInterface -Alias Register-BondedInterface

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Unregister-BondedInterface
Function Unregister-NetworkBondedInterface
{
	[CmdletBinding()]
	Param(
		[Int16]$InterfaceID,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	if (Get-Interface -InterfaceID $InterfaceID -LoadBalancer $LoadBalancer -Credential $Credential)
	{
		$response = Send-LBMessage -Command unbond -ParameterValuePair @{iface=$InterfaceID} -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		if ($response -eq "ok")
		{
			Get-Interface -InterfaceID $InterfaceID -LoadBalancer $LoadBalancer -Credential $Credential
		}
		else
		{
			Write-Error $response.Error
		}
	}
}
New-Alias -Name Unregister-BondedInterface -value Unregister-NetworkBondedInterface -Description "Alias for Unregister-BondedInterface command"
Export-ModuleMember -function Unregister-NetworkBondedInterface -Alias Unregister-BondedInterface

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Add-BondedInterface
Function Add-NetworkBondedInterface
{
	[CmdletBinding()]
	Param(
		[Int16]$InterfaceID,
		[Int16]$BondID,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.PSCredential]$Credential = $script:cred
	)

	if (Get-Interface -InterfaceID $InterfaceID -LoadBalancer $LoadBalancer -Credential $Credential)
	{
		$response = Send-LBMessage -Command addbond -ParameterValuePair @{iface=$InterfaceID;bond=$BondID} -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		if ($response -eq "ok")
		{
			Get-Interface -InterfaceID $InterfaceID -LoadBalancer $LoadBalancer -Credential $Credential
		}
		else
		{
			Write-Error $response.Error
		}
	}
}
New-Alias -Name Add-BondedInterface -value Add-NetworkBondedInterface -Description "Alias for Add-BondedInterface command"
Export-ModuleMember -function Add-NetworkBondedInterface -Alias Add-BondedInterface

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Remove-BondedInterface
Function Remove-NetworkBondedInterface
{
	[CmdletBinding()]
	Param(
		[Int16]$InterfaceID,
		[Int16]$BondID,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	if (Get-Interface -InterfaceID $InterfaceID -LoadBalancer $LoadBalancer -Credential $Credential)
	{
		$response = Send-LBMessage -Command delbond -ParameterValuePair @{iface=$InterfaceID;bond=$BondID} -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		if ($response -eq "ok")
		{
			Get-Interface -InterfaceID $InterfaceID -LoadBalancer $LoadBalancer -Credential $Credential
		}
		else
		{
			Write-Error $response.Error
		}
	}
}
New-Alias -Name Remove-BondedInterface -value Remove-NetworkBondedInterface -Description "Alias for Remove-BondedInterface command"
Export-ModuleMember -function Remove-NetworkBondedInterface -Alias Remove-BondedInterface

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Add-VLan
Function Add-NetworkVLAN
{
	[CmdletBinding()]
	Param(
		[Int16]$InterfaceID,
		[ValidateRange(1,4095)]
		[Int16]$VLAN,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	if (Get-Interface -InterfaceID $InterfaceID -LoadBalancer $LoadBalancer -Credential $Credential)
	{
		$response = Send-LBMessage -Command addvlan -ParameterValuePair @{iface=$InterfaceID;vlanid=$VLAN} -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		if ($response -eq "ok")
		{
            "VLAN $VLAN created on interface $InterfaceID"
		}
		else
		{
			Write-Error $response.Error
		}
	}
}
New-Alias -Name Add-VLan -value Add-NetworkVLAN -Description "Alias for Add-VLan command"
Export-ModuleMember -function Add-NetworkVLAN -Alias Add-VLan

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Remove-VLan
Function Remove-NetworkVLAN
{
	[CmdletBinding()]
	Param(
		[Int16]$InterfaceID,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	if (Get-Interface -InterfaceID $InterfaceID -LoadBalancer $LoadBalancer -Credential $Credential)
	{
		$response = Send-LBMessage -Command delvlan -ParameterValuePair @{iface=$InterfaceID} -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		if ($response -eq "ok")
		{
            "VLAN removed"
			Get-Interface -InterfaceID $InterfaceID -LoadBalancer $LoadBalancer -Credential $Credential
		}
		else
		{
			Write-Error $response.Error
		}
	}
}
New-Alias -Name Remove-VLan -value Remove-NetworkVLAN -Description "Alias for Remove-VLan command"
Export-ModuleMember -function Remove-NetworkVLAN -Alias Remove-VLan

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Add-VxLan
Function Add-NetworkVxLAN
{
	[CmdletBinding()]
	Param(
		[Int16]$InterfaceID,
		[ValidateRange(1,16777214)]
		[Int32]$VXLAN,
		[ValidateNotNullOrEmpty()]
		[string]$Addr,
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	if((($Addr -As [IPAddress]) -As [Bool]))
	{
		if (Get-Interface -InterfaceID $InterfaceID -LoadBalancer $LoadBalancer -Credential $Credential)
		{
			$sep = "."
			$parts = [System.StringSplitOptions]::RemoveEmptyEntries
			$AddrParts = $Addr.Split($sep,4,$parts)
			[int]$parti = [convert]::ToInt32($AddrParts[0], 10)

			if ($parti -gt 223 -and $parti -lt 240)
			{
				$response = Send-LBMessage -Command addvxlan -ParameterValuePair @{iface=$InterfaceID;vni=$VXLAN;group=$Addr} -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
			}
			else
			{
				$response = Send-LBMessage -Command addvxlan -ParameterValuePair @{iface=$InterfaceID;vni=$VXLAN;remote=$Addr} -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
			}

			if ($response -eq "ok")
			{
				"VXLAN $VXLAN created on interface $InterfaceID"
			}
			else
			{
				Write-Error $response.Error
			}
		}
	}
	else
	{
		Write-Error "No valid group or remote IP address given"
	}
}
New-Alias -Name Add-VxLan -value Add-NetworkVxLAN -Description "Alias for Add-VxLan command"
Export-ModuleMember -function Add-NetworkVxLAN -Alias Add-VxLan

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Remove-VxLan
Function Remove-NetworkVxLAN
{
	[CmdletBinding()]
	Param(
		[Int16]$InterfaceID,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	if (Get-Interface -InterfaceID $InterfaceID -LoadBalancer $LoadBalancer -Credential $Credential)
	{
		$response = Send-LBMessage -Command delvxlan -ParameterValuePair @{iface=$InterfaceID} -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		if ($response -eq "ok")
		{
			"VXLAN removed"
			Get-Interface -InterfaceID $InterfaceID -LoadBalancer $LoadBalancer -Credential $Credential
		}
		else
		{
			Write-Error $response.Error
		}
	}
}
New-Alias -Name Remove-VxLan -value Remove-NetworkVxLAN -Description "Alias for Remove-VxLan command"
Export-ModuleMember -function Remove-NetworkVxLAN -Alias Remove-VxLan

#endregion - Interfaces

#region - DNS Configuration

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Get-DNSConfiguration
Function Get-NetworkDNSConfiguration
{
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
	#Property "NamServer" is misspelled in the API.
	$parameters = @("Hostname","HA1Hostname","HA2Hostname","NamServer","SearchList")
	$settings = @{}
	foreach ($param in $parameters)
	{
		$response = Send-LBMessage -command get -parametername $param -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		if ($response.FirstChild)
		{
			$settings.add($param, $response.firstchild.InnerText)
		}
		else
		{
			$settings.add($param, $response)
		}
	}

	New-Object -TypeName PSObject -Property $settings
}
New-Alias -Name Get-DNSConfiguration -value Get-NetworkDNSConfiguration -Description "Alias for Get-DNSConfiguration command"
Export-ModuleMember -function Get-NetworkDNSConfiguration -Alias Get-DNSConfiguration

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Set-DNSConfiguration
Function Set-NetworkDNSConfiguration
{
	[CmdletBinding()]
	Param(
		[string]$Hostname,
		[string]$HA1Hostname,
		[string]$HA2Hostname,
		[string]$NameServer,
		[string]$Searchlist,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	foreach ($entry in $propertyTable.Keys)
	{
		$response = Send-LBMessage -Command set -parameterName $entry -ParameterValue $propertyTable[$entry] -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	}

	Get-DNSConfiguration -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name Set-DNSConfiguration -value Set-NetworkDNSConfiguration -Description "Alias for Set-DNSConfiguration command"
Export-ModuleMember -function Set-NetworkDNSConfiguration -Alias Set-DNSConfiguration

Function Update-LmDnsCache
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	try {
		$response = Send-LBMessage -Command resolvenow -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

		$tempApiRetObj = @{}
		$tempApiRetObj.PSTypeName = "KempAPI"
		$tempApiRetObj.ReturnCode = 200
		$tempApiRetObj.Response = "Command successfully executed"
		$tempApiRetObj.Data = $null

		$apiRetObject = New-Object -TypeName PSObject -Prop $tempApiRetObj
		$apiRetObject
	}
	catch {
		write-host "Caught an exception" -ForegroundColor Red
		write-host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
		write-host "Exception Message: $($_.Exception.Message)" -ForegroundColor Red
	}
}
Export-ModuleMember -function Update-LmDnsCache

#endregion - DNS Configuration

#region - Hosts Management

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-Hosts
{
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

	$response = Send-LBMessage -command gethosts -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	if ($response.hasChildNodes)
	{
		$response.HostsEntry | Convert-XmlToPSObject
	}
}

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Add-HostsEntry
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[string]$HostIP,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullOrEmpty()]
		[string]$HostFQDN,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$response = Send-LBMessage -Command addhostsentry -ParameterValuePair @{hostip=$HostIP;hostfqdn=$HostFQDN} -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response
}

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-HostsEntry
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[string]$HostIP,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$response = Send-LBMessage -Command delhostsentry -ParameterValuePair @{hostip=$HostIP} -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response
}
#endregion - Hosts Management

#region - Route Management

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Get-Route
Function Get-NetworkRoute
{
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

	$response = Send-LBMessage -command showroute -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	if ($response.hasChildNodes)
	{
		$response.Route | Convert-XmlToPSObject
	}
}
New-Alias -Name Get-Route -value Get-NetworkRoute -Description "Alias for Get-Route command"
Export-ModuleMember -function Get-NetworkRoute -Alias Get-Route

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function New-Route
Function New-NetworkRoute
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[string]$Destination,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullOrEmpty()]
		[Alias("Mask","SubnetMask")]
		[Int16]$CIDR,
		[Parameter(Mandatory=$true,Position=2)]
		[ValidateNotNullOrEmpty()]
		[string]$Gateway,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$DestIP = "$Destination/$CIDR"
	$response = Send-LBMessage -Command addroute -ParameterValuePair @{dest=$DestIP;gateway=$Gateway} -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response | Convert-XMLToPSObject
	Get-Route
}
New-Alias -Name New-Route -value New-NetworkRoute -Description "Alias for New-Route command"
Export-ModuleMember -function New-NetworkRoute -Alias New-Route

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Remove-Route
Function Remove-NetworkRoute
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[string]$Destination,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$response = Send-LBMessage -Command delroute -ParameterValuePair @{dest=$Destination} -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	Get-Route -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name Remove-Route -value Remove-NetworkRoute -Description "Alias for Remove-Route command"
Export-ModuleMember -function Remove-NetworkRoute -Alias Remove-Route

#endregion - Route Management

#region - Packet Filter Options

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-PacketFilterOption
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateSet("enable","drop","ifblock")]
		[String]$Option,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	if ($Option -eq "enable")
	{
		$ParameterName = "isenabled"
	}
	else
	{
		$ParameterName = "is$Option"
	}

	Send-LBMessage -Command aclcontrol -ParameterName $ParameterName -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
}

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Set-PacketFilterOption
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateSet("enable","drop","ifblock")]
		[String]$Option,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullOrEmpty()]
		[bool]$Value,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = @{}
	$propertyTable.Add($Option, $Value -as [int])

	$response = Send-LBMessage -Command aclcontrol -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	if ($response.code -eq "fail")
	{
		$response.Error
	}
	else
	{
		$response.cmdexitstatus
	}
}

#endregion - Packet Filter Options

#region - Global Black and White Lists

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-GlobalPacketFilterACL
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateSet("black","white")]
		[String]$Type,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$propertyTable = @{}
	$propertyTable.Add("list", $Type)

	$response = Send-LBMessage -Command aclcontrol -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response | Convert-XmlToPSObject
}

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Add-GlobalPacketFilterAddr
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateSet("black","white")]
		[String]$Type,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullOrEmpty()]
		[String]$Address,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$propertyTable = @{}
	$propertyTable.Add("add", $Type)
	$propertyTable.Add("addr", $Address)

	Send-LBMessage -Command aclcontrol -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
}

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-GlobalPacketFilterAddr
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateSet("black","white")]
		[String]$Type,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullOrEmpty()]
		[String]$Address,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$propertyTable = @{}
	$propertyTable.Add("del", $Type)
	$propertyTable.Add("addr", $Address)

	Send-LBMessage -Command aclcontrol -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
}

#endregion - Global Black and White Lists

#region - System Administration

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Update-License
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateScript({Test-Path $_})]
		[string]$Path,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$response = Send-LBMessage -Command license -File $Path -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response
}
Export-ModuleMember -function Update-License

Function Request-LicenseOffline
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateScript({Test-Path $_})]
		[string]$Path,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	try {
		$response = Send-LBMessage -Command license -File $Path -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort

		$tempApiRetObj = @{}
		$tempApiRetObj.PSTypeName = "KempAPI"
		$tempApiRetObj.ReturnCode = 200
		$tempApiRetObj.Response = "Command successfully executed"
		$tempApiRetObj.Data = $null

		$apiRetObject = New-Object -TypeName PSObject -Prop $tempApiRetObj
		$apiRetObject
	}
	catch {
		write-host "Caught an exception" -ForegroundColor Red
		write-host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
		write-host "Exception Message: $($_.Exception.Message)" -ForegroundColor Red
	}
}
New-Alias -Name Update-LicenseOffline -value Request-LicenseOffline -Description "Alias for Update-LicenseOffline command"
Export-ModuleMember -function Request-LicenseOffline -Alias Update-LicenseOffline

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Get-AccessKey
Function Get-LicenseAccessKey
{
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

	$response = Send-LBMessage -command accesskey -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response.AccessKey
}
New-Alias -Name Get-AccessKey -value Get-LicenseAccessKey -Description "Alias for Get-AccessKey command"
Export-ModuleMember -function Get-LicenseAccessKey -Alias Get-AccessKey

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Restart-LoadBalancer
Function Restart-Lm
{
	[CmdletBinding(SupportsShouldProcess=$true)]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred,
		[switch]$Shutdown,
		[switch]$Force
	)
	$Command = $null
	if ($Shutdown)
	{
		$Command = "shutdown"
	}
	else
	{
		$Command = "reboot"
	}
	if (($Force) -or ($PsCmdlet.ShouldProcess($Command, "Shutdown $LoadBalancer")))
	{
		$response = Send-LBMessage -Command $Command -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		$response
	}
}
New-Alias -Name Restart-LoadBalancer -value Restart-Lm -Description "Alias for Restart-LoadBalancer command"
Export-ModuleMember -function Restart-Lm -Alias Restart-LoadBalancer

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Install-Patch
Function Install-LmPatch
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred,
		[Parameter(Mandatory=$true)]
		[ValidateScript({Test-Path $_})]
		[string]$Path
	)
	$response = Send-LBMessage -Command installpatch -File $Path -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response
}
New-Alias -Name Install-Patch -value Install-LmPatch -Description "Alias for Install-Patch command"
Export-ModuleMember -function Install-LmPatch -Alias Install-Patch

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Restore-Patch
Function Uninstall-LmPatch
{
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
	$response = Send-LBMessage -command restorepatch -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response
	if ($response.ToString().ToLower() -eq "ok")
	{
		Write-Warning "You must restart the LoadMaster for this process to be completed."
	}
}
New-Alias -Name Restore-Patch -value Uninstall-LmPatch -Description "Alias for Restore-Patch command"
Export-ModuleMember -function Uninstall-LmPatch -Alias Restore-Patch

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Backup-LoadBalancer
Function Backup-LmConfiguration
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred,
		[Parameter(Mandatory=$true)]
		[string]$Path
	)
	$params = @{}
	if (-not ($Path))
	{
		$Path = "$($Env:SystemRoot)\Temp\LMBackup_$(Get-Date -format yyyy-MM-dd_HH-mm-ss)"
	}
	Write-Verbose "Path = $Path"
	$response = Send-LBMessage -command backup -File $Path -Output -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response
}
New-Alias -Name Backup-LoadBalancer -value Backup-LmConfiguration -Description "Alias for Backup-LoadBalancer command"
Export-ModuleMember -function Backup-LmConfiguration -Alias Backup-LoadBalancer

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Restore-LoadBalancer
Function Restore-LmConfiguration
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred,
		[Parameter(Mandatory=$true)]
		[ValidateScript({Test-Path $_})]
		[string]$Path,
		[Parameter(Mandatory=$true)]
		[ValidateSet("Base","VS","Geo")]
		[string]$Type
	)
	$params = @{}
	$TypeInt = $RestoreType[$Type]
	Write-Verbose "Type = $TypeInt"
	$params.Add("Type", $TypeInt)
	$response = Send-LBMessage -Command restore -ParameterValuePair $params -File $Path -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response
}
New-Alias -Name Restore-LoadBalancer -value Restore-LmConfiguration -Description "Alias for Restore-LoadBalancer command"
Export-ModuleMember -function Restore-LmConfiguration -Alias Restore-LoadBalancer

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Get-BackupOption
Function Get-LmBackupConfiguration
{
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
	$parameters = @("backupday","backupenable","backuphost","backuphour","backupminute",
		"backuppassword","backuppath","backupuser")
	$settings = @{}
	foreach ($param in $parameters)
	{
		$response = Send-LBMessage -command get -parametername $param -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		$settings.add($param, $response.firstchild.InnerText)
	}
	New-Object -TypeName PSObject -Property $settings
}
New-Alias -Name Get-BackupOption -value Get-LmBackupConfiguration -Description "Alias for Get-BackupOption command"
Export-ModuleMember -function Get-LmBackupConfiguration -Alias Get-BackupOption

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Set-BackupOption
Function Set-LmBackupConfiguration
{
	[CmdletBinding()]
	Param(
		[bool]$BackupEnable,
		[string]$BackupPath,
		[string]$BackupUser,
		[string]$BackupPassword,
		[string]$BackupHost,
		[ValidateRange(0,7)]
		[Int16]$BackupDay,
		[ValidateRange(0,23)]
		[Int16]$BackupHour,
		[ValidateRange(0,59)]
		[Int16]$BackupMinute,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	foreach ($entry in $propertyTable.Keys)
	{
		$response = Send-LBMessage -Command set -ParameterName $entry -ParameterValue $propertyTable[$entry] -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	}
	Get-BackupOption
}
New-Alias -Name Set-BackupOption -value Set-LmBackupConfiguration -Description "Alias for Set-BackupOption command"
Export-ModuleMember -function Set-LmBackupConfiguration -Alias Set-BackupOption

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Get-DateTimeOption
Function Get-LmDateTimeConfiguration
{
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
	# Don't get NTPKeySecret - no valid data is returned
	$parameters = @("NTPHost","Time","BootTime","ActiveTime","TimeZone","NTPKeyId")
	$settings = @{}
	foreach ($param in $parameters)
	{
		$response = Send-LBMessage -command get -parametername $param -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		$settings.add($param, $response.firstchild.InnerText)
	}
	New-Object -TypeName PSObject -Property $settings
}
New-Alias -Name Get-DateTimeOption -value Get-LmDateTimeConfiguration -Description "Alias for Get-DateTimeOption command"
Export-ModuleMember -function Get-LmDateTimeConfiguration -Alias Get-DateTimeOption

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Set-DateTimeOption
Function Set-LmDateTimeConfiguration
{
	[CmdletBinding()]
	Param(
		[string]$NTPHost,
		[Int32]$Time,
		[string]$TimeZone,
		[ValidateRange(1,100)]
		[int]$NTPKeyId,
		[string]$NTPKeySecret,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	foreach ($entry in $propertyTable.Keys)
	{
		$response = Send-LBMessage -Command set -parameterName $entry -ParameterValue $propertyTable[$entry] -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	}

	Get-DateTimeOption -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name Set-DateTimeOption -value Set-LmDateTimeConfiguration -Description "Alias for Set-DateTimeOption command"
Export-ModuleMember -function Set-LmDateTimeConfiguration -Alias Set-DateTimeOption

Function Get-PreviousVersion
{
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
	try {
		$response = Send-LBMessage -Command getpreviousversion -LoadBalancer $LoadBalancer -Credential $Credential
		$tempApiRetObj = @{}
		$tempApiRetObj.PSTypeName = "KempAPI"
		$tempApiRetObj.ReturnCode = 200
		$tempApiRetObj.Response = "Command successfully executed"
		$tempApiRetObj.PreviousVersion = $response.PreviousVersion

		$apiRetObject = New-Object -TypeName PSObject -Prop $tempApiRetObj
		$apiRetObject
	}
	catch {
		write-host "Caught an exception" -ForegroundColor Red
		write-host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
		write-host "Exception Message: $($_.Exception.Message)" -ForegroundColor Red
	}
}
Export-ModuleMember -function Get-PreviousVersion

#endregion - System Administration

#region - Logging Options

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Get-DebugOption
Function Get-LmDebugConfiguration
{
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
	$parameters = @("IRQBalance","LineAREspLogs","NetConsole","NetConsoleInterface")
	$settings = @{}
	foreach ($param in $parameters)
	{
		$response = Send-LBMessage -command get -parametername $param -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		$settings.add($param, $response.firstchild.InnerText)
	}
	New-Object -TypeName PSObject -Property $settings
}
New-Alias -Name Get-DebugOption -value Get-LmDebugConfiguration -Description "Alias for Get-DebugOption command"
Export-ModuleMember -function Get-LmDebugConfiguration -Alias Get-DebugOption

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Set-DebugOption
Function Set-LmDebugConfiguration
{
	[CmdletBinding()]
	Param(
		[bool]$IRQBalance,
		[bool]$LineAREspLogs,
		[string]$NetConsole,
		[Int16]$NetConsoleInterface,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	foreach ($entry in $propertyTable.Keys)
	{
		$response = Send-LBMessage -Command set -ParameterName $entry -ParameterValue $propertyTable[$entry] -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	}
	Get-DebugOption -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name Set-DebugOption -value Set-LmDebugConfiguration -Description "Alias for Set-DebugOption command"
Export-ModuleMember -function Set-LmDebugConfiguration -Alias Set-DebugOption

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Get-SyslogOption
Function Get-LogSyslogConfiguration
{
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

	$parameters = @("SyslogCritical","SyslogEmergency","SyslogError","SyslogInfo","SyslogNotice","SyslogWarn")
	$settings = @{}
	foreach ($param in $parameters)
	{
		$response = Send-LBMessage -command get -parametername $param -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		$settings.add($param, $response.firstchild.InnerText)
	}

	New-Object -TypeName PSObject -Property $settings
}
New-Alias -Name Get-SyslogOption -value Get-LogSyslogConfiguration -Description "Alias for Get-SyslogOption command"
Export-ModuleMember -function Get-LogSyslogConfiguration -Alias Get-SyslogOption

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Set-SyslogOption
Function Set-LogSyslogConfiguration
{
	[CmdletBinding()]
	Param(
		[string]$SyslogCritical,
		[string]$SyslogEmergency,
		[string]$SyslogError,
		[string]$SyslogInfo,
		[string]$SyslogNotice,
		[string]$SyslogWarn,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	foreach ($entry in $propertyTable.Keys)
	{
		$response = Send-LBMessage -Command set -ParameterName $entry -ParameterValue $propertyTable[$entry] -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		$response
	}

	Get-SyslogOption -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name Set-SyslogOption -value Set-LogSyslogConfiguration -Description "Alias for Set-SyslogOption command"
Export-ModuleMember -function Set-LogSyslogConfiguration -Alias Set-SyslogOption

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Get-SNMPOption
Function Get-NetworkSNMPConfiguration
{
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

	$parameters = @("SNMPCommunity","SNMPv3user","SNMPv3userpasswd","snmpAuthProt", "snmpPrivProt", "SNMPContact","SNMPEnable", "SNMPv3enable","SNMPTrapEnable","SNMPv1Sink","SNMPv2Sink", "SNMPHaTrap", "SNMPClient", "SNMPLocation")
	$settings = @{}
	foreach ($param in $parameters)
	{
		$response = Send-LBMessage -command get -parametername $param -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		$settings.add($param, $response.firstchild.InnerText)
	}

	New-Object -TypeName PSObject -Property $settings
}
New-Alias -Name Get-SNMPOption -value Get-NetworkSNMPConfiguration -Description "Alias for Get-SNMPOption command"
Export-ModuleMember -function Get-NetworkSNMPConfiguration -Alias Get-SNMPOption

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Set-SNMPOption
Function Set-NetworkSNMPConfiguration
{
	[CmdletBinding()]
	Param(
		[string]$SNMPCommunity,
		[string]$SNMPv3user,
		[string]$SNMPv3userpasswd,
		[string]$snmpAuthProt,
		[string]$snmpPrivProt,
		[string]$SNMPContact,
		[bool]$SNMPEnable,
		[bool]$SNMPv3enable,
		[bool]$SNMPTrapEnable,
		[string]$SNMPv1Sink,
		[string]$SNMPv2Sink,
		[bool]$SNMPHaTrap,
		[string]$SNMPClient,
		[string]$SNMPLocation,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	foreach ($entry in $propertyTable.Keys)
	{
		$response = Send-LBMessage -Command set -ParameterName $entry -ParameterValue $propertyTable[$entry] -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	}

	Get-SNMPOption -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name Set-SNMPOption -value Set-NetworkSNMPConfiguration -Description "Alias for Set-SNMPOption command"
Export-ModuleMember -function Set-NetworkSNMPConfiguration -Alias Set-SNMPOption

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Get-EmailOption
Function Get-LogEmailConfiguration
{
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

	$parameters = @("EmailCritical","EmailDomain","EmailEmergency","EmailEnable","EmailError","EmailInfo",
		"EmailNotice","EmailPassword","EmailPort","EmailServer","EmailSSLMode","EmailUser","EmailWarn")
	$settings = @{}
	foreach ($param in $parameters)
	{
		$response = Send-LBMessage -command get -parametername $param -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		$settings.add($param, $response.firstchild.InnerText)
	}

	New-Object -TypeName PSObject -Property $settings
}
New-Alias -Name Get-EmailOption -value Get-LogEmailConfiguration -Description "Alias for Get-EmailOption command"
Export-ModuleMember -function Get-LogEmailConfiguration -Alias Get-EmailOption

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Set-EmailOption
Function Set-LogEmailConfiguration
{
	[CmdletBinding()]
	Param(
		[string]$EmailUser,
		[string]$EmailDomain,
		[string]$EmailPassword,
		[ValidateRange(3,65530)]
		[string]$EmailPort,
		[string]$EmailServer,
		[bool]$EmailEnable,
		[ValidateRange(0,3)]
		[Int16]$EmailSSLMode,
		[string]$EmailInfo,
		[string]$EmailNotice,
		[string]$EmailWarn,
		[string]$EmailError,
		[string]$EmailEmergency,
		[string]$EmailCritical,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	foreach ($entry in $propertyTable.Keys)
	{
		$response = Send-LBMessage -Command set -ParameterName $entry -ParameterValue $propertyTable[$entry] -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	}

	Get-EmailOption -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name Set-EmailOption -value Set-LogEmailConfiguration -Description "Alias for Set-EmailOption command"
Export-ModuleMember -function Set-LogEmailConfiguration -Alias Set-EmailOption

#endregion - Logging Options

#region - Miscellaneous Options

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Get-WUISetting
Function Get-SecWebUIConfiguration
{
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
	$parameters = @("hoverhelp","motd","sessioncontrol","sessionidletime","sessionmaxfailattempts","wuidisplaylines")
	$settings = @{}
	foreach ($param in $parameters)
	{
		$response = Send-LBMessage -command get -parametername $param -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		$settings.add($param, $response.firstchild.InnerText)
	}
	New-Object -TypeName PSObject -Property $settings
}
New-Alias -Name Get-WUISetting -value Get-SecWebUIConfiguration -Description "Alias for Get-WUISetting command"
Export-ModuleMember -function Get-SecWebUIConfiguration -Alias Get-WUISetting

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Set-WUISetting
Function Set-SecWebUIConfiguration
{
	[CmdletBinding()]
	Param(
		[bool]$HoverHelp,
		[string]$Motd,
		[bool]$SessionControl,
		[ValidateRange(60,86400)]
		[Int32]$SessionIdleTime,
		[ValidateRange(1,999)]
		[Int16]$SessionMaxFailAttempts,
		[ValidateRange(10,100)]
		[Int16]$WUIDisplayLines,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	foreach ($entry in $propertyTable.keys)
	{
		$response = Send-LBMessage -Command set -ParameterName $entry -ParameterValue $propertyTable[$entry] -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	}
	Get-WUISetting -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name Set-WUISetting -value Set-SecWebUIConfiguration -Description "Alias for Set-WUISetting command"
Export-ModuleMember -function Set-SecWebUIConfiguration -Alias Set-WUISetting

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Get-RemoteAccess
Function Get-SecRemoteAccess
{
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
	$parameters = @("admingw","enableapi","geoclients","geosshport","sshaccess","sshiface","sshport","wuiaccess","wuiiface","wuiport")
	$settings = @{}
	foreach ($param in $parameters)
	{
		$response = Send-LBMessage -command get -parametername $param -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		$settings.add($param, $response.firstchild.InnerText)
	}

	New-Object -TypeName PSObject -Property $settings
}
New-Alias -Name Get-RemoteAccess -value Get-SecRemoteAccess -Description "Alias for Get-RemoteAccess command"
Export-ModuleMember -function Get-SecRemoteAccess -Alias Get-RemoteAccess

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Set-RemoteAccess
Function Set-SecRemoteAccess
{
	[CmdletBinding()]
	Param(
		[string]$AdminGW,
		[bool]$EnableAPI,
		[ValidateRange(3,65530)]
		[Int64]$GeoSSHPort,
		[bool]$SSHAccess,
		[string]$SSHIface,
		[ValidateRange(3,65530)]
		[Int64]$SSHPort,
		[bool]$WUIAccess,
		[int32]$WUIIface,
		[ValidateRange(3,65530)]
		[Int64]$WUIPort,
		[String[]]$GeoClients,
		[String[]]$GeoPartners,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	foreach ($entry in $propertyTable.Keys)
	{
		$response = Send-LBMessage -Command set -ParameterName $entry -ParameterValue $propertyTable[$entry] -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	}
	Get-RemoteAccess -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name Set-RemoteAccess -value Set-SecRemoteAccess -Description "Alias for Set-RemoteAccess command"
Export-ModuleMember -function Set-SecRemoteAccess -Alias Set-RemoteAccess

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Get-WUIAuth
Function Get-SecWebUIAuth
{
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
	$parameters = @("ldapserver","ldapbackupserver","ldapsecurity","ldaprevalidateinterval","radiusserver","radiusport","radiussecret",
		"radiusrevalidateinterval","radiusbackupserver","radiusbackupport","radiusbackupsecret","sessionlocalauth","sessionauthmode")
	$settings = @{}
	foreach ($param in $parameters)
	{
		$response = Send-LBMessage -command get -parametername $param -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		$settings.add($param, $response.firstchild.InnerText)
	}
	New-Object -TypeName PSObject -Property $settings
}
New-Alias -Name Get-WUIAuth -value Get-SecWebUIAuth -Description "Alias for Get-WUIAuth command"
Export-ModuleMember -function Get-SecWebUIAuth -Alias Get-WUIAuth

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Set-WUIAuth
Function Set-SecWebUIAuth
{
	[CmdletBinding()]
	Param(
		[string]$LDAPServer,
		[string]$LDAPBackupServer,
		[ValidateRange(0,2)]
		[Int16]$LDAPSecurity,
		[ValidateRange(10,86400)]
		[int16]$LDAPRevalidateInterval,
		[string]$RADIUSServer,
		[string]$RADIUSBackupServer,
		[ValidateRange(3,65530)]
		[Int64]$RADIUSPort,
		[ValidateRange(3,65530)]
		[Int64]$RADIUSBackupPort,
		[string]$RADIUSSecret,
		[string]$RADIUSBackupSecret,
		[bool]$SessionLocalAuth,
		[ValidateSet(7,22,23,262,263,278,279,772,773,774,775,788,789,790,791)]
		[Int16]$SessionAuthMode,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	foreach ($entry in $propertyTable.Keys)
	{
		$response = Send-LBMessage -Command set -ParameterName $entry -ParameterValue $propertyTable[$entry] -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		$response
	}
	Get-WUIAuth -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name Set-WUIAuth -value Set-SecWebUIAuth -Description "Alias for Set-WUIAuth command"
Export-ModuleMember -function Set-SecWebUIAuth -Alias Set-WUIAuth

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Get-L7Configuration
Function Get-AdcL7Configuration
{
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

	$parameters = @("addcookieport","addvia","alwayspersist","closeonerror","dropatdrainend","droponfail","expect100","rfcconform",
		"rsarelocal","localbind","transparent","slowstart","addforwardheader", "allowemptyposts", "authtimeout", "clienttokentimeout")
	$settings = @{}
	foreach ($param in $parameters)
	{
		$response = Send-LBMessage -command get -parametername $param -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		$settings.add($param, $response.firstchild.InnerText)
	}

	New-Object -TypeName PSObject -Property $settings
}
New-Alias -Name Get-L7Configuration -value Get-AdcL7Configuration -Description "Alias for Get-L7Configuration command"
Export-ModuleMember -function Get-AdcL7Configuration -Alias Get-L7Configuration

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Set-L7Configuration
Function Set-AdcL7Configuration
{
	[CmdletBinding()]
	Param(
		[bool]$AddCookiePort,
		[bool]$AddVia,
		[bool]$AlwaysPersist,
		[bool]$CloseOnError,
		[bool]$DropAtDrainEnd,
		[ValidateRange(30,300)]
		[Int16]$AuthTimeout,
		[ValidateRange(60,300)]
		[Int16]$ClientTokenTimeout,
		[bool]$DropOnFail,
		[ValidateRange(0,2)]
		[int16]$Expect100,
		[bool]$RFConform,
		[bool]$RSAreLocal,
		[bool]$LocalBind,
		[bool]$Transparent,
		[bool]$AllowEmptyPosts,
		[ValidateRange(0,600)]
		[Int16]$SlowStart,
		[ValidateRange(0,2)]
		[Int16]$AddForwardHeader,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	foreach ($entry in $propertyTable.Keys)
	{
		$response = Send-LBMessage -Command set -ParameterName $entry -ParameterValue $propertyTable[$entry] -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	}

	Get-L7Configuration -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name Set-L7Configuration -value Set-AdcL7Configuration -Description "Alias for Set-L7Configuration command"
Export-ModuleMember -function Set-AdcL7Configuration -Alias Set-L7Configuration

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Get-NetworkOptions
Function Get-NetworkConfiguration
{
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

	$parameters = @("snat","allowupload","conntimeout","keepalive","multigw","nonlocalrs","onlydefaultroutes","resetclose",
		"subnetorigin","subnetoriginating","tcptimestamp","routefilter", "dhkeysize", "http_proxy")
	$settings = @{}
	foreach ($param in $parameters)
	{
		$response = Send-LBMessage -command get -parametername $param -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		$settings.add($param, $response.firstchild.InnerText)
	}

	New-Object -TypeName PSObject -Property $settings

}
New-Alias -Name Get-NetworkOptions -value Get-NetworkConfiguration -Description "Alias for Get-NetworkOptions command"
Export-ModuleMember -function Get-NetworkConfiguration -Alias Get-NetworkOptions

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Set-NetworkOptions
Function Set-NetworkConfiguration
{
	[CmdletBinding()]
	Param(
		[bool]$SNAT,
		[bool]$AllowUpload,
		[ValidateRange(0,86400)]
		[Int64]$ConnTimeout,
		[bool]$KeepAlive,
		[bool]$MultiGW,
		[bool]$NonLocalRS,
		[bool]$OnlyDefaultRoutes,
		[bool]$ResetClose,
		[bool]$SubnetOrigin,
		[bool]$SubnetOriginating,
		[bool]$TCPTimeStamp,
		[bool]$RouteFilter,
		[ValidateRange(512,4096)]
		[Int32]$DHKeySize,
		[string]$Http_Proxy,
    [ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	foreach ($entry in $propertyTable.Keys)
	{
		$response = Send-LBMessage -Command set -ParameterName $entry -ParameterValue $propertyTable[$entry] -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	}

	Get-NetworkOptions -LoadBalancer $LoadBalancer -Credential $Credential

}
New-Alias -Name Set-NetworkOptions -value Set-NetworkConfiguration -Description "Alias for Set-NetworkOptions command"
Export-ModuleMember -function Set-NetworkConfiguration -Alias Set-NetworkOptions


#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Update-IDSRules
Function Update-WafIDSRules
{
	[CmdletBinding()]
	Param(
		[ValidateScript({Test-Path -Path $_})]
		[ValidateNotNullOrEmpty()]
		[string]$Path,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$response = Send-LBMessage -Command updatedetect -File $Path -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	if ($response.code -eq "fail")
	{
		$response.Error
	}
	else {
		$response
	}
}
New-Alias -Name Update-IDSRules -value Update-WafIDSRules -Description "Alias for Update-IDSRules command"
Export-ModuleMember -function Update-WafIDSRules -Alias Update-IDSRules

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Add-NoCacheExtension
Function Add-AdcHttpCacheException
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
		[ValidatePattern({^\.})]
		[String[]]$Extension,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	PROCESS
	{
		foreach ($ext in $Extension)
		{
			$response = Send-LBMessage -command addnocache -ParameterValuePair @{param=$ext} -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		}
	}
}
New-Alias -Name Add-NoCacheExtension -value Add-AdcHttpCacheException -Description "Alias for Add-NoCacheExtension command"
Export-ModuleMember -function Add-AdcHttpCacheException -Alias Add-NoCacheExtension

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Remove-NoCacheExtension
Function Remove-AdcHttpCacheException
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
		[ValidatePattern({^\.})]
		[String[]]$Extension,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	PROCESS
	{
		foreach ($ext in $Extension)
		{
			$response = Send-LBMessage -command delnocache -ParameterValuePair @{param=$ext} -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		}
	}

}
New-Alias -Name Remove-NoCacheExtension -value Remove-AdcHttpCacheException -Description "Alias for Remove-NoCacheExtension command"
Export-ModuleMember -function Remove-AdcHttpCacheException -Alias Remove-NoCacheExtension

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Add-NoCompressExtension
Function Add-AdcHttpCompressionException
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
		[ValidatePattern({^\.})]
		[String[]]$Extension,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	PROCESS
	{
		foreach ($ext in $Extension)
		{
			$response = Send-LBMessage -command addnocompress -ParameterValuePair @{param=$ext} -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		}
	}
}
New-Alias -Name Add-NoCompressExtension -value Add-AdcHttpCompressionException -Description "Alias for Add-NoCompressExtension command"
Export-ModuleMember -function Add-AdcHttpCompressionException -Alias Add-NoCompressExtension

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Remove-NoCompressExtension
Function Remove-AdcHttpCompressionException
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
		[ValidatePattern({^\.})]
		[String[]]$Extension,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	PROCESS
	{
		foreach ($ext in $Extension)
		{
			$response = Send-LBMessage -command delnocompress -ParameterValuePair @{param=$ext} -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		}
	}
}
New-Alias -Name Remove-NoCompressExtension -value Remove-AdcHttpCompressionException -Description "Alias for Remove-NoCompressExtension command"
Export-ModuleMember -function Remove-AdcHttpCompressionException -Alias Remove-NoCompressExtension

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Get-AFEConfiguration
Function Get-LmAFEConfiguration
{
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
	$parameters = @("Cachesize","HostCache","Paranoia","LimitInput")
	$settings = @{}
	foreach ($param in $parameters)
	{
		$response = Send-LBMessage -command get -parametername $param -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		$settings.add($param, $response.firstchild.InnerText)
	}
	New-Object -TypeName PSObject -Property $settings
}
New-Alias -Name Get-AFEConfiguration -value Get-LmAFEConfiguration -Description "Alias for Get-AFEConfiguration command"
Export-ModuleMember -function Get-LmAFEConfiguration -Alias Get-AFEConfiguration

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Set-AFEConfiguration
Function Set-LmAFEConfiguration
{
	[CmdletBinding()]
	Param(
		[ValidateRange(1,250)]
		[Int16]$CacheSize,
		[bool]$HostCache,
		[ValidateRange(0,3)]
		[Int16]$Paranoia,
		[ValidateRange(0,100000)]
		[Int64]$LimitInput,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	foreach ($entry in $propertyTable.Keys)
	{
		$response = Send-LBMessage -Command set -ParameterName $entry -ParameterValue $propertyTable[$entry] -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	}
	Get-AFEConfiguration -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name Set-AFEConfiguration -value Set-LmAFEConfiguration -Description "Alias for Set-AFEConfiguration command"
Export-ModuleMember -function Set-LmAFEConfiguration -Alias Set-AFEConfiguration

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Switch-HAUnit
Function Switch-ClusterHAUnit
{
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
	$response = Send-LBMessage -Command switchha -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response
}
New-Alias -Name Switch-HAUnit -value Switch-ClusterHAUnit -Description "Alias for Switch-HAUnit command"
Export-ModuleMember -function Switch-ClusterHAUnit -Alias Switch-HAUnit

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Get-HAOption
Function Get-ClusterHAConfiguration
{
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

	$parameters = @("HAIf","HAInitial","HAPrefered","HAStyle","HATimeout","HAVhid","HAWait","MCast","Vmac","TCPFailover","CookieUpdate","FinalPersist")
	$settings = @{}
	foreach ($param in $parameters)
	{
		$response = Send-LBMessage -command get -parametername $param -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		if ($response.ToString().Contains("non HA mode"))
		{
			"This unit is not in HA mode."
			break
		}
		$settings.add($param, $response.firstchild.InnerText)
	}

	New-Object -TypeName PSObject -Property $settings
}
New-Alias -Name Get-HAOption -value Get-ClusterHAConfiguration -Description "Alias for Get-HAOption command"
Export-ModuleMember -function Get-ClusterHAConfiguration -Alias Get-HAOption

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Set-HAOption
Function Set-ClusterHAConfiguration
{
	[CmdletBinding()]
	Param(
		[Int16]$HAIf,
		[bool]$HAInitial,
		[ValidateRange(0,2)]
		[Int16]$HAPrefered,
		[bool]$HAStyle,
		[ValidateRange(1,5)]
		[Int16]$HATimeout,
		[ValidateRange(0,255)]
		[Int16]$HAVhid,
		[ValidateRange(0,200)]
		[Int16]$HAWait,
		[Int16]$MCast,
		[bool]$Vmac,
		[bool]$TCPFailover,
		[bool]$CookieUpdate,
		[ValidateScript({($_ -eq 0) -or (($_ -ge 60) -and ($_ -le 86400))})]
		[Int32]$FinalPersist,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	foreach ($entry in $propertyTable.Keys)
	{
		$response = Send-LBMessage -Command set -ParameterName $entry -ParameterValue $propertyTable[$entry] -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	}

	Get-HAOption  -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name Set-HAOption -value Set-ClusterHAConfiguration -Description "Alias for Set-HAOption command"
Export-ModuleMember -function Set-ClusterHAConfiguration -Alias Set-HAOption

#Function Get-MultiWui
Function Get-SecMultipleWebUIAccess
{
	[cmdletbinding()]
	param(
		[validatenotnullorempty()]
		[string]$loadbalancer = $loadbalanceraddress,
		[validatenotnullorempty()]
		[system.management.automation.credential()]$credential = $script:cred
	)
	$parameters = @("multihomedwui")
	$settings = @{}
	foreach ($param in $parameters)
	{
		$response = send-lbmessage -command get -parametername $param -loadbalancer $loadbalancer -credential $credential
		$settings.add($param, $response.firstchild.innertext)
	}
	new-object -typename psobject -property $settings
}
New-Alias -Name Get-MultiWui -value Get-SecMultipleWebUIAccess -Description "Alias for Get-MultiWui command"
Export-ModuleMember -function Get-SecMultipleWebUIAccess -Alias Get-MultiWui

#Function Set-MultiWui
Function Set-SecMultipleWebUIAccess
{
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[string]$multi,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$response = Send-LBMessage -Command set -ParameterName multihomedwui -ParameterValue $multi -LoadBalancer $LoadBalancer -Credential $Credential
	Get-MultiWui  -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name Set-MultiWui -value Set-SecMultipleWebUIAccess -Description "Alias for Set-MultiWui command"
Export-ModuleMember -function Set-SecMultipleWebUIAccess -Alias Set-MultiWui

#Function Get-LogSplitInterval
Function Get-AdcL7LogInsightSplitConfiguration
{
	[cmdletbinding()]
	param(
		[validatenotnullorempty()]
		[string]$loadbalancer = $loadbalanceraddress,
		[validatenotnullorempty()]
		[system.management.automation.credential()]$credential = $script:cred
	)
	$parameters = @("logsplitinterval")
	$settings = @{}
	foreach ($param in $parameters)
	{
		$response = send-lbmessage -command get -parametername $param -loadbalancer $loadbalancer -credential $credential
		$settings.add($param, $response.firstchild.innertext)
	}
	new-object -typename psobject -property $settings
}
New-Alias -Name Get-LogSplitInterval -value Get-AdcL7LogInsightSplitConfiguration -Description "Alias for Get-LogSplitInterval command"
Export-ModuleMember -function Get-AdcL7LogInsightSplitConfiguration -Alias Get-LogSplitInterval

#Function Set-LogSplitInterval
Function Set-AdcL7LogInsightSplitConfiguration
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[string]$logsplit,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$response = Send-LBMessage -Command set -ParameterName logsplitinterval -ParameterValue $logsplit -LoadBalancer $LoadBalancer -Credential $Credential
	Get-LogSplitInterval  -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name Set-LogSplitInterval -value Set-AdcL7LogInsightSplitConfiguration -Description "Alias for Set-LogSplitInterval command"
Export-ModuleMember -function Set-AdcL7LogInsightSplitConfiguration -Alias Set-LogSplitInterval

#Function Set-AzureHAMode
Function Set-ClusterAzureHAMode
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateSet("master", "slave", "single")]
		[string]$HAMode,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command azurehamode -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name Set-AzureHAMode -value Set-ClusterAzureHAMode -Description "Alias for Set-AzureHAMode command"
Export-ModuleMember -function Set-ClusterAzureHAMode -Alias Set-AzureHAMode

#Function Get-AzureHAOption
Function Get-ClusterAzureHAConfiguration
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$response = Send-LBMessage -command getazurehaparams -LoadBalancer $LoadBalancer -Credential $Credential
	$response | Convert-XmlToPSObject
}
New-Alias -Name Get-AzureHAOption -value Get-ClusterAzureHAConfiguration -Description "Alias for Get-AzureHAOption command"
Export-ModuleMember -function Get-ClusterAzureHAConfiguration -Alias Get-AzureHAOption

#Function Set-AzureHAOption
Function Set-ClusterAzureHAConfiguration
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$Partner,
		[ValidateNotNullOrEmpty()]
		[string]$Hcp,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	if (!$Partner -and !$Hcp) {
		Throw "One or both parameters must be provided."
	}

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command azurehaparam -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name Set-AzureHAOption -value Set-ClusterAzureHAConfiguration -Description "Alias for Set-AzureHAOption command"
Export-ModuleMember -function Set-ClusterAzureHAConfiguration -Alias Set-AzureHAOption

#Function Set-AwsHAMode
Function Set-ClusterAwsHAMode
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateSet("master", "slave", "single")]
		[string]$HAMode,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command awshamode -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name Set-AwsHAMode -value Set-ClusterAwsHAMode -Description "Alias for Set-AwsHAMode command"
Export-ModuleMember -function Set-ClusterAwsHAMode -Alias Set-AwsHAMode

#Function Get-AwsHAOption
Function Get-ClusterAwsHaConfiguration
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$response = Send-LBMessage -command getawshaparams -LoadBalancer $LoadBalancer -Credential $Credential
	$response | Convert-XmlToPSObject
}
New-Alias -Name Get-AwsHAOption -value Get-ClusterAwsHaConfiguration -Description "Alias for Get-AwsHAOption command"
Export-ModuleMember -function Get-ClusterAwsHaConfiguration -Alias Get-AwsHAOption

#Function Set-AwsHAOption
Function Set-ClusterAwsHAConfiguration
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$Partner,
		[ValidateNotNullOrEmpty()]
		[string]$Hcp,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	if (!$Partner -and !$Hcp) {
		Throw "One or both parameters must be provided."
	}

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command awshaparam -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name Set-AwsHAOption -value Set-ClusterAwsHAConfiguration -Description "Alias for Set-AwsHAOption command"
Export-ModuleMember -function Set-ClusterAwsHAConfiguration -Alias Set-AwsHAOption

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function Set-AdminAccess
Function Set-SecAdminAccess
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[int32]$WuiIface,
		[Parameter(Mandatory=$true)]
		[int32]$WuiPort,
		[string]$WuiDefaultGateway,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command setadminaccess -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response
}
New-Alias -Name Set-AdminAccess -value Set-SecAdminAccess -Description "Alias for Set-AdminAccess command"
Export-ModuleMember -function Set-SecAdminAccess -Alias Set-AdminAccess

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function AfeClientLimitAdd
Function Add-LmIPConnectionLimit
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[String]$L7addr,
		[Parameter(Mandatory=$true)]
		[int32]$L7limit,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command afeclientlimitadd -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response
}
New-Alias -Name AfeClientLimitAdd -value Add-LmIPConnectionLimit -Description "Alias for AfeClientLimitAdd command"
Export-ModuleMember -function Add-LmIPConnectionLimit -Alias AfeClientLimitAdd

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function AfeClientLimitDelete
Function Remove-LmIPConnectionLimit
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[String]$L7addr,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command afeclientlimitdel -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response
}
New-Alias -Name AfeClientLimitDelete -value Remove-LmIPConnectionLimit -Description "Alias for AfeClientLimitDelete command"
Export-ModuleMember -function Remove-LmIPConnectionLimit -Alias AfeClientLimitDelete

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#Function AfeClientLimitList
Function Get-LmIPConnectionLimit
{
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
	$response = Send-LBMessage -Command afeclientlimitlist -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response.ClientLimit | Convert-XmlToPSObject
}
New-Alias -Name AfeClientLimitList -value Get-LmIPConnectionLimit -Description "Alias for AfeClientLimitList command"
Export-ModuleMember -function Get-LmIPConnectionLimit -Alias AfeClientLimitList

#endregion - Miscellaneous Options

#region - GeoIPBlacklist/Whitelist

Function setKempAPIReturnObject($retCode, $apiResponse, $geoAcl)
{
	$tempApiRetObj = @{}
	$tempApiRetObj.PSTypeName = "KempAPI"
	$tempApiRetObj.ReturnCode = $retCode
	$tempApiRetObj.Response = $apiResponse
	$tempApiRetObj.Data = $geoAcl

	$kempApiRetObject = New-Object -TypeName PSObject -Prop $tempApiRetObj

	$kempApiRetObject
}

Function setGetGeoAclBlacklistConfigurationAnswer($autoupdate, $lastupdate, $autoinstall, $installtime, $lastinstall)
{
	$tempGeoAcl = @{}
	$tempGeoAcl.PSTypeName = "GeoAcl"
	$tempGeoAcl.DatabaseAutoUpdate = $autoupdate
	$tempGeoAcl.DatabaseLastUpdate = $lastupdate
	$tempGeoAcl.DatabaseAutoInstall = $autoinstall
	$tempGeoAcl.DatabaseInstallTimeHour = $installtime
	$tempGeoAcl.DatabaseLastInstall = $lastinstall

	$geoAclAnswer = New-Object -TypeName PSObject -Prop $tempGeoAcl

	$geoAclAnswer
}

Function getDateFromString($dateString)
{
	if ($dateString -ne "Never")
	{
		$date_s = [Datetime]::ParseExact($dateString,"d MMM yyyy HH:mm:ss", $null)
	}
	else {
		$date_s = $null
	}
	$date_s
}

Function handleGeoIPBlacklistAnswer()
{
	$tempApiRetObj = @{}
	$tempApiRetObj.PSTypeName = "KempAPI"
	$tempApiRetObj.ReturnCode = 200
	$tempApiRetObj.Response = "Command successfully executed"
	$tempApiRetObj.Data = $null

	$kempApiRetObject = New-Object -TypeName PSObject -Prop $tempApiRetObj

	$kempApiRetObject
}

# (1) Function Get-GeoIPBlacklistDatabaseConfiguration
Function Get-GeoIPBlacklistDatabaseConfiguration
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$ErrorActionPreference = "Stop"
	try {
		$response = Send-LBMessage -Command geoacl/getsettings -LoadBalancer $LoadBalancer -Credential $Credential

		[string]$r_string = $response | Convert-XmlToPSObject

		$eqp = $r_string.IndexOf("=")
		$lbp = $r_string.IndexOf("}")

		$r_string = $r_string.substring($eqp + 1, $lbp - $eqp - 1)

		$p1 = $r_string.IndexOf(",")					# auto update
		$p2 = $r_string.IndexOf(",", $p1 + 1)	# last update date
		$p3 = $r_string.IndexOf(",", $p2 + 1)	# auto install
		$p4 = $r_string.IndexOf(",", $p3 + 1)	# default auto install hour

		$autoupdate  = $r_string.substring(0, $p1)
		$autoinstall = $r_string.substring($p2 + 1, $p3 - $p2 - 1)
		$installtime = $r_string.substring($p3 + 1, $p4 - $p3 - 1)

		$lastupdate_s = $r_string.substring($p1 + 1, $p2 - $p1 - 1)
		$lastupdate   = getDateFromString $lastupdate_s

		$lastinstall_s = $r_string.substring($p4 + 1)
		$lastinstall   = getDateFromString $lastinstall_s

		$geoACL = setGetGeoAclBlacklistConfigurationAnswer $autoupdate $lastupdate $autoinstall $installtime $lastinstall

		$retCode = 200
		$apiResponse = "Command successfully executed"

		$kempAPI = setKempAPIReturnObject $retCode $apiResponse $geoACL

		$kempAPI
	}
	catch {
		write-host "Caught an exception" -ForegroundColor Red
		write-host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
		write-host "Exception Message: $($_.Exception.Message)" -ForegroundColor Red
	}
}
Export-ModuleMember -function Get-GeoIPBlacklistDatabaseConfiguration

# (2) Function Set-GeoIPBlacklistDatabaseConfiguration
Function Set-GeoIPBlacklistDatabaseConfiguration
{
	Param(
		[Parameter(ParameterSetName="Update", Mandatory=$True)]
			[switch]$DatabaseAutoUpdate,

		[Parameter(ParameterSetName="Install")]
			[switch]$DatabaseAutoInstall,

		[Parameter(ParameterSetName="Install")]
		[ValidateRange(0,23)]
		[ValidateNotNullOrEmpty()]
		[Int32]$DatabaseInstallTimeHour,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$ErrorActionPreference = "Stop"
	$tempPT = Convert-BoundParameters -hashtable $psboundparameters
	$propertyTable = $tempPT.GetEnumerator() | sort-object -Property Name
	try {
		#ForEach ($h in $propertyTable.GetEnumerator()) {
		ForEach ($h in $propertyTable) {
			switch($($h.Name))
			{
				"DatabaseAutoUpdate"
				{
					$cmd2do = "geoacl/setautoupdate"
					if($($h.Value) -eq $true) {
						$dbUpdateParam = @{"enable"=1}
					}
					else {
						$dbUpdateParam = @{"enable"=0}
					}
					break
				}
				"DatabaseAutoInstall"
				{
					$cmd2do = "geoacl/setautoinstall"
					if($($h.Value) -eq $true) {
						$dbUpdateParam = @{"enable"=1}
					}
					else {
						$dbUpdateParam = @{"enable"=0}
					}
					break
				}
				"DatabaseInstallTimeHour"
				{
					$cmd2do = "geoacl/setinstalltime"
					$dbUpdateParam = @{"hour"=$($h.Value)}
					break
				}
			}
			if($cmd2do -eq $null) {
				continue
			}
			$response = Send-LBMessage -Command $cmd2do -ParameterValuePair $dbUpdateParam -Credential $Credential -LoadBalancer $LoadBalancer
		}
		$kempAPI = handleGeoIPBlacklistAnswer
		$kempAPI
	}
	catch {
		write-host "Caught an exception" -ForegroundColor Red
		write-host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
		write-host "Exception Message: $($_.Exception.Message)" -ForegroundColor Red
	}
}
Export-ModuleMember -function Set-GeoIPBlacklistDatabaseConfiguration

# (3) Function Update-GeoIPBlacklistDatabase
Function Update-GeoIPBlacklistDatabase
{
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$ErrorActionPreference = "Stop"
	try {
		$response = Send-LBMessage -Command geoacl/updatenow -Credential $Credential -LoadBalancer $LoadBalancer
		$kempAPI = handleGeoIPBlacklistAnswer
		$kempAPI
	}
	catch {
		write-host "Caught an exception" -ForegroundColor Red
		write-host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
		write-host "Exception Message: $($_.Exception.Message)" -ForegroundColor Red
	}
}
Export-ModuleMember -function Update-GeoIPBlacklistDatabase

# (4) Function Install-GeoIPBlacklistDatabase
Function Install-GeoIPBlacklistDatabase
{
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$ErrorActionPreference = "Stop"
	try {
		$response = Send-LBMessage -Command geoacl/installnow -Credential $Credential -LoadBalancer $LoadBalancer
		$kempAPI = handleGeoIPBlacklistAnswer
		$kempAPI
	}
	catch {
		write-host "Caught an exception" -ForegroundColor Red
		write-host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
		write-host "Exception Message: $($_.Exception.Message)" -ForegroundColor Red
	}
}
Export-ModuleMember -function Install-GeoIPBlacklistDatabase

# (5) Function Export-GeoIPBlacklistDatabase
Function Export-GeoIPBlacklistDatabase
{
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$filename,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$ErrorActionPreference = "Stop"
	$rpath = split-path "$filename"
	if (-NOT (Test-Path $rpath -PathType 'Container'))
	{
		Throw "$($rpath) is not a valid folder"
	}
	$fname = split-path "$filename" -leaf
	if ([string]::IsNullOrEmpty($fname))
	{
		Throw "file name is NULL"
	}
	if ((Test-Path $fname -PathType 'Container'))
	{
		Throw "file name is a folder"
	}
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters
	$response = Send-LBMessage -Command geoacl/downloadlist -File $filename -Output -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
	$kempAPI = handleGeoIPBlacklistAnswer
	$kempAPI
}
Export-ModuleMember -function Export-GeoIPBlacklistDatabase

# (6) Function Export-GeoIPBlacklistDatabaseChanges
Function Export-GeoIPBlacklistDatabaseChanges
{
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$filename,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$ErrorActionPreference = "Stop"
	$rpath = split-path "$filename"
	if (-NOT (Test-Path $rpath -PathType 'Container'))
	{
		Throw "$($rpath) is not a valid folder"
	}
	$fname = split-path "$filename" -leaf
	if ([string]::IsNullOrEmpty($fname))
	{
		Throw "file name is NULL"
	}
	if ((Test-Path $fname -PathType 'Container'))
	{
		Throw "file name is a folder"
	}
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters
	$response = Send-LBMessage -Command geoacl/downloadchanges -File $filename -Output -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
	$kempAPI = handleGeoIPBlacklistAnswer
	$kempAPI
}
Export-ModuleMember -function Export-GeoIPBlacklistDatabaseChanges

# (7) Function Add-GeoIPWhitelist
Function Add-GeoIPWhitelist
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[string]$Addr,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$ErrorActionPreference = "Stop"
	try {
		$propertyTable = Convert-BoundParameters -hashtable $psboundparameters
		$response = Send-LBMessage -Command geoacl/addcustom -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

		$kempAPI = handleGeoIPBlacklistAnswer
		$kempAPI
	}
	catch {
		write-host "Caught an exception" -ForegroundColor Red
		write-host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
		write-host "Exception Message: $($_.Exception.Message)" -ForegroundColor Red
	}
}
Export-ModuleMember -function Add-GeoIPWhitelist

# (8) Function Remove-GeoIPWhitelist
Function Remove-GeoIPWhitelist
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[string]$Addr,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$ErrorActionPreference = "Stop"
	try {
		$propertyTable = Convert-BoundParameters -hashtable $psboundparameters
		$response = Send-LBMessage -Command geoacl/removecustom -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

		$kempAPI = handleGeoIPBlacklistAnswer
		$kempAPI
	}
	catch {
		write-host "Caught an exception" -ForegroundColor Red
		write-host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
		write-host "Exception Message: $($_.Exception.Message)" -ForegroundColor Red
	}
}
Export-ModuleMember -function Remove-GeoIPWhitelist

# (9) Function Export-GeoIPWhitelistDatabase
Function Export-GeoIPWhitelistDatabase
{
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$filename,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$ErrorActionPreference = "Stop"
	$rpath = split-path "$filename"
	if (-NOT (Test-Path $rpath -PathType 'Container'))
	{
		Throw "$($rpath) is not a valid folder"
	}
	$fname = split-path "$filename" -leaf
	if ([string]::IsNullOrEmpty($fname))
	{
		Throw "file name is NULL"
	}
	if ((Test-Path $fname -PathType 'Container'))
	{
		Throw "file name is a folder"
	}
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters
	$response = Send-LBMessage -Command geoacl/listcustom -Output -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

	[string]$r_string = $response | Convert-XmlToPSObject
	$eqp = $r_string.IndexOf("=")
	$lbp = $r_string.IndexOf("}")
	$r_string = $r_string.substring($eqp + 1, $lbp - $eqp - 1)

	$today = Get-Date
	Out-File $filename -NoClobber
	Add-Content $filename "----------------------------------------------"
	Add-Content $filename " Whitelisted IPs ($today)"
	Add-Content $filename "----------------------------------------------"
	$r_string.Split(',') | ForEach {
		Add-Content $filename "$_"
	}
	$kempAPI = handleGeoIPBlacklistAnswer
	$kempAPI
}
Export-ModuleMember -function Export-GeoIPWhitelistDatabase

#endregion - GeoIPBlacklist/Whitelist

#region - WAF

#Function GetWafSettings
Function Get-WafRulesAutoUpdateConfiguration
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$response = Send-LBMessage -command getwafsettings -LoadBalancer $LoadBalancer -Credential $Credential
	[string]$r_string = $response | Convert-XmlToPSObject

	$eqp = $r_string.IndexOf("=")
	$lbp = $r_string.IndexOf("}")

	$r_string = $r_string.substring($eqp + 1, $lbp - $eqp - 1)
	$r_string = $r_string -replace "`n|`r",""

	$p1 = $r_string.IndexOf(",")					# auto update
	$p2 = $r_string.IndexOf(",", $p1 + 1)	# auto install
	$p3 = $r_string.IndexOf(",", $p2 + 1)	# default auto install hour
	$p4 = $r_string.IndexOf(",", $p3 + 1)	# last update date

	$autoupdate   = $r_string.substring(0, $p1)
	$autoinstall  = $r_string.substring($p1 + 1, $p2 - $p1 - 1)
	$installtime  = $r_string.substring($p2 + 1, $p3 - $p2 - 1)
	$lastupdate_tmp = $r_string.substring($p3 + 1)

	$idx1 = $lastupdate_tmp.IndexOf("-")
	$idx2 = $lastupdate_tmp.IndexOf("-", $idx1 + 1)
	$dd = $lastupdate_tmp.Substring($idx1 + 1, $idx2 - $idx1 - 1)
	$mm = $lastupdate_tmp.Substring($idx2 + 1)
	$yy = $lastupdate_tmp.Substring(0, $idx1)
	$lastupdate_s = "$yy/$mm/$dd"
	$lastupdate = [Datetime]::ParseExact($lastupdate_s, "yyyy/MM/d", $null)

	$tempData = @{}
	$tempData.PSTypeName = "Waf"
	$tempData.DatabaseAutoUpdate = $autoupdate
	$tempData.DatabaseLastUpdate = $lastupdate
	$tempData.DatabaseAutoInstall = $autoinstall
	$tempData.DatabaseInstallTimeHour = $installtime

	$Data = New-Object -TypeName PSObject -Prop $tempData

	$answer = setKempAPIReturnObject 200 "Command successfully executed" $Data
	$answer
}
New-Alias -Name GetWafSettings -value Get-WafRulesAutoUpdateConfiguration -Description "Alias for GetWafSettings command"
Export-ModuleMember -function Get-WafRulesAutoUpdateConfiguration -Alias GetWafSettings

Function Set-WafRulesAutoUpdateConfiguration
{
	Param(
		[Parameter(ParameterSetName="AutoUpdate", Mandatory=$True)]
			[switch]$DatabaseAutoUpdate,

		[Parameter(ParameterSetName="AutoInstall")]
			[switch]$DatabaseAutoInstall,

		[Parameter(ParameterSetName="AutoInstall")]
		[ValidateRange(0,23)]
		[ValidateNotNullOrEmpty()]
		[Int32]$DatabaseInstallTimeHour,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$ErrorActionPreference = "Stop"
	$tempPT = Convert-BoundParameters -hashtable $psboundparameters
	$propertyTable = $tempPT.GetEnumerator() | sort-object -Property Name
	try {
		ForEach ($h in $propertyTable) {
			switch($($h.Name))
			{
				"DatabaseAutoUpdate"
				{
					$cmd2do = "setwafautoupdate"
					if($($h.Value) -eq $true) {
						$dbUpdateParam = @{"Enable"=1}
					}
					else {
						$dbUpdateParam = @{"Enable"=0}
					}
					break
				}
				"DatabaseAutoInstall"
				{
					$cmd2do = "enablewafautoinstall"
					if($($h.Value) -eq $true) {
						$dbUpdateParam = @{"Enable"=1}
					}
					else {
						$dbUpdateParam = @{"Enable"=0}
					}
					break
				}
				"DatabaseInstallTimeHour"
				{
					$cmd2do = "setwafinstalltime"
					$dbUpdateParam = @{"Hour"=$($h.Value)}
					break
				}
			}
			if($cmd2do -eq $null) {
				continue
			}
			$response = Send-LBMessage -Command $cmd2do -ParameterValuePair $dbUpdateParam -Credential $Credential -LoadBalancer $LoadBalancer
		}
		$answer = setKempAPIReturnObject 200 "Command successfully executed" $null
		$answer
	}
	catch {
		write-host "Caught an exception" -ForegroundColor Red
		write-host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
		write-host "Exception Message: $($_.Exception.Message)" -ForegroundColor Red
	}
}
Export-ModuleMember -function Set-WafRulesAutoUpdateConfiguration

# ----------- WAF LEGACY START ---------------------------
Function SetWafAutoUpdate
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[bool]$Enable,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command setwafautoupdate -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
Export-ModuleMember -function SetWafAutoUpdate
# ----------- WAF LEGACY END -----------------------------

#Function DownloadWafRules
Function Update-WafRulesDatabase
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	try {
		Send-LBMessage -command downloadwafrules -LoadBalancer $LoadBalancer -Credential $Credential

		$retCode = 200
		$apiResponse = "Command successfully executed"

		$kempAPI = setKempAPIReturnObject $retCode $apiResponse $null

		$kempAPI
	}
	catch {
		write-host "Caught an exception" -ForegroundColor Red
		write-host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
		write-host "Exception Message: $($_.Exception.Message)" -ForegroundColor Red
	}
}
New-Alias -Name DownloadWafRules -value Update-WafRulesDatabase -Description "Alias for DownloadWafRules command"
Export-ModuleMember -function Update-WafRulesDatabase -Alias DownloadWafRules

# ----------- WAF LEGACY START ---------------------------
Function SetWafAutoInstall
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[string]$Enable
	)
	EnableWafAutoInstall -Enable $Enable
}
Export-ModuleMember -function SetWafAutoInstall

Function EnableWafAutoInstall
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[string]$Enable,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command enablewafautoinstall -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
Export-ModuleMember -function EnableWafAutoInstall

Function SetWafInstallTime
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateRange(0,23)]
		[Int32]$Hour,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command setwafinstalltime -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
Export-ModuleMember -function SetWafInstallTime
# ----------- WAF LEGACY END -----------------------------

#Function AddCustomLocation
Function Add-GeoCustomLocation
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[string]$Location,
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command addcustomlocation -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name AddCustomLocation -value Add-GeoCustomLocation -Description "Alias for AddCustomLocation command"
Export-ModuleMember -function Add-GeoCustomLocation -Alias AddCustomLocation

#Function EditCustomLocation
Function Set-GeoCustomLocation
{
	[CmdletBinding()]
	Param(
		#[Parameter(Mandatory=$true,Position=0)]
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$clOldName,
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$clNewName,
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command editcustomlocation -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name EditCustomLocation -value Set-GeoCustomLocation -Description "Alias for EditCustomLocation command"
Export-ModuleMember -function Set-GeoCustomLocation -Alias EditCustomLocation

#Function DeleteCustomLocation
Function Remove-GeoCustomLocation
{
	[CmdletBinding()]
	Param(
		#[Parameter(Mandatory=$true,Position=0)]
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$clName,
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command deletecustomlocation -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name DeleteCustomLocation -value Remove-GeoCustomLocation -Description "Alias for DeleteCustomLocation command"
Export-ModuleMember -function Remove-GeoCustomLocation -Alias DeleteCustomLocation

#Function ListCustomLocation
Function Get-GeoCustomLocation
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command listcustomlocation -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

	$response.location | Convert-XmlToPSObject
}
New-Alias -Name ListCustomLocation -value Get-GeoCustomLocation -Description "Alias for ListCustomLocation command"
Export-ModuleMember -function Get-GeoCustomLocation -Alias ListCustomLocation

#Function AddWafCustomRule
Function Add-WafCustomRuleSet
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[string]$Filename,
		[Parameter(Mandatory=$true)]
		[string]$Path,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$params = @{}
	#$params.Add("Type", $Type)

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command addwafcustomrule -ParameterValuePair $propertyTable -File $Path -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response
}
New-Alias -Name AddWafCustomRule -value Add-WafCustomRuleSet -Description "Alias for AddWafCustomRule command"
Export-ModuleMember -function Add-WafCustomRuleSet -Alias AddWafCustomRule

#Function DelWafCustomRule
Function Uninstall-WafCustomRuleSet
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$Filename,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command delwafcustomrule -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name DelWafCustomRule -value Uninstall-WafCustomRuleSet -Description "Alias for DelWafCustomRule command"
Export-ModuleMember -function Uninstall-WafCustomRuleSet -Alias DelWafCustomRule

#Function DownloadWafCustomRule
Function Export-WafCustomRule
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred,
		[Parameter(Mandatory=$true)]
		[string]$Path,
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Filename
	)
	$params = @{}
	if (-not ($Path))
	{
		$Path = "$($Env:SystemRoot)\Temp\LMBackup_$(Get-Date -format yyyy-MM-dd_HH-mm-ss)"
	}
	Write-Verbose "Path = $Path"

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command downloadwafcustomrule -ParameterValuePair $propertyTable -File $Path -Output -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response
}
New-Alias -Name DownloadWafCustomRule -value Export-WafCustomRule -Description "Alias for DownloadWafCustomRule command"
Export-ModuleMember -function Export-WafCustomRule -Alias DownloadWafCustomRule

#Function AddWafCustomData
Function Add-WafCustomRuleData
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[string]$Filename,
		[Parameter(Mandatory=$true)]
		[string]$Path,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$params = @{}
	#$params.Add("Type", $Type)

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command addwafcustomdata -ParameterValuePair $propertyTable -File $Path -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response
}
New-Alias -Name AddWafCustomData -value Add-WafCustomRuleData -Description "Alias for AddWafCustomData command"
Export-ModuleMember -function Add-WafCustomRuleData -Alias AddWafCustomData

#Function DelWafCustomData
Function Uninstall-WafCustomRuleData
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$Filename,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command delwafcustomdata -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name DelWafCustomData -value Uninstall-WafCustomRuleData -Description "Alias for DelWafCustomData command"
Export-ModuleMember -function Uninstall-WafCustomRuleData -Alias DelWafCustomData

#Function DownloadWafCustomData
Function Export-WafCustomRuleData
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred,
		[Parameter(Mandatory=$true)]
		[string]$Path,
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Filename
	)
	$params = @{}
	if (-not ($Path))
	{
		$Path = "$($Env:SystemRoot)\Temp\LMBackup_$(Get-Date -format yyyy-MM-dd_HH-mm-ss)"
	}
	Write-Verbose "Path = $Path"

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command downloadwafcustomdata -ParameterValuePair $propertyTable -File $Path -Output -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response
}
New-Alias -Name DownloadWafCustomData -value Export-WafCustomRuleData -Description "Alias for DownloadWafCustomData command"
Export-ModuleMember -function Export-WafCustomRuleData -Alias DownloadWafCustomData

#Function ManInstallWafRules
Function Install-WafRulesDatabase
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	try {
		Send-LBMessage -Command maninstallwafrules -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

		$retCode = 200
		$apiResponse = "Command successfully executed"

		$kempAPI = setKempAPIReturnObject $retCode $apiResponse $null

		$kempAPI
	}
	catch {
		write-host "Caught an exception" -ForegroundColor Red
		write-host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
		write-host "Exception Message: $($_.Exception.Message)" -ForegroundColor Red
	}
}
New-Alias -Name ManInstallWafRules -value Install-WafRulesDatabase -Description "Alias for ManInstallWafRules command"
Export-ModuleMember -function Install-WafRulesDatabase -Alias ManInstallWafRules

#Function ListWafAuditFiles
Function Get-WafAuditFiles
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command listwafauditfiles -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
	$response.WAFAuditFiles | Convert-XmlToPSObject
}
New-Alias -Name ListWafAuditFiles -value Get-WafAuditFiles -Description "Alias for ListWafAuditFiles command"
Export-ModuleMember -function Get-WafAuditFiles -Alias ListWafAuditFiles

#Function DownloadWafAuditLog
Function Export-WafAuditLog
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred,
		[Parameter(Mandatory=$true)]
		[string]$Path,
		[ValidateNotNullOrEmpty()]
		[string]$File,
		[string]$Filter
	)
	$params = @{}
	if (-not ($Path))
	{
		$Path = "$($Env:SystemRoot)\Temp\wafaudit.log"
	}
	Write-Verbose "Path = $Path"

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command downloadwafauditlog -ParameterValuePair $propertyTable -File $Path -Output -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response
}
New-Alias -Name DownloadWafAuditLog -value Export-WafAuditLog -Description "Alias for DownloadWafAuditLog command"
Export-ModuleMember -function Export-WafAuditLog -Alias DownloadWafAuditLog

#Function ListWafRules
Function Get-WafRules
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command listwafrules -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
	$response.Rules | Convert-XmlToPSObject
}
New-Alias -Name ListWafRules -value Get-WafRules -Description "Alias for ListWafRules command"
Export-ModuleMember -function Get-WafRules -Alias ListWafRules

#Function GetWafChangeLog
Function Export-WafChangeLog
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred,
		[Parameter(Mandatory=$true)]
		[string]$Path
	)
	$params = @{}
	if (-not ($Path))
	{
		$Path = "$($Env:SystemRoot)\Temp\WAF_changes.log"
	}
	Write-Verbose "Path = $Path"
	$response = Send-LBMessage -command getwafchangelog -File $Path -Output -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response
}
New-Alias -Name GetWafChangeLog -value Export-WafChangeLog -Description "Alias for GetWafChangeLog command"
Export-ModuleMember -function Export-WafChangeLog -Alias GetWafChangeLog

#Function VSAddWafRule
Function Add-AdcWafRule
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[string]$VS,
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[string]$Port,
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[string]$Prot,
		[string]$Rule,
		[string]$Disablerules,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command vsaddwafrule -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
	$response
}
New-Alias -Name VSAddWafRule -value Add-AdcWafRule -Description "Alias for VSAddWafRule command"
Export-ModuleMember -function Add-AdcWafRule -Alias VSAddWafRule

#Function VSRemoveWafRule
Function Remove-AdcWafRule
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[string]$VS,
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[string]$Port,
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[string]$Prot,
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[string]$Rule,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command vsremovewafrule -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
	$response
}
New-Alias -Name VSRemoveWafRule -value Remove-AdcWafRule -Description "Alias for VSRemoveWafRule command"
Export-ModuleMember -function Remove-AdcWafRule -Alias VSRemoveWafRule

#Function VSListWafRuleIds
Function Get-WafVSRules
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[string]$VS,
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[string]$Port,
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[string]$Prot,
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[string]$Rule,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command vslistwafruleids -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
	$rulename = $Rule.Split("/")[1]
    [array]$xmla = $response.$rulename
    New-Variable -Name "xmltag" -Value $xmla[0]
    If($xmltag -eq $rulename){ $response.$rulename | Convert-XmlToPSObject }
    Else{ $xmltag }
}
New-Alias -Name VSListWafRuleIds -value Get-WafVSRules -Description "Alias for VSListWafRuleIds command"
Export-ModuleMember -function Get-WafVSRules -Alias VSListWafRuleIds

#Function EnableWafRemoteLogging
Function Enable-WafRemoteLogging
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$RemoteURI,
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Username,
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Passwd,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command enablewafremotelogging -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name EnableWafRemoteLogging -value Enable-WafRemoteLogging -Description "Alias for EnableWafRemoteLogging command"
Export-ModuleMember -function Enable-WafRemoteLogging -Alias EnableWafRemoteLogging

#Function DisableWafRemoteLogging
Function Disable-WafRemoteLogging
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command disablewafremotelogging -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name DisableWafRemoteLogging -value Disable-WafRemoteLogging -Description "Alias for DisableWafRemoteLogging command"
Export-ModuleMember -function Disable-WafRemoteLogging -Alias DisableWafRemoteLogging

#endregion - WAF

#region - GEO

#FQDN

#Function AddFQDN
Function Add-GeoFQDN
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$FQDN,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command addfqdn -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name AddFQDN -value Add-GeoFQDN -Description "Alias for AddFQDN command"
Export-ModuleMember -function Add-GeoFQDN -Alias AddFQDN

#Function DeleteFQDN
Function Remove-GeoFQDN
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$FQDN,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command delfqdn -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name DeleteFQDN -value Remove-GeoFQDN -Description "Alias for DeleteFQDN command"
Export-ModuleMember -function Remove-GeoFQDN -Alias DeleteFQDN

#Function ModifyFQDN
Function Set-GeoFQDN
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$FQDN,
		[String]$SelectionCriteria,
		[Int32]$FailTime,
		[String]$SiteRecoveryMode,
		[ValidateRange(0,3)]
		[Int16]$PublicRequestValue,
		[ValidateRange(0,3)]
		[Int16]$PrivateRequestValue,
		[String]$Failover,

		[ValidateRange(0,1)]
		[Int16]$LocalSettings,

		[ValidateRange(1,86400)]
		[Int32]$localttl,

		[ValidateRange(0,86400)]
		[Int32]$localsticky,

		[bool]$UnanimousChecks,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command modfqdn -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

	$response.fqdn | Convert-XmlToPSObject
}
New-Alias -Name ModifyFQDN -value Set-GeoFQDN -Description "Alias for ModifyFQDN command"
Export-ModuleMember -function Set-GeoFQDN -Alias ModifyFQDN

#Function ListFQDNs
Function Get-GeoFQDN
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[String]$FQDN,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	if ($FQDN -eq "")
	{
		$response =	Send-LBMessage -Command listfqdns -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
	}
	else {
		$response = Send-LBMessage -Command showfqdn -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
	}

	$response.fqdn | Convert-XmlToPSObject
}
New-Alias -Name ListFQDNs -value Get-GeoFQDN -Description "Alias for ListFQDNs command"
Export-ModuleMember -function Get-GeoFQDN -Alias ListFQDNs

#Function ShowFQDN
Function Get-GeoSingleFQDN
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$FQDN,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command showfqdn -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

	$response.fqdn | Convert-XmlToPSObject
}
New-Alias -Name ShowFQDN -value Get-GeoSingleFQDN -Description "Alias for ShowFQDN command"
Export-ModuleMember -function Get-GeoSingleFQDN -Alias ShowFQDN

#Function AddMap
Function Add-GeoFQDNSiteAddress
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$FQDN,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullOrEmpty()]
		[String]$IP,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[string]$Cluster,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command addmap -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name AddMap -value Add-GeoFQDNSiteAddress -Description "Alias for AddMap command"
Export-ModuleMember -function Add-GeoFQDNSiteAddress -Alias AddMap

#Function DeleteMap
Function Remove-GeoFQDNSiteAddress
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$FQDN,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullOrEmpty()]
		[String]$IP,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command delmap -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name DeleteMap -value Remove-GeoFQDNSiteAddress -Description "Alias for DeleteMap command"
Export-ModuleMember -function Remove-GeoFQDNSiteAddress -Alias DeleteMap

#Function ModifyMap
Function Set-GeoFQDNSiteAddress
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$FQDN,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullOrEmpty()]
		[String]$IP,
		[String]$Checker,
		[Int32]$Weight,
		[String]$Enable,
		[String]$Cluster,
		[String]$Mapaddress,
		[String]$Mapport,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command modmap -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

	$response.fqdn.map | Convert-XMLToPSObject
}
New-Alias -Name ModifyMap -value Set-GeoFQDNSiteAddress -Description "Alias for ModifyMap command"
Export-ModuleMember -function Set-GeoFQDNSiteAddress -Alias ModifyMap

#Function ChangeCheckerAddr
Function Set-GeoFQDNSiteCheckerAddress
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$FQDN,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullOrEmpty()]
		[String]$IP,
		[Parameter(Mandatory=$true,Position=2)]
		[ValidateNotNullOrEmpty()]
		[String]$CheckerIP,
		[Parameter(Mandatory=$true,Position=3)]
		[ValidateNotNullOrEmpty()]
		[String]$Port,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command changecheckeraddr -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name ChangeCheckerAddr -value Set-GeoFQDNSiteCheckerAddress -Description "Alias for ChangeCheckerAddr command"
Export-ModuleMember -function Set-GeoFQDNSiteCheckerAddress -Alias ChangeCheckerAddr

#Function AddCountry
Function Add-GeoCountry
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$FQDN,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullOrEmpty()]
		[String]$IP,
		[ValidateNotNullOrEmpty()]
		[String]$CountryCode,
		[ValidateNotNullOrEmpty()]
		[String]$IsContinent,
		[ValidateNotNullOrEmpty()]
		[String]$CustomLocation,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	if (!$CountryCode -and !$CustomLocation) {
		Throw "A country code or custom location must be provided."
	}

	if ($CountryCode -and !$IsContinent) {
		Throw "Please indicate if country code refers to a continent."
	}

	if (!$CountryCode -and $IsContinent) {
		Throw "IsContinent parameter requires a country code."
	}

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command addcountry -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name AddCountry -value Add-GeoCountry -Description "Alias for AddCountry command"
Export-ModuleMember -function Add-GeoCountry -Alias AddCountry

#Function RemoveCountry
Function Remove-GeoCountry
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$FQDN,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullOrEmpty()]
		[String]$IP,
		[ValidateNotNullOrEmpty()]
		[String]$CountryCode,
		[ValidateNotNullOrEmpty()]
		[String]$IsContinent,
		[ValidateNotNullOrEmpty()]
		[String]$CustomLocation,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	if (!$CountryCode -and !$CustomLocation) {
		Throw "A country code or custom location must be provided."
	}

	if ($CountryCode -and !$IsContinent) {
		Throw "Please indicate if country code refers to a continent."
	}

	if (!$CountryCode -and $IsContinent) {
		Throw "IsContinent parameter requires a country code."
	}

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command removecountry -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name RemoveCountry -value Remove-GeoCountry -Description "Alias for RemoveCountry command"
Export-ModuleMember -function Remove-GeoCountry -Alias RemoveCountry

#Function ChangeMapLocation
Function Set-GeoFQDNSiteCoordinates
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$FQDN,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullOrEmpty()]
		[String]$IP,
		[Parameter(Mandatory=$true,Position=2)]
		[Int32]$Lat,
		[Parameter(Mandatory=$true,Position=3)]
		[Int32]$Long,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command changemaploc -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name ChangeMapLocation -value Set-GeoFQDNSiteCoordinates -Description "Alias for ChangeMapLocation command"
Export-ModuleMember -function Set-GeoFQDNSiteCoordinates -Alias ChangeMapLocation

#Cluster

#Function ListClusters
Function Get-GeoCluster
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[String]$IP,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	if ($ip -eq "")
	{
		$response =	Send-LBMessage -Command listclusters -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
	}
	else {
		$response = Send-LBMessage -Command showcluster -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
	}
	$response.cluster | Convert-XmlToPSObject
}
New-Alias -Name ListClusters -value Get-GeoCluster -Description "Alias for ListClusters command"
New-Alias -Name ShowCluster -value Get-GeoCluster -Description "Alias for ShowCluster command"
Export-ModuleMember -function Get-GeoCluster -Alias ListClusters, ShowCluster

#Function ShowCluster
#{
#	[CmdletBinding()]
#	Param(
#		[Parameter(Mandatory=$true,Position=0)]
#		[ValidateNotNullOrEmpty()]
#		[String]$IP,
#		[ValidateNotNullOrEmpty()]
#		[string]$LoadBalancer = $LoadBalancerAddress,
#		[ValidateNotNullOrEmpty()]
#		[System.Management.Automation.Credential()]$Credential = $script:cred
#	)
#	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters
#
#	$response = Send-LBMessage -Command showcluster -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
#
#	$response.cluster | Convert-XmlToPSObject
#}

#Function AddCluster
Function Add-GeoCluster
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$IP,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command addcluster -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name AddCluster -value Add-GeoCluster -Description "Alias for AddCluster command"
Export-ModuleMember -function Add-GeoCluster -Alias AddCluster

#Function DeleteCluster
Function Remove-GeoCluster
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$IP,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command delcluster -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name DeleteCluster -value Remove-GeoCluster -Description "Alias for DeleteCluster command"
Export-ModuleMember -function Remove-GeoCluster -Alias DeleteCluster

#Function ModifyCluster
Function Set-GeoCluster
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$IP,
		[String]$Type,
		[String]$Name,
		[String]$Checker,
		[Int32]$CheckerPort,
		[String]$Enable,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response =	Send-LBMessage -Command modcluster -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
	$response.cluster | Convert-XMLToPSObject
}
New-Alias -Name ModifyCluster -value Set-GeoCluster -Description "Alias for ModifyCluster command"
Export-ModuleMember -function Set-GeoCluster -Alias ModifyCluster

#Function ClusterChangeLocation
Function Set-GeoClusterCoordinates
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$IP,
		[Parameter(Mandatory=$true,Position=1)]
		[Int32]$LatSecs,
		[Parameter(Mandatory=$true,Position=2)]
		[Int32]$LongSecs,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command clustchangeloc -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name ClusterChangeLocation -value Set-GeoClusterCoordinates -Description "Alias for ClusterChangeLocation command"
Export-ModuleMember -function Set-GeoClusterCoordinates -Alias ClusterChangeLocation

#Misc params

#Function ListMiscParameters
Function Get-LmMiscParameter
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$vals = @{}

	$response =	Send-LBMessage -Command listparams -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

	$vals.add("SourceOfAuthority", $response.soa.SourceOfAuthority)
	$vals.add("NameSrv", $response.soa.NameSrv)
	$vals.add("SOAEmail", $response.soa.SOAEmail)
	$vals.add("TTL", $response.soa.TTL)
	$vals.add("Persist", $response.soa.persist)
	$vals.add("CheckInterval", $response.check.CheckInterval)
	$vals.add("ConnTimeout", $response.check.ConnTimeout)
	$vals.add("RetryAttempts", $response.check.RetryAttempts)

	New-Object -TypeName PSObject -Property $vals
}
New-Alias -Name ListMiscParameters -value Get-LmMiscParameter -Description "Alias for ListMiscParameters command"
Export-ModuleMember -function Get-LmMiscParameter -Alias ListMiscParameters

#Function ModifyMiscParameters
Function Set-LmMiscParameter
{
	[CmdletBinding()]
	Param(
		[String]$SourceOfAuthority,
		[String]$NameSrv,
		[String]$SOAEmail,
		[String]$TTL,
		[String]$Persist,
		[String]$CheckInterval,
		[String]$ConnTimeout,
		[String]$RetryAttempts,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$vals = @{}

	$response = Send-LBMessage -Command modparams -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

	$vals.add("SourceOfAuthority", $response.soa.SourceOfAuthority)
	$vals.add("NameSrv", $response.soa.NameSrv)
	$vals.add("SOAEmail", $response.soa.SOAEmail)
	$vals.add("TTL", $response.soa.TTL)
	$vals.add("Persist", $response.soa.persist)
	$vals.add("CheckInterval", $response.check.CheckInterval)
	$vals.add("ConnTimeout", $response.check.ConnTimeout)
	$vals.add("RetryAttempts", $response.check.RetryAttempts)

	New-Object -TypeName PSObject -Property $vals
}
New-Alias -Name ModifyMiscParameters -value Set-LmMiscParameter -Description "Alias for ModifyMiscParameters command"
Export-ModuleMember -function Set-LmMiscParameter -Alias ModifyMiscParameters

#Function LocationDataUpdate
Function Update-GeoDatabase
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[string]$Path,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$params = @{}
	#$params.Add("Type", $Type)

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command locdataupdate -ParameterValuePair $propertyTable -File $Path -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response
}
New-Alias -Name LocationDataUpdate -value Update-GeoDatabase -Description "Alias for LocationDataUpdate command"
Export-ModuleMember -function Update-GeoDatabase -Alias LocationDataUpdate

#IP Range

#Function ListIPs
Function Get-GeoIpRange
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[String]$IP,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	if ($IP -eq "")
	{
		$response =	Send-LBMessage -Command listips -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
	}
	else {
		$response = Send-LBMessage -Command showip -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
	}
	$response.IPAddress | Convert-XmlToPSObject
}
New-Alias -Name ListIPs -value Get-GeoIpRange -Description "Alias for ListIPs command"
New-Alias -Name ShowIP -value Get-GeoIpRange -Description "Alias for ShowIP command"
Export-ModuleMember -function Get-GeoIpRange -Alias ListIPs, ShowIP

##Function ShowIP
#Function Get-GeoSingleIpRange
#{
#	[CmdletBinding()]
#	Param(
#		[Parameter(Mandatory=$true,Position=0)]
#		[ValidateNotNullOrEmpty()]
#		[String]$IP,
#		[ValidateNotNullOrEmpty()]
#		[string]$LoadBalancer = $LoadBalancerAddress,
#		[ValidateNotNullOrEmpty()]
#		[System.Management.Automation.Credential()]$Credential = $script:cred
#	)
#	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters
#
#	$response = Send-LBMessage -Command showip -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
#
#	$response.IPAddress | Convert-XmlToPSObject
#}
#New-Alias -Name ShowIP -value Get-GeoSingleIpRange -Description "Alias for ShowIP command"
#Export-ModuleMember -function Get-GeoSingleIpRange -Alias ShowIP

#Function AddIP
Function New-GeoIPRange
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$IP,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command addip -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name AddIP -value New-GeoIPRange -Description "Alias for AddIP command"
Export-ModuleMember -function New-GeoIPRange -Alias AddIP

#Function DeleteIP
Function Remove-GeoIPRange
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$IP,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command delip -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name DeleteIP -value Remove-GeoIPRange -Description "Alias for DeleteIP command"
Export-ModuleMember -function Remove-GeoIPRange -Alias DeleteIP

#Function ModifyIPLocation
Function Set-GeoIPRangeCoordinates
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$IP,

		[Parameter(Mandatory=$true,Position=1)]
		[Int32]$Lat,

		[Parameter(Mandatory=$true,Position=2)]
		[Int32]$Long,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command modiploc -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name ModifyIPLocation -value Set-GeoIPRangeCoordinates -Description "Alias for ModifyIPLocation command"
Export-ModuleMember -function Set-GeoIPRangeCoordinates -Alias ModifyIPLocation

#Function DeleteIPLocation
Function Remove-GeoIPRangeCoordinates
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$IP,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command deliploc -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name DeleteIPLocation -value Remove-GeoIPRangeCoordinates -Description "Alias for DeleteIPLocation command"
Export-ModuleMember -function Remove-GeoIPRangeCoordinates -Alias DeleteIPLocation

#Function AddIPCountry
Function Set-GeoIPRangeCountry
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$IP,
		[Parameter(Mandatory=$true,Position=0)]
		[String]$CountryCode,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command addipcountry -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name AddIPCountry -value Set-GeoIPRangeCountry -Description "Alias for AddIPCountry command"
Export-ModuleMember -function Set-GeoIPRangeCountry -Alias AddIPCountry

#Function AddIPCountryCustom
Function Set-GeoIPRangeCustomLocation
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$IP,
		[Parameter(Mandatory=$true,Position=0)]
		[String]$CustomLoc,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command addipcountry -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name AddIPCountryCustom -value Set-GeoIPRangeCustomLocation -Description "Alias for AddIPCountryCustom command"
Export-ModuleMember -function Set-GeoIPRangeCustomLocation -Alias AddIPCountryCustom

#Function RemoveIPCountry
Function Remove-GeoIPRangeCountry
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$IP,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command removeipcountry -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name RemoveIPCountry -value Remove-GeoIPRangeCountry -Description "Alias for RemoveIPCountry command"
New-Alias -Name RemoveIPCountryCustom -value Remove-GeoIPRangeCountry -Description "Alias for RemoveIPCountryCustom command"
New-Alias -Name Remove-GeoIPRangeCustomLocation -value Remove-GeoIPRangeCountry -Description "Alias for Remove-GeoIPRangeCustomLocation command"
Export-ModuleMember -function Remove-GeoIPRangeCountry -Alias RemoveIPCountry, RemoveIPCountryCustom, Remove-GeoIPRangeCustomLocation

#Function EnableGEO
Function Enable-LmGeoPack
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command enablegeo -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name EnableGEO -value Enable-LmGeoPack -Description "Alias for EnableGEO command"
Export-ModuleMember -function Enable-LmGeoPack -Alias EnableGEO

#Function DisableGEO
Function Disable-LmGeoPack
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command disablegeo -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name DisableGEO -value Disable-LmGeoPack -Description "Alias for DisableGEO command"
Export-ModuleMember -function Disable-LmGeoPack -Alias DisableGEO

#Function IsGEOEnabled
Function Test-LmGeoEnabled
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command isgeoenabled -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name IsGEOEnabled -value Test-LmGeoEnabled -Description "Alias for IsGEOEnabled command"
Export-ModuleMember -function Test-LmGeoEnabled -Alias IsGEOEnabled

#endregion - GEO

#region - HSM

#Function HSMShow
Function Get-TlsHSM
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response =	Send-LBMessage -Command showhsm -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

	$response.HSM | Convert-XmlToPSObject
}
New-Alias -Name HSMShow -value Get-TlsHSM -Description "Alias for HSMShow command"
Export-ModuleMember -function Get-TlsHSM -Alias HSMShow

#Function HSMConfigure
Function Set-TlsHSM
{
	[CmdletBinding()]
	Param(
		[String]$Sethsm,
		[String]$Safeaddr,
		[String]$Clpass,
		[String]$Enable,
		[String]$Cavhsmaddr,
		[String]$Cavhsmpasswd,
		[String]$Cavhsmuser,
		[String]$Cavhsmenable,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command hsmconfig -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

	$response.HSM | Convert-XmlToPSObject
}
New-Alias -Name HSMConfigure -value Set-TlsHSM -Description "Alias for HSMConfigure command"
Export-ModuleMember -function Set-TlsHSM -Alias HSMConfigure

#Function HSMUploadCACert
Function Set-TlsHSMCACert
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[string]$Path,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$params = @{}
	#$params.Add("Type", $Type)

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command hsmuploadca -ParameterValuePair $propertyTable -File $Path -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response
}
New-Alias -Name HSMUploadCACert -value Set-TlsHSMCACert -Description "Alias for HSMUploadCACert command"
Export-ModuleMember -function Set-TlsHSMCACert -Alias HSMUploadCACert

#Function HSMGenerateClientCert
Function New-TlsHSMClientCert
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred,
		[Parameter(Mandatory=$true)]
		[string]$Path,
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Clcertname
	)
	$params = @{}
	if (-not ($Path))
	{
		$Path = "$($Env:SystemRoot)\Temp\LMBackup_$(Get-Date -format yyyy-MM-dd_HH-mm-ss)"
	}
	else {
		if($Path.EndsWith("\\") -or $Path.EndsWith("/"))
		{
			$Path = $Path + $Clcertname + ".pem"
		}
		else {
			$Path = $Path + "\\" + $Clcertname + ".pem"
		}
	}
	Write-Verbose "Path = $Path"

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command hsmgenclientcert -ParameterValuePair $propertyTable -File $Path -Output -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response
}
New-Alias -Name HSMGenerateClientCert -value New-TlsHSMClientCert -Description "Alias for HSMGenerateClientCert command"
Export-ModuleMember -function New-TlsHSMClientCert -Alias HSMGenerateClientCert

#endregion - HSM

#region - User management

#Function UserSetSystemPassword
Function Set-SecSystemUserPassword
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[String]$CurrPassword,
		[Parameter(Mandatory=$true)]
		[String]$Password,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command usersetsyspassword -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

	$response
}
New-Alias -Name UserSetSystemPassword -value Set-SecSystemUserPassword -Description "Alias for UserSetSystemPassword command"
Export-ModuleMember -function Set-SecSystemUserPassword -Alias UserSetSystemPassword

#Function UserAddLocal
Function New-SecUser
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[String]$User,
		[Parameter(Mandatory=$true)]
		[String]$Password,
		[Parameter(Mandatory=$true)]
		[String]$Radius,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command useraddlocal -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

	$response
}
New-Alias -Name UserAddLocal -value New-SecUser -Description "Alias for UserAddLocal command"
Export-ModuleMember -function New-SecUser -Alias UserAddLocal

#Function UserSetPermissions
Function Set-SecUserPermission
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[String]$User,
		[Parameter(Mandatory=$true)]
		[String]$Perms,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command usersetperms -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

	$response
}
New-Alias -Name UserSetPermissions -value Set-SecUserPermission -Description "Alias for UserSetPermissions command"
Export-ModuleMember -function Set-SecUserPermission -Alias UserSetPermissions

#Function UserChangeLocalPassword
Function Set-SecUserPassword
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[String]$User,
		[Parameter(Mandatory=$true)]
		[String]$Password,
		[Parameter(Mandatory=$true)]
		[String]$Radius,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command userchangelocpass -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

	$response
}
New-Alias -Name UserChangeLocalPassword -value Set-SecUserPassword -Description "Alias for UserChangeLocalPassword command"
Export-ModuleMember -function Set-SecUserPassword -Alias UserChangeLocalPassword

#Function UserDeleteLocal
Function Remove-SecUser
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[String]$User,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command userdellocal -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

	$response
}
New-Alias -Name UserDeleteLocal -value Remove-SecUser -Description "Alias for UserDeleteLocal command"
Export-ModuleMember -function Remove-SecUser -Alias UserDeleteLocal

#Function UserShow
Function Get-SecSingleUser
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[String]$User,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command usershow -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

	if($response.User)
	{
		$response.User | Convert-XmlToPSObject
	}
	else {
		$response
	}
}
New-Alias -Name UserShow -value Get-SecSingleUser -Description "Alias for UserShow command"
Export-ModuleMember -function Get-SecSingleUser -Alias UserShow

#Function UserList
Function Get-SecUser
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command userlist -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

	$response.User | Convert-XmlToPSObject
}
New-Alias -Name UserList -value Get-SecUser -Description "Alias for UserList command"
Export-ModuleMember -function Get-SecUser -Alias UserList

#Function UserGenerateCert
Function New-SecUserCertificate
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$User,
		[ValidateNotNullOrEmpty()]
		[String]$Passphrase,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$params = @{}
	$params.Add("user", $User)

	if ($Passphrase) {
		$params.Add("passphrase", [System.Web.HttpUtility]::UrlEncode($Passphrase))
	}
	Send-LBMessage -Command usernewcert -ParameterValuePair $params -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
}
New-Alias -Name UserGenerateCert -value New-SecUserCertificate -Description "Alias for UserGenerateCert command"
Export-ModuleMember -function New-SecUserCertificate -Alias UserGenerateCert

#Function UserDownloadCert
Function Export-SecUserCertificate
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$User,
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Path,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$params = @{}
	$params.Add("user", $User)

	Send-LBMessage -Command userdownloadcert -ParameterValuePair $params -File $Path -Output -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
}
New-Alias -Name UserDownloadCert -value Export-SecUserCertificate -Description "Alias for UserDownloadCert command"
Export-ModuleMember -function Export-SecUserCertificate -Alias UserDownloadCert

#Function UserDeleteCert
Function Remove-SecUserCertificate
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$User,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command userdelcert -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
}
New-Alias -Name UserDeleteCert -value Remove-SecUserCertificate -Description "Alias for UserDeleteCert command"
Export-ModuleMember -function Remove-SecUserCertificate -Alias UserDeleteCert

#endregion - User management

Function AlsiLicense
{
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred,
		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$true,Position=0)]
		[string]$KempId = $KempId,
		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$true,Position=1)]
		[string]$Password = $Password,
		[string]$http_proxy
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command alsilicense -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
Export-ModuleMember -function AlsiLicense

Function Request-LicenseOnline
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred,
		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$true,Position=0)]
		[string]$KempId = $KempId,
		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$true,Position=1)]
		[string]$Password = $Password,
		[string]$http_proxy
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters
	try {
		Send-LBMessage -Command alsilicense2 -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

		$tempApiRetObj = @{}
		$tempApiRetObj.PSTypeName = "KempAPI"
		$tempApiRetObj.ReturnCode = 200
		$tempApiRetObj.Response = "Command successfully executed"
		$tempApiRetObj.Data = $null

		$apiRetObject = New-Object -TypeName PSObject -Prop $tempApiRetObj
		$apiRetObject
	}
	catch {
		write-host "Caught an exception" -ForegroundColor Red
		write-host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
		write-host "Exception Message: $($_.Exception.Message)" -ForegroundColor Red
	}
}
New-Alias -Name Update-LicenseOnline -value Request-LicenseOnline -Description "Alias for Update-LicenseOnline command"
Export-ModuleMember -function Request-LicenseOnline -Alias Update-LicenseOnline

#region - Addons

#Function UploadAddon
Function Install-LmAddon
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[string]$Path,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3,65530)]
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$params = @{}

	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command addaddon -ParameterValuePair $propertyTable -File $Path -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response
}
New-Alias -Name UploadAddon -value Install-LmAddon -Description "Alias for UploadAddon command"
Export-ModuleMember -function Install-LmAddon -Alias UploadAddon

#Function DeleteAddon
Function Remove-LmAddon
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command deladdon -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
	$response
}
New-Alias -Name DeleteAddon -value Remove-LmAddon -Description "Alias for DeleteAddon command"
Export-ModuleMember -function Remove-LmAddon -Alias DeleteAddon

#Function ListAddons
Function Get-LmAddOn
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response = Send-LBMessage -Command listaddon -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
	$response | Convert-XmlToPSObject
}
New-Alias -Name ListAddons -value Get-LmAddOn -Description "Alias for ListAddons command"
Export-ModuleMember -function Get-LmAddOn -Alias ListAddons

#endregion - Addons

#region - IPsec

#Function CreateVpnConnection
Function New-VpnConnection
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command createvpncon -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name CreateVpnConnection -value New-VpnConnection -Description "Alias for CreateVpnConnection command"
Export-ModuleMember -function New-VpnConnection -Alias CreateVpnConnection

#Function DeleteVpnConnection
Function Remove-VpnConnection
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command deletevpncon -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name DeleteVpnConnection -value Remove-VpnConnection -Description "Alias for DeleteVpnConnection command"
Export-ModuleMember -function Remove-VpnConnection -Alias DeleteVpnConnection

#Function SetVpnAddrs
Function Set-VpnAddrs
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullOrEmpty()]
		[String]$LocalIp,
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$LocalSubnets,
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$RemoteIp,
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$RemoteSubnets,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command setvpnaddr -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name SetVpnAddrs -value Set-VpnAddrs -Description "Alias for SetVpnAddrs command"
Export-ModuleMember -function Set-VpnAddrs -Alias SetVpnAddrs

#Function SetVpnLocalIp
Function Set-VpnLocalIp
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullOrEmpty()]
		[String]$LocalIp,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command setvpnlocalip -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name SetVpnLocalIp -value Set-VpnLocalIp -Description "Alias for SetVpnLocalIp command"
Export-ModuleMember -function Set-VpnLocalIp -Alias SetVpnLocalIp

#Function SetVpnLocalSubnets
Function Set-VpnLocalSubnet
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullOrEmpty()]
		[String]$LocalSubnets,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command setvpnlocalsubnet -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name SetVpnLocalSubnets -value Set-VpnLocalSubnet -Description "Alias for SetVpnLocalSubnets command"
Export-ModuleMember -function Set-VpnLocalSubnet -Alias SetVpnLocalSubnets

#Function SetVpnRemoteIp
Function Set-VpnRemoteIp
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullOrEmpty()]
		[String]$RemoteIp,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command setvpnremoteip -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name SetVpnRemoteIp -value Set-VpnRemoteIp -Description "Alias for SetVpnRemoteIp command"
Export-ModuleMember -function Set-VpnRemoteIp -Alias SetVpnRemoteIp

#Function SetVpnRemoteSubnets
Function Set-VpnRemoteSubnet
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullOrEmpty()]
		[String]$RemoteSubnets,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command setvpnremotesubnet -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name SetVpnRemoteSubnets -value Set-VpnRemoteSubnet -Description "Alias for SetVpnRemoteSubnets command"
Export-ModuleMember -function Set-VpnRemoteSubnet -Alias SetVpnRemoteSubnets

#Function SetVpnSecret
Function Set-VpnSecret
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullOrEmpty()]
		[String]$LocalId,
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$RemoteId,
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$Key,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command setvpnsecret -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name SetVpnSecret -value Set-VpnSecret -Description "Alias for SetVpnSecret command"
Export-ModuleMember -function Set-VpnSecret -Alias SetVpnSecret

#Function StartVpnConnection
Function Start-VpnConnection
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command startvpncon -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name StartVpnConnection -value Start-VpnConnection -Description "Alias for StartVpnConnection command"
Export-ModuleMember -function Start-VpnConnection -Alias StartVpnConnection

#Function StopVpnConnection
Function Stop-VpnConnection
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command stopvpncon -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name StopVpnConnection -value Stop-VpnConnection -Description "Alias for StopVpnConnection command"
Export-ModuleMember -function Stop-VpnConnection -Alias StopVpnConnection

#Function StartIkeDaemon
Function Start-VpnIkeDaemon
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command startikedaemon -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name StartIkeDaemon -value Start-VpnIkeDaemon -Description "Alias for StartIkeDaemon command"
Export-ModuleMember -function Start-VpnIkeDaemon -Alias StartIkeDaemon

#Function StopIkeDaemon
Function Stop-VpnIkeDaemon
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command stopikedaemon -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name StopIkeDaemon -value Stop-VpnIkeDaemon -Description "Alias for StopIkeDaemon command"
Export-ModuleMember -function Stop-VpnIkeDaemon -Alias StopIkeDaemon

#Function StatusIkeDaemon
Function Get-VpnIkeDaemonStatus
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command statusikedaemon -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name StatusIkeDaemon -value Get-VpnIkeDaemonStatus -Description "Alias for StatusIkeDaemon command"
Export-ModuleMember -function Get-VpnIkeDaemonStatus -Alias StatusIkeDaemon

#Function ListVpns
Function Get-VpnConnection
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[String]$Name,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	if ($name -eq "")
	{
		$response = Send-LBMessage -Command listvpns -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
		$response.VPN | Convert-XmlToPSObject
	}
	else {
		Send-LBMessage -Command getvpnstatus -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
	}
}
New-Alias -Name ListVpns -value Get-VpnConnection -Description "Alias for ListVpns command"
Export-ModuleMember -function Get-VpnConnection -Alias ListVpns

# LEGACY: see the above command Get-VpnConnection
Function GetVpnStatus
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command getvpnstatus -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
Export-ModuleMember -function GetVpnStatus

#Function SetVpnPfsEnable
Function Set-VpnPfsEnable
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command setvpnpfsenable -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name SetVpnPfsEnable -value Set-VpnPfsEnable -Description "Alias for SetVpnPfsEnable command"
Export-ModuleMember -function Set-VpnPfsEnable -Alias SetVpnPfsEnable

#Function SetVpnPfsDisable
Function Set-VpnPfsDisable
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	Send-LBMessage -Command setvpnpfsdisable -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
}
New-Alias -Name SetVpnPfsDisable -value Set-VpnPfsDisable -Description "Alias for SetVpnPfsDisable command"
Export-ModuleMember -function Set-VpnPfsDisable -Alias SetVpnPfsDisable

#endregion - IPsec

#region - Clusters

#Function NMClusterStatus
Function Get-ClusterStatus
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response =	Send-LBMessage -Command "cluster/status" -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

	$response.childnodes | Convert-XmlToPSObject
}
New-Alias -Name NMClusterStatus -value Get-ClusterStatus -Description "Alias for NMClusterStatus command"
Export-ModuleMember -function Get-ClusterStatus -Alias NMClusterStatus

#Function NMClusterCreate
Function New-Cluster
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$SharedAddress,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response =	Send-LBMessage -Command "cluster/create" -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

	$response
}
New-Alias -Name NMClusterCreate -value New-Cluster -Description "Alias for NMClusterCreate command"
Export-ModuleMember -function New-Cluster -Alias NMClusterCreate

#Function NMAddNode
Function Add-ClusterNode
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$Address,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response =	Send-LBMessage -Command "cluster/addnode" -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

	$response
}
New-Alias -Name NMAddNode -value Add-ClusterNode -Description "Alias for NMAddNode command"
Export-ModuleMember -function Add-ClusterNode -Alias NMAddNode

#Function NMJoinCluster
Function Join-Cluster
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response =	Send-LBMessage -Command "cluster/joincluster" -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

	$response
}
New-Alias -Name NMJoinCluster -value Join-Cluster -Description "Alias for NMJoinCluster command"
Export-ModuleMember -function Join-Cluster -Alias NMJoinCluster

#Function NMEnableNode
Function Enable-ClusterNode
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[Int32]$NodeId,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response =	Send-LBMessage -Command "cluster/enablenode" -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

	$response
}
New-Alias -Name NMEnableNode -value Enable-ClusterNode -Description "Alias for NMEnableNode command"
Export-ModuleMember -function Enable-ClusterNode -Alias NMEnableNode

#Function NMDisableNode
Function Disable-ClusterNode
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[Int32]$NodeId,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response =	Send-LBMessage -Command "cluster/disablenode" -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

	$response
}
New-Alias -Name NMDisableNode -value Disable-ClusterNode -Description "Alias for NMDisableNode command"
Export-ModuleMember -function Disable-ClusterNode -Alias NMDisableNode

#Function NMDeleteNode
Function Remove-ClusterNode
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[Int32]$NodeId,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response =	Send-LBMessage -Command "cluster/deletenode" -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

	$response
}
New-Alias -Name NMDeleteNode -value Remove-ClusterNode -Description "Alias for NMDeleteNode command"
Export-ModuleMember -function Remove-ClusterNode -Alias NMDeleteNode

#endregion - Clusters

#region - EULA

Function ReadEULA
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters
	$response = Send-LBMessage -Command readeula -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
	$response
}
Export-ModuleMember -function ReadEULA

Function Read-LicenseEULA
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	try {
		$response =	Send-LBMessage -Command readeula -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

		$mlidx = $response.IndexOf("`<Magic`>") + 7
		$muidx = $response.IndexOf("`<`/Magic`>")
		$mstr  = $response.SubString($mlidx, $muidx - $mlidx)

		$elidx = $response.IndexOf("`<Eula`>") + 6
		$euidx = $response.IndexOf("`<`/Eula`>")
		$eula  = $response.SubString($elidx, $euidx - $elidx)

		$tempEulaAnswer = @{}
		$tempEulaAnswer.PSTypeName = "Eula"
		$tempEulaAnswer.Eula = $eula
		$tempEulaAnswer.MagicString = $mstr
		$eulaAnswer = New-Object -TypeName PSObject -Prop $tempEulaAnswer

		$tempApiRetObj = @{}
		$tempApiRetObj.PSTypeName = "KempAPI"
		$tempApiRetObj.ReturnCode = 200
		$tempApiRetObj.Response = "Command successfully executed"
		$tempApiRetObj.Data = $eulaAnswer

		$apiRetObject = New-Object -TypeName PSObject -Prop $tempApiRetObj
		$apiRetObject
	}
	catch {
		write-host "Caught an exception" -ForegroundColor Red
		write-host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
		write-host "Exception Message: $($_.Exception.Message)" -ForegroundColor Red
	}
}
Export-ModuleMember -function Read-LicenseEULA

Function AcceptEULA
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$Type,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullOrEmpty()]
		[String]$Magic,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters
	$response =	Send-LBMessage -Command accepteula -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
	$response
}
Export-ModuleMember -function AcceptEULA

Function Confirm-LicenseEULA
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$Type,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullOrEmpty()]
		[String]$Magic,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	try {
		$response =	Send-LBMessage -Command accepteula -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

		$mlidx = $response.IndexOf("`<Magic`>") + 7
		$muidx = $response.IndexOf("`<`/Magic`>")
		$mstr  = $response.SubString($mlidx, $muidx - $mlidx)

		$elidx = $response.IndexOf("`<Eula`>") + 6
		$euidx = $response.IndexOf("`<`/Eula`>")
		$eula2 = $response.SubString($elidx, $euidx - $elidx)

		$tempEula2Answer = @{}
		$tempEula2Answer.PSTypeName = "Eula2"
		$tempEula2Answer.Eula2 = $eula2
		$tempEula2Answer.MagicString = $mstr
		$eulaAnswer2 = New-Object -TypeName PSObject -Prop $tempEula2Answer

		$tempApiRetObj = @{}
		$tempApiRetObj.PSTypeName = "KempAPI"
		$tempApiRetObj.ReturnCode = 200
		$tempApiRetObj.Response = "Command successfully executed"
		$tempApiRetObj.Data = $eulaAnswer2

		$apiRetObject = New-Object -TypeName PSObject -Prop $tempApiRetObj
		$apiRetObject
	}
	catch {
		write-host "Caught an exception" -ForegroundColor Red
		write-host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
		write-host "Exception Message: $($_.Exception.Message)" -ForegroundColor Red
	}
}
Export-ModuleMember -function Confirm-LicenseEULA

Function AcceptEULA2
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$Magic,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullOrEmpty()]
		[String]$Accept,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters
	$response =	Send-LBMessage -Command accepteula2 -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
	$response
}
Export-ModuleMember -function AcceptEULA2

Function Confirm-LicenseEULA2
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$Magic,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullOrEmpty()]
		[String]$Accept,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	try {
		$response =	Send-LBMessage -Command accepteula2 -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

		$tempApiRetObj = @{}
		$tempApiRetObj.PSTypeName = "KempAPI"
		$tempApiRetObj.ReturnCode = 200
		$tempApiRetObj.Response = "Command successfully executed"
		$tempApiRetObj.Data = $null

		$apiRetObject = New-Object -TypeName PSObject -Prop $tempApiRetObj
		$apiRetObject
	}
	catch {
		write-host "Caught an exception" -ForegroundColor Red
		write-host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
		write-host "Exception Message: $($_.Exception.Message)" -ForegroundColor Red
	}
}
Export-ModuleMember -function Confirm-LicenseEULA2

Function SetInitialPasswd
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$Passwd,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response =	Send-LBMessage -Command set_initial_passwd -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential
	$response
}
Export-ModuleMember -function SetInitialPasswd

Function Set-LicenseInitialPassword
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$Passwd,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters
	try {
		$response =	Send-LBMessage -Command set_initial_passwd2 -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

		$tempApiRetObj = @{}
		$tempApiRetObj.PSTypeName = "KempAPI"
		$tempApiRetObj.ReturnCode = 200
		$tempApiRetObj.Response = "Command successfully executed"
		$tempApiRetObj.Data = $null

		$apiRetObject = New-Object -TypeName PSObject -Prop $tempApiRetObj
		$apiRetObject
	}
	catch {
		write-host "Caught an exception" -ForegroundColor Red
		write-host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
		write-host "Exception Message: $($_.Exception.Message)" -ForegroundColor Red
	}
}
Export-ModuleMember -function Set-LicenseInitialPassword

#endregion - EULA

#region - SDN

#Function AddSDNController
Function Add-SdnController
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$IPV4,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullOrEmpty()]
		[Int32]$Port,
		[Int32]$Clid,
		[Boolean]$Https,
		[String]$User,
		[String]$Password,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response =	Send-LBMessage -Command addsdncontroller -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

	$response.childnodes.childnodes.childnodes | Convert-XmlToPSObject
}
New-Alias -Name AddSDNController -value Add-SdnController -Description "Alias for AddSDNController command"
Export-ModuleMember -function Add-SdnController -Alias AddSDNController

#Function DeleteSDNController
Function Remove-SdnController
{
	[CmdletBinding()]
	Param(
		[Int32]$Clid,
		[Int32]$Cid,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response =	Send-LBMessage -Command delsdncontroller -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

	$response | Convert-XmlToPSObject
}
New-Alias -Name DeleteSDNController -value Remove-SdnController -Description "Alias for DeleteSDNController command"
Export-ModuleMember -function Remove-SdnController -Alias DeleteSDNController

#Function ModifySDNController
Function Set-SdnController
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[Int32]$Cid,
		[Int32]$Clid,
		[String]$IPV4,
		[Int32]$Port,
		[Boolean]$Https,
		[String]$User,
		[String]$Password,
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response =	Send-LBMessage -Command modsdncontroller -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

	$response.childnodes.childnodes.childnodes | Convert-XmlToPSObject
}
New-Alias -Name ModifySDNController -value Set-SdnController -Description "Alias for ModifySDNController command"
Export-ModuleMember -function Set-SdnController -Alias ModifySDNController

#Function GetSDNController
Function Get-SdnController
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response =	Send-LBMessage -Command getsdncontroller -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

	$response.childnodes.childnodes.childnodes | Convert-XmlToPSObject
}
New-Alias -Name GetSDNController -value Get-SdnController -Description "Alias for GetSDNController command"
Export-ModuleMember -function Get-SdnController -Alias GetSDNController

#endregion - SDN

#region - Logging and Debug

#Function FlushSsoCache
Function Clear-SSOCache
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters

	$response =	Send-LBMessage -Command logging/debug/ssoflush -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

	if ($response.code -eq "fail")
	{
	        Write-Error $response.Error
	}
	else
	{
		$response
	}
}
New-Alias -Name FlushSsoCache -value Clear-SSOCache -Description "Alias for FlushSsoCache command"
Export-ModuleMember -function Clear-SSOCache -Alias FlushSsoCache

#endregion

Function DoTcpDump
{
	[CmdletBinding()]
	Param(
		[string]$LoadBalancer = $LoadBalancerAddress,
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred,
		[ValidateNotNullOrEmpty()]
		[int]$MaxPackets,
		[ValidateNotNullOrEmpty()]
		[int]$MaxTime,
		[ValidateNotNullOrEmpty()]
		[string]$Interface,
		[ValidateNotNullOrEmpty()]
		[string]$Port,
		[ValidateNotNullOrEmpty()]
		[string]$Address,
		[ValidateNotNullOrEmpty()]
		[string]$TcpOptions,
		[string]$Path
	)
	$params = @{}
	if($MaxPackets){
		$params.Add("maxpackets", $MaxPackets)
	}
	if($MaxTime){
		$params.Add("maxtime", $MaxTime)
	}
	if($Interface){
		$params.Add("interface", $Interface)
	}
	if($Port){
		$params.Add("port", $Port)
	}
	if($Address){
		$params.Add("address", $Address)
	}
	if($TcpOptions){
		$params.Add("tcpoptions", $TcpOptions)
	}
	if (-not ($Path))
	{
		$Path = "$($Env:SystemRoot)\Temp\tcpdump_$(Get-Date -format yyyy-MM-dd_HH-mm-ss).pcap"
	}
	Write-Verbose "Path = $Path"
	$response = Send-LBMessage -command tcpdump -ParameterValuePair $params -File $Path -Output -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
	$response
}
Export-ModuleMember -function DoTcpDump

#endregion

# region ASL

Function get_stringbyname([String]$strToSearch, [String]$inputStr)
{
	$tmp = $inputStr
	$len = $strToSearch.Length

	$idx = $tmp.IndexOf($strToSearch) + 1
	if ($idx -eq 0)
	{
		$idx = $len
	}
	else {
		if ($idx -gt 0)
		{
			$tmp = $tmp.SubString($idx)
			$idx = $len
		}
		else {
			throw "Internal error."
		}
	}
	$icomma = $tmp.IndexOf(";")
	if ($icomma -gt 0) {
		$response = $tmp.SubString($idx, $icomma - $idx)
	}
	else {
		$icomma = $tmp.IndexOf("=") + 1
		$response = $tmp.SubString($icomma)
	}
	$response
}

Function Request-LicenseOnPremise
{
	[CmdletBinding()]
	Param(
		[Parameter(Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$aslipaddr,
		[Parameter(Position=1)]
		[ValidateNotNullOrEmpty()]
		[String]$aslname,
		[Parameter(Position=2)]
		[ValidateNotNullOrEmpty()]
		[ValidateRange(1,65535)]
		[int]$aslport,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	$propertyTable = Convert-BoundParameters -hashtable $psboundparameters
	try {
		$response =	Send-LBMessage -Command aslactivate -ParameterValuePair $propertyTable -LoadBalancer $LoadBalancer -Credential $Credential

		[string]$str_response = $response | Convert-XmlToPSObject
		Write-Verbose "str_response [$str_response]"

		$eqp = $str_response.IndexOf("{")
		$lbp = $str_response.IndexOf("}")
		$str_response = $str_response.substring($eqp + 1, $lbp - $eqp - 1)
		Write-Verbose "str_response [$str_response]"

		$ipStr   = get_stringbyname "aslipaddr" $str_response
		$portStr = get_stringbyname "aslport" $str_response
		$nameStr = get_stringbyname "aslname" $str_response

		$tempData = @{}
		$tempData.PSTypeName = "Asl"
		$tempData.AslIpAddress = $ipStr
		$tempData.AslName = $nameStr
		$tempData.AslPort = $portStr

		$AslData = New-Object -TypeName PSObject -Prop $tempData

		$tempApiRetObj = @{}
		$tempApiRetObj.PSTypeName = "KempAPI"
		$tempApiRetObj.ReturnCode = 200
		$tempApiRetObj.Response = "Command successfully executed"
		$tempApiRetObj.Data = $AslData

		$apiRetObject = New-Object -TypeName PSObject -Prop $tempApiRetObj
		$apiRetObject
	}
	catch {
		write-host "Caught an exception" -ForegroundColor Red
		write-host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
		write-host "Exception Message: $($_.Exception.Message)" -ForegroundColor Red
	}
}
Export-ModuleMember -function Request-LicenseOnPremise

Function Stop-AslInstance
{
	[CmdletBinding()]
	Param(
		[string]$LoadBalancer = $LoadBalancerAddress,
		[int]$LBPort = $LBAccessPort,
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)

	$ErrorActionPreference = "Stop"
	try{
		$response = Send-LBMessage -Command killaslinstance -LoadBalancer $LoadBalancer -Credential $Credential -LBPort $LBPort
		if ($response -eq "kill_asl_instance: success.")
		{
			$tempApiRetObj = @{}
			$tempApiRetObj.PSTypeName = "KempAPI"
			$tempApiRetObj.ReturnCode = 200
			$tempApiRetObj.Response = "Command successfully executed"
			$tempApiRetObj.Data = $null

			$apiRetObject = New-Object -TypeName PSObject -Prop $tempApiRetObj
			$apiRetObject
		}
		else {
			throw "ERROR: command failed."
		}
	}
	catch {
		write-host "Caught an exception" -ForegroundColor Red
		write-host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
		write-host "Exception Message: $($_.Exception.Message)" -ForegroundColor Red
	}
}
Export-ModuleMember -function Stop-AslInstance

# end ASL region

#endregion Originating script: 'c:\devhome\powershell\KempTechPowershellModule\Kemp.LoadBalancer.Powershell.ps1'
