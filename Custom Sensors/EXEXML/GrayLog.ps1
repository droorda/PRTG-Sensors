[CmdletBinding()]
Param(
	[Parameter(Position=1)]
	[string]$prtg_host				= "$env:prtg_host"
    ,
	# [string]$prtg_windowsdomain		= "$env:prtg_windowsdomain"
    # ,
	[string]$prtg_windowsuser		= "$env:prtg_windowsuser"
    ,
	[string]$prtg_windowspassword	= "$env:prtg_windowspassword"
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

if (!($prtg_host)) {
    Set-PrtgError "Host Name Not specified"
}

if ($prtg_windowspassword) {
    [SecureString]$prtg_windowspassword = $prtg_windowspassword | ConvertTo-SecureString -AsPlainText -Force
    $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $prtg_windowsuser , $prtg_windowspassword
} else {
    Set-PrtgError "prtg_windowspassword Not specified"
}


[String]$BaseURI = "https://${prtg_host}:9000/api/system/metrics"

$Stats = @(
    'org.apache.logging.log4j.core.Appender.trace'
    'org.apache.logging.log4j.core.Appender.debug'
    'org.apache.logging.log4j.core.Appender.info'
    'org.apache.logging.log4j.core.Appender.warn'
    'org.apache.logging.log4j.core.Appender.error'
    'org.apache.logging.log4j.core.Appender.fatal'
    'org.graylog2.filters.StreamMatcherFilter.executionTime'
    'org.graylog2.shared.buffers.processors.ProcessBufferProcessor.processTime'
    'org.graylog2.buffers.input.size'
    'org.graylog2.buffers.input.usage'
    'org.graylog2.buffers.output.size'
    'org.graylog2.buffers.output.usage'
    'org.graylog2.buffers.process.size'
    'org.graylog2.buffers.process.usage'
    'org.graylog2.journal.append.1-sec-rate'
    'org.graylog2.journal.entries-uncommitted'
    'org.graylog2.journal.oldest-segment'
    'org.graylog2.journal.read.1-sec-rate'
    'org.graylog2.journal.segments'
    # 'org.graylog2.journal.size'
    # 'org.graylog2.journal.size-limit'
    'org.graylog2.journal.utilization-ratio'
)

$StatsHash = @{}
Foreach ($Stat in $Stats) {
    $StatsHash[$Stat] = Invoke-RestMethod -Uri "$BaseURI/$Stat" -UseBasicParsing -Credential $Credential
}

$Node_id = (Invoke-RestMethod -Uri "https://${prtg_host}:9000/api/system" -UseBasicParsing -Credential $Credential).node_id

$Node_jvm = Invoke-RestMethod -Uri "https://${prtg_host}:9000/api/cluster/$Node_id/jvm" -UseBasicParsing -Credential $Credential



$GrayLogInputs = @()
$InputList = Invoke-RestMethod -Uri "https://${prtg_host}:9000/api/system/inputs" -UseBasicParsing -Credential $Credential

Foreach ($Input in $InputList.inputs) {
    $GrayLogInput = [ordered]@{
        Name = $Input.title
    }
    Try {
        $GrayLogInput.processedMessages = (Invoke-RestMethod -Uri "$BaseURI/org.graylog2.inputs.codecs.RawCodec.$($Input.id).processedMessages" -UseBasicParsing -Credential $Credential).m5_rate
    } Catch {
        $GrayLogInput.processedMessages = -1
    }
    $GrayLogInput.read_bytes_1sec = (Invoke-RestMethod -Uri "$BaseURI/$($Input.type).$($Input.id).read_bytes_1sec" -UseBasicParsing -Credential $Credential).Value
    $GrayLogInputs += [PSCUSTOMOBJECT]$GrayLogInput
}

$Return = @{}
$Return.'Apache Trace'              = $StatsHash['org.apache.logging.log4j.core.Appender.trace'].m5_rate
$Return.'Apache Debug'              = $StatsHash['org.apache.logging.log4j.core.Appender.debug'].m5_rate
$Return.'Apache Info'               = $StatsHash['org.apache.logging.log4j.core.Appender.info'].m5_rate
$Return.'Apache Warn'               = $StatsHash['org.apache.logging.log4j.core.Appender.warn'].m5_rate
$Return.'Apache Error'              = $StatsHash['org.apache.logging.log4j.core.Appender.error'].m5_rate
$Return.'Apache Fatal'              = $StatsHash['org.apache.logging.log4j.core.Appender.fatal'].m5_rate
$Return.'Buffer Input'              = [long](($StatsHash['org.graylog2.buffers.input.usage'].Value/$StatsHash['org.graylog2.buffers.input.size'].Value)*100)
$Return.'Buffer Output'             = [long](($StatsHash['org.graylog2.buffers.output.usage'].Value/$StatsHash['org.graylog2.buffers.output.size'].Value)*100)
$Return.'Buffer Process'            = [long](($StatsHash['org.graylog2.buffers.process.usage'].Value/$StatsHash['org.graylog2.buffers.process.size'].Value)*100)
$Return.'Journal Append'            = $StatsHash['org.graylog2.journal.append.1-sec-rate'].Value
$Return.'Journal Uncommited'        = $StatsHash['org.graylog2.journal.entries-uncommitted'].Value
$Return.'Journal Read'              = $StatsHash['org.graylog2.journal.read.1-sec-rate'].Value
$Return.'Journal Segments'          = $StatsHash['org.graylog2.journal.segments'].Value
# $Return.'Journal Size'              = $StatsHash['org.graylog2.journal.size'].Value
# $Return.'Journal Size-Limit'        = $StatsHash['org.graylog2.journal.size-limit'].Value
$Return.'Journal Utilization-Ratio' = $StatsHash['org.graylog2.journal.utilization-ratio'].Value
$Return.'Journal Oldest-Segment'    = ((get-date) - [datetime]$StatsHash['org.graylog2.journal.oldest-segment'].Value).TotalSeconds
$Return.'Buffer processTime'        = $StatsHash['org.graylog2.shared.buffers.processors.ProcessBufferProcessor.processTime'].m5_rate
$Return.'Filter executionTime'      = $StatsHash['org.graylog2.filters.StreamMatcherFilter.executionTime'].m5_rate
$Return.'jvm heap'                  = [int](($Node_jvm.used_memory.bytes/$Node_jvm.max_memory.bytes)*100)

# https://graylog01.prod.local.eventphotographygroup.com:9000/api/system/indexer/overview

if ($VerbosePreference -eq 'Continue') {
    $GrayLogInputs          | Format-Table | out-String | Write-Verbose
    [PSCustomObject]$Return | Format-List  | out-String | Write-Verbose
} else {
    if ($Return){
        $XMLOutput = "<prtg>`n"
        $XMLOutput += Set-PrtgResult -Channel 'Journal Append'            -Value $Return.'Journal Append'            -Unit Count   -sc
        $XMLOutput += Set-PrtgResult -Channel 'Journal Uncommited'        -Value $Return.'Journal Uncommited'        -Unit Count   -sc -maxe 5000
        $XMLOutput += Set-PrtgResult -Channel 'Journal Read'              -Value $Return.'Journal Read'              -Unit Count   -sc
        $XMLOutput += Set-PrtgResult -Channel 'Journal Segments'          -Value $Return.'Journal Segments'          -Unit Count   -sc -maxe 10
        $XMLOutput += Set-PrtgResult -Channel 'Apache Trace'              -Value $Return.'Apache Trace'              -Unit Count   -sc
        $XMLOutput += Set-PrtgResult -Channel 'Apache Debug'              -Value $Return.'Apache Debug'              -Unit Count   -sc
        $XMLOutput += Set-PrtgResult -Channel 'Apache Info'               -Value $Return.'Apache Info'               -Unit Count   -sc
        $XMLOutput += Set-PrtgResult -Channel 'Apache Warn'               -Value $Return.'Apache Warn'               -Unit Count   -sc -maxe 2
        $XMLOutput += Set-PrtgResult -Channel 'Apache Error'              -Value $Return.'Apache Error'              -Unit Count   -sc -maxe 1
        $XMLOutput += Set-PrtgResult -Channel 'Apache Fatal'              -Value $Return.'Apache Fatal'              -Unit Count   -sc -maxe 1
        $XMLOutput += Set-PrtgResult -Channel 'Buffer Input'              -Value $Return.'Buffer Input'              -Unit Percent -sc -maxe 50
        $XMLOutput += Set-PrtgResult -Channel 'Buffer Output'             -Value $Return.'Buffer Output'             -Unit Percent -sc -maxe 50
        $XMLOutput += Set-PrtgResult -Channel 'Buffer Process'            -Value $Return.'Buffer Process'            -Unit Percent -sc -maxe 50
        # $XMLOutput += Set-PrtgResult -Channel 'Journal Size'              -Value $Return.'Journal Size'              -Unit Count
        # $XMLOutput += Set-PrtgResult -Channel 'Journal Size-Limit'        -Value $Return.'Journal Size-Limit'        -Unit Count
        $XMLOutput += Set-PrtgResult -Channel 'Journal Utilization-Ratio' -Value $Return.'Journal Utilization-Ratio' -Unit Count   -sc -maxe 20
        $XMLOutput += Set-PrtgResult -Channel 'Journal Oldest-Segment'    -Value $Return.'Journal Oldest-Segment'    -Unit Count   -sc -maxe 120
        $XMLOutput += Set-PrtgResult -Channel 'Buffer processTime'        -Value $Return.'Buffer processTime'        -Unit Count   -sc
        $XMLOutput += Set-PrtgResult -Channel 'Filter executionTime'      -Value $Return.'Filter executionTime'      -Unit Count   -sc
        $XMLOutput += Set-PrtgResult -Channel 'Jvm Heap'                  -Value $Return.'jvm heap'                  -Unit Percent -sc -maxe 70

        Foreach ($GrayLogInput in $GrayLogInputs) {
            $XMLOutput += Set-PrtgResult -Channel "$($GrayLogInput.Name) Messages"   -Value $GrayLogInput.'processedMessages'   -Unit Count   -sc -Mine 0
            $XMLOutput += Set-PrtgResult -Channel "$($GrayLogInput.Name) Bytes"      -Value $GrayLogInput.'read_bytes_1sec'     -Unit Count   -sc -Mine 0
        }
        # $XMLOutput += Set-PrtgResult -Channel
        $XMLOutput += "</prtg>"
        Write-Host $XMLOutput
    } else {
        Set-PrtgError "No Stats returned"
    }
}
