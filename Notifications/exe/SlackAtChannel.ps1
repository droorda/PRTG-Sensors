[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='Low')]
param
(
    [string]$SlackURI,
    [string]$colorofstate,
    [string]$cumsince,
    [string]$datetime,
    [string]$device,
    [string]$down,
    [string]$downtime,
    [string]$group,
    [string]$homeURI,
    [string]$lastcheck,
    [string]$lastdown,
    [string]$lastup,
    [string]$lastvalue,
    [string]$message,
    [string]$name,
    [string]$probe,
    [string]$sensorid,
    [string]$status,
    [string]$uptime

)
#PRTG Param
#-SlackURI = 'https://hooks.slack.com/services/xxx/xxx/xxx' -colorofstate '%colorofstate' -cumsince '%cumsince' -datetime '%datetime' -device '%device' -down '%down' -downtime '%downtime' -group '%group' -homeURI '%home' -lastcheck '%lastcheck' -lastdown '%lastdown' -lastup '%lastup' -lastvalue '%lastvalue' -message '%message' -name '%name' -probe '%probe' -sensorid '%sensorid' -status '%status' -uptime '%uptime'


$JSON = @"
{
    "text": "$device $status $down ($message)... <!channel>",
    "link_names": 1,
    "attachments": [
        {
            "title": "Sensor: $device $name",
            "title_link": "${homeURI}sensor.htm?id=$sensorid",
            "text": "*Status:* $status $down \n*Date/Time:* $datetime (UTC) \n*Last Result:* $lastvalue \n*Last Message:* $message \n*Probe:* $probe \n*Group:* $group \n*Device:* $device () \n*Last Scan:* $lastcheck \n*Last Up:* $lastup \n*Last Down:* $lastdown \n*Uptime:* $uptime \n*Downtime:* $downtime \n*Cumulated since:* $cumsince",
            "color": "$colorofstate",
            "mrkdwn_in": ["text", "pretext"]
        }
    ]
}
"@

$return = Invoke-WebRequest -UseBasicParsing $SlackURI -ContentType "application/json" -Method POST -Body $JSON

if ($return.StatusCode -eq 200) {
    exit 0;
} else {
    exit $return.StatusCode;
}
