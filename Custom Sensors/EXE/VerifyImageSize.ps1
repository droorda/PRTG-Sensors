[CmdletBinding()]
Param(
    [Parameter(
    Mandatory = $True,
    HelpMessage = "Server URL to inspect")]
    [string]$url
)

try {
    $Image = (New-Object System.Net.WebClient).DownloadString($url)
} catch {
    write-host "-1:$($_.Exception.Message) $url" 
    exit
}

write-host $Image.Length,":OK" 
