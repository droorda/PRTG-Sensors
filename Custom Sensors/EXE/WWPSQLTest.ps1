PARAM(
    $ConnectionString = "Data Source=127.0.0.1,910;User ID=UserName;Password=************;Connection Timeout=30;encrypt = false"
)

$conn = New-Object -TypeName System.Data.SqlClient.SqlConnection
$conn.ConnectionString = $ConnectionString
$exitCode = 0
try{
    $conn.Open()
} catch {
    $x=[string]"0"+":ERROR"
    $exitCode = 1
}
$command1 = $conn.CreateCommand()
$command1.CommandText = "SELECT @@SPID"
try{
    $sqlReader = $command1.ExecuteReader()
} catch {
    $x=[string]"0"+":ERROR"
    $exitCode = 2
}
while ($sqlReader.Read()) { $NewSPID = $sqlReader.item(0) }
$server.SPID = $NewSPID
$sqlReader.Close()
$conn.Close()


if ($NewSPID -lt 10) {
    $exitCode = 3
}
$x=[string]$NewSPID+":OK"
write-host $x

exit $exitCode
