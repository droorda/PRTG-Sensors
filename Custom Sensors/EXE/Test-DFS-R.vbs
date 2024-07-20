Set ArgObj = wscript.Arguments
strDFSPath1 = ArgObj(0)
strDFSPath2 = ArgObj(1)

i = 0
' Modify the value for intSecondsToWait for the timeout value of this script
intSecondsToWait = 60

' Build strings for testing the DFS paths
strTime = Cstr(Timer) 'Convert number of seconds since midnight to string
strPath1 = strDFSPath1 & "\TestDFS-R-" & strTime & ".txt"
strPath2 = strDFSPath2 & "\TestDFS-R-" & strTime & ".txt"
Set objFSO = CreateObject("Scripting.FileSystemObject")

' Check if both paths exist
If objFSO.FolderExists(strDFSPath1) Then
    ' MsgBox "The path exists!"
Else
    WScript.Echo "0:Unable to Access " & strDFSPath1
    WScript.Quit(2)
End If
If objFSO.FolderExists(strDFSPath2) Then
    ' MsgBox "The path exists!"
Else
    WScript.Echo "0:Unable to Access " & strDFSPath2
    WScript.Quit(2)
End If
Set objTextFile = objFSO.CreateTextFile(strPath1, True)

' Write a date and time stamp to the test file.
strText = Date & Time
objTextFile.Write ("0:This file is safe to delete.  Timestamp: " & strText)
objTextFile.Close

' Check if file exists in the second path every second for 60 seconds, then clean up.
For i = 1 To intSecondsToWait
    If objFSO.FileExists(strPath2) Then
        WScript.Echo i & ":OK"
        objFSO.DeleteFile(strPath1)
            WScript.Quit(0)
    End If
    WScript.Sleep 1000
Next

' WScript.Echo "Replication failed.  The test file does not exist in both paths."
objFSO.DeleteFile(strPath1)
WScript.Echo "0:Replication time exceeded " & intSecondsToWait & " seconds"
WScript.Quit(2)