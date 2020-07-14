Set args = Wscript.Arguments
for x=0 to (args.count -1)
	Select Case lcase(args(x))
		Case "-d" 
			x=x+1 : strTarget=args(x)
		Case "-h" 
			x=x+1 : strHops=args(x)
		Case Else
			wscript.echo "0:Invalid switch " & args(x)
			WScript.Quit("1")
	End Select

next


Set objExec = CreateObject("WScript.Shell").Exec("ping -n 1 -w 1000 -i " & strHops & " " & strTarget)
strPingResults = LCase(objExec.StdOut.ReadAll)
strPingResults = mid (strPingResults,instr(strPingResults,vbCrLF)+2)
strPingResults = mid (strPingResults,instr(strPingResults,vbCrLF)+2)
if lcase(left(strPingResults,10))="reply from" then
	strPingResults = mid (strPingResults,12)
	strPingResults = left (strPingResults,instr(strPingResults,":")-1)
else 
	strPingResults = left(strPingResults,10) 
end if


WScript.echo mid(strPingResults,instrrev(strPingResults,".")+1) & ":Responding FW " & strPingResults
WScript.Quit("0")
