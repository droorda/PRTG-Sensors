Option Explicit
Dim restReq, url, userName, password, tzo, strTest, strTags, strCurrentTag, arrayTags, x, DesiredTag, aryTag, args, bolDebug
 
'********************************
' Script by Doug Roorda
' 
' Call from prtg with Paramaters 'UserName Password "Tag Name" //T:15'
' if using multiple tags I would suggest a mutex name. 
' 
'
'
'********************************


'Switch to native 64-bit environment if called from emulated 32-bit
Dim objFSO, WinDir
Set objFSO = CreateObject("Scripting.FileSystemObject")
WinDir = objFSO.GetSpecialFolder(0)
If (objFSO.FileExists(WinDir & "\SysNative\cscript.exe")) Then
	Dim getCommandOutput, i
	Dim objCmdExec
	ReDim args(WScript.Arguments.Count-1)
	For i = 0 To WScript.Arguments.Count-1
	  If InStr(WScript.Arguments(i), " ") > 0 Then
	    args(i) = Chr(34) & WScript.Arguments(i) & Chr(34)
	  Else
	    args(i) = WScript.Arguments(i)
	  End If
	Next
	Set objCmdExec = CreateObject("WScript.Shell").exec(WinDir & "\SysNative\cscript.exe //NoLogo """ & WScript.ScriptFullName & """ " & Join(args) )
	getCommandOutput = objCmdExec.StdOut.ReadAll
	WScript.Echo getCommandOutput
'	WScript.Echo("File exists!")
	Set objCmdExec = nothing
	Set objFSO = nothing
	WScript.Quit()
End If

Set objFSO = nothing


Set args = WScript.Arguments 
Set restReq = CreateObject("Microsoft.XMLHTTP")

 
If args.Count > 2 Then 
	userName = args(0)
	password = args(1)
	DesiredTag = args(2)
Else
	WriteXMLErrorArray 1 , "0:Invalid Parameters passed " & restReq.status & " UserName:" & userName & " Pass:" & password & " Tag:" & DesiredTag
	WScript.Quit
End If
bolDebug = False
If args.Count > 3 Then 
	If args(3) = "/debug" Then
		bolDebug = True
	End If
End if
		
		


'Allow for retry of temorary issues with Web service
For x=1 To 1000
	restReq.open "POST", "https://www.mytaglist.com/ethAccount.asmx/SignIn", false
	restReq.setRequestHeader "Content-Type", "application/json; charset=utf-8"
	restReq.send "{email:'" & userName & "', password:'" & password & "'}"
	If (restReq.status = 200 And restReq.responseText = "{""d"":null}") Then
		Exit For
	Else
		If x > 60 Then
			WriteXMLErrorArray 1 , "1:Invalid Status Returned " & restReq.status & " " & x & " Times Output:" & restReq.responseText
			Set restReq = nothing
			WScript.Quit
		Else
			WScript.Sleep 2000
		End if
	End If
Next

restReq.open "POST", "https://www.mytaglist.com/ethAccount.asmx/IsSignedInEx", false
restReq.setRequestHeader "Content-Type", "application/json; charset=utf-8"
restReq.send "{}"
If Not (restReq.status = 200 or InStr(restReq.responseText,"tzo")) Then
	WriteXMLErrorArray 2 , "2:Invalid Status Returned " & restReq.status & " Output:" & restReq.responseText
	Set restReq = nothing
	WScript.Quit
End If
'If InStr(restReq.responseText,"tzo") Then
'	tzo = restReq.responseText
'	tzo = mid(tzo,InStr(tzo,"tzo")+5)
'	tzo = mid(tzo,1,InStr(tzo,",")-1)
'Else
'	WScript.Echo "invalid data Returned"
'	WScript.Echo restReq.responseText
'	WScript.Quit
'End if

'restReq.open "POST", "https://www.mytaglist.com/ethClient.asmx/GetServerTime2", false
'restReq.setRequestHeader "Content-Type", "application/json; charset=utf-8"
'restReq.send "{tzo: " & tzo & "}"

'restReq.open "POST", "https://www.mytaglist.com/ethAccount.asmx/GetTagManagers", false
'restReq.setRequestHeader "Content-Type", "application/json; charset=utf-8"
'restReq.send "{}"

restReq.open "POST", "https://www.mytaglist.com/ethClient.asmx/GetTagList", false
restReq.setRequestHeader "Content-Type", "application/json; charset=utf-8"
restReq.send "{}"
If Not (restReq.status = 200 or InStr(restReq.responseText,"""d"":[")) Then
	WriteXMLErrorArray 3 , "3:Invalid Status Returned " & restReq.status 
	Set restReq = nothing
	WScript.Quit
End If

strTags = restReq.responseText
Set restReq = nothing

strTags = mid(strTags,InStr(strTags,"[")+1)
strTags = mid(strTags,1,InStr(strTags,"]")-1)
'If bolDebug Then 
'	WScript.Echo ""
'	WScript.Echo strTags
'	WScript.Echo ""
'End If

If InStr(strTags,"}") Then 
	strTags = Mid(strTags,1,InStrrev(strTags,"}")-1)
Else
	WriteXMLErrorArray 4 , "Error in array"
	WScript.Quit
End If

arrayTags = Split(strTags,"}")

For x=0 To UBound(arrayTags)
	arrayTags(x) = Mid(arrayTags(x),InStr(arrayTags(x),"{")+1)
	If bolDebug Then 
		WScript.Echo arrayTags(x)
	End If
Next


For Each x In arrayTags
	If InStr(LCase(x),LCase(DesiredTag)) Then
		aryTag = Split(x,",")
	End If
Next

If aryTag(0) = """__type"":""MyTagList.Tag""" Then
	For x=0 To UBound(aryTag)
		aryTag(x) = Mid(aryTag(x),InStr(aryTag(x),",")+1)
		If bolDebug Then 
			WScript.Echo aryTag(x)
		End If
	Next

	WriteXMLArray(aryTag)
Else
	WriteXMLErrorArray 5 , "Unknown Sensor Type: " & aryTag(0)
End if



Function WriteXMLArray(aryForPRTG)
	Dim xmlDoc, objRoot, objRecord, objChannel, objValue, objIntro
	Dim strName, strValue, strUnit, strCustomUnit
	Dim aryTemp, strTemp
	Dim bolFloat, bolWarning, bolShowChart, bolShowTable, bolReportSensor
	Dim IntLimitMaxError, intLimitMaxWarning, intLimitMinWarning, intLimitMinError, LocalTimeZone, TimeZoneOffset, intpostBackInterval, inttempEventState

	
	Set xmlDoc = CreateObject("Microsoft.XMLDOM")  
	
	Set objRoot = xmlDoc.createElement("prtg")  
	xmlDoc.appendChild objRoot  
	For x=1 To UBound(aryForPRTG)
		bolReportSensor = False
		aryTemp = Split(aryForPRTG(x),":")
		If UBound(aryTemp)>0 Then
			strName = Replace(aryTemp(0),"""","")
			strValue = aryTemp(1)
			If strName = "postBackInterval" Then
				intpostBackInterval = strValue
			End If
			If strName = "tempEventState" Then
				inttempEventState = strValue
			End If
		End If
		
	Next
	For x=1 To UBound(aryForPRTG)
		bolReportSensor = False
		aryTemp = Split(aryForPRTG(x),":")
		If UBound(aryTemp)>0 Then
'		If bolDebug Then 
'			WScript.Echo "Name: Array Size           Value: " & UBound(aryTemp)
'			WScript.Echo "Name: Array data           Value: " & aryForPRTG(x)
'		End If
			strName = Replace(aryTemp(0),"""","")
			strValue = aryTemp(1)
			strUnit = Null
			bolFloat = Null ' 1 = yes
			bolWarning = Null ' 1=yes
			bolShowChart = Null ' 0=no
			bolShowTable = Null ' 0=no
			IntLimitMaxError = Null
			intLimitMaxWarning = Null
			intLimitMinWarning = Null
			intLimitMinError = Null
			strCustomUnit = Null
			
			
			If strName = "batteryRemaining" Then
				bolReportSensor = TRUE
				strValue = Round(strValue * 100)
				intLimitMinWarning = 30
				intLimitMinError = 10
			End If
			If strName = "lastComm" Then
				bolReportSensor = TRUE
				bolShowChart = 0
				bolShowTable = 0
				For Each LocalTimeZone in GetObject("winmgmts:").InstancesOf("Win32_ComputerSystem")
					TimeZoneOffset = LocalTimeZone.CurrentTimeZone
				Next
	
'				If bolDebug Then 
'					WScript.Echo "Name: TimeZoneOffset           Value: " & TimeZoneOffset/60 & " hrs"
'				End If
				
				strValue = Round(DateDiff ("s","1-Jan-1970 00:00:00",Now()) - ((((strValue/10000)-11644473600000)/1000)+ (TimeZoneOffset*60)))'14400 4hr time offset for daylight savings
				strUnit = "Seconds"
				IntLimitMaxError = intpostBackInterval * 2.1
				intLimitMaxWarning = intpostBackInterval + 60
			End If
			If strName = "glitchDetected" Then
				bolReportSensor = True
				If strValue = "false" Then strValue = false
				If strValue = "true" Then strValue = True
			End If
			If strName = "name" Then
'				bolReportSensor = True
				strCustomUnit = strValue
				strValue=0
			End If
			If strName = "comment" Then
'				bolReportSensor = True
				strCustomUnit = strValue
				strValue=0
			End If
			If strName = "tagType" Then
				bolReportSensor = True
				strCustomUnit = strValue
				strValue=0
			End If
			If strName = "alive" Then
				bolReportSensor = True
				If strValue = "false" Then 
					strValue = False
					bolWarning = 1
				End If
				If strValue = "true" Then strValue = True
			End If
			If strName = "notificationJS" Then
				'bolReportSensor = True
				If Not InStr(aryForPRTG(x+1),":") Then
					strValue = strValue & aryForPRTG(x+1)
					x=x+1
				End if
			End If
			If strName = "signaldBm" Then
				bolReportSensor = True
			End If
			If strName = "beeping" Then
				bolReportSensor = True
				If strValue = "false" Then strValue = false
				If strValue = "true" Then strValue = True
			End If
			If strName = "lit" Then
				bolReportSensor = True
				If strValue = "false" Then strValue = false
				If strValue = "true" Then strValue = True
			End If
			If strName = "tempEventState" Then
'				bolReportSensor = True
			End If
			If strName = "OutOfRange" Then
				bolReportSensor = False
				If strValue = "false" Then strValue = false
				If strValue = "true" Then 
					strValue = True
					WriteXMLErrorArray 5 , "Sensor Out of Range: " 
					WScript.Quit
				End If
				intLimitMinError = 0
			End If
			If strName = "solarVolt" Then
'				bolReportSensor = True
			End If
			If strName = "temperature" Then
				bolReportSensor = True
				strValue = Round(((strValue/5)*9)+32,1)
				bolFloat = 1
				strUnit = "Temperature"
'				If inttempEventState>1 Then bolWarning = 1
			End If
			If strName = "cap" Then
				bolReportSensor = True
				strName = "Humidity"
				strValue = Round(strValue)
				strUnit = "Percent"
			End If
			
			If bolDebug Then 
				WScript.Echo "Name: " & strName & String(20-Len(strName)," ") & "   Value: " & strValue
			End if
	
			
			If bolReportSensor Then
				'WScript.Echo strName & " = " & strValue
				Set objRecord = xmlDoc.createElement("result") 
				objRoot.appendChild objRecord 
					Set objChannel = xmlDoc.createElement("channel")  
						objChannel.Text = strName
						objRecord.appendChild objChannel 
					Set objValue = xmlDoc.createElement("value")  
						objValue.Text = strValue
						objRecord.appendChild objValue 
					If Not IsNull(strUnit) Then
						Set objValue = xmlDoc.createElement("Unit")  
							objValue.Text = strUnit
							objRecord.appendChild objValue 
					End If
					If Not IsNull(strCustomUnit) Then
						Set objValue = xmlDoc.createElement("CustomUnit")  
							objValue.Text = strCustomUnit
							objRecord.appendChild objValue 
					End If
					If Not IsNull(bolFloat) Then
						Set objValue = xmlDoc.createElement("Float")  
							objValue.Text = bolFloat
							objRecord.appendChild objValue 
					End If
					If Not IsNull(bolWarning) Then
						Set objValue = xmlDoc.createElement("Warning")  
							objValue.Text = bolWarning
							objRecord.appendChild objValue 
					End If
					If Not IsNull(bolShowChart) Then
						Set objValue = xmlDoc.createElement("Chart")  
							objValue.Text = bolShowChart
							objRecord.appendChild objValue 
					End If
					If Not IsNull(bolShowTable) Then
						Set objValue = xmlDoc.createElement("value")  
							objValue.Text = bolShowTable
							objRecord.appendChild objValue 
					End If
					If Not IsNull(intLimitMaxError) Then
						Set objValue = xmlDoc.createElement("LimitMaxError")  
							objValue.Text = IntLimitMaxError
							objRecord.appendChild objValue 
					End If
					If Not IsNull(intLimitMaxWarning) Then
						Set objValue = xmlDoc.createElement("LimitMaxWarning")  
							objValue.Text = IntLimitMaxWarning
							objRecord.appendChild objValue 
					End If
					If Not IsNull(intLimitMinWarning) Then
						Set objValue = xmlDoc.createElement("LimitMinWarning")  
							objValue.Text = IntLimitMinWarning
							objRecord.appendChild objValue 
					End If
					If Not IsNull(intLimitMinError) Then
						Set objValue = xmlDoc.createElement("LimitMinError")  
							objValue.Text = IntLimitMinError
							objRecord.appendChild objValue 
					End If
			End If
		Else
			WScript.Echo aryTemp
		End If
	Next

	
	Set objIntro = xmlDoc.createProcessingInstruction ("xml","version='1.0'")  
	xmlDoc.insertBefore objIntro,xmlDoc.childNodes(0)  
	'xmlDoc.Save "Audits.xml"  
	WScript.Echo xmlDoc.xml
	
	Set objIntro = nothing
	Set xmlDoc = nothing
	Set objRoot = nothing

End Function

Function WriteXMLErrorArray(intError, strError)
	Dim xmlDoc, objRoot, objRecord, objChannel, objValue, objIntro
	
	Set xmlDoc = CreateObject("Microsoft.XMLDOM")  
	  
	Set objRoot = xmlDoc.createElement("prtg")  
	xmlDoc.appendChild objRoot  
	
	Set objChannel = xmlDoc.createElement("error")  
		objChannel.Text = intError
		objRoot.appendChild objChannel 
	Set objValue = xmlDoc.createElement("text")  
		objValue.Text = strError
		objRoot.appendChild objValue 
	
	Set objIntro = xmlDoc.createProcessingInstruction ("xml","version='1.0'")  
	xmlDoc.insertBefore objIntro,xmlDoc.childNodes(0)  
	'xmlDoc.Save "Audits.xml"
	WScript.Echo xmlDoc.xml
	Set objValue = nothing
	Set objChannel = nothing
	Set objIntro = nothing
	Set xmlDoc = nothing
	Set objRoot = nothing
End Function

'<prtg>
'	<error>1</error>
'	<text>Your error message</text>
'</prtg>

'strTest = restReq.responseText

'<prtg>
'	<result>
'		<channel>First channel</channel>
'		<value>10</value>
'	</result>
'	<result>
'		<channel>Second channel</channel>
'		<value>20</value>
'	</result>
'</prtg>