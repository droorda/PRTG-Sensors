
'Version 0.1.4

Dim strWebsite, strWebServer
Dim FontInstalled, InRotation, LoadBalancerOK, ServerOnline, ProviderError, StalledOrders, strBuildNumber
InRotation = vbTrue
LoadBalancerOK = vbFalse
PRTGOK = vbFalse
StalledVisitorPackets = vbTrue
ProviderError = vbFalse
StalledOrders = vbTrue
CorrectHostOK = vbFalse
'strWebsite = "www.sitename.com"
If WScript.Arguments.Count < 1 Then WScript.Quit
strWebsite = WScript.Arguments(0)
If InStr(strWebsite,"/") Then
	strWebServer = Left(strWebsite,InStr(strWebsite,"/")-1)
Else
	strWebServer = strWebsite
End If

' 0 = OK

' 10 = Server Not in Rotation (warning)
' 11 = Stalled Packet (warning)
' 19 = Unknown Issue
' 20 = Server Failed (error)
' 21 = Font Not Installed (error)

If PingSite( strWebsite ) Then
	If CorrectHostOK Then
		If LoadBalancerOK Then
			If PRTGOK Then
				WScript.Echo "0:Server is online and functioning normally " & strBuildNumber
				WScript.Quit 0
			Else
				If StalledVisitorPackets Then
					WScript.Echo "11:Server Has Stalled Visitor Packets"
					WScript.Quit 1
				else
					If StalledOrders Then
						WScript.Echo "12:Server Has stalled Orders"
						WScript.Quit 1
					Else
						WScript.Echo "19:Server Has Unknown Issue"
						WScript.Quit 1
					End If
				end if
			End If
		Else
			If ProviderError then
				WScript.Echo "22:Server error connecting to SQL"
				WScript.Quit 2
			Else
				WScript.Echo "10:Server Not in Rotation"
				WScript.Quit 1
			End If
		End If
	Else
		WScript.Echo "21:Web site " & strWebsite & " Did not indicate the correct host name"
		WScript.Quit 2
	End If
Else
    WScript.Echo "20:Web site " & strWebsite & " is down!!!"
    WScript.Quit 2
End If


Function PingSite( myWebsite )
' This function checks if a website is running by sending an HTTP request.
' If the website is up, the function returns True, otherwise it returns False.
' Argument: myWebsite [string] in "www.domain.tld" format, without the
' "http://" prefix.
'
' Written by Rob van der Woude
' http://www.robvanderwoude.com
    Dim intStatus, objHTTP

    Set objHTTP = CreateObject( "WinHttp.WinHttpRequest.5.1" )

    objHTTP.Open "GET", "http://" & myWebsite & "/", False
    objHTTP.SetRequestHeader "User-Agent", "Mozilla/4.0 (compatible; MyApp 1.0; Windows NT 5.1)"

    On Error Resume Next

    objHTTP.Send
    intStatus = objHTTP.Status

    On Error Goto 0

    If intStatus = 200 Then
        PingSite = True
        If InStr(LCase(objHTTP.ResponseText),LCase("Host: " & strWebServer))                  Then CorrectHostOK = vbTrue
        If InStr(LCase(objHTTP.ResponseText),LCase("LoadBalancer-OK"))                        Then LoadBalancerOK = vbTrue
        If InStr(LCase(objHTTP.ResponseText),LCase("PRTG-OK"))                                Then PRTGOK = vbTrue
        If InStr(LCase(objHTTP.ResponseText),LCase("In Rotation? FAILURE!"))                  Then InRotation = vbFalse
        If InStr(LCase(objHTTP.ResponseText),LCase("Visit Packets. OK"))                      Then StalledVisitorPackets = vbFalse
        If InStr(LCase(objHTTP.ResponseText),LCase("The underlying provider failed on Open")) Then ProviderError = vbTrue
        If InStr(LCase(objHTTP.ResponseText),LCase("No stalled Orders."))                     Then StalledOrders = vbFalse
        strResponseText = objHTTP.ResponseText
        For Each strResponseLine In Split(strResponseText,vbNewLine)
			If InStr(LCase(strResponseLine),"build:")            Then strBuildNumber = strResponseLine
        Next
    Else
        PingSite = False
    End If

    Set objHTTP = Nothing
End Function