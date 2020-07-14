
'Version 0.1.3

Dim strWebsite
Dim FontInstalled, InRotation, LoadBalancerOK, ServerOnline, ProviderError, StalledOrders
FontInstalled = vbFalse
InRotation = vbTrue
LoadBalancerOK = vbFalse
PRTGOK = vbFalse
StalledVisitorPackets = vbTrue
ProviderError = vbFalse
StalledOrders = vbTrue
'strWebsite = "www.sitename.com"
If WScript.Arguments.Count < 1 Then WScript.Quit
strWebsite = WScript.Arguments(0)

' 0 = OK

' 10 = Server Not in Rotation (warning)
' 11 = Stalled Packet (warning)
' 19 = Unknown Issue
' 20 = Server Failed (error)
' 21 = Font Not Installed (error)

If PingSite( strWebsite ) Then
	If FontInstalled Then
		If LoadBalancerOK Then
			If PRTGOK Then
				WScript.Echo "0:Server is online and functioning normally"
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
			If PRTGOK Then
				WScript.Echo "10:Server Not in Rotation"
				WScript.Quit 1
			Else
				If ProviderError then
					WScript.Echo "21:Server error connecting to SQL"
					WScript.Quit 2
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
					End If
				end if
			End If
		End If
	Else
		WScript.Echo "21:Font Not Installed"
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
        If InStr(objHTTP.ResponseText,"LoadBalancer-OK") Then LoadBalancerOK = vbTrue
        If InStr(objHTTP.ResponseText,"PRTG-OK") Then PRTGOK = vbTrue
        If InStr(objHTTP.ResponseText,"In Rotation? FAILURE!") Then InRotation = vbFalse
        If InStr(objHTTP.ResponseText,"Is Font Installed? (Abri Barcode39W) OK") Then FontInstalled = vbTrue
        If Not InStr(objHTTP.ResponseText,"-WEB50") Then FontInstalled = vbTrue
        If InStr(objHTTP.ResponseText,"Visit Packets. OK") Then StalledVisitorPackets = vbFalse
        If InStr(objHTTP.ResponseText,"The underlying provider failed on Open") Then ProviderError = vbTrue
        If InStr(objHTTP.ResponseText,"No stalled GradTrak Orders.") Then StalledOrders = vbFalse
        'strResponseText = objHTTP.ResponseText
        'WScript.Echo strResponseText
    Else
        PingSite = False
    End If

    Set objHTTP = Nothing
End Function