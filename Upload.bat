@echo off

Copy /y "\\tsclient\D\Projects\PRTG-Sensors\Upload.bat" "E:\Tools\Upload.bat"





Echo Backing Up Current installer
robocopy "C:\Program Files (x86)\PRTG Network Monitor\download" "\\tsclient\S\PRTG\download" *.exe /eta /NJH /NJS /XX /J

echo Backing Up config Dumps
robocopy "E:\ProgramData\Paessler\PRTG Network Monitor\Configuration Auto-Backups" "\\tsclient\S\PRTG\Configuration Auto-Backups" *.* /eta /MAXAGE:7 /NJH /NJS /XX /J


Echo Uploading Custom Sensors
FOR /F "usebackq" %%v IN (`wmic datafile where name^='C:\\Program Files ^(x86^)\\PRTG Network Monitor\\PRTG Server.exe' get version`) DO call :setPRTGVersion %%v

if Not Exist "\\tsclient\D\Projects\PRTG-Sensors\devicetemplates.OEM\%PRTGVersion%" (
    Echo "New Version deviceTemplates %PRTGVersion%"
    RoboCopy "C:\Program Files (x86)\PRTG Network Monitor\devicetemplates"       "\\tsclient\D\Projects\PRTG-Sensors\devicetemplates.OEM\%PRTGVersion%"           /MIR /NJH /NJS /NFL /W:3 /J
)

RoboCopy "\\tsclient\D\Projects\PRTG-Sensors\Custom Sensors\EXE"            "C:\Program Files (x86)\PRTG Network Monitor\Custom Sensors\EXE"    /MIR /NJH /NJS /NDL /W:3 /l
RoboCopy "\\tsclient\D\Projects\PRTG-Sensors\Custom Sensors\EXEXML"         "C:\Program Files (x86)\PRTG Network Monitor\Custom Sensors\EXEXML" /MIR /NJH /NJS /NDL /W:3 /l
RoboCopy "\\tsclient\D\Projects\PRTG-Sensors\lookups\custom"                "C:\Program Files (x86)\PRTG Network Monitor\lookups\custom"        /MIR /NJH /NJS /NDL /W:3 /l
RoboCopy "\\tsclient\D\Projects\PRTG-Sensors\devicetemplates"               "C:\Program Files (x86)\PRTG Network Monitor\devicetemplates"       /MIR /NJH /NJS /NDL /W:3 /l
RoboCopy "\\tsclient\D\Projects\Scripts\Servers\AMZ-PRTG"                   "E:\Batch"                                                        S*.ps1 /NJH /NJS /NDL /W:3 /l /XX
pause

RoboCopy "\\tsclient\D\Projects\PRTG-Sensors\Custom Sensors\EXE"            "C:\Program Files (x86)\PRTG Network Monitor\Custom Sensors\EXE"    /MIR /NJH /NJS /NDL /W:3 /J
RoboCopy "\\tsclient\D\Projects\PRTG-Sensors\Custom Sensors\EXEXML"         "C:\Program Files (x86)\PRTG Network Monitor\Custom Sensors\EXEXML" /MIR /NJH /NJS /NDL /W:3 /J
RoboCopy "\\tsclient\D\Projects\PRTG-Sensors\lookups\custom"                "C:\Program Files (x86)\PRTG Network Monitor\lookups\custom"        /MIR /NJH /NJS /NDL /W:3 /J
RoboCopy "\\tsclient\D\Projects\PRTG-Sensors\devicetemplates"               "C:\Program Files (x86)\PRTG Network Monitor\devicetemplates"       /MIR /NJH /NJS /NDL /W:3 /J
RoboCopy "\\tsclient\D\Projects\Scripts\Servers\AMZ-PRTG"                   "E:\Batch"                                                        S*.ps1 /NJH /NJS /NDL /W:3 /J /XX


GOTO:EOF

:setPRTGVersion %%v
    if "[]" NEQ "[%1]" set PRTGVersion=%1
GOTO:EOF

pause
