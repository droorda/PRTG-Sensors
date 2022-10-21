@Copy /y "\\tsclient\D\Projects\PRTG-Sensors\Upload.bat" "E:\Tools\Upload.bat"

@echo off
Echo Uploading Custom Sensors

FOR /F "usebackq" %%v IN (`wmic datafile where name^='C:\\Program Files ^(x86^)\\PRTG Network Monitor\\PRTG Server.exe' get version`) DO call :setPRTGVersion %%v

if Not Exist "\\tsclient\D\Projects\PRTG-Sensors\devicetemplates.OEM\%PRTGVersion%" (
    Echo "New Version deviceTemplates %PRTGVersion%"
    RoboCopy "C:\Program Files (x86)\PRTG Network Monitor\devicetemplates"       "\\tsclient\D\Projects\PRTG-Sensors\devicetemplates.OEM\%PRTGVersion%"           /MIR /NJH /NJS /NFL /W:3
)

RoboCopy "\\tsclient\D\Projects\PRTG-Sensors\Custom Sensors\EXE"            "C:\Program Files (x86)\PRTG Network Monitor\Custom Sensors\EXE"    /MIR /NJH /NJS /NDL /W:3 /l
RoboCopy "\\tsclient\D\Projects\PRTG-Sensors\Custom Sensors\EXEXML"         "C:\Program Files (x86)\PRTG Network Monitor\Custom Sensors\EXEXML" /MIR /NJH /NJS /NDL /W:3 /l
RoboCopy "\\tsclient\D\Projects\PRTG-Sensors\lookups\custom"                "C:\Program Files (x86)\PRTG Network Monitor\lookups\custom"        /MIR /NJH /NJS /NDL /W:3 /l
RoboCopy "\\tsclient\D\Projects\PRTG-Sensors\devicetemplates"                "C:\Program Files (x86)\PRTG Network Monitor\devicetemplates"      /MIR /NJH /NJS /NDL /W:3 /l

pause

RoboCopy "\\tsclient\D\Projects\PRTG-Sensors\Custom Sensors\EXE"            "C:\Program Files (x86)\PRTG Network Monitor\Custom Sensors\EXE"    /MIR /NJH /NJS /NDL /W:3
RoboCopy "\\tsclient\D\Projects\PRTG-Sensors\Custom Sensors\EXEXML"         "C:\Program Files (x86)\PRTG Network Monitor\Custom Sensors\EXEXML" /MIR /NJH /NJS /NDL /W:3
RoboCopy "\\tsclient\D\Projects\PRTG-Sensors\lookups\custom"                "C:\Program Files (x86)\PRTG Network Monitor\lookups\custom"        /MIR /NJH /NJS /NDL /W:3
RoboCopy "\\tsclient\D\Projects\PRTG-Sensors\devicetemplates"                "C:\Program Files (x86)\PRTG Network Monitor\devicetemplates"      /MIR /NJH /NJS /NDL /W:3


GOTO:EOF

:setPRTGVersion %%v
    if "[]" NEQ "[%1]" set PRTGVersion=%1
GOTO:EOF
