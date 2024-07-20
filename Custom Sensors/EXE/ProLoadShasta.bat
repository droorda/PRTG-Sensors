@echo off
cls
call :GetDate
set LogPath=\\tlh-file04\C$\GTS\Agent\Logs\ProLoadShastaFullExportTask\
FOR /f "tokens=*" %%i IN ('dir "%LogPath%ProLoadShastaFullExportTask*%Today%*.txt" /o:-d /b') DO (set LAST=%%i& goto :stop1)
:stop1
if "%LAST%"=="" (
	FOR /f "tokens=*" %%i IN ('dir "%LogPath%ProLoadShastaFullExportTask*%Yesterday%*.txt" /o:-d /b') DO (set LAST=%%i& goto :stop2)
)
:stop2
if "%LAST%"=="" (echo 0:Error Finding Log File & exit 2)
FOR /f "tokens=7" %%i IN ('findstr /I "frames/minute" "%LogPath%%last%" ^| find "%Today% %time:~0,4%"') DO set FramesPerMin=%%i
if "%FramesPerMin%"=="" (echo 0:Error Finding Frames per min in "%LogPath%%last%" & exit 1)
SET /A FramesPerMin *= 10
SET /A FramesPerMin /= 10
echo %FramesPerMin%:OK
::exit /b %FramesPerMin%
goto :EOF

:GetDate

@ECHO OFF
:: Windows NT 4 or later only
IF NOT "%OS%"=="Windows_NT" GOTO Syntax
:: No command line arguments required
::IF NOT [%1]==[] GOTO Syntax

:: Keep variables local
SETLOCAL ENABLEDELAYEDEXPANSION

:: Query the registry for the date format and delimiter
CALL :DateFormat

:: Parse today's date depending on registry's local date format settings
IF %iDate%==0 FOR /F "TOKENS=1-4* DELIMS=%sDate%" %%A IN ('DATE/T') DO (
	SET LocalFormat=MM%sDate%DD%sDate%YYYY
	SET tLocal=%%tMonth%%%sDate%%%tDay%%%sDate%%%tYear%%
	SET yLocal=%%yMonth%%%sDate%%%yDay%%%sDate%%%yYear%%
	SET Year=%%C
	SET Month=%%A
	SET Day=%%B
)
IF %iDate%==1 FOR /F "TOKENS=1-4* DELIMS=%sDate%" %%A IN ('DATE/T') DO (
	SET LocalFormat=DD%sDate%MM%sDate%YYYY
	SET tLocal=%%tDay%%%sDate%%%tMonth%%%sDate%%%tYear%%
	SET yLocal=%%yDay%%%sDate%%%yMonth%%%sDate%%%yYear%%
	SET Year=%%C
	SET Month=%%B
	SET Day=%%A
)
IF %iDate%==2 FOR /F "TOKENS=1-4* DELIMS=%sDate%" %%A IN ('DATE/T') DO (
	SET LocalFormat=YYYY%sDate%MM%sDate%DD
	SET tLocal=%%tYear%%%sDate%%%tMonth%%%sDate%%%tDay%%
	SET yLocal=%%yYear%%%sDate%%%yMonth%%%sDate%%%yDay%%
	SET Year=%%A
	SET Month=%%B
	SET Day=%%C
)

:: Remove the day of week if applicable
FOR %%A IN (%Year%)  DO SET Year=%%A
FOR %%A IN (%Month%) DO SET Month=%%A
FOR %%A IN (%Day%)   DO SET Day=%%A

:: Today's date in YYYYMMDD format
SET SortDate=%Year%-%Month%-%Day%

:: Today's date in local format
FOR %%A IN (%Date%) DO SET Today=%%A

:: Remove leading zeroes
IF   "%Day:~0,1%"=="0" SET   Day=%Day:~1%
IF "%Month:~0,1%"=="0" SET Month=%Month:~1%

:: Calculate yesterday's date
CALL :JDate %Year% %Month% %Day%
SET /A JDate -= 1
CALL :GDate %JDate%
FOR /F "tokens=1-3" %%A IN ('ECHO %GDate%') DO (
	SET yYear=%%A
	SET yMonth=%%B
	SET yDay=%%C
)
:: Calculate tomorrow's date
SET /A JDate += 2
CALL :GDate %JDate%
FOR /F "tokens=1-3" %%A IN ('ECHO %GDate%') DO (
	SET tYear=%%A
	SET tMonth=%%B
	SET tDay=%%C
)

:: Add leading zero to tDay, yDay, tMonth and/or yMonth if necessary
IF 1%tDay%   LSS 20 SET tDay=0%tDay%
IF 1%yDay%   LSS 20 SET yDay=0%yDay%
IF 1%tMonth% LSS 20 SET tMonth=0%tMonth%
IF 1%yMonth% LSS 20 SET yMonth=0%yMonth%

:: Yesterday's and tomorrow's date in YYYYMMDD format
SET SortTom=%tYear%-%tMonth%-%tDay%
SET SortYest=%yYear%-%yMonth%-%yDay%

:: Display the results
::ECHO Format:     YYYYMMDD  (%LocalFormat%)
::ECHO.==================================
::CALL ECHO Yesterday:  %SortYest%  (%yLocal%)
::ECHO Today:      %SortDate%  (%Today%)
::CALL ECHO Tomorrow:   %SortTom%  (%tLocal%)

:: Done
ENDLOCAL&SET Yesterday=%SortYest%&SET Today=%SortDate%&SET Tomorrow=%SortTom%
GOTO:EOF

:: * * * * * * * *  Subroutines  * * * * * * * *


:DateFormat
REG.EXE /? 2>&1 | FIND "REG QUERY" >NUL
IF ERRORLEVEL 1 (
	CALL :DateFormatRegEdit
) ELSE (
	CALL :DateFormatReg
)
GOTO:EOF


:DateFormatReg
FOR /F "tokens=1-3" %%A IN ('REG Query "HKCU\Control Panel\International" ^| FINDSTR /R /C:"[is]Date"') DO (
	IF "%%~A"=="REG_SZ" (
		SET %%~B=%%~C
	) ELSE (
		SET %%~A=%%~C
	)
)
GOTO:EOF


:DateFormatRegEdit
:: Export registry's date format settings to a temporary file, in case REG.EXE is not available
START /W REGEDIT /E %TEMP%.\_TEMP.REG "HKEY_CURRENT_USER\Control Panel\International"
:: Read the exported data
FOR /F "tokens=1* delims==" %%A IN ('TYPE %TEMP%.\_TEMP.REG ^| FIND /I "iDate"') DO SET iDate=%%B
FOR /F "tokens=1* delims==" %%A IN ('TYPE %TEMP%.\_TEMP.REG ^| FIND /I "sDate"') DO SET sDate=%%B
DEL %TEMP%.\_TEMP.REG
:: Remove quotes from exported values
SET iDate=%iDate:"=%
SET sDate=%sDate:"=%
GOTO:EOF


:GDate
:: Convert Julian date back to "normal" Gregorian date
:: Argument : Julian date
:: Returns  : YYYY MM DD
::
:: Algorithm based on Fliegel-Van Flandern
:: algorithm from the Astronomical Almanac,
:: provided by Doctor Fenton on the Math Forum
:: (http://mathforum.org/library/drmath/view/51907.html),
:: and converted to batch code by Ron Bakowski.
::
SET /A P      = %1 + 68569
SET /A Q      = 4 * %P% / 146097
SET /A R      = %P% - ( 146097 * %Q% +3 ) / 4
SET /A S      = 4000 * ( %R% + 1 ) / 1461001
SET /A T      = %R% - 1461 * %S% / 4 + 31
SET /A U      = 80 * %T% / 2447
SET /A V      = %U% / 11
SET /A GYear  = 100 * ( %Q% - 49 ) + %S% + %V%
SET /A GMonth = %U% + 2 - 12 * %V%
SET /A GDay   = %T% - 2447 * %U% / 80
:: Clean up the mess
FOR %%A IN (P Q R S T U V) DO SET %%A=
:: Add leading zeroes
IF 1%GMonth% LSS 20 SET GMonth=0%GMonth%
IF 1%GDay%   LSS 20 SET GDay=0%GDay%
:: Return value
SET GDate=%GYear% %GMonth% %GDay%
GOTO:EOF


:JDate
:: Convert date to Julian
:: Arguments : YYYY MM DD
:: Returns   : Julian date
::
:: Algorithm based on Fliegel-Van Flandern
:: algorithm from the Astronomical Almanac,
:: provided by Doctor Fenton on the Math Forum
:: (http://mathforum.org/library/drmath/view/51907.html),
:: and converted to batch code by Ron Bakowski.
::
SET /A Month1 = ( %2 - 14 ) / 12
SET /A Year1  = %1 + 4800
SET /A JDate  = 1461 * ( %Year1% + %Month1% ) / 4 + 367 * ( %2 - 2 -12 * %Month1% ) / 12 - ( 3 * ( ( %Year1% + %Month1% + 100 ) / 100 ) ) / 4 + %3 - 32075
FOR %%A IN (Month1 Year1) DO SET %%A=
GOTO:EOF


:UpCase
SET UpCase=%1
SET UpCase=%UpCase:a=A%
SET UpCase=%UpCase:b=B%
SET UpCase=%UpCase:c=C%
SET UpCase=%UpCase:d=D%
SET UpCase=%UpCase:e=E%
SET UpCase=%UpCase:f=F%
SET UpCase=%UpCase:g=G%
SET UpCase=%UpCase:h=H%
SET UpCase=%UpCase:i=I%
SET UpCase=%UpCase:j=J%
SET UpCase=%UpCase:k=K%
SET UpCase=%UpCase:l=L%
SET UpCase=%UpCase:m=M%
SET UpCase=%UpCase:n=N%
SET UpCase=%UpCase:o=O%
SET UpCase=%UpCase:p=P%
SET UpCase=%UpCase:q=Q%
SET UpCase=%UpCase:r=R%
SET UpCase=%UpCase:s=S%
SET UpCase=%UpCase:t=T%
SET UpCase=%UpCase:u=U%
SET UpCase=%UpCase:v=V%
SET UpCase=%UpCase:w=W%
SET UpCase=%UpCase:x=X%
SET UpCase=%UpCase:y=Y%
SET UpCase=%UpCase:z=Z%
GOTO:EOF


:Syntax
ECHO.
ECHO Yesterday.bat,  Version 3.10 for Windows NT
ECHO Display yesterday's, today's and tomorrow's dates in sorted and local format
ECHO.
IF     "%OS%"=="Windows_NT" CALL :UpCase %~n0
IF     "%OS%"=="Windows_NT" ECHO Usage:  %UpCase%
IF NOT "%OS%"=="Windows_NT" ECHO Usage:  %0
ECHO.
ECHO Notes:  Environment variables Yesterday, Today and Tomorrow are set to the
ECHO         sorted date values found.
ECHO         Adapted for Windows XP with help from Kailash Chanduka.
ECHO         Local date code by Frederic Guigand and Rob van der Woude.
ECHO         Julian date math algorithms based on Fliegel-Van Flandern algorithm
ECHO         from the Astronomical Almanac, provided by Doctor Fenton on the Math
ECHO         Forum (http://mathforum.org/library/drmath/view/51907.html), and
ECHO         converted to batch code by Ron Bakowski.
ECHO.
ECHO Written by Rob van der Woude
ECHO http://www.robvanderwoude.com

IF "%OS%"=="Windows_NT" COLOR 00

