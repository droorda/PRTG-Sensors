@echo off
cls
setlocal
::echo %cd%

cd /d %~d0%~p0\DIG

::echo %cd%


if not exist "dig.exe" echo 0:dig.exe Missing & Exit 2
if not exist "libeay32.dll" echo 0:libeay32.dll Missing & Exit 2
if not exist "libbind9.dll" echo 0:libbind9.dll Missing & Exit 2
if not exist "libdns.dll" echo 0:libdns.dll Missing & Exit 2
if not exist "libisc.dll" echo 0:libisc.dll Missing & Exit 2
if not exist "libisccfg.dll" echo 0:libisccfg.dll Missing & Exit 2
if not exist "liblwres.dll" echo 0:liblwres.dll Missing & Exit 2
if not exist "msvcr110.dll" echo 0:msvcr110.dll Missing & Exit 2


set ReplyTime=
FOR /F "eol=! usebackq tokens=4" %%i IN (`dig.exe %1 %2 ^| find "time"`) DO set ReplyTime=%%i

FOR /F "tokens=1 delims=0123456789" %%A IN ("%ReplyTime%") DO (
    ECHO 0:%ReplyTime% is NOT a valid decimal, octal or binary number
    exit 2
)
if "%ReplyTime%"=="" echo 0:No responce from DIG & Exit 2 

echo %ReplyTime%:OK


goto:EOF
echo.
echo sleeping
ping 1.1.1.1 -n 1 >NUL
                                       
                                                 
dig.cmd %1 %2



