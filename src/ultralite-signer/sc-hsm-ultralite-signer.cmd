@echo off

rem This is a convenience script for running sc-hsm-ultralite-signer.
rem 
rem This script implements rotating logs for capturing the stdout
rem and stderr info/warning/error messages. Each log is rotated after
rem the size of the log exceeds max_size. Two backups are kept.
rem 
rem This script also automates (and speeds up) finding all files from 
rem today and yesterday. It searches for all files matching the regex
rem yyyy-mm-dd where yyyy-mm-dd is once today's date and once yesterday's 
rem date. It only searches the sub-folder(s) matching the regex yyyy-mm 
rem where yyyy-mm is once today's month and once yesterday's month. Note 
rem yyyy-mm will always be the same folder for yesterday and today except 
rem for the first day of any particular month.
rem Uncomment the first "for" command below to make the script also
rem search the base path itself (i.e. flat hierarchy).
rem It skips hidden files (i.e. name begins with '.') and ".p7s" files.
rem 
rem For example, consider the path d:\data with the following contents...
rem + d:\data\2013-08
rem   - ...
rem + d:\data\2013-09
rem   - xxxx-2013-09-01.dat
rem   - ...
rem   - xxxx-2013-09-30.dat
rem   - xxxx-2013-09-30.dat.p7s
rem + d:\data\2013-10
rem   - xxxx-2013-10-01.dat
rem   - xxxx-2013-10-01.log
rem
rem This script is executed with the following arguments...
rem sc-hsm-ultralite-signer.cmd out.log err.log 123456 sign0 d:\data
rem 
rem If today's date is 2013-10-01, the following commands will be executed...
rem sc-hsm-ultralite-signer.exe 123456 sign0 d:\data\2013-10\xxxx-2013-10-01.dat >> out.log 2>> err.log
rem sc-hsm-ultralite-signer.exe 123456 sign0 d:\data\2013-10\xxxx-2013-10-01.log >> out.log 2>> err.log
rem sc-hsm-ultralite-signer.exe 123456 sign0 d:\data\2013-09\xxxx-2013-09-30.dat >> out.log 2>> err.log
rem 
rem This script requires the unix date utility.
rem Download a Windows implementation from http://sourceforge.net/projects/unxutils/
rem Rename date.exe to unix_date.exe to avoid conflict with the native 'date' command.

if "%1" == "--rotate" GOTO :ROTATE
if "%1" == "" GOTO :USAGE
if "%2" == "" GOTO :USAGE
if "%3" == "" GOTO :USAGE
if "%4" == "" GOTO :USAGE
if "%5" == "" GOTO :USAGE
if exist "%1" CMD /C ""%0" --rotate %1"
if exist "%2" CMD /C ""%0" --rotate %2"

for /F "delims=" %%i in ('unix_date.exe +%%Y-%%m-%%d') do set CUR_DAY=%%i
for /F "delims=" %%i in ('unix_date.exe --date="%CUR_DAY%" +%%Y-%%m') do set CUR_DAY_MTH=%%i
for /F "delims=" %%i in ('unix_date.exe --date="%CUR_DAY% -1 day" +%%Y-%%m-%%d') do set PRV_DAY=%%i
for /F "delims=" %%i in ('unix_date.exe --date="%PRV_DAY%" +%%Y-%%m') do set PRV_DAY_MTH=%%i
set exe=%~dpn0%.exe
rem for /F "delims=" %%I in ('dir /b %5\*%CUR_DAY%* %5\*%PRV_DAY%* 2^>nul ^| findstr /v /i "\<\. \.p7s\>"') do CALL %exe% %3 %4 %5\%%~nxI               >> %1 2>> %2
    for /F "delims=" %%I in ('dir /b %5\%CUR_DAY_MTH%\*%CUR_DAY%*  2^>nul ^| findstr /v /i "\<\. \.p7s\>"') do CALL %exe% %3 %4 %5\%CUR_DAY_MTH%\%%~nxI >> %1 2>> %2
    for /F "delims=" %%I in ('dir /b %5\%PRV_DAY_MTH%\*%PRV_DAY%*  2^>nul ^| findstr /v /i "\<\. \.p7s\>"') do CALL %exe% %3 %4 %5\%PRV_DAY_MTH%\%%~nxI >> %1 2>> %2
GOTO :eof

:ROTATE
set /a max_size = 0x100000
set /a log_size = %~z2%
set log1=%~dpf2%.1
set log2=%~dpf2%.2
if %log_size% lss %max_size% GOTO :eof
if exist "%log1%" move /y "%log1%" "%log2%" >nul 2>&1
move "%2" "%log1%" >nul 2>&1
GOTO :eof

:USAGE
echo Usage: "stdout-log" "stderr-log" "pin" "label" "base-path"
