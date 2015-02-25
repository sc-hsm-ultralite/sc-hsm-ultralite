@echo off
setlocal enableDelayedExpansion

rem This is a convenience script for running sc-hsm-ultralite-signer.
rem 
rem This script also automates finding all files from today and 
rem yesterday. It recursively searches for all files matching the regex
rem yyyy-mm-dd where yyyy-mm-dd is once today's date and once yesterday's 
rem date.
rem 
rem It further speeds up processing, by skipping old folders. If a 
rem folder contains a date in the format yyyy-mm, this script will only 
rem recurse into the folder if the name matches either today's month 
rem or yesterday's month.
rem 
rem If a folder does NOT match the regex yyyy-mm, it will unconditionally 
rem recurse into that folder looking for files from yesterday or today.
rem 
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
rem ... The script is executed with the following arguments...
rem sc-hsm-ultralite-signer.cmd 123456 sign0 d:\data log.log
rem 
rem If today's date is 2013-10-01, the following commands will be executed...
rem sc-hsm-ultralite-signer.exe 123456 sign0 d:\data\2013-10\xxxx-2013-10-01.dat >>log.log 2>&1
rem sc-hsm-ultralite-signer.exe 123456 sign0 d:\data\2013-10\xxxx-2013-10-01.log >>log.log 2>&1
rem sc-hsm-ultralite-signer.exe 123456 sign0 d:\data\2013-09\xxxx-2013-09-30.dat >>log.log 2>&1
rem 
rem This script also implements rotating logs for capturing the stdout
rem and stderr info/warning/error messages. Each log is rotated after
rem the size of the log exceeds max_size. Two backups are kept. Note that
rem all log messages are redirected to stdout-log if stderr-log is not 
rem specified.
rem 
rem This script requires the unix date utility.
rem Download a Windows implementation from: 
rem http://sourceforge.net/projects/unxutils/
rem Rename date.exe to unix_date.exe to avoid conflict with the native 'date' 
rem command.

if "%1" == "--rotate" GOTO :ROTATE
if "%1" == "" GOTO :USAGE
if "%2" == "" GOTO :USAGE
if "%3" == "" GOTO :USAGE
if "%4" == "" GOTO :USAGE
if exist "%4" CMD /C ""%0" --rotate %4"
if exist "%5" CMD /C ""%0" --rotate %5"

rem parse the args
set exe=%~dpn0%.exe
set outlog=%4
if "%5" == "" (set errlog="2>&1") else (set errlog="2>>%5")

rem get the current date and previous date
for /F "delims=" %%I in ('unix_date.exe +%%Y-%%m-%%d') do set CUR_DAY=%%I
for /F "delims=" %%I in ('unix_date.exe --date="%CUR_DAY%" +%%Y-%%m') do set CUR_DAY_MTH=%%I
for /F "delims=" %%I in ('unix_date.exe --date="%CUR_DAY% -1 day" +%%Y-%%m-%%d') do set PRV_DAY=%%I
for /F "delims=" %%I in ('unix_date.exe --date="%PRV_DAY%" +%%Y-%%m') do set PRV_DAY_MTH=%%I

rem sign files from yesterday and today, but skip .p7s files
for /F "delims=" %%I in ('dir /b /a-d %~dpn3\*%CUR_DAY%* 2^>nul ^| findstr /v /i "\<\. \.p7s\>"') do CALL %exe% %1 %2 %~dpn3\%%~nxI >>%outlog% %errlog:"=%
for /F "delims=" %%I in ('dir /b /a-d %~dpn3\*%PRV_DAY%* 2^>nul ^| findstr /v /i "\<\. \.p7s\>"') do CALL %exe% %1 %2 %~dpn3\%%~nxI >>%outlog% %errlog:"=%

rem iterate over every directory in the current folder
rem if the directory name contains a month date in the format yyyy-mm
rem     if directory name matches the current month (CUR_DAY_MTH) or previous month (PRV_DAY_MTH)
rem         call this script recursively
rem else (i.e. the directory name does NOT contain a month date) 
rem     call this script recursively (i.e. unconditionally)
for /D %%I in (%~dpn3\*) do (
	echo %%I | findstr [2-9][0-9][0-9][0-9]-[0-1][0-9] >nul 2>&1
	if !errorlevel! EQU 0 (
		if "%%~nI" == "%CUR_DAY_MTH%" (
			CMD /C "%0 %1 %2 "%%~dpnxI" %4 %5"
		) else (
			if "%%~nI" == "%PRV_DAY_MTH%" CMD /C "%0 %1 %2 "%%~dpnxI" %4 %5"
		)
	) else (
		CMD /C "%0 %1 %2 "%%~dpnxI" %4 %5"
	)
)

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
set usage="Usage: %0 ^<pin^> ^<label^> ^<base-path^> ^<stdout-log^> [stderr-log]"
set  note="All log messages are redirected to stdout-log if stderr-log is not specified."
echo %usage:"=%
echo %note:"=%
