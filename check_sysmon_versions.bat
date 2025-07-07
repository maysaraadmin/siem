@echo off
echo Checking for Sysmon installations...
echo ====================================

echo.
echo Checking 64-bit Sysmon (System32):
if exist "%SystemRoot%\System32\Sysmon64.exe" (
    echo Found: %SystemRoot%\System32\Sysmon64.exe
    "%SystemRoot%\System32\Sysmon64.exe" -s
) else (
    echo 64-bit Sysmon not found in System32
)

echo.
echo Checking 32-bit Sysmon (SysWOW64):
if exist "%SystemRoot%\SysWOW64\Sysmon.exe" (
    echo Found: %SystemRoot%\SysWOW64\Sysmon.exe
    "%SystemRoot%\SysWOW64\Sysmon.exe" -s
) else (
    echo 32-bit Sysmon not found in SysWOW64
)

echo.
echo Checking Sysmon service status:
sc query Sysmon 2>nul
if %ERRORLEVEL% EQU 1060 (
    echo Sysmon service is not installed.
) else (
    echo.
    echo Sysmon service details:
    sc queryex Sysmon
)

echo.
echo Checking Sysmon drivers:
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv" /s 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo No Sysmon driver found in registry.
)

echo.
pause
