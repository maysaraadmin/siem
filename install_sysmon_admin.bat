@echo off
:: BatchGotAdmin
:-------------------------------------
REM  --> Check for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*""
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"
:--------------------------------------

@echo off
cd /d %~dp0

echo Installing Python dependencies...
pip install -r requirements.txt

echo.
echo Installing Sysmon...
python install_sysmon.py

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Sysmon installed successfully!
    echo.
    echo Verifying installation...
    python check_sysmon.py
) else (
    echo.
    echo Failed to install Sysmon. Please check the error messages above.
)

echo.
pause
