@echo off
echo Downloading Sysmon...
powershell -Command "(New-Object System.Net.WebClient).DownloadFile('https://download.sysinternals.com/files/Sysmon.zip', 'Sysmon.zip')"

if not exist Sysmon.zip (
    echo Failed to download Sysmon.
    pause
    exit /b 1
)

echo Extracting Sysmon...
powershell -Command "Expand-Archive -Path Sysmon.zip -DestinationPath . -Force"

if not exist Sysmon64.exe (
    echo Failed to extract Sysmon.
    pause
    exit /b 1
)

echo Installing Sysmon with default configuration...
:: Create a basic Sysmon configuration file
echo ^<?xml version="1.0" encoding="UTF-8"?^> > sysmon_config.xml
echo ^<Sysmon schemaversion="4.90"^> >> sysmon_config.xml
echo     ^<EventFiltering^> >> sysmon_config.xml
echo         ^<!-- Process creation --^> >> sysmon_config.xml
echo         ^<ProcessCreate onmatch="exclude"^> >> sysmon_config.xml
echo             ^<Image condition="is"^>C:\\Windows\\Sysmon64.exe^</Image^> >> sysmon_config.xml
echo         ^</ProcessCreate^> >> sysmon_config.xml
echo     ^</EventFiltering^> >> sysmon_config.xml
echo ^</Sysmon^> >> sysmon_config.xml

:: Install Sysmon
Sysmon64.exe -accepteula -i sysmon_config.xml

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Sysmon installed successfully!
    echo Starting Sysmon service...
    net start Sysmon
    
    echo.
    echo Verifying installation...
    sc query Sysmon
    
    echo.
    echo Sysmon should now be running. You can check the logs in Event Viewer under:
    echo "Applications and Services Logs > Microsoft > Windows > Sysmon > Operational"
) else (
    echo.
    echo Failed to install Sysmon. Please run this script as Administrator.
)

echo.
pause
