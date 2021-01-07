@echo off
pushd "%~dp0"

echo :: Checking For Administrator Elevation...
timeout /t 1 /nobreak > NUL

openfiles > NUL 2>&1
if %errorlevel%==0 (
        echo.
        echo :: Elevation found! Proceeding...
) else (
        echo :: You are NOT running as Administrator!
        echo.
        echo  Right-click and select ^'Run as Administrator^' and try again.
        echo.
        echo  [HIT RETURN]
        pause > NUL
        exit 1
)

PowerShell -Command "Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name Enabled -Force -ErrorAction SilentlyContinue | .\Fresh.ps1"
