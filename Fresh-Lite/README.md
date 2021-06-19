# Fresh-Lite

## RUNNING

### ONLINE
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force; Start-BitsTransfer -Source "https://raw.githubusercontent.com/YurinDoctrine/Fresh-Lite/main/Fresh-Lite/ooshutup.cfg"; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/YurinDoctrine/Fresh-Lite/main/Fresh-Lite/Lite.ps1'))
```
### OFFLINE
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force
```

 Open a Powershell prompt as Administrator then paste above code, after that Right-click and Run as
 Administrator setup.bat or setup.exe file inside of the directory...
