ConvertFrom-StringData -StringData @'
UnsupportedOSBitness = The script supports Windows 10 x64 only
ControlledFolderAccessDisabled = Controlled folder access disabled
NoData = Nothing to do

# OneDrive
OneDriveUninstalling = Uninstalling OneDrive...
OneDriveNotEmptyFolder = "The $OneDriveUserFolder folder is not empty `nDelete it manually"
OneDriveFileSyncShell64dllBlocked = "$FileSyncShell64dll is blocked `nDelete it manually"
OneDriveInstalling = OneDriveSetup.exe is starting...
OneDriveDownloading = Downloading OneDrive... ~33 MB
NoInternetConnection = No Internet connection

# SetTempPath
LOCALAPPDATANotEmptyFolder = "The $env:LOCALAPPDATA\\Temp folder is not empty `nDeleteClear it manually and try again"

# ChangeUserShellFolderLocation
UserShellFolderNotEmpty = "Some files left in the $UserShellFolderRegValue folder `nMove them manually to a new location"

# DisableReservedStorage
ReservedStorageIsInUse = This operation is not supported when reserved storage is in use `nPlease wait for any servicing operations to complete and then try again later

# CreateEventViewerCustomView
EventViewerCustomViewName = Process Creation
EventViewerCustomViewDescription = Process Creation and Command-line Auditing Events

# WSL
WSLUpdateDownloading = Downloading the Linux kernel update package... ~14 MB
WSLUpdateInstalling = Installing the Linux kernel update package...

# ChocolateyPackageManager
OOShutup = Running O&O Shutup with Recommended Settings

# Refresh
RestartWarning = Restart your PC

# Errors
ErrorsLine = Line
ErrorsFile = File
ErrorsMessage = Errors/Warnings
'@
