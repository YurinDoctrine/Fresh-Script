# Do not remove double quotes in double-quoted strings where they are present

ConvertFrom-StringData -StringData @'
UnsupportedOSBitness = The script supports Windows 10 x64 only
ControlledFolderAccessDisabled = Controlled folder access disabled

# OneDrive
OneDriveUninstalling = Uninstalling OneDrive...
OneDriveNotEmptyFolder = "The $OneDriveUserFolder folder is not empty `nDelete it manually"
OneDriveFileSyncShell64dllBlocked = "$FileSyncShell64dll is blocked `nDelete it manually"
OneDriveInstalling = OneDriveSetup.exe is starting...
OneDriveDownloading = Downloading OneDrive... ~33 MB
NoInternetConnection = No Internet connection

# SetTempPath
LOCALAPPDATANotEmptyFolder = "The $env:LOCALAPPDATA\\Temp folder is not empty `nDeleteClear it manually and try again"

# WSL
WSLUpdateDownloading = Downloading the Linux kernel update package... ~14 MB
WSLUpdateInstalling = Installing the Linux kernel update package...

# DisableWindowsCapabilities
FODWindowTitle = Optional features (FODv2) to remove
FODWindowButton = Uninstall
DialogBoxOpening = Displaying the dialog box...
NoData = Nothing to display

# ChangeUserShellFolderLocation
UserShellFolderNotEmpty = "Some files left in the $UserShellFolderRegValue folder `nMove them manually to a new location"
RetrievingDrivesList = Retrieving drives list...
# Desktop
DesktopChangeFolderRequest = Would you like to change the location of the Desktop folder?
DesktopFilesWontBeMoved = Files will not be moved
DesktopFolderChange = Change
DesktopFolderSkip = Skip
DesktopDriveSelect = Select the drive within the root of which the Desktop folder will be created
DesktopSkipped = Skipped
# Documents
DocumentsChangeFolderRequest = Would you like to change the location of the Documents folder?
DocumentsFilesWontBeMoved = Files will not be moved
DocumentsFolderChange = Change
DocumentsFolderSkip = Skip
DocumentsDriveSelect = Select the drive within the root of which the Documents folder will be created
DocumentsSkipped = Skipped
# Downloads
DownloadsChangeFolderRequest = Would you like to change the location of the Downloads folder?
DownloadsFilesWontBeMoved = Files will not be moved
DownloadsFolderChange = Change
DownloadsFolderSkip = Skip
DownloadsDriveSelect = Select the drive within the root of which the Downloads folder will be created
DownloadsSkipped = Skipped
# Music
MusicChangeFolderRequest = Would you like to change the location of the Music folder?
MusicFilesWontBeMoved = Files will not be moved
MusicFolderChange = Change
MusicFolderSkip = Skip
MusicDriveSelect = Select the drive within the root of which the Music folder will be created
MusicSkipped = Skipped
# Pictures
PicturesChangeFolderRequest = Would you like to change the location of the Pictures folder?
PicturesFilesWontBeMoved = Files will not be moved
PicturesFolderChange = Change
PicturesFolderSkip = Skip
PicturesDriveSelect = Select the drive within the root of which the Pictures folder will be created
PicturesSkipped = Skipped
# Videos
VideosChangeFolderRequest = Would you like to change the location of the Videos folder?
VideosFilesWontBeMoved = Files will not be moved
VideosFolderChange = Change
VideosFolderSkip = Skip
VideosDriveSelect = Select the drive within the root of which the Videos folder will be created
VideosSkipped = Skipped

# SetDefaultUserShellFolderLocation
# Desktop
DesktopDefaultFolder = Would you like to change the location of the Desktop folder to the default value?
# Documents
DocumentsDefaultFolder = Would you like to change the location of the Documents folder to the default value?
# Downloads
DownloadsDefaultFolder = Would you like to change the location of the Downloads folder to the default value?
# Music
MusicDefaultFolder = Would you like to change the location of the Music folder to the default value?
# Pictures
PicturesDefaultFolder = Would you like to change the location of the Pictures folder to the default value?
# Videos
VideosDefaultFolder = Would you like to change the location of the Videos folder to the default value?

# DisableReservedStorage
ReservedStorageIsInUse = This operation is not supported when reserved storage is in use `nPlease wait for any servicing operations to complete and then try again later

# UninstallUWPApps
UninstallUWPForAll = Uninstall for All Users
UninstallUWPTitle = UWP Packages to Uninstall
UninstallUWPUninstallButton = Uninstall

# CreateCleanUpTask
CleanUpTaskToast = Cleaning up unused Windows files and updates starts in a minute
CleanUpTaskDescription = Cleaning up unused Windows files and updates using built-in Disk cleanup app. To decode encoded command use [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("string"))

# CreateSoftwareDistributionTask
SoftwareDistributionTaskDescription = The %SystemRoot%\\SoftwareDistribution\\Download

# CreateTempTask
TempTaskDescription = The %TEMP% folder cleaning

# CreateEventViewerCustomView
EventViewerCustomViewName = Process Creation
EventViewerCustomViewDescription = Process Creation and Command-line Auditing Events

# ChocolateyPackageManager
OOShutup = Running O&O Shutup with Recommended Settings

# Refresh
RestartWarning = Restart your PC

# Errors
ErrorsLine = Line
ErrorsFile = File
ErrorsMessage = Errors/Warnings
'@
