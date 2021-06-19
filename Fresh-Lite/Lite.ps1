# Checking
# Проверка
function Check {
	Set-StrictMode -Version Latest

	# Сlear the $Error variable
	# Очистка переменной $Error
	$Global:Error.Clear()

	# Detect the OS bitness
	# Определить разрядность ОС
	switch ([Environment]::Is64BitOperatingSystem) {
		$false {
			Write-Warning -Message "The script supports Windows 10 x64 only" -Verbose
			break
		}
	}

	# Turn off Controlled folder access to let the script proceed
	# Выключить контролируемый доступ к папкам
	switch ((Get-MpPreference).EnableControlledFolderAccess -eq 1) {
		$true {
			Write-Warning -Message "Controlled folder access disabled" -Verbose
			Set-MpPreference -EnableControlledFolderAccess Disabled
		}
	}
	Read-Host 'Please make sure your network connection is available... [HIT RETURN]'
}
Check
#region O&OShutup
function OOShutup {
	Write-Warning -Message "Running O&O Shutup with Recommended Settings" -Verbose
	Import-Module BitsTransfer
	Start-BitsTransfer -Source "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -Destination OOSU10.exe
	./OOSU10.exe ooshutup.cfg /quiet
}
OOShutup
#endregion O&OShutup
#region UWP apps
<#
	Uninstall UWP apps
	A dialog box that enables the user to select packages to remove
	App packages will not be installed for new users if "Uninstall for All Users" is checked
	Add UWP apps packages names to the $UncheckedAppXPackages array list by retrieving their packages names using the following command:
		(Get-AppxPackage -PackageTypeFilter Bundle -AllUsers).Name

	Удалить UWP-приложения
	Диалоговое окно, позволяющее пользователю отметить пакеты на удаление
	Приложения не будут установлены для новых пользователе, если отмечено "Удалять для всех пользователей"
	Добавьте имена пакетов UWP-приложений в массив $UncheckedAppXPackages, получив названия их пакетов с помощью команды:
		(Get-AppxPackage -PackageTypeFilter Bundle -AllUsers).Name
#>
function UninstallUWPApps {
	# UWP apps that won't be shown in the form
	# UWP-приложения, которые не будут выводиться в форме
	$ExcludedAppxPackages = @(

		# Microsoft Store
		"Microsoft.WindowsStore",
		
		# AMD Radeon UWP panel
		"AdvancedMicroDevicesInc*",

		# NVIDIA Control Panel
		"NVIDIACorp.NVIDIAControlPanel",

		# Realtek Audio Control
		"RealtekSemiconductorCorp.RealtekAudioControl"
		
	)
	
	if (Get-AppxPackage -PackageTypeFilter Bundle -AllUsers | Where-Object -FilterScript { $_.Name -cnotmatch ($ExcludedAppxPackages -join "|") } | Remove-AppxPackage -AllUsers ) {
		Write-Verbose -Message 'Removed UWP apps' -Verbose
	}
 else {
		Write-Verbose -Message "Nothing to do" -Verbose
	}
}
UninstallUWPApps
# Do not let UWP apps run in the background, except the followings... (current user only)
# Не разрешать UWP-приложениям работать в фоновом режиме, кроме следующих... (только для текущего пользователя)
function DisableBackgroundUWPApps {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications -Name GlobalUserDisabled -PropertyType DWord -Value 1 -Force
	Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications | ForEach-Object -Process {
		Remove-ItemProperty -Path $_.PsPath -Name * -Force
	}

	$ExcludedBackgroundApps = @(

		# Windows Search
		"Microsoft.Windows.Search",

		# Windows Security
		"Microsoft.Windows.SecHealthUI",

		# Microsoft Store
		"Microsoft.WindowsStore"
	)
	$OFS = "|"
	Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications | Where-Object -FilterScript { $_.PSChildName -notmatch "^$($ExcludedBackgroundApps.ForEach({[regex]::Escape($_)}))" } | ForEach-Object -Process {
		New-ItemProperty -Path $_.PsPath -Name Disabled -PropertyType DWord -Value 1 -Force
		New-ItemProperty -Path $_.PsPath -Name DisabledByUser -PropertyType DWord -Value 1 -Force
	}
	$OFS = " "
}
DisableBackgroundUWPApps
# Disable the following Windows features
# Отключить следующие компоненты Windows
function DisableWindowsFeatures {
	$WindowsOptionalFeatures = @(
		# Media Features
		# Компоненты работы с мультимедиа
		"MediaPlayback",

		# Work Folders Client
		# Клиент рабочих папок
		"WorkFolders-Client"
	)
	Disable-WindowsOptionalFeature -Online -FeatureName $WindowsOptionalFeatures -NoRestart
}
DisableWindowsFeatures
# Disable certain Feature On Demand v2 (FODv2) capabilities
# Отключить определенные компоненты "Функции по требованию" (FODv2)
function DisableWindowsCapabilities {
	# The following FODv2 items will be shown, but their checkboxes would be clear
	# Следующие дополнительные компоненты будут видны, но их чекбоксы не будут отмечены
	$ExcludedCapabilities = @(
		# The DirectX Database to configure and optimize apps when multiple Graphics Adapters are present
		# База данных DirectX для настройки и оптимизации приложений при наличии нескольких графических адаптеров
		"DirectX.Configuration.Database*",

		# Language components
		"Language.*"
	)
	
	if (Get-WindowsCapability -Online | Where-Object -FilterScript { ($_.State -eq "Installed") -and ($_.Name -cnotmatch ($ExcludedCapabilities -join "|")) } | Remove-WindowsCapability -Online ) {
		Write-Verbose -Message 'Removed Capabilities' -Verbose
	}
 else {
		Write-Verbose -Message "Nothing to do" -Verbose
	}
}
DisableWindowsCapabilities
# Turn off Cortana autostarting
# Удалить Кортана из автозагрузки
function DisableCortanaAutostart {
	if (Get-AppxPackage -Name Microsoft.549981C3F5F10) {
		if (-not (Test-Path -Path "Registry::HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.549981C3F5F10_8wekyb3d8bbwe\CortanaStartupId")) {
			New-Item -Path "Registry::HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.549981C3F5F10_8wekyb3d8bbwe\CortanaStartupId" -Force
		}
		New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.549981C3F5F10_8wekyb3d8bbwe\CortanaStartupId" -Name State -PropertyType DWord -Value 1 -Force
	}
}
DisableCortanaAutostart
#endregion UWP apps
#region OneDrive
# Uninstall OneDrive
# Удалить OneDrive
function UninstallOneDrive {
	[string]$UninstallString = Get-Package -Name "Microsoft OneDrive" -ProviderName Programs -ErrorAction Ignore | ForEach-Object -Process { $_.Meta.Attributes["UninstallString"] }
	if ($UninstallString) {
		Write-Verbose -Message "Uninstalling OneDrive..." -Verbose
		Stop-Process -Name OneDrive -Force -ErrorAction Ignore
		Stop-Process -Name OneDriveSetup -Force -ErrorAction Ignore
		Stop-Process -Name FileCoAuth -Force -ErrorAction Ignore

		# Getting link to the OneDriveSetup.exe and its' argument(s)
		# Получаем ссылку на OneDriveSetup.exe и его аргумент(ы)
		[string[]]$OneDriveSetup = ($UninstallString -Replace ("\s*/", ",/")).Split(",").Trim()
		if ($OneDriveSetup.Count -eq 2) {
			Start-Process -FilePath $OneDriveSetup[0] -ArgumentList $OneDriveSetup[1..1] -Wait
		}
		else {
			Start-Process -FilePath $OneDriveSetup[0] -ArgumentList $OneDriveSetup[1..2] -Wait
		}

		# Getting the OneDrive user folder path
		# Получаем путь до папки пользователя OneDrive
		$OneDriveUserFolder = Get-ItemPropertyValue -Path HKCU:\Environment -Name OneDrive
		if ((Get-ChildItem -Path $OneDriveUserFolder | Measure-Object).Count -eq 0) {
			Remove-Item -Path $OneDriveUserFolder -Recurse -Force
		}
		else {
			$Message = Invoke-Command -ScriptBlock ([ScriptBlock]::Create("The $OneDriveUserFolder folder is not empty Delete it manually"))
			Write-Error -Message $Message -ErrorAction SilentlyContinue
			Invoke-Item -Path $OneDriveUserFolder
		}

		Remove-ItemProperty -Path HKCU:\Environment -Name OneDrive, OneDriveConsumer -Force -ErrorAction Ignore
		Remove-Item -Path HKCU:\SOFTWARE\Microsoft\OneDrive -Recurse -Force -ErrorAction Ignore
		Remove-Item -Path HKLM:\SOFTWARE\WOW6432Node\Microsoft\OneDrive -Recurse -Force -ErrorAction Ignore
		Remove-Item -Path "$env:ProgramData\Microsoft OneDrive" -Recurse -Force -ErrorAction Ignore
		Remove-Item -Path $env:SystemDrive\OneDriveTemp -Recurse -Force -ErrorAction Ignore
		Unregister-ScheduledTask -TaskName *OneDrive* -Confirm:$false

		# Getting the OneDrive folder path
		# Получаем путь до папки OneDrive
		$OneDriveFolder = Split-Path -Path (Split-Path -Path $OneDriveSetup[0] -Parent)

		# Save all opened folders in order to restore them after File Explorer restarting
		# Сохранить все открытые папки, чтобы восстановить их после перезапуска проводника
		Clear-Variable -Name OpenedFolders -Force -ErrorAction Ignore
		$OpenedFolders = { (New-Object -ComObject Shell.Application).Windows() | ForEach-Object -Process { $_.Document.Folder.Self.Path } }.Invoke()
        
		# Restart explorer process
		TASKKILL /F /IM explorer.exe
		Start-Process "explorer.exe"
		
		# Attempt to unregister FileSyncShell64.dll and remove
		# Попытка разрегистрировать FileSyncShell64.dll и удалить
		$FileSyncShell64dlls = Get-ChildItem -Path "$OneDriveFolder\*\amd64\FileSyncShell64.dll" -Force
		foreach ($FileSyncShell64dll in $FileSyncShell64dlls.FullName) {
			Start-Process -FilePath regsvr32.exe -ArgumentList "/u /s $FileSyncShell64dll" -Wait
			Remove-Item -Path $FileSyncShell64dll -Force -ErrorAction Ignore

			if (Test-Path -Path $FileSyncShell64dll) {
				$Message = Invoke-Command -ScriptBlock ([ScriptBlock]::Create("$FileSyncShell64dll is blocked Delete it manually"))
				Write-Error -Message $Message -ErrorAction SilentlyContinue
			}
		}

		# Restoring closed folders
		# Восстановляем закрытые папки
		foreach ($OpenedFolder in $OpenedFolders) {
			if (Test-Path -Path $OpenedFolder) {
				Invoke-Item -Path $OpenedFolder
			}
		}

		Remove-Item -Path $OneDriveFolder -Recurse -Force -ErrorAction Ignore
		Remove-Item -Path $env:LOCALAPPDATA\OneDrive -Recurse -Force -ErrorAction Ignore
		Remove-Item -Path $env:LOCALAPPDATA\Microsoft\OneDrive -Recurse -Force -ErrorAction Ignore
		Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -Force -ErrorAction Ignore
	}
}
UninstallOneDrive
# Do not show sync provider notification within File Explorer (current user only)
# Не показывать уведомления поставщика синхронизации в проводнике (только для текущего пользователя)
function HideOneDriveFileExplorerAd {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowSyncProviderNotifications -PropertyType DWord -Value 0 -Force
}
HideOneDriveFileExplorerAd
#endregion OneDrive
#region Performance
function Performance {
	if (!(Test-Path "HKCU:\AppEvents\Schemes")) {
		New-Item -Path "HKCU:\AppEvents\Schemes" -Force
	}	
	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Force
	}
	if (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Psched")) {
		New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Psched" -Force
	}
	if (!(Test-Path "HKCU:\System\GameConfigStore")) {
		New-Item -Force "HKCU:\System\GameConfigStore"
	}
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Name NonBestEffortLimit -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Psched" -Name NonBestEffortLimit -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_EFSEFeatureFlags" -Type DWord -Value 0 -Force
	New-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DSEBehavior" -Type DWord -Value 0 -Force
	New-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Type DWord -Value 0 -Force
	New-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Type DWord -Value 0 -Force
	New-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_HonorUserFSEBehaviorMode" -Type DWord -Value 2 -Force
	New-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Type DWord -Value 1 -Force
	New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Type DWord -Value 32 -Force
	New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Type DWord -Value 2 -Force
	New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name "NtfsDisable8dot3NameCreation" -PropertyType DWord -Value 1 -Force
	New-ItemProperty -Path HKLM:\SYSTEM\ControlSet001\Control\FileSystem -Name "NtfsDisable8dot3NameCreation" -PropertyType DWord -Value 1 -Force
	New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name "NtfsAllowExtendedCharacter8dot3Rename" -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKLM:\SYSTEM\ControlSet001\Control\FileSystem -Name "NtfsAllowExtendedCharacter8dot3Rename" -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\DWM -Name AlwaysHibernateThumbnails -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\DWM -Name EnableWindowColorization -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\DWM -Name EnableAeroPeek -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\DWM -Name ColorPrevalence -PropertyType DWord -Value 1 -Force
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\DWM -Name Composition -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\DWM -Name CompositionPolicy -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\DWM -Name DWMWA_TRANSITIONS_FORCEDISABLED -PropertyType DWord -Value 1 -Force
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\DWM -Name DisallowAnimations -PropertyType DWord -Value 1 -Force
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name EnableTransparency -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name AltTabSettings -PropertyType DWord -Value 1 -Force
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name FirstRunTelemetryComplete -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name DesktopReadyTimeout -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name ExplorerStartupTraceRecorded -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name TelemetrySalt -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ListviewAlphaSelect -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ListviewShadow -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name DisableThumbnailCache -PropertyType DWord -Value 1 -Force
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name DisallowShaking -PropertyType DWord -Value 1 -Force
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name DesktopLivePreviewHoverTimes -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name DesktopLivePreviewHoverTime -PropertyType DWord -Value 1 -Force
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name DisableThumbsDBOnNetworkFolders -PropertyType DWord -Value 1 -Force
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name EnableBalloonTips -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name SharingWizardOn -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name StartButtonBalloonTip -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowSyncProviderNotifications -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowInfoTip -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowTaskViewButton -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name "Start_ShowRun" -PropertyType DWord -Value 1 -Force
	New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name ActiveWndTrackTimeout -PropertyType String -Value 0 -Force
	New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name MouseWheelRouting -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name FontSmoothing -PropertyType String -Value 2 -Force
	New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name MenuShowDelay -PropertyType String -Value 10 -Force
	New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name AutoColorization -PropertyType String -Value 1 -Force
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name BranchReadinessLevel -PropertyType DWord -Value 20 -Force
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name DeferFeatureUpdatesPeriodInDays -PropertyType DWord -Value 365 -Force
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name DeferQualityUpdatesPeriodInDays -PropertyType DWord -Value 4 -Force
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name ActiveHoursEnd -Value 1 -Force
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name ActiveHoursStart -Value 10 -Force
	New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name IRQ8Priority -PropertyType DWord -Value 1 -Force
	New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name Win32PrioritySeparation -PropertyType DWord -Value 30 -Force
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name SystemResponsiveness -PropertyType DWord -Value 10 -Force
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name LazyModeTimeout -PropertyType DWord -Value 10000 -Force
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name NetworkThrottlingIndex -PropertyType DWord -Value 10 -Force
	New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control -Name WaitToKillServiceTimeout -PropertyType DWord -Value 1000 -Force
	New-ItemProperty -Path "HKLM:\HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" -Name "WaitToKillServiceTimeout" -PropertyType String -Value 1000 -Force
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\GameBar -Name ShowStartupPanel -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -PropertyType DWord -Value 18 -Force
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Latency Sensitive" -PropertyType String -Value "True" -Force
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -PropertyType DWord -Value 8 -Force
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "NoLazyMode" -PropertyType String -Value 1 -Force
	New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name "WaitToKillServiceTimeout" -PropertyType String -Value 1000 -Force
	New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name CoalescingTimerInterval -Type "DWORD" -Value "0" -Force
	New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name CoalescingTimerInterval -Type "DWORD" -Value "0" -Force
	New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name SleepStudyDisabled -Type "DWORD" -Value "1" -Force
}
Performance
function FixTimers {
	bcdedit /set `{current`} useplatformtick true
	bcdedit /set `{current`} disabledynamictick true
	bcdedit /set `{current`} tscsyncpolicy legacy
	bcdedit /deletevalue `{current`} useplatformclock
}
FixTimers
function Network {
	netsh int tcp set global timestamps=disabled
	netsh int tcp set heuristics disabled
	netsh int tcp set global netdma=enabled
	netsh int tcp set global dca=enabled
	netsh int tcp set global autotuninglevel=disabled
	netsh int tcp set supplemental template=internet congestionprovider=ctcp
	netsh int tcp set global rss=enabled
}
Network
function Memory {
	fsutil behavior set memoryusage 1
	fsutil behavior set disablelastaccess 1
	fsutil behavior set mftzone 3
}
Memory
#endregion Performance
#region Chocolatey
# Install Chocolatey package manager and pre-installs as well
function ChocolateyPackageManager {
	[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')); choco feature enable -n=allowGlobalConfirmation; choco feature enable -n useFipsCompliantChecksums; choco feature enable -n=useEnhancedExitCodes; choco config set --name="'proxyBypassOnLocal'" --value="'true'"; cinst dotnetfx; cinst --ignore-checksums dotnetfx; cinst 7zip.install notepadplusplus.install; cinst --ignore-checksums 7zip.install notepadplusplus.install
}
ChocolateyPackageManager
#endregion Chocolatey
function Errors {
	if ($Global:Error) {
		($Global:Error | ForEach-Object -Process {
				[PSCustomObject] @{
					Line    = $_.InvocationInfo.ScriptLineNumber
					File    = Split-Path -Path $PSCommandPath -Leaf
					'Errors/Warnings' = $_.Exception.Message
				}
			} | Sort-Object -Property Line | Format-Table -AutoSize -Wrap | Out-File -FilePath $HOME\Documents\errorlog.txt
		)
	}
}
Errors
