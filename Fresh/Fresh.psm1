#region Check
function Check {
	Set-StrictMode -Version Latest

	# Сlear the $Error variable
	# Очистка переменной $Error
	$Global:Error.Clear()

	# Detect the OS bitness
	# Определить разрядность ОС
	switch ([Environment]::Is64BitOperatingSystem) {
		$false {
			Write-Warning -Message $Localization.UnsupportedOSBitness
			break
		}
	}

	# Turn off Controlled folder access to let the script proceed
	# Выключить контролируемый доступ к папкам
	switch ((Get-MpPreference).EnableControlledFolderAccess -eq 1) {
		$true {
			Write-Warning -Message $Localization.ControlledFolderAccessDisabled
			Set-MpPreference -EnableControlledFolderAccess Disabled

			# Open "Ransomware protection" page
			# Открыть раздел "Защита от программ-шатажистов"
			Start-Process -FilePath windowsdefender://RansomwareProtection
		}
	}
}
#endregion Check
# Create a restore point
# Создать точку восстановления
function CreateRestorePoint {
	if (-not (Get-ComputerRestorePoint)) {
		Enable-ComputerRestore -Drive $env:SystemDrive
	}

	# Set system restore point creation frequency to 5 minutes
	# Установить частоту создания точек восстановления на 5 минут
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name SystemRestorePointCreationFrequency -PropertyType DWord -Value 5 -Force

	Checkpoint-Computer -Description "Windows 10 Fresh Setup.ps1" -RestorePointType MODIFY_SETTINGS

	# Revert the System Restore checkpoint creation frequency to 1440 minutes
	# Вернуть частоту создания точек восстановления на 1440 минут
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name SystemRestorePointCreationFrequency -PropertyType DWord -Value 1440 -Force
}

#region Privacy & Telemetry
# Disable the "Connected User Experiences and Telemetry" service (DiagTrack)
# Отключить службу "Функциональные возможности для подключенных пользователей и телеметрия" (DiagTrack)
function DisableTelemetryServices {
	Get-Service -Name DiagTrack | Stop-Service -Force
	Get-Service -Name DiagTrack | Set-Service -StartupType Disabled
}

# Enable the "Connected User Experiences and Telemetry" service (DiagTrack)
# Включить службу "Функциональные возможности для подключенных пользователей и телеметрия" (DiagTrack)
function EnableTelemetryServices {
	Get-Service -Name DiagTrack | Set-Service -StartupType Automatic
	Get-Service -Name DiagTrack | Start-Service
}

# Set the OS level of diagnostic data gathering to "Minimum"
# Установить уровень сбора диагностических сведений ОС на "Минимальный"
function SetMinimalDiagnosticDataLevel {
	if (Get-WindowsEdition -Online | Where-Object -FilterScript { $_.Edition -like "Enterprise*" -or $_.Edition -eq "Education" }) {
		# "Security"
		# "Безопасность"
		New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection -Name AllowTelemetry -PropertyType DWord -Value 0 -Force
	}
	else {
		# "Basic"
		# "Базовая настройка"
		New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection -Name AllowTelemetry -PropertyType DWord -Value 0 -Force
	}
}

# Set the default OS level of diagnostic data gathering
# Установить уровень сбора диагностических сведений ОС по умолчанию
function SetDefaultDiagnosticDataLevel {
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection -Name AllowTelemetry -PropertyType DWord -Value 3 -Force
}

# Turn off Windows Error Reporting for the current user
# Отключить отчеты об ошибках Windows для текущего пользователя
function DisableWindowsErrorReporting {
	if ((Get-WindowsEdition -Online).Edition -notmatch "Core*") {
		Get-ScheduledTask -TaskName QueueReporting | Disable-ScheduledTask
		New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name Disabled -PropertyType DWord -Value 1 -Force
	}
}

# Turn on Windows Error Reporting for the current user
# Включить отчеты об ошибках Windows для текущего пользователя
function EnableWindowsErrorReporting {
	Get-ScheduledTask -TaskName QueueReporting | Enable-ScheduledTask
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name Disabled -Force -ErrorAction SilentlyContinue
}

# Change Windows feedback frequency to "Never" for the current user
# Изменить частоту формирования отзывов на "Никогда" для текущего пользователя
function DisableWindowsFeedback {
	if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Siuf\Rules)) {
		New-Item -Path HKCU:\SOFTWARE\Microsoft\Siuf\Rules -Force
	}
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Siuf\Rules -Name NumberOfSIUFInPeriod -PropertyType DWord -Value 0 -Force
}

# Change Windows Feedback frequency to "Automatically" for the current user
# Изменить частоту формирования отзывов на "Автоматически" для текущего пользователя
function EnableWindowsFeedback {
	Remove-Item -Path HKCU:\SOFTWARE\Microsoft\Siuf\Rules -Force -ErrorAction SilentlyContinue
}

# Turn off tracking apps launch event
function TurnOffAppLaunchTracking { 
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Start_TrackProgs -PropertyType DWord -Value 0 -Force
}

# Turn off diagnostics tracking scheduled tasks
# Отключить задачи диагностического отслеживания
function DisableScheduledTasks {
	$ScheduledTaskList = @(
		# Collects program telemetry information if opted-in to the Microsoft Customer Experience Improvement Program.
		# Собирает телеметрические данные программы при участии в Программе улучшения качества программного обеспечения Майкрософт
		"Microsoft Compatibility Appraiser",

		# Collects program telemetry information if opted-in to the Microsoft Customer Experience Improvement Program
		# Сбор телеметрических данных программы при участии в программе улучшения качества ПО
		"ProgramDataUpdater",

		# This task collects and uploads autochk SQM data if opted-in to the Microsoft Customer Experience Improvement Program
		# Эта задача собирает и загружает данные SQM при участии в программе улучшения качества программного обеспечения
		"Proxy",

		# If the user has consented to participate in the Windows Customer Experience Improvement Program, this job collects and sends usage data to Microsoft
		# Если пользователь изъявил желание участвовать в программе по улучшению качества программного обеспечения Windows, эта задача будет собирать и отправлять сведения о работе программного обеспечения в Майкрософт
		"Consolidator",

		# The USB CEIP (Customer Experience Improvement Program) task collects Universal Serial Bus related statistics and information about your machine and sends it to the Windows Device Connectivity engineering group at Microsoft
		# При выполнении задачи программы улучшения качества ПО шины USB (USB CEIP) осуществляется сбор статистических данных об использовании универсальной последовательной шины USB и с ведений о компьютере, которые направляются инженерной группе Майкрософт по вопросам подключения устройств в Windows
		"UsbCeip",

		# The Windows Disk Diagnostic reports general disk and system information to Microsoft for users participating in the Customer Experience Program
		# Для пользователей, участвующих в программе контроля качества программного обеспечения, служба диагностики дисков Windows предоставляет общие сведения о дисках и системе в корпорацию Майкрософт
		"Microsoft-Windows-DiskDiagnosticDataCollector",

		# Protects user files from accidental loss by copying them to a backup location when the system is unattended
		# Защищает файлы пользователя от случайной потери за счет их копирования в резервное расположение, когда система находится в автоматическом режиме
		"File History (maintenance mode)",

		# Measures a system's performance and capabilities
		# Измеряет быстродействие и возможности системы
		"WinSAT",

		# This task shows various Map related toasts
		# Эта задача показывает различные тосты (всплывающие уведомления) приложения "Карты"
		"MapsToastTask",

		# This task checks for updates to maps which you have downloaded for offline use
		# Эта задача проверяет наличие обновлений для карт, загруженных для автономного использования
		"MapsUpdateTask",

		# Initializes Family Safety monitoring and enforcement
		# Инициализация контроля и применения правил семейной безопасности
		"FamilySafetyMonitor",

		# Synchronizes the latest settings with the Microsoft family features service
		# Синхронизирует последние параметры со службой функций семьи учетных записей Майкрософт
		"FamilySafetyRefreshTask",

		# XblGameSave Standby Task
		"XblGameSaveTask"
	)

	# If device is not a laptop disable FODCleanupTask too
	# Если устройство не является ноутбуком, отключить также и FODCleanupTask
	if ((Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType -ne 2) {
		# Windows Hello
		$ScheduledTaskList += "FODCleanupTask"
	}

	Get-ScheduledTask -TaskName $ScheduledTaskList | Disable-ScheduledTask
}

# Turn on diagnostics tracking scheduled tasks
# Включить задачи диагностического отслеживания
function EnableScheduledTasks {
	$ScheduledTaskList = @(
		# Collects program telemetry information if opted-in to the Microsoft Customer Experience Improvement Program.
		# Собирает телеметрические данные программы при участии в Программе улучшения качества программного обеспечения Майкрософт
		"Microsoft Compatibility Appraiser",

		# Collects program telemetry information if opted-in to the Microsoft Customer Experience Improvement Program
		# Сбор телеметрических данных программы при участии в программе улучшения качества ПО
		"ProgramDataUpdater",

		# This task collects and uploads autochk SQM data if opted-in to the Microsoft Customer Experience Improvement Program
		# Эта задача собирает и загружает данные SQM при участии в программе улучшения качества программного обеспечения
		"Proxy",

		# If the user has consented to participate in the Windows Customer Experience Improvement Program, this job collects and sends usage data to Microsoft
		# Если пользователь изъявил желание участвовать в программе по улучшению качества программного обеспечения Windows, эта задача будет собирать и отправлять сведения о работе программного обеспечения в Майкрософт
		"Consolidator",

		# The USB CEIP (Customer Experience Improvement Program) task collects Universal Serial Bus related statistics and information about your machine and sends it to the Windows Device Connectivity engineering group at Microsoft
		# При выполнении задачи программы улучшения качества ПО шины USB (USB CEIP) осуществляется сбор статистических данных об использовании универсальной последовательной шины USB и с ведений о компьютере, которые направляются инженерной группе Майкрософт по вопросам подключения устройств в Windows
		"UsbCeip",

		# The Windows Disk Diagnostic reports general disk and system information to Microsoft for users participating in the Customer Experience Program
		# Для пользователей, участвующих в программе контроля качества программного обеспечения, служба диагностики дисков Windows предоставляет общие сведения о дисках и системе в корпорацию Майкрософт
		"Microsoft-Windows-DiskDiagnosticDataCollector",

		# Protects user files from accidental loss by copying them to a backup location when the system is unattended
		# Защищает файлы пользователя от случайной потери за счет их копирования в резервное расположение, когда система находится в автоматическом режиме
		"File History (maintenance mode)",

		# Measures a system's performance and capabilities
		# Измеряет быстродействие и возможности системы
		"WinSAT",

		# This task shows various Map related toasts
		# Эта задача показывает различные тосты (всплывающие уведомления) приложения "Карты"
		"MapsToastTask",

		# This task checks for updates to maps which you have downloaded for offline use
		# Эта задача проверяет наличие обновлений для карт, загруженных для автономного использования
		"MapsUpdateTask",

		# Initializes Family Safety monitoring and enforcement
		# Инициализация контроля и применения правил семейной безопасности
		"FamilySafetyMonitor",

		# Synchronizes the latest settings with the Microsoft family features service
		# Синхронизирует последние параметры со службой функций семьи учетных записей Майкрософт
		"FamilySafetyRefreshTask",

		# XblGameSave Standby Task
		"XblGameSaveTask"
	)

	# If device is not a laptop disable FODCleanupTask too
	# Если устройство не является ноутбуком, отключить также и FODCleanupTask
	if ((Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType -ne 2) {
		# HelloFace
		$ScheduledTaskList += "FODCleanupTask"
	}

	Get-ScheduledTask -TaskName $ScheduledTaskList | Enable-ScheduledTask
}

# Do not use sign-in info to automatically finish setting up device and reopen apps after an update or restart (current user only)
# Не использовать данные для входа для автоматического завершения настройки устройства и открытия приложений после перезапуска или обновления (только для текущего пользователя)
function DisableSigninInfo {
	$SID = (Get-CimInstance -ClassName Win32_UserAccount | Where-Object -FilterScript { $_.Name -eq $env:USERNAME }).SID
	if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID" -Force
	}
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID" -Name OptOut -PropertyType DWord -Value 1 -Force
}

# Use sign-in info to automatically finish setting up device and reopen apps after an update or restart (current user only)
# Использовать данные для входа для автоматического завершения настройки устройства и открытия приложений после перезапуска или обновления (только для текущего пользователя)
function EnableSigninInfo {
	$SID = (Get-CimInstance -ClassName Win32_UserAccount | Where-Object -FilterScript { $_.Name -eq $env:USERNAME }).SID
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID" -Name OptOut -Force -ErrorAction SilentlyContinue
}

# Do not let websites provide locally relevant content by accessing language list (current user only)
# Не позволять веб-сайтам предоставлять местную информацию за счет доступа к списку языков (только для текущего пользователя)
function DisableLanguageListAccess {
	New-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name HttpAcceptLanguageOptOut -PropertyType DWord -Value 1 -Force
}

# Let websites provide locally relevant content by accessing language list (current user only)
# Позволять веб-сайтам предоставлять местную информацию за счет доступа к списку языков (только для текущего пользователя)
function EnableLanguageListAccess {
	Remove-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name HttpAcceptLanguageOptOut -Force -ErrorAction SilentlyContinue
}

# Do not allow apps to use advertising ID (current user only)
# Не разрешать приложениям использовать идентификатор рекламы (только для текущего пользователя)
function DisableAdvertisingID {
	if (-not (Test-Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo)) {
		New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Force
	}
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Name Enabled -PropertyType DWord -Value 0 -Force
}

# Allow apps to use advertising ID (current user only)
# Разрешать приложениям использовать идентификатор рекламы (только для текущего пользователя)
function EnableAdvertisingID {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Name Enabled -PropertyType DWord -Value 1 -Force
}

# Do not let apps on other devices open and message apps on this device, and vice versa (current user only)
# Не разрешать приложениям на других устройствах запускать приложения и отправлять сообщения на этом устройстве и наоборот (только для текущего пользователя)
function DisableShareAcrossDevices {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP -Name RomeSdkChannelUserAuthzPolicy -PropertyType DWord -Value 0 -Force
}

# Let apps on other devices open and message apps on this device, and vice versa (current user only)
# Разрешать приложениям на других устройствах запускать приложения и отправлять сообщения на этом устройстве и наоборот (только для текущего пользователя)
function EnableShareAcrossDevices {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP -Name RomeSdkChannelUserAuthzPolicy -PropertyType DWord -Value 1 -Force
}

# Do not show the Windows welcome experiences after updates and occasionally when I sign in to highlight what's new and suggested (current user only)
# Не показывать экран приветствия Windows после обновлений и иногда при входе, чтобы сообщить о новых функциях и предложениях (только для текущего пользователя)
function DisableWindowsWelcomeExperience {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-310093Enabled -PropertyType DWord -Value 0 -Force
}

# Show the Windows welcome experiences after updates and occasionally when I sign in to highlight what's new and suggested (current user only)
# Показывать экран приветствия Windows после обновлений и иногда при входе, чтобы сообщить о новых функциях и предложениях (только для текущего пользователя)
function EnableWindowsWelcomeExperience {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-310093Enabled -PropertyType DWord -Value 1 -Force
}

# Get tip, trick, and suggestions as you use Windows (current user only)
# Получать советы, подсказки и рекомендации при использованию Windows (только для текущего пользователя)
function EnableWindowsTips {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338389Enabled -PropertyType DWord -Value 1 -Force
}

# Do not get tip, trick, and suggestions as you use Windows (current user only)
# Не получать советы, подсказки и рекомендации при использованию Windows (только для текущего пользователя)
function DisableWindowsTips {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338389Enabled -PropertyType DWord -Value 0 -Force
}

# Do not show suggested content in the Settings app (current user only)
# Не показывать рекомендуемое содержимое в приложении "Параметры" (только для текущего пользователя)
function DisableSuggestedContent {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338393Enabled -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-353694Enabled -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-353696Enabled -PropertyType DWord -Value 0 -Force
}

# Show suggested content in the Settings app (current user only)
# Показывать рекомендуемое содержимое в приложении "Параметры" (только для текущего пользователя)
function EnableSuggestedContent {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338393Enabled -PropertyType DWord -Value 1 -Force
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-353694Enabled -PropertyType DWord -Value 1 -Force
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-353696Enabled -PropertyType DWord -Value 1 -Force
}

# Turn off automatic installing suggested apps (current user only)
# Отключить автоматическую установку рекомендованных приложений (только для текущего пользователя)
function DisableAppsSilentInstalling {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SilentInstalledAppsEnabled -PropertyType DWord -Value 0 -Force
}

# Turn on automatic installing suggested apps (current user only)
# Включить автоматическую установку рекомендованных приложений (только для текущего пользователя)
function EnableAppsSilentInstalling {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SilentInstalledAppsEnabled -PropertyType DWord -Value 1 -Force
}

# Do not suggest ways I can finish setting up my device to get the most out of Windows (current user only)
# Не предлагать способы завершения настройки устройства для максимально эффективного использования Windows (только для текущего пользователя)
function DisableWhatsNewInWindows {
	if (-not (Test-Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement)) {
		New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement -Force
	}
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement -Name ScoobeSystemSettingEnabled -PropertyType DWord -Value 0 -Force
}

# Suggest ways I can finish setting up my device to get the most out of Windows
# Предлагать способы завершения настройки устройства для максимально эффективного использования Windows
function EnableWhatsNewInWindows {
	if (-not (Test-Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement)) {
		New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement -Force
	}
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement -Name ScoobeSystemSettingEnabled -PropertyType DWord -Value 1 -Force
}

# Do not offer tailored experiences based on the diagnostic data setting (current user only)
# Не предлагать персонализированные возможности, основанные на выбранном параметре диагностических данных (только для текущего пользователя)
function DisableTailoredExperiences {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy -Name TailoredExperiencesWithDiagnosticDataEnabled -PropertyType DWord -Value 0 -Force
}

# Offer tailored experiences based on the diagnostic data setting
# Предлагать персонализированные возможности, основанные на выбранном параметре диагностических данных
function EnableTailoredExperiences {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy -Name TailoredExperiencesWithDiagnosticDataEnabled -PropertyType DWord -Value 1 -Force
}

# Disable Bing search in the Start Menu (for the USA only)
# Отключить поиск через Bing в меню "Пуск" (только для США)
function DisableBingSearch {
	if ((Get-WinHomeLocation).GeoId -eq 244) {
		if (-not (Test-Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer)) {
			New-Item -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Force
		}
		New-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name DisableSearchBoxSuggestions -PropertyType DWord -Value 1 -Force
	}
}

# Enable Bing search in the Start Menu only (for the USA only)
# Включить в меню "Пуск" поиск через Bing (только для США)
function EnableBingSearch {
	if ((Get-WinHomeLocation).GeoId -eq 244) {
		Remove-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name DisableSearchBoxSuggestions -Force -ErrorAction SilentlyContinue
	}
}
#endregion Privacy & Telemetry
#region Start menu
# Unpin all the Start tiles
# Открепить все ярлыки от начального экрана
function UnpinAllStartTiles {
	$StartMenuLayout = @"
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
<LayoutOptions StartTileGroupCellWidth="6" />
	<DefaultLayoutOverride>
		<StartLayoutCollection>
			<defaultlayout:StartLayout GroupCellWidth="6" />
		</StartLayoutCollection>
	</DefaultLayoutOverride>
</LayoutModificationTemplate>
"@
	$StartMenuLayoutPath = "$env:TEMP\StartMenuLayout.xml"
	# Saving StartMenuLayout.xml in UTF-8 encoding
	# Сохраняем StartMenuLayout.xml в кодировке UTF-8
	Set-Content -Path $StartMenuLayoutPath -Value (New-Object -TypeName System.Text.UTF8Encoding).GetBytes($StartMenuLayout) -Encoding Byte -Force

	# Temporarily disable changing the Start menu layout
	# Временно выключаем возможность редактировать начальный экран меню "Пуск"
	if (-not (Test-Path -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer)) {
		New-Item -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Force
	}
	New-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name LockedStartLayout -Value 1 -Force
	New-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name StartLayoutFile -Value $StartMenuLayoutPath -Force

	# Restart the Start menu
	# Перезапустить меню "Пуск"
	Stop-Process -Name StartMenuExperienceHost -Force -ErrorAction Ignore
	Start-Sleep -Seconds 3

	Remove-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name LockedStartLayout -Force -ErrorAction Ignore
	Remove-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name StartLayoutFile -Force -ErrorAction Ignore

	Stop-Process -Name StartMenuExperienceHost -Force -ErrorAction Ignore
	Get-Item -Path $StartMenuLayoutPath | Remove-Item -Force -ErrorAction Ignore
}

# Do not show recently added apps in the Start menu
# Не показывать недавно добавленные приложения в меню "Пуск"
function HideRecentlyAddedApps {
	if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer)) {
		New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Force
	}
	New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name HideRecentlyAddedApps -PropertyType DWord -Value 1 -Force
}

# Show recently added apps in the Start menu
# Показывать недавно добавленные приложения в меню "Пуск"
function ShowRecentlyAddedApps {
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name HideRecentlyAddedApps -Force -ErrorAction SilentlyContinue
}

# Do not show app suggestions in the Start menu
# Не показывать рекомендации в меню "Пуск"
function HideAppSuggestions {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338388Enabled -PropertyType DWord -Value 0 -Force
}

# Show app suggestions in the Start menu
# Показывать рекомендации в меню "Пуск"
function ShowAppSuggestions {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338388Enabled -PropertyType DWord -Value 1 -Force
}
#endregion Start menu
#region UI & Personalization
# Do not use check boxes to select items (current user only)
# Не использовать флажки для выбора элементов (только для текущего пользователя)
function DisableCheckBoxes {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name AutoCheckSelect -PropertyType DWord -Value 0 -Force
}

# Use check boxes to select items (current user only)
# Использовать флажки для выбора элементов (только для текущего пользователя)
function EnableCheckBoxes {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name AutoCheckSelect -PropertyType DWord -Value 1 -Force
}

# Show hidden files, folders, and drives (current user only)
# Показывать скрытые файлы, папки и диски (только для текущего пользователя)
function ShowHiddenItems {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Hidden -PropertyType DWord -Value 1 -Force
}

# Do not show hidden files, folders, and drives (current user only)
# Не показывать скрытые файлы, папки и диски (только для текущего пользователя)
function HideHiddenItems {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Hidden -PropertyType DWord -Value 2 -Force
}

# Show file name extensions (current user only)
# Показывать расширения имён файлов (только для текущего пользователя)
function ShowFileExtensions {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -PropertyType DWord -Value 0 -Force
}

# Do not show file name extensions (current user only)
# Не показывать расширения имён файлов файлов (только для текущего пользователя)
function HideFileExtensions {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -PropertyType DWord -Value 1 -Force
}

# Do not hide folder merge conflicts (current user only)
# Не скрывать конфликт слияния папок (только для текущего пользователя)
function ShowMergeConflicts {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideMergeConflicts -PropertyType DWord -Value 1 -Force
}

# Hide folder merge conflicts (current user only)
# Скрывать конфликт слияния папок (только для текущего пользователя)
function HideMergeConflicts {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideMergeConflicts -PropertyType DWord -Value 0 -Force
}

# Open File Explorer to: "This PC" (current user only)
# Открывать проводник для: "Этот компьютер" (только для текущего пользователя)
function OpenFileExplorerToThisPC {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -PropertyType DWord -Value 1 -Force
}

# Open File Explorer to: "Quick access" (current user only)
# Открывать проводник для: "Быстрый доступ" (только для текущего пользователя)
function OpenFileExplorerToQuickAccess {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -PropertyType DWord -Value 2 -Force
}

# Do not show Cortana button on the taskbar (current user only)
# Не показывать кнопку Кортаны на панели задач (только для текущего пользователя)
function HideCortanaButton {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowCortanaButton -PropertyType DWord -Value 0 -Force
}

# Show Cortana button on the taskbar (current user only)
# Показывать кнопку Кортаны на панели задач (только для текущего пользователя)
function ShowCortanaButton {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowCortanaButton -PropertyType DWord -Value 1 -Force
}

# Do not show Task View button on the taskbar (current user only)
# Не показывать кнопку Просмотра задач (только для текущего пользователя)
function HideTaskViewButton {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowTaskViewButton -PropertyType DWord -Value 0 -Force
}

# Show Task View button on the taskbar (current user only)
# Показывать кнопку Просмотра задач (только для текущего пользователя)
function ShowTaskViewButton {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowTaskViewButton -PropertyType DWord -Value 1 -Force
}

# Do not show People button on the taskbar (current user only)
# Не показывать панель "Люди" на панели задач (только для текущего пользователя)
function HidePeopleTaskbar {
	if (-not (Test-Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People)) {
		New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People -Force
	}
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People -Name PeopleBand -PropertyType DWord -Value 0 -Force
}

# Show People button on the taskbar (current user only)
# Показывать панель "Люди" на панели задач (только для текущего пользователя)
function ShowPeopleTaskbar {
	if (-not (Test-Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People)) {
		New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People -Force
	}
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People -Name PeopleBand -PropertyType DWord -Value 1 -Force
}

# Show seconds on the taskbar clock (current user only)
# Отображать секунды в системных часах на панели задач (только для текущего пользователя)
function ShowSecondsInSystemClock {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowSecondsInSystemClock -PropertyType DWord -Value 1 -Force
}

# Do not show seconds on the taskbar clock (current user only)
# не отображать секунды в системных часах на панели задач (только для текущего пользователя)
function HideSecondsInSystemClock {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowSecondsInSystemClock -PropertyType DWord -Value 0 -Force
}

# Do not show when snapping a window, what can be attached next to it (current user only)
# Не показывать при прикреплении окна, что можно прикрепить рядом с ним (только для текущего пользователя)
function DisableSnapAssist {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name SnapAssist -PropertyType DWord -Value 0 -Force
}

# Show when snapping a window, what can be attached next to it (current user only)
# Показывать при прикреплении окна, что можно прикрепить рядом с ним (только для текущего пользователя)
function EnableSnapAssist {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name SnapAssist -PropertyType DWord -Value 1 -Force
}

# Always open the file transfer dialog box in the detailed mode (current user only)
# Всегда открывать диалоговое окно передачи файлов в развернутом виде (только для текущего пользователя)
function FileTransferDialogDetailed {
	if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager)) {
		New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager -Force
	}
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager -Name EnthusiastMode -PropertyType DWord -Value 1 -Force
}

# Always open the file transfer dialog box in the compact mode (current user only)
# Всегда открывать диалоговое окно передачи файлов в свернутом виде (только для текущего пользователя)
function FileTransferDialogCompact {
	if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager)) {
		New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager -Force
	}
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager -Name EnthusiastMode -PropertyType DWord -Value 0 -Force
}

# Show the ribbon expanded in File Explorer (current user only)
# Отображать ленту проводника в развернутом виде (только для текущего пользователя)
function FileExplorerRibbonExpanded {
	if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Ribbon)) {
		New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Ribbon -Force
	}
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Ribbon -Name MinimizedStateTabletModeOff -PropertyType DWord -Value 0 -Force
}

# Do not show the ribbon expanded in File Explorer (current user only)
# Не отображать ленту проводника в развернутом виде (только для текущего пользователя)
function FileExplorerRibbonMinimized {
	if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Ribbon)) {
		New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Ribbon -Force
	}
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Ribbon -Name MinimizedStateTabletModeOff -PropertyType DWord -Value 1 -Force
}

# Display recycle bin files delete confirmation
# Запрашивать подтверждение на удаление файлов в корзину
function EnableRecycleBinDeleteConfirmation {
	$ShellState = Get-ItemPropertyValue -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShellState
	$ShellState[4] = 51
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShellState -PropertyType Binary -Value $ShellState -Force

	$UpdateDesktop = @{
		Namespace        = "WinAPI"
		Name             = "UpdateDesktop"
		Language         = "CSharp"
		MemberDefinition = @"
private static readonly IntPtr hWnd = new IntPtr(65535);
private const int Msg = 273;
// Virtual key ID of the F5 in File Explorer
// Виртуальный код клавиши F5 в проводнике
private static readonly UIntPtr UIntPtr = new UIntPtr(41504);

[DllImport("user32.dll", SetLastError=true)]
public static extern int PostMessageW(IntPtr hWnd, uint Msg, UIntPtr wParam, IntPtr lParam);
public static void PostMessage()
{
	// F5 pressing simulation to refresh the desktop
	// Симуляция нажатия F5 для обновления рабочего стола
	PostMessageW(hWnd, Msg, UIntPtr, IntPtr.Zero);
}
"@
	}
	if (-not ("WinAPI.UpdateDesktop" -as [type])) {
		Add-Type @UpdateDesktop
	}

	# Send F5 pressing simulation to refresh the desktop
	# Симулировать нажатие F5 для обновления рабочего стола
	[WinAPI.UpdateDesktop]::PostMessage()
}

# Do not display recycle bin files delete confirmation
# Не запрашивать подтверждение на удаление файлов в корзину
function DisableRecycleBinDeleteConfirmation {
	$ShellState = Get-ItemPropertyValue -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShellState
	$ShellState[4] = 55
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShellState -PropertyType Binary -Value $ShellState -Force

	$UpdateDesktop = @{
		Namespace        = "WinAPI"
		Name             = "UpdateDesktop"
		Language         = "CSharp"
		MemberDefinition = @"
private static readonly IntPtr hWnd = new IntPtr(65535);
private const int Msg = 273;
// Virtual key ID of the F5 in File Explorer
// Виртуальный код клавиши F5 в проводнике
private static readonly UIntPtr UIntPtr = new UIntPtr(41504);

[DllImport("user32.dll", SetLastError=true)]
public static extern int PostMessageW(IntPtr hWnd, uint Msg, UIntPtr wParam, IntPtr lParam);
public static void PostMessage()
{
	// F5 pressing simulation to refresh the desktop
	// Симуляция нажатия F5 для обновления рабочего стола
	PostMessageW(hWnd, Msg, UIntPtr, IntPtr.Zero);
}
"@
	}
	if (-not ("WinAPI.UpdateDesktop" -as [type])) {
		Add-Type @UpdateDesktop
	}

	# Send F5 pressing simulation to refresh the desktop
	# Симулировать нажатие F5 для обновления рабочего стола
	[WinAPI.UpdateDesktop]::PostMessage()
}

# Hide the "3D Objects" folder from "This PC" and "Quick access" (current user only)
# Скрыть папку "Объемные объекты" из "Этот компьютер" и из панели быстрого доступа (только для текущего пользователя)
function Hide3DObjects {
	if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force
	}
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name ThisPCPolicy -PropertyType String -Value Hide -Force

	# Save all opened folders in order to restore them after File Explorer restart
	# Сохранить все открытые папки, чтобы восстановить их после перезапуска проводника
	Clear-Variable -Name OpenedFolders -Force -ErrorAction Ignore
	$OpenedFolders = { (New-Object -ComObject Shell.Application).Windows() | ForEach-Object -Process { $_.Document.Folder.Self.Path } }.Invoke()

	# In order for the changes to take effect the File Explorer process has to be restarted
	# Чтобы изменения вступили в силу, необходимо перезапустить процесс проводника
	Stop-Process -Name explorer -Force

	# Restore closed folders
	# Восстановить закрытые папки
	foreach ($OpenedFolder in $OpenedFolders) {
		if (Test-Path -Path $OpenedFolder) {
			Invoke-Item -Path $OpenedFolder
		}
	}
}

# Show the "3D Objects" folder from "This PC" and "Quick access" (current user only)
# Отобразить папку "Объемные объекты" из "Этот компьютер" и из панели быстрого доступа (только для текущего пользователя)
function Show3DObjects {
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name ThisPCPolicy -Force -ErrorAction SilentlyContinue

	# Save all opened folders in order to restore them after File Explorer restart
	# Сохранить все открытые папки, чтобы восстановить их после перезапуска проводника
	Clear-Variable -Name OpenedFolders -Force -ErrorAction Ignore
	$OpenedFolders = { (New-Object -ComObject Shell.Application).Windows() | ForEach-Object -Process { $_.Document.Folder.Self.Path } }.Invoke()

	# In order for the changes to take effect the File Explorer process has to be restarted
	# Чтобы изменения вступили в силу, необходимо перезапустить процесс проводника
	Stop-Process -Name explorer -Force

	# Restore closed folders
	# Восстановить закрытые папки
	foreach ($OpenedFolder in $OpenedFolders) {
		if (Test-Path -Path $OpenedFolder) {
			Invoke-Item -Path $OpenedFolder
		}
	}
}

# Do not show frequently used folders in "Quick access" (current user only)
# Не показывать недавно используемые папки на панели быстрого доступа (только для текущего пользователя)
function HideQuickAccessFrequentFolders {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowFrequent -PropertyType DWord -Value 0 -Force
}

# Show frequently used folders in "Quick access" (current user only)
# Показывать недавно используемые папки на панели быстрого доступа (только для текущего пользователя)
function ShowQuickAccessFrequentFolders {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowFrequent -PropertyType DWord -Value 1 -Force
}

# Do not show recently used files in Quick access (current user only)
# Не показывать недавно использовавшиеся файлы на панели быстрого доступа (только для текущего пользователя)
function HideQuickAccessRecentFiles {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowRecent -PropertyType DWord -Value 0 -Force
}

# Show recently used files in Quick access (current user only)
# Показывать недавно использовавшиеся файлы на панели быстрого доступа (только для текущего пользователя)
function ShowQuickAccessShowRecentFiles {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowRecent -PropertyType DWord -Value 1 -Force
}

# Hide the search box or the search icon from the taskbar (current user only)
# Скрыть поле или значок поиска на панели задач (только для текущего пользователя)
function HideTaskbarSearch {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name SearchboxTaskbarMode -PropertyType DWord -Value 0 -Force
}

# Show the search box from the taskbar (current user only)
# Показать поле поиска на панели задач (только для текущего пользователя)
function ShowTaskbarSearch {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name SearchboxTaskbarMode -PropertyType DWord -Value 2 -Force
}

# Do not show the "Windows Ink Workspace" button on the taskbar (current user only)
# Не показывать кнопку Windows Ink Workspace на панели задач (current user only)
function HideWindowsInkWorkspace {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace -Name PenWorkspaceButtonDesiredVisibility -PropertyType DWord -Value 0 -Force
}

# Show the "Windows Ink Workspace" button in taskbar (current user only)
# Показывать кнопку Windows Ink Workspace на панели задач (current user only)
function ShowWindowsInkWorkspace {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace -Name PenWorkspaceButtonDesiredVisibility -PropertyType DWord -Value 1 -Force
}

# Always show all icons in the notification area (current user only)
# Всегда отображать все значки в области уведомлений (только для текущего пользователя)
function ShowTrayIcons {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name EnableAutoTray -PropertyType DWord -Value 0 -Force
}

# Do not show all icons in the notification area (current user only)
# Не отображать все значки в области уведомлений (только для текущего пользователя)
function HideTrayIcons {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name EnableAutoTray -PropertyType DWord -Value 1 -Force
}

# Unpin all taskbar icons
function UnpinAllTaskbarIcons {
	New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "Favorites" -Type Binary -Value ([byte[]](255)) -Force
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "FavoritesResolve" -ErrorAction SilentlyContinue -Force
}

# View the Control Panel icons by: large icons (current user only)
# Просмотр иконок Панели управления как: крупные значки (только для текущего пользователя)
function ControlPanelLargeIcons {
	if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel)) {
		New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Force
	}
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Name AllItemsIconView -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Name StartupPage -PropertyType DWord -Value 1 -Force
}

# View the Control Panel icons by: category (current user only)
# Просмотр значки Панели управления как "категория" (только для текущего пользователя)
function ControlPanelCategoryIcons {
	if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel)) {
		New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Force
	}
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Name AllItemsIconView -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Name StartupPage -PropertyType DWord -Value 0 -Force
}

# Set the Windows mode color scheme to the light (current user only)
# Установить режим цвета для Windows на светлый (только для текущего пользователя)
function WindowsColorSchemeLight {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name SystemUsesLightTheme -PropertyType DWord -Value 1 -Force
}

# Set the Windows mode color scheme to the dark (current user only)
# Установить цвет режима Windows по умолчанию на темный (только для текущего пользователя)
function WindowsColorSchemeDark {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name SystemUsesLightTheme -PropertyType DWord -Value 0 -Force
}

# Set the default app mode color scheme to the light (current user only)
# Установить цвет режима приложений по умолчанию на светлый (только для текущего пользователя)
function AppModeLight {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -PropertyType DWord -Value 1 -Force
}

# Set the default app mode color scheme to the dark (current user only)
# Установить цвет режима приложений по умолчанию на темный (только для текущего пользователя)
function AppModeDark {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -PropertyType DWord -Value 0 -Force
}

# Do not show the "New App Installed" indicator
# Не показывать уведомление "Установлено новое приложение"
function DisableNewAppInstalledNotification {
	if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer)) {
		New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Force
	}
	New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name NoNewAppAlert -PropertyType DWord -Value 1 -Force
}

# Show the "New App Installed" indicator
# Показывать уведомление "Установлено новое приложение"
function EnableNewAppInstalledNotification {
	if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer)) {
		New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Force
	}
	New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name NoNewAppAlert -PropertyType DWord -Value 0 -Force
}

# Do not show user first sign-in animation after the upgrade
# Не показывать анимацию при первом входе в систему после обновления
function HideFirstSigninAnimation {
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableFirstLogonAnimation -PropertyType DWord -Value 0 -Force
}

# Show user first sign-in animation the upgrade
# Показывать анимацию при первом входе в систему после обновления
function ShowFirstSigninAnimation {
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableFirstLogonAnimation -PropertyType DWord -Value 1 -Force
}

# Set the quality factor of the JPEG desktop wallpapers to maximum (current user only)
# Установить коэффициент качества обоев рабочего стола в формате JPEG на максимальный (только для текущего пользователя)
function JPEGWallpapersQualityMax {
	New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name JPEGImportQuality -PropertyType DWord -Value 100 -Force
}

# Set the quality factor of the JPEG desktop wallpapers to default (current user only)
# Установить коэффициент качества обоев рабочего стола в формате JPEG по умолчанию (только для текущего пользователя)
function JPEGWallpapersQualityDefault {
	Remove-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name JPEGImportQuality -Force -ErrorAction SilentlyContinue
}

# Start Task Manager in expanded mode (current user only)
# Запускать Диспетчера задач в развернутом виде (только для текущего пользователя)
function TaskManagerWindowExpanded {
	$Taskmgr = Get-Process -Name Taskmgr -ErrorAction Ignore
	if ($Taskmgr) {
		$Taskmgr.CloseMainWindow()
	}
	Start-Process -FilePath Taskmgr.exe -WindowStyle Hidden -PassThru

	do {
		Start-Sleep -Milliseconds 100
		$Preferences = Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\TaskManager -Name Preferences -ErrorAction Ignore
	}
	until ($Preferences)

	Stop-Process -Name Taskmgr

	$Preferences.Preferences[28] = 0
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\TaskManager -Name Preferences -PropertyType Binary -Value $Preferences.Preferences -Force
}

# Start Task Manager in compact mode (current user only)
# Запускать Диспетчера задач в свернутом виде (только для текущего пользователя)
function TaskManagerWindowCompact {
	$Taskmgr = Get-Process -Name Taskmgr -ErrorAction Ignore
	if ($Taskmgr) {
		$Taskmgr.CloseMainWindow()
	}
	Start-Process -FilePath Taskmgr.exe -WindowStyle Hidden -PassThru

	do {
		Start-Sleep -Milliseconds 100
		$Preferences = Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\TaskManager -Name Preferences -ErrorAction Ignore
	}
	until ($Preferences)

	Stop-Process -Name Taskmgr

	$Preferences.Preferences[28] = 1
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\TaskManager -Name Preferences -PropertyType Binary -Value $Preferences.Preferences -Force
}

# Show a notification when your PC requires a restart to finish updating
# Показывать уведомление, когда компьютеру требуется перезагрузка для завершения обновления
function ShowRestartNotification {
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name RestartNotificationsAllowed2 -PropertyType DWord -Value 1 -Force
}

# Do not show a notification when your PC requires a restart to finish updating
# Не показывать уведомление, когда компьютеру требуется перезагрузка для завершения обновления
function HideRestartNotification {
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name RestartNotificationsAllowed2 -PropertyType DWord -Value 0 -Force
}

# Do not add the "- Shortcut" suffix to the file name of created shortcuts (current user only)
# Нe дoбaвлять "- яpлык" к имени coздaвaeмых яpлыков (только для текущего пользователя)
function DisableShortcutsSuffix {
	if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates)) {
		New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates -Force
	}
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates -Name ShortcutNameTemplate -PropertyType String -Value "%s.lnk" -Force
}

# Add the "- Shortcut" suffix to the file name of created shortcuts (current user only)
# Дoбaвлять "- яpлык" к имени coздaвaeмых яpлыков (только для текущего пользователя)
function EnableShortcutsSuffix {
	Remove-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates -Name ShortcutNameTemplate -Force -ErrorAction SilentlyContinue
}

# Use the PrtScn button to open screen snipping (current user only)
# Использовать кнопку PRINT SCREEN, чтобы запустить функцию создания фрагмента экрана (только для текущего пользователя)
function EnablePrtScnSnippingTool {
	New-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name PrintScreenKeyForSnippingEnabled -PropertyType DWord -Value 1 -Force
}

# Do not use the PrtScn button to open screen snipping (current user only)
# Не использовать кнопку PRINT SCREEN, чтобы запустить функцию создания фрагмента экрана (только для текущего пользователя)
function DisablePrtScnSnippingTool {
	New-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name PrintScreenKeyForSnippingEnabled -PropertyType DWord -Value 0 -Force
}

# Change taskbar location
function ChangeTaskbarLocation {
	$Value = "28,00,00,00,ff,ff,ff,ff,02,00,00,00,00,00,00,00,3e,00,00,00,2e,00,00,00,00,00,00,00,00,00,00,00,3e,00,00,00,b0,04,00,00"
	$RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3"
	$Name = "Settings"
	$hexified = $Value.Split(',') | ForEach-Object { "0x$_" }
	
	New-ItemProperty -Path $RegPath -Name $Name -PropertyType Binary -Value ([byte[]]$hexified) -Force
}

# Change desktop background
function ChangeDesktopBackground {
    Read-Host 'Please make sure your internet is available [ENTER TO CONTINUE]'
	Start-BitsTransfer -Source "https://raw.githubusercontent.com/YurinDoctrine/W10-Fresh/main/Fresh/Wallpaper.jpg" -Destination $env\Windows\Web\Wallpaper\Windows\Wallpaper.jpg
	New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name WallPaper -Type String -Value "C:\Windows\Web\Wallpaper\Windows\Wallpaper.jpg" -Force
	New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name WallPaperStyle -Type String -Value 10 -Force
}
#endregion UI & Personalization
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
		# Microsoft Desktop App Installer
		#"Microsoft.DesktopAppInstaller",

		# Microsoft Store
		"Microsoft.WindowsStore",
		
		# AMD Radeon UWP panel
		# UWP-панель AMD Radeon
		"AdvancedMicroDevicesInc*",

		# NVIDIA Control Panel
		# Панель управления NVidia
		"NVIDIACorp.NVIDIAControlPanel",

		# Realtek Audio Control
		"RealtekSemiconductorCorp.RealtekAudioControl"
		
	)
	
	if (Get-AppxPackage -PackageTypeFilter Bundle -AllUsers | Where-Object -FilterScript { $_.Name -cnotmatch ($ExcludedAppxPackages -join "|") } | Remove-AppxPackage -AllUsers ) {
		Write-Verbose -Message 'Removed UWP apps' -Verbose
	}
	else {
		Write-Verbose -Message $Localization.NoData -Verbose
	}
}

# Do not let UWP apps run in the background, except the followings... (current user only)
# Не разрешать UWP-приложениям работать в фоновом режиме, кроме следующих... (только для текущего пользователя)
function DisableBackgroundUWPApps {
	Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications | ForEach-Object -Process {
		Remove-ItemProperty -Path $_.PsPath -Name * -Force
	}

	$ExcludedBackgroundApps = @(

		# Windows Search
		"Microsoft.Windows.Search",

		# Windows Security
		# Безопасность Windows
		"Microsoft.Windows.SecHealthUI",

		# Windows Shell Experience (Action center, snipping support, toast notification, touch screen keyboard)
		# Windows Shell Experience (Центр уведомлений, приложение "Ножницы", тостовые уведомления, сенсорная клавиатура)
		"Microsoft.Windows.ShellExperienceHost",

		# The Start menu
		# Меню "Пуск"
		"Microsoft.Windows.StartMenuExperienceHost",

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

# Turn on Cortana autostarting
# Добавить Кортана в автозагрузку
function EnableCortanaAutostart {
	if (Get-AppxPackage -Name Microsoft.549981C3F5F10) {
		Remove-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.549981C3F5F10_8wekyb3d8bbwe\CortanaStartupId" -Name State -Force -ErrorAction SilentlyContinue
	}
}
#endregion UWP apps
#region System
# Uninstall OneDrive
# Удалить OneDrive
function UninstallOneDrive {
	[string]$UninstallString = Get-Package -Name "Microsoft OneDrive" -ProviderName Programs -ErrorAction Ignore | ForEach-Object -Process { $_.Meta.Attributes["UninstallString"] }
	if ($UninstallString) {
		Write-Verbose -Message $Localization.OneDriveUninstalling -Verbose
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
			$Message = Invoke-Command -ScriptBlock ([ScriptBlock]::Create($Localization.OneDriveNotEmptyFolder))
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
        
        # Terminate File Explorer process
		# Завершить процесс проводника
		TASKKILL /F /IM explorer.exe
		
        # Attempt to unregister FileSyncShell64.dll and remove
		# Попытка разрегистрировать FileSyncShell64.dll и удалить
		$FileSyncShell64dlls = Get-ChildItem -Path "$OneDriveFolder\*\amd64\FileSyncShell64.dll" -Force
		foreach ($FileSyncShell64dll in $FileSyncShell64dlls.FullName) {
			Start-Process -FilePath regsvr32.exe -ArgumentList "/u /s $FileSyncShell64dll" -Wait
			Remove-Item -Path $FileSyncShell64dll -Force -ErrorAction Ignore

			if (Test-Path -Path $FileSyncShell64dll) {
				$Message = Invoke-Command -ScriptBlock ([ScriptBlock]::Create($Localization.OneDriveFileSyncShell64dllBlocked))
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

# Do not show sync provider notification within File Explorer (current user only)
# Не показывать уведомления поставщика синхронизации в проводнике (только для текущего пользователя)
function HideOneDriveFileExplorerAd {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowSyncProviderNotifications -PropertyType DWord -Value 0 -Force
}

# Turn on Storage Sense (current user only)
# Включить Контроль памяти (только для текущего пользователя)
function EnableStorageSense {
	if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy)) {
		New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -ItemType Directory -Force
	}
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 01 -PropertyType DWord -Value 1 -Force
}

# Turn off Storage Sense (current user only)
# Выключить Контроль памяти (только для текущего пользователя)
function DisableStorageSense {
	if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy)) {
		New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -ItemType Directory -Force
	}
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 01 -PropertyType DWord -Value 0 -Force
}

# Run Storage Sense every month (current user only)
# Запускать Контроль памяти каждый месяц (только для текущего пользователя)
function StorageSenseMonthFrequency {
	if ((Get-ItemPropertyValue -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 01) -eq "1") {
		New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 2048 -PropertyType DWord -Value 30 -Force
	}
}

# Run Storage Sense during low free disk space (default value) (current user only)
# Запускать Контроль памяти, когда остается мало место на диске (значение по умолчанию) (только для текущего пользователя)
function StorageSenseDefaultFrequency {
	if ((Get-ItemPropertyValue -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 01) -eq "1") {
		New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 2048 -PropertyType DWord -Value 0 -Force
	}
}

# Delete temporary files that apps aren't using (current user only)
# Удалять временные файлы, не используемые в приложениях (только для текущего пользователя)
function EnableStorageSenseTempFiles {
	if ((Get-ItemPropertyValue -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 01) -eq "1") {
		New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 04 -PropertyType DWord -Value 1 -Force
	}
}

# Do not delete temporary files that apps aren't using (current user only)
# Не удалять временные файлы, не используемые в приложениях (только для текущего пользователя)
function DisableStorageSenseTempFiles {
	if ((Get-ItemPropertyValue -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 01) -eq "1") {
		New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 04 -PropertyType DWord -Value 0 -Force
	}
}

# Delete files in recycle bin if they have been there for over 30 days (current user only)
# Удалять файлы из корзины, если они находятся в корзине более 30 дней (только для текущего пользователя)
function EnableStorageSenseRecycleBin {
	if ((Get-ItemPropertyValue -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 01) -eq "1") {
		New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 08 -PropertyType DWord -Value 1 -Force
		New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 256 -PropertyType DWord -Value 30 -Force
	}
}

# Do not delete files in recycle bin if they have been there for over 30 days (current user only)
# Не удалять файлы из корзины, если они находятся в корзине более 30 дней(только для текущего пользователя)
function DisableStorageSenseRecycleBin {
	if ((Get-ItemPropertyValue -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 01) -eq "1") {
		New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 08 -PropertyType DWord -Value 0 -Force
		New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 256 -PropertyType DWord -Value 0 -Force
	}
}

# Disable hibernation if the device is not a laptop
# Отключить режим гибернации, если устройство не является ноутбуком
function DisableHibernate {
	if ((Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType -ne 2) {
		POWERCFG /HIBERNATE OFF
	}
}

# Turn on hibernate
# Включить режим гибернации
function EnableHibernate {
	POWERCFG /HIBERNATE ON
}

# Change the %TEMP% environment variable path to the %SystemDrive%\Temp (both machine-wide, and for the current user)
# Изменить путь переменной среды для %TEMP% на %SystemDrive%\Temp (для всех пользователей)
function SetTempPath {
	if (-not (Test-Path -Path $env:SystemDrive\Temp)) {
		New-Item -Path $env:SystemDrive\Temp -ItemType Directory -Force
	}

	[Environment]::SetEnvironmentVariable("TMP", "$env:SystemDrive\Temp", "User")
	[Environment]::SetEnvironmentVariable("TMP", "$env:SystemDrive\Temp", "Machine")
	[Environment]::SetEnvironmentVariable("TMP", "$env:SystemDrive\Temp", "Process")
	New-ItemProperty -Path HKCU:\Environment -Name TMP -PropertyType ExpandString -Value %SystemDrive%\Temp -Force

	[Environment]::SetEnvironmentVariable("TEMP", "$env:SystemDrive\Temp", "User")
	[Environment]::SetEnvironmentVariable("TEMP", "$env:SystemDrive\Temp", "Machine")
	[Environment]::SetEnvironmentVariable("TEMP", "$env:SystemDrive\Temp", "Process")
	New-ItemProperty -Path HKCU:\Environment -Name TEMP -PropertyType ExpandString -Value %SystemDrive%\Temp -Force

	New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name TMP -PropertyType ExpandString -Value %SystemDrive%\Temp -Force
	New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name TEMP -PropertyType ExpandString -Value %SystemDrive%\Temp -Force

	# Restart the Printer Spooler service (Spooler)
	# Перезапустить службу "Диспетчер печати" (Spooler)
	Restart-Service -Name Spooler -Force

	Stop-Process -Name OneDrive -Force -ErrorAction Ignore
	Stop-Process -Name FileCoAuth -Force -ErrorAction Ignore

	Remove-Item -Path $env:SystemRoot\Temp -Recurse -Force -ErrorAction Ignore
	Get-Item -Path $env:LOCALAPPDATA\Temp | Where-Object -FilterScript { $_.LinkType -ne "SymbolicLink" } | Remove-Item -Recurse -Force -ErrorAction Ignore

	# Create a symbolic link to the %SystemDrive%\Temp folder
	# Создать символическую ссылку к папке %SystemDrive%\Temp
	try {
		New-Item -Path $env:LOCALAPPDATA\Temp -ItemType SymbolicLink -Value $env:SystemDrive\Temp -Force
	}
	catch [System.Exception] {
		$Message = Invoke-Command -ScriptBlock ([ScriptBlock]::Create($Localization.LOCALAPPDATANotEmptyFolder))
		Write-Error -Message $Message -ErrorAction SilentlyContinue
	}
	finally {
		Invoke-Item -Path $env:LOCALAPPDATA\Temp
	}
}

# Change the %TEMP% environment variable path to the %LOCALAPPDATA%\Temp (default value) (both machine-wide, and for the current user)
# Изменить путь переменной среды для %TEMP% на LOCALAPPDATA%\Temp (значение по умолчанию) (для всех пользователей)
function SetDefaultTempPath {
	# Remove a symbolic link to the %SystemDrive%\Temp folder
	# Удалить символическую ссылку к папке %SystemDrive%\Temp
	(Get-Item -Path $env:LOCALAPPDATA\Temp -Force).Delete()

	if (-not (Test-Path -Path $env:SystemRoot\Temp)) {
		New-Item -Path $env:SystemRoot\Temp
	}
	if (-not (Test-Path -Path $env:LOCALAPPDATA\Temp)) {
		New-Item -Path $env:LOCALAPPDATA\Temp -ItemType Directory -Force
	}

	[Environment]::SetEnvironmentVariable("TMP", "$env:LOCALAPPDATA\Temp", "User")
	[Environment]::SetEnvironmentVariable("TMP", "$env:SystemRoot\TEMP", "Machine")
	[Environment]::SetEnvironmentVariable("TMP", "$env:LOCALAPPDATA\Temp", "Process")
	New-ItemProperty -Path HKCU:\Environment -Name TMP -PropertyType ExpandString -Value %LOCALAPPDATA%\Temp -Force

	[Environment]::SetEnvironmentVariable("TEMP", "$env:LOCALAPPDATA\Temp", "User")
	[Environment]::SetEnvironmentVariable("TEMP", "$env:SystemRoot\TEMP", "Machine")
	[Environment]::SetEnvironmentVariable("TEMP", "$env:LOCALAPPDATA\Temp", "Process")
	New-ItemProperty -Path HKCU:\Environment -Name TEMP -PropertyType ExpandString -Value %LOCALAPPDATA%\Temp -Force

	New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name TMP -PropertyType ExpandString -Value %SystemRoot%\TEMP -Force
	New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name TEMP -PropertyType ExpandString -Value %SystemRoot%\TEMP -Force

	# Restart the Printer Spooler service (Spooler)
	# Перезапустить службу "Диспетчер печати" (Spooler)
	Restart-Service -Name Spooler -Force

	Stop-Process -Name OneDrive -Force -ErrorAction Ignore
	Stop-Process -Name FileCoAuth -Force -ErrorAction Ignore

	Remove-Item -Path $env:SystemDrive\Temp -Recurse -Force -ErrorAction Ignore
}

# Enable Windows 260 character path limit
# Включить ограничение Windows на 260 символов в пути
function EnableWin32LongPaths {
	New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name LongPathsEnabled -PropertyType DWord -Value 1 -Force
}

# Disable Windows 260 character path limit
# Отключить ограничение Windows на 260 символов в пути
function DisableWin32LongPaths {
	New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name LongPathsEnabled -PropertyType DWord -Value 0 -Force
}

# Display the Stop error information on the BSoD
# Отображать Stop-ошибку при появлении BSoD
function EnableBSoDStopError {
	New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl -Name DisplayParameters -PropertyType DWord -Value 1 -Force
}

# Do not display the Stop error information on the BSoD
# Не отображать Stop-ошибку при появлении BSoD
function DisableBSoDStopError {
	New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl -Name DisplayParameters -PropertyType DWord -Value 0 -Force
}

# Change "Behavior of the elevation prompt for administrators in Admin Approval Mode" to "Elevate without prompting"
# Изменить "Поведение запроса на повышение прав для администраторов в режиме одобрения администратором" на "Повышение прав без запроса"
function DisableAdminApprovalMode {
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -PropertyType DWord -Value 0 -Force
}

# Change "Behavior of the elevation prompt for administrators in Admin Approval Mode" to "Prompt for consent for non-Windows binaries" (default value)
# Изменить "Поведение запроса на повышение прав для администраторов в режиме одобрения администратором" на "Запрос согласия для исполняемых файлов, отличных от Windows" (значение по умолчанию)
function EnableAdminApprovalMode {
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -PropertyType DWord -Value 5 -Force
}

# Turn on access to mapped drives from app running with elevated permissions with Admin Approval Mode enabled
# Включить доступ к сетевым дискам при включенном режиме одобрения администратором при доступе из программ, запущенных с повышенными правами
function EnableMappedDrivesAppElevatedAccess {
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLinkedConnections -PropertyType DWord -Value 1 -Force
}

# Turn off access to mapped drives from app running with elevated permissions with Admin Approval Mode enabled
# Выключить доступ к сетевым дискам при включенном режиме одобрения администратором при доступе из программ, запущенных с повышенными правами
function DisableMappedDrivesAppElevatedAccess {
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLinkedConnections -PropertyType DWord -Value 0 -Force
}

# Opt out of the Delivery Optimization-assisted updates downloading
# Отказаться от загрузки обновлений с помощью оптимизации доставки
function DisableDeliveryOptimization {
	if ((Test-Path "Registry::HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings")) {
            New-ItemProperty -Path Registry::HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings -Name DownloadMode -PropertyType DWord -Value 0 -Force
	}
    Delete-DeliveryOptimizationCache -Force
}

# Opt-in to the Delivery Optimization-assisted updates downloading
# Включить загрузку обновлений с помощью оптимизации доставки
function EnableDeliveryOptimization {
	New-ItemProperty -Path Registry::HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings -Name DownloadMode -PropertyType DWord -Value 1 -Force
}

# Always wait for the network at computer startup and logon for workgroup networks
# Всегда ждать сеть при запуске и входе в систему для рабочих групп
function AlwaysWaitNetworkStartup {
	if ((Get-CimInstance -ClassName CIM_ComputerSystem).PartOfDomain -eq $true) {
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Force
		}
		New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name SyncForegroundPolicy -PropertyType DWord -Value 1 -Force
	}
}

# Never wait for the network at computer startup and logon for workgroup networks
# Никогда ждать сеть при запуске и входе в систему для рабочих групп
function NeverWaitNetworkStartup {
	if ((Get-CimInstance -ClassName CIM_ComputerSystem).PartOfDomain -eq $true) {
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name SyncForegroundPolicy -Force -ErrorAction SilentlyContinue
	}
}

# Disable the following Windows features
# Отключить следующие компоненты Windows
function DisableWindowsFeatures {
	$WindowsOptionalFeatures = @(
		# Media Features
		# Компоненты работы с мультимедиа
		"MediaPlayback",

		# PowerShell 2.0
		"MicrosoftWindowsPowerShellV2",
		"MicrosoftWindowsPowershellV2Root",

		# Microsoft XPS Document Writer
		# Средство записи XPS-документов (Microsoft)
		"Printing-XPSServices-Features",

		# Work Folders Client
		# Клиент рабочих папок
		"WorkFolders-Client"
	)
	Disable-WindowsOptionalFeature -Online -FeatureName $WindowsOptionalFeatures -NoRestart
}

# Enable the following Windows features
# Включить следующие компоненты Windows
function EnableWindowsFeatures {
	$WindowsOptionalFeatures = @(
		# Legacy Components
		# Компоненты прежних версий
		"LegacyComponents",

		# Media Features
		# Компоненты работы с мультимедиа
		"MediaPlayback",

		# PowerShell 2.0
		"MicrosoftWindowsPowerShellV2",
		"MicrosoftWindowsPowershellV2Root",

		# Microsoft XPS Document Writer
		# Средство записи XPS-документов (Microsoft)
		"Printing-XPSServices-Features",

		# Work Folders Client
		# Клиент рабочих папок
		"WorkFolders-Client"
	)
	Enable-WindowsOptionalFeature -Online -FeatureName $WindowsOptionalFeatures -NoRestart
}

# Disable certain Feature On Demand v2 (FODv2) capabilities
# Отключить определенные компоненты "Функции по требованию" (FODv2)
function DisableWindowsCapabilities {
	# The following FODv2 items will be shown, but their checkboxes would be clear
	# Следующие дополнительные компоненты будут видны, но их чекбоксы не будут отмечены
	$ExcludedCapabilities = @(
		# The DirectX Database to configure and optimize apps when multiple Graphics Adapters are present
		# База данных DirectX для настройки и оптимизации приложений при наличии нескольких графических адаптеров
		"DirectX\.Configuration\.Database",

		# Features critical to Windows functionality
		# Компоненты, критичные для работоспособности Windows
		"Windows\.Client\.ShellComponents",
                
        # Language components
		"Language\."
	)
	
	if (Get-WindowsCapability -Online | Where-Object -FilterScript { ($_.State -eq "Installed") -and ($_.Name -cnotmatch ($ExcludedCapabilities -join "|")) } | Remove-WindowsCapability -Online ) {
		Write-Verbose -Message 'Removed Capabilities' -Verbose
	}
	else {
		Write-Verbose -Message $Localization.NoData -Verbose
	}
}

# Use latest installed .NET runtime for all apps
# Использовать последнюю установленную среду выполнения .NET для всех приложений
function EnableLatestInstalled.NET {
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework -Name OnlyUseLatestCLR -PropertyType DWord -Value 1 -Force
	New-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework -Name OnlyUseLatestCLR -PropertyType DWord -Value 1 -Force
}

# Do not use latest installed .NET runtime for all apps
# Не использовать последнюю установленную версию .NET для всех приложений
function DisableLatestInstalled.NET {
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework -Name OnlyUseLatestCLR -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework -Name OnlyUseLatestCLR -Force -ErrorAction SilentlyContinue
}

<#
	Change the location of the user folders to any drives root (current user only)
	It is suggested to move it to any disks root of your choice using the interactive menu by default
	User files or folders won't me moved to a new location

	Изменить расположение пользовательских папок (только для текущего пользователя)
	По умолчанию предлагается переместить в корень любого диска на выбор с помощью интерактивного меню
	Пользовательские файлы и папки не будут перемещены в новое расположение
#>
function ChangeUserShellFolderLocation {
	function UserShellFolder {
		<#
		.SYNOPSIS
		Change the location of the each user folders using SHSetKnownFolderPath function
		https://docs.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderpath

		.EXAMPLE
		UserShellFolder -UserFolder Desktop -FolderPath "$env:SystemDrive:\Desktop" -RemoveDesktopINI

		.NOTES
		User files or folders won't me moved to a new location
		The RemoveDesktopINI argument removes desktop.ini in the old user shell folder
	#>
		[CmdletBinding()]
		param
		(
			[Parameter(Mandatory = $true)]
			[ValidateSet("Desktop", "Documents", "Downloads", "Music", "Pictures", "Videos")]
			[string]
			$UserFolder,

			[Parameter(Mandatory = $true)]
			[string]
			$FolderPath,

			[Parameter(Mandatory = $false)]
			[switch]
			$RemoveDesktopINI
		)

		function KnownFolderPath {
			<#
			.SYNOPSIS
			Redirect user folders to a new location

			.EXAMPLE
			KnownFolderPath -KnownFolder Desktop -Path "$env:SystemDrive:\Desktop"

			.NOTES
			User files or folders won't me moved to the new location
		#>
			[CmdletBinding()]
			param
			(
				[Parameter(Mandatory = $true)]
				[ValidateSet("Desktop", "Documents", "Downloads", "Music", "Pictures", "Videos")]
				[string]
				$KnownFolder,

				[Parameter(Mandatory = $true)]
				[string]
				$Path
			)

			$KnownFolders = @{
				"Desktop"   = @("B4BFCC3A-DB2C-424C-B029-7FE99A87C641");
				"Documents"	= @("FDD39AD0-238F-46AF-ADB4-6C85480369C7", "f42ee2d3-909f-4907-8871-4c22fc0bf756");
				"Downloads"	= @("374DE290-123F-4565-9164-39C4925E467B", "7d83ee9b-2244-4e70-b1f5-5393042af1e4");
				"Music"     = @("4BD8D571-6D19-48D3-BE97-422220080E43", "a0c69a99-21c8-4671-8703-7934162fcf1d");
				"Pictures"  = @("33E28130-4E1E-4676-835A-98395C3BC3BB", "0ddd015d-b06c-45d5-8c4c-f59713854639");
				"Videos"    = @("18989B1D-99B5-455B-841C-AB7C74E4DDFC", "35286a68-3c57-41a1-bbb1-0eae73d76c95");
			}

			$Signature = @{
				Namespace        = "WinAPI"
				Name             = "KnownFolders"
				Language         = "CSharp"
				MemberDefinition = @"
[DllImport("shell32.dll")]
public extern static int SHSetKnownFolderPath(ref Guid folderId, uint flags, IntPtr token, [MarshalAs(UnmanagedType.LPWStr)] string path);
"@
			}
			if (-not ("WinAPI.KnownFolders" -as [type])) {
				Add-Type @Signature
			}

			foreach ($guid in $KnownFolders[$KnownFolder]) {
				[WinAPI.KnownFolders]::SHSetKnownFolderPath([ref]$guid, 0, 0, $Path)
			}
			(Get-Item -Path $Path -Force).Attributes = "ReadOnly"
		}

		$UserShellFoldersRegName = @{
			"Desktop"   =	"Desktop"
			"Documents"	=	"Personal"
			"Downloads"	=	"{374DE290-123F-4565-9164-39C4925E467B}"
			"Music"     =	"My Music"
			"Pictures"  =	"My Pictures"
			"Videos"    =	"My Video"
		}

		$UserShellFoldersGUID = @{
			"Desktop"   =	"{754AC886-DF64-4CBA-86B5-F7FBF4FBCEF5}"
			"Documents"	=	"{F42EE2D3-909F-4907-8871-4C22FC0BF756}"
			"Downloads"	=	"{7D83EE9B-2244-4E70-B1F5-5393042AF1E4}"
			"Music"     =	"{A0C69A99-21C8-4671-8703-7934162FCF1D}"
			"Pictures"  =	"{0DDD015D-B06C-45D5-8C4C-F59713854639}"
			"Videos"    =	"{35286A68-3C57-41A1-BBB1-0EAE73D76C95}"
		}

		# Contents of the hidden desktop.ini file for each type of user folders
		# Содержимое скрытого файла desktop.ini для каждого типа пользовательских папок
		$DesktopINI = @{
			"Desktop"   =	"",
			"[.ShellClassInfo]",
			"LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21769",
			"IconResource=%SystemRoot%\system32\imageres.dll,-183"
			"Documents"	=	"",
			"[.ShellClassInfo]",
			"LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21770",
			"IconResource=%SystemRoot%\system32\imageres.dll,-112",
			"IconFile=%SystemRoot%\system32\shell32.dll",
			"IconIndex=-235"
			"Downloads"	=	"",
			"[.ShellClassInfo]", "LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21798",
			"IconResource=%SystemRoot%\system32\imageres.dll,-184"
			"Music"     =	"",
			"[.ShellClassInfo]", "LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21790",
			"InfoTip=@%SystemRoot%\system32\shell32.dll,-12689",
			"IconResource=%SystemRoot%\system32\imageres.dll,-108",
			"IconFile=%SystemRoot%\system32\shell32.dll", "IconIndex=-237"
			"Pictures"  =	"",
			"[.ShellClassInfo]",
			"LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21779",
			"InfoTip=@%SystemRoot%\system32\shell32.dll,-12688",
			"IconResource=%SystemRoot%\system32\imageres.dll,-113",
			"IconFile=%SystemRoot%\system32\shell32.dll",
			"IconIndex=-236"
			"Videos"    =	"",
			"[.ShellClassInfo]",
			"LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21791",
			"InfoTip=@%SystemRoot%\system32\shell32.dll,-12690",
			"IconResource=%SystemRoot%\system32\imageres.dll,-189",
			"IconFile=%SystemRoot%\system32\shell32.dll", "IconIndex=-238"
		}

		# Determining the current user folder path
		# Определяем текущее значение пути пользовательской папки
		$UserShellFolderRegValue = Get-ItemPropertyValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name $UserShellFoldersRegName[$UserFolder]
		if ($UserShellFolderRegValue -ne $FolderPath) {
			if ((Get-ChildItem -Path $UserShellFolderRegValue | Measure-Object).Count -ne 0) {
				$Message = Invoke-Command -ScriptBlock ([ScriptBlock]::Create($Localization.UserShellFolderNotEmpty))
				Write-Error -Message $Message -ErrorAction SilentlyContinue
			}

			# Creating a new folder if there is no one
			# Создаем новую папку, если таковая отсутствует
			if (-not (Test-Path -Path $FolderPath)) {
				New-Item -Path $FolderPath -ItemType Directory -Force
			}

			# Removing old desktop.ini
			# Удаляем старый desktop.ini
			if ($RemoveDesktopINI.IsPresent) {
				Remove-Item -Path "$UserShellFolderRegValue\desktop.ini" -Force
			}

			KnownFolderPath -KnownFolder $UserFolder -Path $FolderPath
			New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name $UserShellFoldersGUID[$UserFolder] -PropertyType ExpandString -Value $FolderPath -Force

			Set-Content -Path "$FolderPath\desktop.ini" -Value $DesktopINI[$UserFolder] -Encoding Unicode -Force
			(Get-Item -Path "$FolderPath\desktop.ini" -Force).Attributes = "Hidden", "System", "Archive"
			(Get-Item -Path "$FolderPath\desktop.ini" -Force).Refresh()
		}
	}

	<#
		.SYNOPSIS
		The "Show menu" function using PowerShell with the up/down arrow keys and enter key to make a selection

		.EXAMPLE
		ShowMenu -Menu $ListOfItems -Default $DefaultChoice

		.NOTES
		Doesn't work in PowerShell ISE
	#>
	function ShowMenu {
		[CmdletBinding()]
		param
		(
			[Parameter()]
			[string]
			$Title,

			[Parameter(Mandatory = $true)]
			[array]
			$Menu,

			[Parameter(Mandatory = $true)]
			[int]
			$Default
		)

		Write-Information -MessageData $Title -InformationAction Continue

		$minY = [Console]::CursorTop
		$y = [Math]::Max([Math]::Min($Default, $Menu.Count), 0)
		do {
			[Console]::CursorTop = $minY
			[Console]::CursorLeft = 0
			$i = 0
			foreach ($item in $Menu) {
				if ($i -ne $y) {
					Write-Information -MessageData ('  {0}. {1}  ' -f ($i + 1), $item) -InformationAction Continue
				}
				else {
					Write-Information -MessageData ('[ {0}. {1} ]' -f ($i + 1), $item) -InformationAction Continue
				}
				$i++
			}

			$k = [Console]::ReadKey()
			switch ($k.Key) {
				"UpArrow" {
					if ($y -gt 0) {
						$y--
					}
				}
				"DownArrow" {
					if ($y -lt ($Menu.Count - 1)) {
						$y++
					}
				}
				"Enter" {
					return $Menu[$y]
				}
			}
		}
		while ($k.Key -notin ([ConsoleKey]::Escape, [ConsoleKey]::Enter))
	}

	# Store all drives letters to use them within ShowMenu function
	# Сохранить все буквы диска, чтобы использовать их в функции ShowMenu
	Write-Verbose $Localization.RetrievingDrivesList -Verbose
	$DriveLetters = @((Get-Disk | Where-Object -FilterScript { $_.BusType -ne "USB" } | Get-Partition | Get-Volume | Where-Object -FilterScript { $null -ne $_.DriveLetter }).DriveLetter | Sort-Object)

	# If the number of disks is more than one, set the second drive in the list as default drive
	# Если количество дисков больше одного, сделать второй диск в списке диском по умолчанию
	if ($DriveLetters.Count -gt 1) {
		$Default = 1
	}
	else {
		$Default = 0
	}

	# Desktop
	# Рабочий стол
	Write-Verbose -Message $Localization.DesktopDriveSelect -Verbose
	Write-Warning -Message $Localization.DesktopFilesWontBeMoved

	$Title = ""
	$Message = $Localization.DesktopFolderRequest
	$Change = $Localization.DesktopFolderChange
	$Skip = $Localization.DesktopFolderSkip
	$Options = "&$Change", "&$Skip"
	$DefaultChoice = 1
	$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

	switch ($Result) {
		"0" {
			$SelectedDrive = ShowMenu -Title $Localization.DesktopDriveSelect -Menu $DriveLetters -Default $Default
			UserShellFolder -UserFolder Desktop -FolderPath "${SelectedDrive}:\Desktop" -RemoveDesktopINI
		}
		"1" {
			Write-Verbose -Message $Localization.DesktopSkipped -Verbose
		}
	}

	# Documents
	# Документы
	Write-Verbose -Message $Localization.DocumentsDriveSelect -Verbose
	Write-Warning -Message $Localization.DocumentsFilesWontBeMoved

	$Title = ""
	$Message = $Localization.DocumentsFolderRequest
	$Change = $Localization.DocumentsFolderChange
	$Skip = $Localization.DocumentsFolderSkip
	$Options = "&$Change", "&$Skip"
	$DefaultChoice = 1
	$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

	switch ($Result) {
		"0" {
			$SelectedDrive = ShowMenu -Title $Localization.DocumentsDriveSelect -Menu $DriveLetters -Default $Default
			UserShellFolder -UserFolder Documents -FolderPath "${SelectedDrive}:\Documents" -RemoveDesktopINI
		}
		"1" {
			Write-Verbose -Message $Localization.DocumentsSkipped -Verbose
		}
	}

	# Downloads
	# Загрузки
	Write-Verbose -Message $Localization.DownloadsDriveSelect -Verbose
	Write-Warning -Message $Localization.DownloadsFilesWontBeMoved

	$Title = ""
	$Message = $Localization.DownloadsFolderRequest
	$Change = $Localization.DownloadsFolderChange
	$Skip = $Localization.DownloadsFolderSkip
	$Options = "&$Change", "&$Skip"
	$DefaultChoice = 1
	$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

	switch ($Result) {
		"0" {
			$SelectedDrive = ShowMenu -Title $Localization.DownloadsDriveSelect -Menu $DriveLetters -Default $Default
			UserShellFolder -UserFolder Downloads -FolderPath "${SelectedDrive}:\Downloads" -RemoveDesktopINI
		}
		"1" {
			Write-Verbose -Message $Localization.DownloadsSkipped -Verbose
		}
	}

	# Music
	# Музыка
	Write-Verbose -Message $Localization.MusicDriveSelect -Verbose
	Write-Warning -Message $Localization.MusicFilesWontBeMoved

	$Title = ""
	$Message = $Localization.MusicFolderRequest
	$Change = $Localization.MusicFolderChange
	$Skip = $Localization.MusicFolderSkip
	$Options = "&$Change", "&$Skip"
	$DefaultChoice = 1
	$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

	switch ($Result) {
		"0" {
			$SelectedDrive = ShowMenu -Title $Localization.MusicDriveSelect -Menu $DriveLetters -Default $Default
			UserShellFolder -UserFolder Music -FolderPath "${SelectedDrive}:\Music" -RemoveDesktopINI
		}
		"1" {
			Write-Verbose -Message $Localization.MusicSkipped -Verbose
		}
	}

	# Pictures
	# Изображения
	Write-Verbose -Message $Localization.PicturesDriveSelect -Verbose
	Write-Warning -Message $Localization.PicturesFilesWontBeMoved

	$Title = ""
	$Message = $Localization.PicturesFolderRequest
	$Change = $Localization.PicturesFolderChange
	$Skip = $Localization.PicturesFolderSkip
	$Options = "&$Change", "&$Skip"
	$DefaultChoice = 1
	$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

	switch ($Result) {
		"0" {
			$SelectedDrive = ShowMenu -Title $Localization.PicturesDriveSelect -Menu $DriveLetters -Default $Default
			UserShellFolder -UserFolder Pictures -FolderPath "${SelectedDrive}:\Pictures" -RemoveDesktopINI
		}
		"1" {
			Write-Verbose -Message $Localization.PicturesSkipped -Verbose
		}
	}

	# Videos
	# Видео
	Write-Verbose -Message $Localization.VideosDriveSelect -Verbose
	Write-Warning -Message $Localization.VideosFilesWontBeMoved

	$Title = ""
	$Message = $Localization.VideosFolderRequest
	$Change = $Localization.VideosFolderChange
	$Skip = $Localization.VideosFolderSkip
	$Options = "&$Change", "&$Skip"
	$DefaultChoice = 1
	$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

	switch ($Result) {
		"0" {
			$SelectedDrive = ShowMenu -Title $Localization.VideosDriveSelect -Menu $DriveLetters -Default $Default
			UserShellFolder -UserFolder Videos -FolderPath "${SelectedDrive}:\Videos" -RemoveDesktopINI
		}
		"1" {
			Write-Verbose -Message $Localization.VideosSkipped -Verbose
		}
	}
}

<#
	Change the location of the user folders to the default values (current user only)
	User files or folders won't me moved to the new location

	Изменить расположение пользовательских папок на значения по умолчанию (только для текущего пользователя)
	Пользовательские файлы и папки не будут перемещены в новое расположение
#>
function SetDefaultUserShellFolderLocation {
	function UserShellFolder {
		<#
		.SYNOPSIS
		Change the location of the each user folders using SHSetKnownFolderPath function
		https://docs.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderpath

		.EXAMPLE
		UserShellFolder -UserFolder Desktop -FolderPath "$env:SystemDrive:\Desktop" -RemoveDesktopINI

		.NOTES
		User files or folders won't me moved to the new location
		The RemoveDesktopINI argument removes desktop.ini in the old user shell folder
	#>
		[CmdletBinding()]
		param
		(
			[Parameter(Mandatory = $true)]
			[ValidateSet("Desktop", "Documents", "Downloads", "Music", "Pictures", "Videos")]
			[string]
			$UserFolder,

			[Parameter(Mandatory = $true)]
			[string]
			$FolderPath,

			[switch]
			$RemoveDesktopINI
		)

		function KnownFolderPath {
			<#
			.SYNOPSIS
			Redirect user folders to a new location

			.EXAMPLE
			KnownFolderPath -KnownFolder Desktop -Path "C:\Desktop"

			.NOTES
			User files or folders won't me moved to the new location
		#>
			[CmdletBinding()]
			param
			(
				[Parameter(Mandatory = $true)]
				[ValidateSet("Desktop", "Documents", "Downloads", "Music", "Pictures", "Videos")]
				[string]
				$KnownFolder,

				[Parameter(Mandatory = $true)]
				[string]
				$Path
			)

			$KnownFolders = @{
				"Desktop"   = @("B4BFCC3A-DB2C-424C-B029-7FE99A87C641");
				"Documents"	= @("FDD39AD0-238F-46AF-ADB4-6C85480369C7", "f42ee2d3-909f-4907-8871-4c22fc0bf756");
				"Downloads"	= @("374DE290-123F-4565-9164-39C4925E467B", "7d83ee9b-2244-4e70-b1f5-5393042af1e4");
				"Music"     = @("4BD8D571-6D19-48D3-BE97-422220080E43", "a0c69a99-21c8-4671-8703-7934162fcf1d");
				"Pictures"  = @("33E28130-4E1E-4676-835A-98395C3BC3BB", "0ddd015d-b06c-45d5-8c4c-f59713854639");
				"Videos"    = @("18989B1D-99B5-455B-841C-AB7C74E4DDFC", "35286a68-3c57-41a1-bbb1-0eae73d76c95");
			}

			$Signature = @{
				Namespace        = "WinAPI"
				Name             = "KnownFolders"
				Language         = "CSharp"
				MemberDefinition = @"
[DllImport("shell32.dll")]
public extern static int SHSetKnownFolderPath(ref Guid folderId, uint flags, IntPtr token, [MarshalAs(UnmanagedType.LPWStr)] string path);
"@
			}
			if (-not ("WinAPI.KnownFolders" -as [type])) {
				Add-Type @Signature
			}

			foreach ($guid in $KnownFolders[$KnownFolder]) {
				[WinAPI.KnownFolders]::SHSetKnownFolderPath([ref]$guid, 0, 0, $Path)
			}
			(Get-Item -Path $Path -Force).Attributes = "ReadOnly"
		}

		$UserShellFoldersRegName = @{
			"Desktop"   =	"Desktop"
			"Documents"	=	"Personal"
			"Downloads"	=	"{374DE290-123F-4565-9164-39C4925E467B}"
			"Music"     =	"My Music"
			"Pictures"  =	"My Pictures"
			"Videos"    =	"My Video"
		}

		$UserShellFoldersGUID = @{
			"Desktop"   =	"{754AC886-DF64-4CBA-86B5-F7FBF4FBCEF5}"
			"Documents"	=	"{F42EE2D3-909F-4907-8871-4C22FC0BF756}"
			"Downloads"	=	"{7D83EE9B-2244-4E70-B1F5-5393042AF1E4}"
			"Music"     =	"{A0C69A99-21C8-4671-8703-7934162FCF1D}"
			"Pictures"  =	"{0DDD015D-B06C-45D5-8C4C-F59713854639}"
			"Videos"    =	"{35286A68-3C57-41A1-BBB1-0EAE73D76C95}"
		}

		# Contents of the hidden desktop.ini file for each type of user folders
		# Содержимое скрытого файла desktop.ini для каждого типа пользовательских папок
		$DesktopINI = @{
			"Desktop"   =	"",
			"[.ShellClassInfo]",
			"LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21769",
			"IconResource=%SystemRoot%\system32\imageres.dll,-183"
			"Documents"	=	"",
			"[.ShellClassInfo]",
			"LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21770",
			"IconResource=%SystemRoot%\system32\imageres.dll,-112",
			"IconFile=%SystemRoot%\system32\shell32.dll",
			"IconIndex=-235"
			"Downloads"	=	"",
			"[.ShellClassInfo]", "LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21798",
			"IconResource=%SystemRoot%\system32\imageres.dll,-184"
			"Music"     =	"",
			"[.ShellClassInfo]", "LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21790",
			"InfoTip=@%SystemRoot%\system32\shell32.dll,-12689",
			"IconResource=%SystemRoot%\system32\imageres.dll,-108",
			"IconFile=%SystemRoot%\system32\shell32.dll", "IconIndex=-237"
			"Pictures"  =	"",
			"[.ShellClassInfo]",
			"LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21779",
			"InfoTip=@%SystemRoot%\system32\shell32.dll,-12688",
			"IconResource=%SystemRoot%\system32\imageres.dll,-113",
			"IconFile=%SystemRoot%\system32\shell32.dll",
			"IconIndex=-236"
			"Videos"    =	"",
			"[.ShellClassInfo]",
			"LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21791",
			"InfoTip=@%SystemRoot%\system32\shell32.dll,-12690",
			"IconResource=%SystemRoot%\system32\imageres.dll,-189",
			"IconFile=%SystemRoot%\system32\shell32.dll", "IconIndex=-238"
		}

		# Determining the current user folder path
		# Определяем текущее значение пути пользовательской папки
		$UserShellFolderRegValue = Get-ItemPropertyValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name $UserShellFoldersRegName[$UserFolder]
		if ($UserShellFolderRegValue -ne $FolderPath) {
			if ((Get-ChildItem -Path $UserShellFolderRegValue | Measure-Object).Count -ne 0) {
				Write-Error -Message $Localization.UserShellFolderNotEmpty -ErrorAction SilentlyContinue
			}

			# Creating a new folder if there is no one
			# Создаем новую папку, если таковая отсутствует
			if (-not (Test-Path -Path $FolderPath)) {
				New-Item -Path $FolderPath -ItemType Directory -Force
			}

			# Removing old desktop.ini
			# Удаляем старый desktop.ini
			if ($RemoveDesktopINI.IsPresent) {
				Remove-Item -Path "$UserShellFolderRegValue\desktop.ini" -Force
			}

			KnownFolderPath -KnownFolder $UserFolder -Path $FolderPath
			New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name $UserShellFoldersGUID[$UserFolder] -PropertyType ExpandString -Value $FolderPath -Force

			Set-Content -Path "$FolderPath\desktop.ini" -Value $DesktopINI[$UserFolder] -Encoding Unicode -Force
			(Get-Item -Path "$FolderPath\desktop.ini" -Force).Attributes = "Hidden", "System", "Archive"
			(Get-Item -Path "$FolderPath\desktop.ini" -Force).Refresh()
		}
	}

	# Desktop
	# Рабочий стол
	Write-Verbose -Message $Localization.DesktopDriveSelect -Verbose
	Write-Warning -Message $Localization.DesktopFilesWontBeMoved

	$Title = ""
	$Message = $Localization.DesktopDefaultFolder
	$Change = $Localization.DesktopFolderChange
	$Skip = $Localization.DesktopFolderSkip
	$Options = "&$Change", "&$Skip"
	$DefaultChoice = 1
	$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

	switch ($Result) {
		"0" {
			UserShellFolder -UserFolder Desktop -FolderPath "$env:USERPROFILE\Desktop" -RemoveDesktopINI
		}
		"1" {
			Write-Verbose -Message $Localization.DesktopSkipped -Verbose
		}
	}

	# Documents
	# Документы
	Write-Verbose -Message $Localization.DocumentsDriveSelect -Verbose
	Write-Warning -Message $Localization.DocumentsFilesWontBeMoved

	$Title = ""
	$Message = $Localization.DocumentsDefaultFolder
	$Change = $Localization.DocumentsFolderChange
	$Skip = $Localization.DocumentsFolderSkip
	$Options = "&$Change", "&$Skip"
	$DefaultChoice = 1
	$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

	switch ($Result) {
		"0" {
			UserShellFolder -UserFolder Documents -FolderPath "$env:USERPROFILE\Documents" -RemoveDesktopINI
		}
		"1" {
			Write-Verbose -Message $Localization.DocumentsSkipped -Verbose
		}
	}

	# Downloads
	# Загрузки
	Write-Verbose -Message $Localization.DownloadsDriveSelect -Verbose
	Write-Warning -Message $Localization.DownloadsFilesWontBeMoved

	$Title = ""
	$Message = $Localization.DownloadsDefaultFolder
	$Change = $Localization.DownloadsFolderChange
	$Skip = $Localization.DownloadsFolderSkip
	$Options = "&$Change", "&$Skip"
	$DefaultChoice = 1
	$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

	switch ($Result) {
		"0" {
			UserShellFolder -UserFolder Downloads -FolderPath "$env:USERPROFILE\Downloads" -RemoveDesktopINI
		}
		"1" {
			Write-Verbose -Message $Localization.DownloadsSkipped -Verbose
		}
	}

	# Music
	# Музыка
	Write-Verbose -Message $Localization.MusicDriveSelect -Verbose
	Write-Warning -Message $Localization.MusicFilesWontBeMoved

	$Title = ""
	$Message = $Localization.MusicDefaultFolder
	$Change = $Localization.MusicFolderChange
	$Skip = $Localization.MusicFolderSkip
	$Options = "&$Change", "&$Skip"
	$DefaultChoice = 1
	$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

	switch ($Result) {
		"0" {
			UserShellFolder -UserFolder Music -FolderPath "$env:USERPROFILE\Music" -RemoveDesktopINI
		}
		"1" {
			Write-Verbose -Message $Localization.MusicSkipped -Verbose
		}
	}


	# Pictures
	# Изображения
	Write-Verbose -Message $Localization.PicturesDriveSelect -Verbose
	Write-Warning -Message $Localization.PicturesFilesWontBeMoved

	$Title = ""
	$Message = $Localization.PicturesDefaultFolder
	$Change = $Localization.PicturesFolderChange
	$Skip = $Localization.PicturesFolderSkip
	$Options = "&$Change", "&$Skip"
	$DefaultChoice = 1
	$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

	switch ($Result) {
		"0" {
			UserShellFolder -UserFolder Pictures -FolderPath "$env:USERPROFILE\Pictures" -RemoveDesktopINI
		}
		"1" {
			Write-Verbose -Message $Localization.PicturesSkipped -Verbose
		}
	}

	# Videos
	# Видео
	Write-Verbose -Message $Localization.VideosDriveSelect -Verbose
	Write-Warning -Message $Localization.VideosFilesWontBeMoved

	$Title = ""
	$Message = $Localization.VideosDefaultFolder
	$Change = $Localization.VideosFolderChange
	$Skip = $Localization.VideosFolderSkip
	$Options = "&$Change", "&$Skip"
	$DefaultChoice = 1
	$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

	switch ($Result) {
		"0" {
			UserShellFolder -UserFolder Videos -FolderPath "$env:USERPROFILE\Videos" -RemoveDesktopINI
		}
		"1" {
			Write-Verbose -Message $Localization.VideosSkipped -Verbose
		}
	}
}

# Save screenshots by pressing Win+PrtScr to the Desktop folder (current user only)
# Сохранять скриншоты по нажатию Win+PrtScr в папку "рабочий стол" (только для текущего пользователя)
function WinPrtScrDesktopFolder {
	$DesktopFolder = Get-ItemPropertyValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name Desktop
	New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{B7BEDE81-DF94-4682-A7D8-57A52620B86F}" -Type ExpandString -Value $DesktopFolder -Force

	# Save all opened folders in order to restore them after File Explorer restart
	# Сохранить все открытые папки, чтобы восстановить их после перезапуска проводника
	Clear-Variable -Name OpenedFolders -Force -ErrorAction Ignore
	$OpenedFolders = { (New-Object -ComObject Shell.Application).Windows() | ForEach-Object -Process { $_.Document.Folder.Self.Path } }.Invoke()

	# In order for the changes to take effect the File Explorer process has to be restarted
	# Чтобы изменения вступили в силу, необходимо перезапустить процесс проводника
	Stop-Process -Name explorer -Force

	# Restore closed folders
	# Восстановить закрытые папки
	foreach ($OpenedFolder in $OpenedFolders) {
		if (Test-Path -Path $OpenedFolder) {
			Invoke-Item -Path $OpenedFolder
		}
	}
}

<#
	Disable annoying Troubleshooting
	Автоматически запускать средства устранения неполадок, а затем уведомлять
	Необходимо установить уровень сбора диагностических сведений ОС на "Максимальный", чтобы работала данная функция
#>
function DisableTroubleshooting {
	if (-not (Test-Path -Path HKLM:\SOFTWARE\Microsoft\WindowsMitigation)) {
		New-Item -Path HKLM:\SOFTWARE\Microsoft\WindowsMitigation -Force
	}
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsMitigation -Name UserPreference -PropertyType DWord -Value 1 -Force

	# Set the OS level of diagnostic data gathering to "Full"
	# Установить уровень сбора диагностических сведений ОС на "Максимальный"
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection -Name AllowTelemetry -PropertyType DWord -Value 0 -Force
}

<#
	Ask me before running troubleshooters (default value)
	In order this feature to work the OS level of diagnostic data gathering must be set to "Full"

	Спрашивать перед запуском средств устранения неполадок (значение по умолчанию)
	Необходимо установить уровень сбора диагностических сведений ОС на "Максимальный", чтобы работала данная функция
#>
function DefaultRecommendedTroubleshooting {
	if (-not (Test-Path -Path HKLM:\SOFTWARE\Microsoft\WindowsMitigation)) {
		New-Item -Path HKLM:\SOFTWARE\Microsoft\WindowsMitigation -Force
	}
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsMitigation -Name UserPreference -PropertyType DWord -Value 2 -Force

	# Set the OS level of diagnostic data gathering to "Full"
	# Установить уровень сбора диагностических сведений ОС на "Максимальный"
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection -Name AllowTelemetry -PropertyType DWord -Value 3 -Force
}

# Launch folder windows in a separate process (current user only)
# Запускать окна с папками в отдельном процессе (только для текущего пользователя)
function EnableFoldersLaunchSeparateProcess {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name SeparateProcess -PropertyType DWord -Value 1 -Force
}

# Do not folder windows in a separate process (current user only)
# Не запускать окна с папками в отдельном процессе (только для текущего пользователя)
function DisableFoldersLaunchSeparateProcess {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name SeparateProcess -PropertyType DWord -Value 0 -Force
}

# Disable and delete reserved storage after the next update installation
# Отключить и удалить зарезервированное хранилище после следующей установки обновлений
function DisableReservedStorage {
	try {
		Set-WindowsReservedStorageState -State Disabled
	}
	catch [System.Runtime.InteropServices.COMException] {
		Write-Error -Message $Localization.ReservedStorageIsInUse -ErrorAction SilentlyContinue
	}
}

# Turn on reserved storage
# Включить зарезервированное хранилище
function EnableReservedStorage {
	Set-WindowsReservedStorageState -State Enabled
}

# Turn on Num Lock at startup
# Включить Num Lock при загрузке
function EnableNumLock {
	New-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\Control Panel\Keyboard" -Name InitialKeyboardIndicators -PropertyType String -Value 2147483650 -Force
}

# Turn off Num Lock at startup
# Выключить Num Lock при загрузке
function DisableNumLock {
	New-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\Control Panel\Keyboard" -Name InitialKeyboardIndicators -PropertyType String -Value 2147483648 -Force
}

# Do not activate StickyKey after tapping the Shift key 5 times (current user only)
# Не включать залипание клавиши Shift после 5 нажатий (только для текущего пользователя)
function DisableStickyShift {
	New-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name Flags -PropertyType String -Value 506 -Force
}

# Activate StickyKey after tapping the Shift key 5 times (current user only)
# Включать залипание клавиши Shift после 5 нажатий (только для текущего пользователя)
function EnableStickyShift {
	New-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name Flags -PropertyType String -Value 510 -Force
}

# Do not use AutoPlay for all media and devices (current user only)
# Не использовать автозапуск для всех носителей и устройств (только для текущего пользователя)
function DisableAutoplay {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers -Name DisableAutoplay -PropertyType DWord -Value 1 -Force
}

# Use AutoPlay for all media and devices (current user only)
# Использовать автозапуск для всех носителей и устройств (только для текущего пользователя)
function EnableAutoplay {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers -Name DisableAutoplay -PropertyType DWord -Value 0 -Force
}

# Disable thumbnail cache removal
# Отключить удаление кэша миниатюр
function DisableThumbnailCacheRemoval {
	New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name Autorun -PropertyType DWord -Value 0 -Force
}

# Enable thumbnail cache removal
# Включить удаление кэша миниатюр
function EnableThumbnailCacheRemoval {
	New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name Autorun -PropertyType DWord -Value 3 -Force
}

# Automatically save my restartable apps when signing out and restart them after signing in (current user only)
# Автоматически сохранять мои перезапускаемые приложения при выходе из системы и перезапускать их после выхода (только для текущего пользователя)
function EnableSaveRestartableApps {
	New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name RestartApps -Value 1 -Force
}

# Do not automatically save my restartable apps when signing out and restart them after signing in
# Не сохранять автоматически мои перезапускаемые приложения при выходе из системы и перезапускать их после выхода
function DisableSaveRestartableApps {
	New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name RestartApps -Value 0 -Force
}

# Enable "Network Discovery" and "File and Printers Sharing" for workgroup networks
# Включить сетевое обнаружение и общий доступ к файлам и принтерам для рабочих групп
function EnableNetworkDiscovery {
	if ((Get-CimInstance -ClassName CIM_ComputerSystem).PartOfDomain -eq $false) {
		$FirewallRules = @(
			# File and printer sharing
			# Общий доступ к файлам и принтерам
			"@FirewallAPI.dll,-32752",

			# Network discovery
			# Сетевое обнаружение
			"@FirewallAPI.dll,-28502"
		)
		Set-NetFirewallRule -Group $FirewallRules -Profile Private -Enabled True

		Set-NetFirewallRule -Profile Public, Private -Name FPS-SMB-In-TCP -Enabled True
		Set-NetConnectionProfile -NetworkCategory Private
	}
}

# Disable "Network Discovery" and "File and Printers Sharing" for workgroup networks
# Выключить сетевое обнаружение и общий доступ к файлам и принтерам для рабочих групп
function DisableNetworkDiscovery {
	if ((Get-CimInstance -ClassName CIM_ComputerSystem).PartOfDomain -eq $false) {
		$FirewallRules = @(
			# File and printer sharing
			# Общий доступ к файлам и принтерам
			"@FirewallAPI.dll,-32752",

			# Network discovery
			# Сетевое обнаружение
			"@FirewallAPI.dll,-28502"
		)
		Set-NetFirewallRule -Group $FirewallRules -Profile Private -Enabled False
	}
}

# This option must be Enabled by default, otherwise set it so.
function OnlySecurityUpdates {
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name BranchReadinessLevel -PropertyType DWord -Value 20 -Force
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name DeferFeatureUpdatesPeriodInDays -PropertyType DWord -Value 365 -Force
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name DeferQualityUpdatesPeriodInDays -PropertyType DWord -Value 4 -Force
}

# Do not automatically adjust active hours for me based on daily usage
# Не изменять автоматически период активности для этого устройства на основе действий
function DisableSmartActiveHours {
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name SmartActiveHoursState -PropertyType DWord -Value 2 -Force
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name SmartActiveHoursSuggestionState -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name FlightCommitted -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name IsExpedited -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name LastToastAction -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name UxOption -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name InsiderProgramEnabled -PropertyType DWord -Value 0 -Force
}

# Automatically adjust active hours for me based on standart daily usage
# Автоматически изменять период активности для этого устройства на основе действий
function SetActiveHours {
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name ActiveHoursEnd -Value 1 -Force
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name ActiveHoursStart -Value 10 -Force

}

# Перезапускать это устройство как можно быстрее, если для установки обновления требуется перезагрузка
# Restart this device as soon as possible when a restart is required to install an update
function EnableDeviceRestartAfterUpdate {
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name IsExpedited -PropertyType DWord -Value 1 -Force
}

# Не перезапускать это устройство как можно быстрее, если для установки обновления требуется перезагрузка
# Do not restart this device as soon as possible when a restart is required to install an update
function DisableDeviceRestartAfterUpdate {
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name IsExpedited -PropertyType DWord -Value 0 -Force
}

# Disable standart F8 boot menu policy
function EnableF8BootMenuLegacy {
	bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null
}

# Set data execution prevention (DEP) policy to optout
Function SetDEPOptOut {
	bcdedit /set `{current`} nx OptOut | Out-Null
}

# Stop and disable home groups services
function DisableHomeGroups {
	Stop-Service "HomeGroupListener" -WarningAction SilentlyContinue
	Set-Service "HomeGroupListener" -StartupType Disabled
	Stop-Service "HomeGroupProvider" -WarningAction SilentlyContinue
	Set-Service "HomeGroupProvider" -StartupType Disabled
}


# Disable remote assistance
function DisableRemoteAssistance {
	New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0 -Force
}

# Stop and disable superfetch service
function DisableSuperfetch {
	Stop-Service "SysMain" -WarningAction SilentlyContinue
	Set-Service "SysMain" -StartupType Disabled
}

<#
Disable offering of drivers through Windows Update
Note: This doesn't work properly if you use a driver intended for another hardware model. E.g. Intel I219-V on WinServer works only with I219-LM driver.
Therefore Windows update will repeatedly try and fail to install I219-V driver indefinitely even if you use the tweak.
#>
function DisableAutoUpdateDriver {
	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
	}
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1 -Force
	
	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Force | Out-Null
	}
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -Type DWord -Value 1 -Force
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value 1 -Force
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -Type DWord -Value 0 -Force
	
	if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" | Out-Null
	}
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1 -Force
}
#endregion System
#region Performance
# Force disable Battery Saver
function PreventBatterySaver {
	powercfg /setdcvalueindex SCHEME_CURRENT SUB_ENERGYSAVER ESBATTTHRESHOLD 0
	powercfg /setdcvalueindex SCHEME_CURRENT SUB_ENERGYSAVER ESBRIGHTNESS 100 
}

# Disable default disk defragmenter
function DisableDefaultDiskDefragmenter {
	Disable-ScheduledTask -TaskName 'ScheduledDefrag' -TaskPath '\Microsoft\Windows\Defrag'
}

# Let personalize power plan
function LetPersonalizePowerPlan {
	powercfg -setacvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 0
	powercfg -setdcvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 0
	powercfg -setacvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 3
	powercfg -setdcvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 3
	powercfg -setacvalueindex SCHEME_CURRENT e73a048d-bf27-4f12-9731-8b2076e8891f 637ea02f-bbcb-4015-8e2c-a1c7b9c0b546 0
	powercfg -setdcvalueindex SCHEME_CURRENT e73a048d-bf27-4f12-9731-8b2076e8891f 637ea02f-bbcb-4015-8e2c-a1c7b9c0b546 1
	powercfg -setacvalueindex SCHEME_CURRENT e73a048d-bf27-4f12-9731-8b2076e8891f 9a66d8d7-4ff7-4ef9-b5a2-5a326ca2a469 8
	powercfg -setdcvalueindex SCHEME_CURRENT e73a048d-bf27-4f12-9731-8b2076e8891f 9a66d8d7-4ff7-4ef9-b5a2-5a326ca2a469 8
	powercfg -setacvalueindex SCHEME_CURRENT e73a048d-bf27-4f12-9731-8b2076e8891f d8742dcb-3e6a-4b3c-b3fe-374623cdcf06 0
	powercfg -setdcvalueindex SCHEME_CURRENT e73a048d-bf27-4f12-9731-8b2076e8891f d8742dcb-3e6a-4b3c-b3fe-374623cdcf06 0
	powercfg -setacvalueindex SCHEME_CURRENT e73a048d-bf27-4f12-9731-8b2076e8891f 8183ba9a-e910-48da-8769-14ae6dc1170a 15
	powercfg -setdcvalueindex SCHEME_CURRENT e73a048d-bf27-4f12-9731-8b2076e8891f 8183ba9a-e910-48da-8769-14ae6dc1170a 15
	powercfg -setacvalueindex SCHEME_CURRENT 7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 0
	powercfg -setdcvalueindex SCHEME_CURRENT 7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 0
	powercfg -setacvalueindex SCHEME_CURRENT 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0
	powercfg -setdcvalueindex SCHEME_CURRENT 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0
	powercfg -setacvalueindex SCHEME_CURRENT 501a4d13-42af-4429-9fd1-a8218c268e20 ee12f906-d277-404b-b6da-e5fa1a576df5 0
	powercfg -setdcvalueindex SCHEME_CURRENT 501a4d13-42af-4429-9fd1-a8218c268e20 ee12f906-d277-404b-b6da-e5fa1a576df5 0
	powercfg -setacvalueindex SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
	powercfg -setdcvalueindex SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
	powercfg -setacvalueindex SCHEME_CURRENT 238c9fa8-0aad-41ed-83f4-97be242c8f20 9d7815a6-7ee4-497e-8888-515a05f02364 0
	powercfg -setdcvalueindex SCHEME_CURRENT 238c9fa8-0aad-41ed-83f4-97be242c8f20 9d7815a6-7ee4-497e-8888-515a05f02364 0
	powercfg -setacvalueindex SCHEME_CURRENT 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 1500
	powercfg -setdcvalueindex SCHEME_CURRENT 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 1500
	powercfg -setacvalueindex SCHEME_CURRENT 238c9fa8-0aad-41ed-83f4-97be242c8f20 bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d 0
	powercfg -setdcvalueindex SCHEME_CURRENT 238c9fa8-0aad-41ed-83f4-97be242c8f20 bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d 0
}

# Prevent require sign-in when after sleep
function PreventRequireSignInWhenAfterSleep {
	powercfg -setacvalueindex SCHEME_CURRENT SUB_NONE CONSOLELOCK 0
	powercfg -setdcvalueindex SCHEME_CURRENT SUB_NONE CONSOLELOCK 0
}
# Disable indexing
function DisableIndexing {
	$DriveLetters = @((Get-Disk | Where-Object -FilterScript { $_.BusType -ne "USB" } | Get-Partition | Get-Volume | Where-Object -FilterScript { $null -ne $_.DriveLetter }).DriveLetter | Sort-Object)
	$Object = (Get-WmiObject -Class Win32_Volume -Filter "DriveLetter = 'C:'")
    
	if ($DriveLetters.Count -notmatch 2) {
		if (($Object.IndexingEnabled -match $True)) {
			Write-Output "Disabling indexing of drive C:"
			$Object | Set-WmiInstance -Arguments @{IndexingEnabled = $False } | Out-Null
		}
		else {
			Write-Output "Indexing already disabled. SKIPPING..."
		}
	}
    
	if ($DriveLetters.Count -notmatch 3) {
		if (($Object.IndexingEnabled -match $True)) {
			Write-Output "Disabling indexing of drive C:"
			$Object | Set-WmiInstance -Arguments @{IndexingEnabled = $False } | Out-Null
		}
		else {
			Write-Output "Indexing already disabled. SKIPPING..."
		}
	}

	else {
		Write-Output "Unable to find the right option. SKIPPING..."
	}

}

# Adjust best performance(that would able to increase the overall performance)
function AdjustBestPerformance {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects -Name VisualFXSetting -PropertyType DWord -Value 2 -Force
	New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name MenuShowDelay -PropertyType String -Value 0 -Force
	New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name UserPreferencesMask -PropertyType Binary -Value ([byte[]](144, 18, 3, 128, 16, 0, 0, 0)) -Force
	New-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name MinAnimate -PropertyType String -Value 0 -Force
	New-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name KeyboardDelay -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ListviewAlphaSelect -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ListviewShadow -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name TaskbarAnimations -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\DWM -Name EnableAeroPeek -PropertyType DWord -Value 0 -Force
}

# Set current boot timeout value to 0
function SetBootTimeoutValue {
	bcdedit /timeout 0
}
#endregion Performance
#region Gaming
# Turn off Xbox Game Bar
# Отключить Xbox Game Bar
function DisableXboxGameBar {
	if ((Get-AppxPackage -Name Microsoft.XboxGamingOverlay) -or (Get-AppxPackage -Name Microsoft.GamingApp)) {
		New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR -Name AppCaptureEnabled -PropertyType DWord -Value 0 -Force
		New-ItemProperty -Path HKCU:\System\GameConfigStore -Name GameDVR_Enabled -PropertyType DWord -Value 0 -Force
	}
}

# Turn on Xbox Game Bar
# Включить Xbox Game Bar
function EnableXboxGameBar {
	if ((Get-AppxPackage -Name Microsoft.XboxGamingOverlay) -or (Get-AppxPackage -Name Microsoft.GamingApp)) {
		New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR -Name AppCaptureEnabled -PropertyType DWord -Value 1 -Force
		New-ItemProperty -Path HKCU:\System\GameConfigStore -Name GameDVR_Enabled -PropertyType DWord -Value 1 -Force
	}
}

# Turn off Xbox Game Bar tips
# Отключить советы Xbox Game Bar
function DisableXboxGameTips {
	if ((Get-AppxPackage -Name Microsoft.XboxGamingOverlay) -or (Get-AppxPackage -Name Microsoft.GamingApp)) {
		New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\GameBar -Name ShowStartupPanel -PropertyType DWord -Value 0 -Force
	}
}

# Turn on Xbox Game Bar tips
# Включить советы Xbox Game Bar
function EnableXboxGameTips {
	if ((Get-AppxPackage -Name Microsoft.XboxGamingOverlay) -or (Get-AppxPackage -Name Microsoft.GamingApp)) {
		New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\GameBar -Name ShowStartupPanel -PropertyType DWord -Value 1 -Force
	}
}

<#
	Set "High performance" in graphics performance preference for an app
	Only with a dedicated GPU

	Установить параметры производительности графики для отдельных приложений на "Высокая производительность"
	Только при наличии внешней видеокарты
#>

<#
	Turn on hardware-accelerated GPU scheduling. Restart needed
	Only with a dedicated GPU and WDDM verion is 2.7 or higher

	Включить планирование графического процессора с аппаратным ускорением. Необходима перезагрузка
	Только при наличии внешней видеокарты и WDDM версии 2.7 и выше
#>
function EnableGPUScheduling {
	if ((Get-CimInstance -ClassName CIM_VideoController | Where-Object -FilterScript { $_.AdapterDACType -ne "Internal" })) {
		# Determining whether an OS is not installed on a virtual machine
		# Проверяем, не установлена ли ОС на виртуальной машине
		if ((Get-CimInstance -ClassName CIM_ComputerSystem).Model -notmatch "Virtual") {
			# Checking whether a WDDM verion is 2.7 or higher
			# Проверка: имеет ли WDDM версию 2.7 или выше
			$WddmVersion_Min = 	if ((Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers")) { Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\FeatureSetUsage -Name WddmVersion_Min }
			if ($WddmVersion_Min -ge 2700) {
				New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name HwSchMode -PropertyType DWord -Value 2 -Force
			}
		}
	}
}

# Turn off hardware-accelerated GPU scheduling. Restart needed
# Выключить планирование графического процессора с аппаратным ускорением. Необходима перезагрузка
function DisableGPUScheduling {
	New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name HwSchMode -PropertyType DWord -Value 1 -Force
}

# Adjust best performance for all programs and also foreground services
function BestPriorityForeground {
	New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name Win32PrioritySeparation -PropertyType DWord -Value 38 -Force
	if (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{d1f83304-4133-4c30-82d2-07078e47d5a7}")) {
	New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{d1f83304-4133-4c30-82d2-07078e47d5a7}" -Force | Out-Null
	}
	New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{d1f83304-4133-4c30-82d2-07078e47d5a7}" -Name TcpAckFrequency -PropertyType DWord -Value 1 -Force
	New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{d1f83304-4133-4c30-82d2-07078e47d5a7}" -Name TCPNoDelay -PropertyType DWord -Value 1 -Force
	New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{d1f83304-4133-4c30-82d2-07078e47d5a7}" -Name TcpDelAckTicks -PropertyType DWord -Value 0 -Force
	if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Force | Out-Null
	}
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name NetworkThrottlingIndex -PropertyType DWord -Value 4294967295 -Force
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name SystemResponsiveness -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name 'GPU Priority' -PropertyType DWord -Value 8 -Force
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name Priority -PropertyType DWord -Value 6 -Force
	netsh int tcp set global rsc=disabled
}
#endregion Gaming
#region Scheduled tasks
<#
	Create a task to clean up unused files and Windows updates in the Task Scheduler
	A minute before the task starts, a warning in the Windows action center will appear
	The task runs every 10 days

	Создать задачу в Планировщике задач по очистке неиспользуемых файлов и обновлений Windows
	За минуту до выполнения задачи в Центре уведомлений Windows появится предупреждение
	Задача выполняется каждые 10 дней
#>
function CreateCleanUpTask {
	Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches | ForEach-Object -Process {
		Remove-ItemProperty -Path $_.PsPath -Name StateFlags1337 -Force -ErrorAction Ignore
	}

	$VolumeCaches = @(
		# Delivery Optimization Files
		# Файлы оптимизации доставки
		"Delivery Optimization Files",

		# Device driver packages
		# Пакеты драйверов устройств
		"Device Driver Packages",

		# Previous Windows Installation(s)
		# Предыдущие установки Windows
		"Previous Installations",

		# Setup log files
		# Файлы журнала установки
		"Setup Log Files",

		# Temporary Setup Files
		# Временные файлы установки
		"Temporary Setup Files",

		# Microsoft Defender
		"Windows Defender",

		# Windows upgrade log files
		# Файлы журнала обновления Windows
		"Windows Upgrade Log Files"
	)
	foreach ($VolumeCache in $VolumeCaches) {
		New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\$VolumeCache" -Name StateFlags1337 -PropertyType DWord -Value 2 -Force
	}

	$PS1Script = '
$app = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\cleanmgr.exe"

[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
$Template = [Windows.UI.Notifications.ToastTemplateType]::ToastImageAndText01
[xml]$ToastTemplate = ([Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($Template).GetXml())

[xml]$ToastTemplate = @"
<toast launch="app-defined-string">
	<visual>
		<binding template="ToastGeneric">
			<text>$($Localization.CleanUpTaskToast)</text>
		</binding>
	</visual>
</toast>
"@

$ToastXml = New-Object -TypeName Windows.Data.Xml.Dom.XmlDocument
$ToastXml.LoadXml($ToastTemplate.OuterXml)

[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show($ToastXml)

Start-Sleep -Seconds 60

# Process startup info
# Параметры запуска процесса
$ProcessInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
$ProcessInfo.FileName = "$env:SystemRoot\system32\cleanmgr.exe"
$ProcessInfo.Arguments = "/sagerun:1337"
$ProcessInfo.UseShellExecute = $true
$ProcessInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Minimized

# Process object using the startup info
# Объект процесса, используя заданные параметры
$Process = New-Object -TypeName System.Diagnostics.Process
$Process.StartInfo = $ProcessInfo

# Start the process
# Запуск процесса
$Process.Start() | Out-Null

Start-Sleep -Seconds 3
$SourceMainWindowHandle = (Get-Process -Name cleanmgr).MainWindowHandle

function MinimizeWindow
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		$Process
	)

	$ShowWindowAsync = @{
	Namespace = "WinAPI"
	Name = "Win32ShowWindowAsync"
	Language = "CSharp"
	MemberDefinition = @"
[DllImport("user32.dll")]
public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
"@
	}
	if (-not ("WinAPI.Win32ShowWindowAsync" -as [type]))
	{
		Add-Type @ShowWindowAsync
	}

	$MainWindowHandle = (Get-Process -Name $Process).MainWindowHandle
	[WinAPI.Win32ShowWindowAsync]::ShowWindowAsync($MainWindowHandle, 2)
}

while ($true)
{
	$CurrentMainWindowHandle = (Get-Process -Name cleanmgr).MainWindowHandle
	if ([int]$SourceMainWindowHandle -ne [int]$CurrentMainWindowHandle)
	{
		MinimizeWindow -Process cleanmgr
		break
	}
	Start-Sleep -Milliseconds 5
}

$ProcessInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
# Cleaning up unused updates
# Очистка неиспользованных обновлений
$ProcessInfo.FileName = "$env:SystemRoot\system32\dism.exe"
$ProcessInfo.Arguments = "/Online /English /Cleanup-Image /StartComponentCleanup /NoRestart"
$ProcessInfo.UseShellExecute = $true
$ProcessInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Minimized

# Process object using the startup info
# Объект процесса, используя заданные параметры
$Process = New-Object -TypeName System.Diagnostics.Process
$Process.StartInfo = $ProcessInfo

# Start the process
# Запуск процесса
$Process.Start() | Out-Null
'
	# Encode $PS1Script variable to be able to pipeline it as an argument
	# Закодировать переменную $PS1Script, чтобы передать ее как аргумент
	$EncodedScript = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($PS1Script))

	$Action = New-ScheduledTaskAction -Execute powershell.exe -Argument "-WindowStyle Hidden -EncodedCommand $EncodedScript"
	$Trigger = New-ScheduledTaskTrigger -Daily -DaysInterval 10 -At 11am
	$Settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
	$Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest
	$Parameters = @{
		"TaskName"  = "Windows Cleanup"
		"TaskPath"  = "Fresh Script"
		"Principal" = $Principal
		"Action"    = $Action
		"Settings"  = $Settings
		"Trigger"   = $Trigger
	}
	Register-ScheduledTask @Parameters -Force
}

# Delete a task to clean up unused files and Windows updates in the Task Scheduler
# Удалить задачу в Планировщике задач по очистке неиспользуемых файлов и обновлений Windows
function DeleteCleanUpTask {
	Unregister-ScheduledTask -TaskName "Windows Cleanup" -Confirm:$false
}

<#
	Create a task to clear the %SystemRoot%\SoftwareDistribution\Download folder in the Task Scheduler
	The task runs in every 7 days

	Создать задачу в Планировщике задач по очистке папки %SystemRoot%\SoftwareDistribution\Download
	Задача выполняется по четвергам каждую 7 дней
#>
function CreateSoftwareDistributionTask {
	$Argument = "
		(Get-Service -Name wuauserv).WaitForStatus('Stopped', '01:00:00')
		Get-ChildItem -Path $env:SystemRoot\SoftwareDistribution\Download -Recurse -Force | Remove-Item -Recurse -Force
	"
	$Action = New-ScheduledTaskAction -Execute powershell.exe -Argument $Argument
	$Trigger = New-JobTrigger -Daily -DaysInterval 7 -At 11am
	$Settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
	$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest
	$Parameters = @{
		"TaskName"  = "SoftwareDistribution"
		"TaskPath"  = "Fresh Script"
		"Principal" = $Principal
		"Action"    = $Action
		"Settings"  = $Settings
		"Trigger"   = $Trigger
	}
	Register-ScheduledTask @Parameters -Force
}

# Delete a task to clear the %SystemRoot%\SoftwareDistribution\Download folder in the Task Scheduler
# Удалить задачу в Планировщике задач по очистке папки %SystemRoot%\SoftwareDistribution\Download
function DeleteCSoftwareDistributionTask {
	Unregister-ScheduledTask -TaskName SoftwareDistribution -Confirm:$false
}

<#
	Create a task to clear the %TEMP% folder in the Task Scheduler
	The task runs every 5 days

	Создать задачу в Планировщике задач по очистке папки %TEMP%
	Задача выполняется каждые 5 дня
#>
function CreateTempTask {
	$Argument = "Get-ChildItem -Path $env:TEMP -Force -Recurse | Remove-Item -Recurse -Force"
	$Action = New-ScheduledTaskAction -Execute powershell.exe -Argument $Argument
	$Trigger = New-ScheduledTaskTrigger -Daily -DaysInterval 5 -At 11am
	$Settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
	$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest
	$Parameters = @{
		"TaskName"  = "Temp"
		"TaskPath"  = "Fresh Script"
		"Principal" = $Principal
		"Action"    = $Action
		"Settings"  = $Settings
		"Trigger"   = $Trigger
	}
	Register-ScheduledTask @Parameters -Force
}

# Delete a task to clear the %TEMP% folder in the Task Scheduler
# Удалить задачу в Планировщике задач по очистке папки %TEMP%
function DeleteTempTask {
	Unregister-ScheduledTask -TaskName Temp -Confirm:$false
}
#endregion Scheduled tasks
#region Microsoft Defender & Security
# Enable Controlled folder access and add protected folders
# Включить контролируемый доступ к папкам и добавить защищенные папки
function AddProtectedFolders {
	$Title = $Localization.AddProtectedFoldersTitle
	$Message = $Localization.AddProtectedFoldersRequest
	$Add = $Localization.AddProtectedFoldersAdd
	$Skip = $Localization.AddProtectedFoldersSkip
	$Options = "&$Add", "&$Skip"
	$DefaultChoice = 1

	do {
		$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)
		switch ($Result) {
			"0" {
				Add-Type -AssemblyName System.Windows.Forms
				$FolderBrowserDialog = New-Object -TypeName System.Windows.Forms.FolderBrowserDialog
				$FolderBrowserDialog.Description = $Localization.AddProtectedFoldersDescription
				$FolderBrowserDialog.RootFolder = "MyComputer"

				# Focus on open file dialog
				# Перевести фокус на диалог открытия файла
				$tmp = New-Object -TypeName System.Windows.Forms.Form -Property @{TopMost = $true }

				$FolderBrowserDialog.ShowDialog($tmp)
				if ($FolderBrowserDialog.SelectedPath) {
					Set-MpPreference -EnableControlledFolderAccess Enabled
					Add-MpPreference -ControlledFolderAccessProtectedFolders $FolderBrowserDialog.SelectedPath -Force
					Write-Verbose -Message ("{0}" -f $FolderBrowserDialog.SelectedPath) -Verbose
				}
			}
			"1" {
				Write-Verbose -Message $Localization.AddProtectedFoldersSkipped -Verbose
			}
		}
	}
	until ($Result -eq 1)
}

# Remove all added protected folders
# Удалить все добавленные защищенные папки
function RemoveProtectedFolders {
	if ($null -ne (Get-MpPreference).ControlledFolderAccessProtectedFolders) {
		Write-Verbose -Message $Localization.RemoveProtectedFoldersList -Verbose
		(Get-MpPreference).ControlledFolderAccessProtectedFolders | Format-Table -AutoSize -Wrap
		Remove-MpPreference -ControlledFolderAccessProtectedFolders (Get-MpPreference).ControlledFolderAccessProtectedFolders -Force
	}
}

# Allow an app through Controlled folder access
# Разрешить работу приложения через контролируемый доступ к папкам
function AddAppControlledFolder {
	$Title = $Localization.AddAppControlledFolderTitle
	$Message = $Localization.AddAppControlledFolderRequest
	$Add = $Localization.AddAppControlledFolderAdd
	$Skip = $Localization.AddAppControlledFolderSkip
	$Options = "&$Add", "&$Skip"
	$DefaultChoice = 1

	do {
		$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)
		switch ($Result) {
			"0" {
				Add-Type -AssemblyName System.Windows.Forms
				$OpenFileDialog = New-Object -TypeName System.Windows.Forms.OpenFileDialog
				$OpenFileDialog.Filter = $Localization.AddAppControlledFolderFilter
				$OpenFileDialog.InitialDirectory = "::{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
				$OpenFileDialog.Multiselect = $false

				# Focus on open file dialog
				# Перевести фокус на диалог открытия файла
				$tmp = New-Object -TypeName System.Windows.Forms.Form -Property @{TopMost = $true }

				$OpenFileDialog.ShowDialog($tmp)
				if ($OpenFileDialog.FileName) {
					Add-MpPreference -ControlledFolderAccessAllowedApplications $OpenFileDialog.FileName -Force
					Write-Verbose -Message ("{0}" -f $OpenFileDialog.FileName) -Verbose
				}
			}
			"1" {
				Write-Verbose -Message $Localization.AddAppControlledFolderSkipped -Verbose
			}
		}
	}
	until ($Result -eq 1)
}

# Remove all allowed apps through Controlled folder access
# Удалить все добавленные разрешенные приложение через контролируемый доступ к папкам
function RemoveAllowedAppsControlledFolder {
	if ($null -ne (Get-MpPreference).ControlledFolderAccessAllowedApplications) {
		Write-Verbose -Message $Localization.RemoveAllowedAppsControlledFolderList -Verbose
		(Get-MpPreference).ControlledFolderAccessAllowedApplications | Format-Table -AutoSize -Wrap
		Remove-MpPreference -ControlledFolderAccessAllowedApplications (Get-MpPreference).ControlledFolderAccessAllowedApplications -Force
	}
}

# Add a folder to the exclusion from Microsoft Defender scanning
# Добавить папку в список исключений сканирования Microsoft Defender
function AddDefenderExclusionFolder {
	$Title = $Localization.AddDefenderExclusionFolderTitle
	$Message = $Localization.AddDefenderExclusionFolderRequest
	$Add = $Localization.AddDefenderExclusionFolderAdd
	$Skip = $Localization.AddDefenderExclusionFolderSkip
	$Options = "&$Add", "&$Skip"
	$DefaultChoice = 1

	do {
		$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)
		switch ($Result) {
			"0" {
				Add-Type -AssemblyName System.Windows.Forms
				$FolderBrowserDialog = New-Object -TypeName System.Windows.Forms.FolderBrowserDialog
				$FolderBrowserDialog.Description = $Localization.AddDefenderExclusionFolderDescription
				$FolderBrowserDialog.RootFolder = "MyComputer"

				# Focus on open file dialog
				# Перевести фокус на диалог открытия файла
				$tmp = New-Object -TypeName System.Windows.Forms.Form -Property @{TopMost = $true }

				$FolderBrowserDialog.ShowDialog($tmp)
				if ($FolderBrowserDialog.SelectedPath) {
					Add-MpPreference -ExclusionPath $FolderBrowserDialog.SelectedPath -Force
					Write-Verbose -Message ("{0}" -f $FolderBrowserDialog.SelectedPath) -Verbose
				}
			}
			"1" {
				Write-Verbose -Message $Localization.AddDefenderExclusionFolderSkipped -Verbose
			}
		}
	}
	until ($Result -eq 1)
}

# Remove all excluded folders from Microsoft Defender scanning
# Удалить все папки из списка исключений сканирования Microsoft Defender
function RemoveDefenderExclusionFolders {
	if ($null -ne (Get-MpPreference).ExclusionPath) {
		Write-Verbose -Message $Localization.RemoveDefenderExclusionFoldersList -Verbose
		$ExcludedFolders = (Get-Item -Path (Get-MpPreference).ExclusionPath -Force -ErrorAction Ignore | Where-Object -FilterScript { $_.Attributes -match "Directory" }).FullName
		$ExcludedFolders | Format-Table -AutoSize -Wrap
		Remove-MpPreference -ExclusionPath $ExcludedFolders -Force
	}
}

# Add a file to the exclusion from Microsoft Defender scanning
# Добавить файл в список исключений сканирования Microsoft Defender
function AddDefenderExclusionFile {
	$Title = $Localization.AddDefenderExclusionFileTitle
	$Message = $Localization.AddDefenderExclusionFileRequest
	$Add = $Localization.AddDefenderExclusionFileAdd
	$Skip = $Localization.AddDefenderExclusionFileSkip
	$Options = "&$Add", "&$Skip"
	$DefaultChoice = 1

	do {
		$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)
		switch ($Result) {
			"0" {
				Add-Type -AssemblyName System.Windows.Forms
				$OpenFileDialog = New-Object -TypeName System.Windows.Forms.OpenFileDialog
				$OpenFileDialog.Filter = $Localization.AddDefenderExclusionFileFilter
				$OpenFileDialog.InitialDirectory = "::{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
				$OpenFileDialog.Multiselect = $false

				# Focus on open file dialog
				# Перевести фокус на диалог открытия файла
				$tmp = New-Object -TypeName System.Windows.Forms.Form -Property @{TopMost = $true }

				$OpenFileDialog.ShowDialog($tmp)
				if ($OpenFileDialog.FileName) {
					Add-MpPreference -ExclusionPath $OpenFileDialog.FileName -Force
					Write-Verbose -Message ("{0}" -f $OpenFileDialog.FileName) -Verbose
				}
			}
			"1" {
				Write-Verbose -Message $Localization.AddDefenderExclusionFileSkipped -Verbose
			}
		}
	}
	until ($Result -eq 1)
}

# Remove all excluded files from Microsoft Defender scanning
# Удалить все файлы из списка исключений сканирования Microsoft Defender
function RemoveDefenderExclusionFiles {
	if ($null -ne (Get-MpPreference).ExclusionPath) {
		Write-Verbose -Message $Localization.RemoveDefenderExclusionFilesList -Verbose
		$ExcludedFiles = (Get-Item -Path (Get-MpPreference).ExclusionPath -Force -ErrorAction Ignore | Where-Object -FilterScript { $_.Attributes -notmatch "Directory" }).FullName
		$ExcludedFiles | Format-Table -AutoSize -Wrap
		Remove-MpPreference -ExclusionPath $ExcludedFiles -Force
	}
}

# Turn on Microsoft Defender Exploit Guard network protection
# Включить защиту сети в Microsoft Defender Exploit Guard
function EnableNetworkProtection {
	Set-MpPreference -EnableNetworkProtection Enabled
}

# Turn off Microsoft Defender Exploit Guard network protection
# Выключить защиту сети в Microsoft Defender Exploit Guard
function DisableNetworkProtection {
	Set-MpPreference -EnableNetworkProtection Disabled
}

# Turn on detection for potentially unwanted applications and block them
# Включить обнаружение потенциально нежелательных приложений и блокировать их
function EnablePUAppsDetection {
	Set-MpPreference -PUAProtection Enabled
}

# Turn off detection for potentially unwanted applications and block them
# Выключить обнаружение потенциально нежелательных приложений и блокировать их
function DisabledPUAppsDetection {
	Set-MpPreference -PUAProtection Disabled
}

# Run Microsoft Defender within a sandbox
# Запускать Microsoft Defender в песочнице
function EnableDefenderSandbox {
	setx /M MP_FORCE_USE_SANDBOX 1
}

# Do not run Microsoft Defender within a sandbox
# Не запускать Microsoft Defender в песочнице
function DisableDefenderSandbox {
	setx /M MP_FORCE_USE_SANDBOX 0
}

# Dismiss Microsoft Defender offer in the Windows Security about signing in Microsoft account
# Отклонить предложение Microsoft Defender в "Безопасность Windows" о входе в аккаунт Microsoft
function DismissMSAccount {
	New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Security Health\State" -Name AccountProtection_MicrosoftAccount_Disconnected -PropertyType DWord -Value 1 -Force
}

# Dismiss Microsoft Defender offer in the Windows Security about turning on the SmartScreen filter for Microsoft Edge
# Отклонить предложение Microsoft Defender в "Безопасность Windows" включить фильтр SmartScreen для Microsoft Edge
function DismissSmartScreenFilter {
	New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Security Health\State" -Name AppAndBrowser_EdgeSmartScreenOff -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name EnableSmartScreen -Type DWord -Value 0 -Force
	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Force | Out-Null
	}
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name EnabledV9 -Type DWord -Value 0 -Force
}

<#
	Include command line in process creation events
	In order this feature to work events auditing must be enabled ("EnableAuditProcess" function)

	Включать командную строку в событиях создания процесса
	Необходимо включить аудит событий, чтобы работал данный функционал (функция "EnableAuditProcess")
#>
function EnableAuditProcess {
	auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
}

# Turn off events auditing generated when a process is created or starts
# Выключить аудит событий, возникающих при создании или запуске процесса
function DisableAuditProcess {
	auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:disable /failure:disable
}

# Turn on events auditing generated when a process is created or starts
# Включить аудит событий, возникающих при создании или запуске процесса
function EnableAuditCommandLineProcess {
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit -Name ProcessCreationIncludeCmdLine_Enabled -PropertyType DWord -Value 1 -Force
}

# Do not include command line in process creation events
# Не включать командную строку в событиях создания процесса
function DisableAuditCommandLineProcess {
	if ((Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit")) {
	        Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit -Name ProcessCreationIncludeCmdLine_Enabled -Force -ErrorAction SilentlyContinue
	} 
}

<#
	Create "Process Creation" Event Viewer Custom View
	In order this feature to work events auditing and command line in process creation events must be enabled ("EnableAuditProcess" function)

	Создать настаиваемое представление "Создание процесса" в Просмотре событий
	Необходимо включить аудит событий и командной строки в событиях создания процесса, чтобы работал данный функционал (функция "EnableAuditProcess")
#>
function CreateEventViewerCustomView {
	$XML = @"
	<ViewerConfig>
		<QueryConfig>
			<QueryParams>
				<UserQuery />
			</QueryParams>
			<QueryNode>
				<Name>$($Localization.EventViewerCustomViewName)</Name>
				<Description>$($Localization.EventViewerCustomViewDescription)</Description>
				<QueryList>
					<Query Id="0" Path="Security">
						<Select Path="Security">*[System[(EventID=4688)]]</Select>
					</Query>
				</QueryList>
			</QueryNode>
		</QueryConfig>
	</ViewerConfig>
"@
	if (-not (Test-Path -Path "$env:ProgramData\Microsoft\Event Viewer\Views")) {
		New-Item -Path "$env:ProgramData\Microsoft\Event Viewer\Views" -ItemType Directory -Force
	}
	# Saving ProcessCreation.xml in UTF-8 encoding
	# Сохраняем ProcessCreation.xml в кодировке UTF-8
	Set-Content -Path "$env:ProgramData\Microsoft\Event Viewer\Views\ProcessCreation.xml" -Value (New-Object -TypeName System.Text.UTF8Encoding).GetBytes($XML) -Encoding Byte -Force
}

# Remove "Process Creation" Event Viewer Custom View
# Удалить настаиваемое представление "Создание процесса" в Просмотре событий
function RemoveEventViewerCustomView {
	if ((Test-Path -Path "$env:ProgramData\Microsoft\Event Viewer\Views\")) {
	        Remove-Item -Path "$env:ProgramData\Microsoft\Event Viewer\Views\ProcessCreation.xml" -Force -ErrorAction SilentlyContinue
	}
}

# Log for all Windows PowerShell modules
# Вести журнал для всех модулей Windows PowerShell
function EnablePowerShellModulesLogging {
	if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames)) {
		New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames -Force
	}
	New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging -Name EnableModuleLogging -PropertyType DWord -Value 1 -Force
	New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames -Name * -PropertyType String -Value * -Force
}

# Do not log for all Windows PowerShell modules
# Не вести журнал для всех модулей Windows PowerShell
function DisablePowerShellModulesLogging {
	if ((Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging")) {
		Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging -Name EnableModuleLogging -Force -ErrorAction SilentlyContinue
		Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames -Name * -Force -ErrorAction SilentlyContinue
	}
}

# Log all PowerShell scripts input to the Windows PowerShell event log
# Вести регистрацию всех вводимых сценариев PowerShell в журнале событий Windows PowerShell
function EnablePowerShellScriptsLogging {
	if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging)) {
		New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Force
	}
	New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging -PropertyType DWord -Value 1 -Force
}

# Do not log all PowerShell scripts input to the Windows PowerShell event log
# Не вести регистрацию всех вводимых сценариев PowerShell в журнале событий Windows PowerShell
function DisablePowerShellScriptsLogging {
	if ((Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging")) {
	        Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging -Force -ErrorAction SilentlyContinue
	}
}

# Do not check apps and files within Microsoft Defender SmartScreen
# Не проверять приложения и файлы фильтром SmartScreen в Microsoft Defender
function DisableAppsSmartScreen {
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name SmartScreenEnabled -PropertyType String -Value Off -Force
}

# Check apps and files within Microsoft Defender SmartScreen
# Проверять приложения и файлы фильтром SmartScreen в Microsoft Defender
function EnableAppsSmartScreen {
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name SmartScreenEnabled -PropertyType String -Value Warn -Force
}

# Prevent SmartScreen from marking files that have been downloaded from the Internet as unsafe (current user only)
# Не позволять SmartScreen отмечать файлы, скачанные из интернета, как небезопасные (только для текущего пользователя)
function DisableSaveZoneInformation {
	if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments)) {
		New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments -Force
	}
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments -Name SaveZoneInformation -PropertyType DWord -Value 1 -Force
}

# Mark files that have been downloaded from the Internet as unsafe within SmartScreen (current user only)
# Отмечать файлы, скачанные из интернета, как небезопасные с помощью SmartScreen (только для текущего пользователя)
function EnableSaveZoneInformation {
	Remove-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments -Name SaveZoneInformation -Force -ErrorAction SilentlyContinue
}

# Turn off Windows Script Host (current user only)
# Отключить Windows Script Host (только для текущего пользователя)
function DisableWindowsScriptHost {
	if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Force
	}
	New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name Enabled -PropertyType DWord -Value 0 -Force
}

# Turn on Windows Script Host (current user only)
# Включить Windows Script Host (только для текущего пользователя)
function EnableWindowsScriptHost {
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name Enabled -Force -ErrorAction SilentlyContinue
}

# Disable activity history
function DisableActivityHistory {
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name EnableActivityFeed -Type DWord -Value 0 -Force
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name PublishUserActivities -Type DWord -Value 0 -Force
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name UploadUserActivities -Type DWord -Value 0 -Force
}

# Disable automatic map updates
function DisableMapUpdates {
	New-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0 -Force
}

# Disable wap push service
function DisableWAPPush {
	Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
	Set-Service "dmwappushservice" -StartupType Disabled
}

# Enable strong cryptography for .NET Framework(version 4 and above)
function EnableDotNetStrongCrypto {
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1 -Force
	New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1 -Force
	if (!(Test-Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.5.1")) {
		New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.5.1" | Out-Null
    }
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.5.1" -Name "SchUseStrongCrypto" -Type DWord -Value 1 -Force
	if (!(Test-Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.5.25000")) {
		New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.5.25000" | Out-Null
    }
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.5.25000" -Name "SchUseStrongCrypto" -Type DWord -Value 1 -Force
}

<#
Enable Meltdown (CVE-2017-5754) compatibility flag(required for january 2018 and all subsequent windows updates)
This flag is normally automatically enabled by compatible antivirus software (such as Windows Defender).
Use the tweak only if you have confirmed that your AV is compatible but unable to set the flag automatically or if you don't use any AV at all
#>
function EnableMeltdownCompatFlag {
	if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" | Out-Null
	}
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -Type DWord -Value 0 -Force
}

# Disable password complexity and maximum age requirements
function DisablePasswordPolicy {
	$tmpfile = New-TemporaryFile
	secedit /export /cfg $tmpfile /quiet
	(Get-Content $tmpfile).Replace("PasswordComplexity = 1", "PasswordComplexity = 0").Replace("MaximumPasswordAge = 42", "MaximumPasswordAge = -1") | Out-File $tmpfile
	secedit /configure /db "$env:SYSTEMROOT\security\database\local.sdb" /cfg $tmpfile /areas SECURITYPOLICY | Out-Null
	Remove-Item -Path $tmpfile
}

# Schedule automatic maintenance hours
function AutomaticMaintenanceHours {
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "Activation Boundary" -Type String -Value "2001-01-01T11:00:00" -Force
}

# Turn on memory integry(virtualization based security)
function TurnOnMemoryIntegry {
	if (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity")) {
		New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Force | Out-Null
	}
	New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name Enabled -PropertyType DWord -Value 1 -Force
}

# Disable implicit administrative shares
function DisableAdminShares {
	New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -PropertyType DWord -Value 0 -Force
}

# Disable obsolete SMB protocol(disabled by default since 1709)
function DisableSMB {
	Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
	Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force
}

# Disable link-local multicast name resolution(LLMNR) protocol
function DisableLLMNR {
	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
	}
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -PropertyType DWord -Value 0 -Force
}

# Set unknown networks profile to public(deny file sharing, device discovery, etc.)
function SetUnknownNetworksPublic {
	if ((Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24")) {
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -ErrorAction SilentlyContinue
	}
}

# Disable automatic installation of network devices
function DisableNetDevicesAutoInst {
	if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null
	}
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0 -Force
}
#endregion Microsoft Defender & Security
#region Context menu
# Add the "Extract all" item to Windows Installer (.msi) context menu
# Добавить пункт "Извлечь все" в контекстное меню Windows Installer (.msi)
function AddMSIExtractContext {
	if (-not (Test-Path -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\Command)) {
		New-Item -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\Command -Force
	}
	$Value = "{0}" -f 'msiexec.exe /a "%1" /qb TARGETDIR="%1 extracted"'
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\Command -Name "(Default)" -PropertyType String -Value $Value -Force
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract -Name MUIVerb -PropertyType String -Value "@shell32.dll,-37514" -Force
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract -Name Icon -PropertyType String -Value "shell32.dll,-16817" -Force
}

# Remove the "Extract all" item from Windows Installer (.msi) context menu
# Удалить пункт "Извлечь все" из контекстного меню Windows Installer (.msi)
function RemoveMSIExtractContext {
	Remove-Item -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract -Recurse -Force -ErrorAction SilentlyContinue
}

# Add the "Install" item to the .cab archives context menu
# Добавить пункт "Установить" в контекстное меню .cab архивов
function AddCABInstallContext {
	if (-not (Test-Path -Path Registry::HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs\Command)) {
		New-Item -Path Registry::HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs\Command -Force
	}
	$Value = "{0}" -f "cmd /c DISM.exe /Online /Add-Package /PackagePath:`"%1`" /NoRestart & pause"
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs\Command -Name "(Default)" -PropertyType String -Value $Value -Force
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs -Name MUIVerb -PropertyType String -Value "@shell32.dll,-10210" -Force
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs -Name HasLUAShield -PropertyType String -Value "" -Force
}

# Remove the "Install" item from the .cab archives context menu
# Удалить пункт "Установить" из контекстного меню .cab архивов
function RemoveCABInstallContext {
	Remove-Item -Path Registry::HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs\Command -Recurse -Force -ErrorAction SilentlyContinue
}

# Add the "Run as different user" item to the .exe files types context menu
# Добавить пункт "Запуск от имени другого пользователя" в контекстное меню .exe файлов
function AddExeRunAsDifferentUserContext {
	Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\exefile\shell\runasuser -Name Extended -Force -ErrorAction Ignore
}

# Remove the "Run as different user" item from the .exe files types context menu
# Удалить пункт "Запуск от имени другого пользователя" из контекстное меню .exe файлов
function RemoveExeRunAsDifferentUserContext {
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\exefile\shell\runasuser -Name Extended -PropertyType String -Value "" -Force
}

# Hide the "Cast to Device" item from the context menu
# Скрыть пункт "Передать на устройство" из контекстного меню
function HideCastToDeviceContext {
	if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Force
	}
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" -PropertyType String -Value "Play to menu" -Force
}

# Show the "Cast to Device" item in the context menu
# Показывать пункт "Передать на устройство" в контекстном меню
function ShowCastToDeviceContext {
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" -Force -ErrorAction SilentlyContinue
}

# Hide the "Share" item from the context menu
# Скрыть пункт "Отправить" (поделиться) из контекстного меню
function HideShareContext {
	if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Force
	}
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{E2BF9676-5F8F-435C-97EB-11607A5BEDF7}" -PropertyType String -Value "" -Force
}

# Show the "Share" item in the context menu
# Показывать пункт "Отправить" (поделиться) в контекстном меню
function ShowShareContext {
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{E2BF9676-5F8F-435C-97EB-11607A5BEDF7}" -Force -ErrorAction SilentlyContinue
}

# Hide the "Edit with Paint 3D" item from the context menu
# Скрыть пункт "Изменить с помощью Paint 3D" из контекстного меню
function HideEditWithPaint3DContext {
	$Extensions = @(".bmp", ".gif", ".jpe", ".jpeg", ".jpg", ".png", ".tif", ".tiff")
	foreach ($extension in $extensions) {
		New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\$Extension\Shell\3D Edit" -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
	}
}

# Show the "Edit with Paint 3D" item in the context menu
# Показывать пункт "Изменить с помощью Paint 3D" в контекстном меню
function ShowEditWithPaint3DContext {
	$Extensions = @(".bmp", ".gif", ".jpe", ".jpeg", ".jpg", ".png", ".tif", ".tiff")
	foreach ($Extension in $Extensions) {
		Remove-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\$Extension\Shell\3D Edit" -Name ProgrammaticAccessOnly -Force -ErrorAction SilentlyContinue
	}
}

# Hide the "Edit with Photos" item from the context menu
# Скрыть пункт "Изменить с помощью приложения "Фотографии"" из контекстного меню
function HideEditWithPhotosContext {
	if (Get-AppxPackage -Name Microsoft.Windows.Photos) {
		New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellEdit -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
	}
}

# Show the "Edit with Photos" item in the context menu
# Показывать пункт "Изменить с помощью приложения "Фотографии"" в контекстном меню
function ShowEditWithPhotosContext {
	if (Get-AppxPackage -Name Microsoft.Windows.Photos) {
		Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellEdit -Name ProgrammaticAccessOnly -Force -ErrorAction SilentlyContinue
	}
}

# Hide the "Create a new video" item from the context menu
# Скрыть пункт "Создать новое видео" из контекстного меню
function HideCreateANewVideoContext {
	if (Get-AppxPackage -Name Microsoft.Windows.Photos) {
		New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellCreateVideo -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
	}
}

# Show the "Create a new video" item in the context menu
# Показывать пункт "Создать новое видео" в контекстном меню
function ShowCreateANewVideoContext {
	if (Get-AppxPackage -Name Microsoft.Windows.Photos) {
		Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellCreateVideo -Name ProgrammaticAccessOnly -Force -ErrorAction SilentlyContinue
	}
}

# Hide the "Edit" item from the images context menu
# Скрыть пункт "Изменить" из контекстного меню изображений
function HideImagesEditContext {
	if ((Get-WindowsCapability -Online -Name "Microsoft.Windows.MSPaint*").State -eq "Installed") {
		New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\image\shell\edit -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
	}
}

# Show the "Edit" item from in images context menu
# Показывать пункт "Изменить" в контекстном меню изображений
function ShowImagesEditContext {
	if ((Get-WindowsCapability -Online -Name "Microsoft.Windows.MSPaint*").State -eq "Installed") {
		Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\image\shell\edit -Name ProgrammaticAccessOnly -Force -ErrorAction SilentlyContinue
	}
}

# Hide the "Print" item from the .bat and .cmd context menu
# Скрыть пункт "Печать" из контекстного меню .bat и .cmd файлов
function HidePrintCMDContext {
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\batfile\shell\print -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\cmdfile\shell\print -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
}

# Show the "Print" item in the .bat and .cmd context menu
# Показывать пункт "Печать" в контекстном меню .bat и .cmd файлов
function ShowPrintCMDContext {
	Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\batfile\shell\print -Name ProgrammaticAccessOnly -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\cmdfile\shell\print -Name ProgrammaticAccessOnly -Force -ErrorAction SilentlyContinue
}

# Hide the "Include in Library" item from the context menu
# Скрыть пункт "Добавить в библиотеку" из контекстного меню
function HideIncludeInLibraryContext {
	New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers\Library Location" -Name "(Default)" -PropertyType String -Value "-{3dad6c5d-2167-4cae-9914-f99e41c12cfa}" -Force
}

# Show the "Include in Library" item in the context menu
# Показывать пункт "Добавить в библиотеку" в контекстном меню
function ShowIncludeInLibraryContext {
	New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers\Library Location" -Name "(Default)" -PropertyType String -Value "{3dad6c5d-2167-4cae-9914-f99e41c12cfa}" -Force
}

# Hide the "Send to" item from the folders context menu
# Скрыть пункт "Отправить" из контекстного меню папок
function HideSendToContext {
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\SendTo -Name "(Default)" -PropertyType String -Value "-{7BA4C740-9E81-11CF-99D3-00AA004AE837}" -Force
}

# Show the "Send to" item in the folders context menu
# Показывать пункт "Отправить" в контекстном меню папок
function ShowSendToContext {
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\SendTo -Name "(Default)" -PropertyType String -Value "{7BA4C740-9E81-11CF-99D3-00AA004AE837}" -Force
}

# Hide the "Turn on BitLocker" item from the context menu
# Скрыть пункт "Включить BitLocker" из контекстного меню
function HideBitLockerContext {
	if (Get-WindowsEdition -Online | Where-Object -FilterScript { $_.Edition -eq "Professional" -or $_.Edition -like "Enterprise*" }) {
		New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\encrypt-bde -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
		New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\encrypt-bde-elev -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
		New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\manage-bde -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
		New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\resume-bde -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
		New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\resume-bde-elev -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
		New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\unlock-bde -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
	}
}

# Show the "Turn on BitLocker" item in the context menu
# Показывать пункт "Включить BitLocker" в контекстном меню
function ShowBitLockerContext {
	if (Get-WindowsEdition -Online | Where-Object -FilterScript { $_.Edition -eq "Professional" -or $_.Edition -like "Enterprise*" }) {
		Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\encrypt-bde -Name ProgrammaticAccessOnly -Force -ErrorAction SilentlyContinue
		Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\encrypt-bde-elev -Name ProgrammaticAccessOnly -Force -ErrorAction SilentlyContinue
		Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\manage-bde -Name ProgrammaticAccessOnly -Force -ErrorAction SilentlyContinue
		Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\resume-bde -Name ProgrammaticAccessOnly -Force -ErrorAction SilentlyContinue
		Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\resume-bde-elev -Name ProgrammaticAccessOnly -Force -ErrorAction SilentlyContinue
		Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\unlock-bde -Name ProgrammaticAccessOnly -Force -ErrorAction SilentlyContinue
	}
}

# Remove the "Bitmap image" item from the "New" context menu
# Удалить пункт "Точечный рисунок" из контекстного меню "Создать"
function RemoveBitmapImageNewContext {
	if ((Get-WindowsCapability -Online -Name "Microsoft.Windows.MSPaint*").State -eq "Installed") {
		Remove-Item -Path Registry::HKEY_CLASSES_ROOT\.bmp\ShellNew -Force -ErrorAction SilentlyContinue
	}
}

# Restore the "Bitmap image" item in the "New" context menu
# Восстановить пункт "Точечный рисунок" в контекстного меню "Создать"
function RestoreBitmapImageNewContext {
	if ((Get-WindowsCapability -Online -Name "Microsoft.Windows.MSPaint*").State -eq "Installed") {
		if (-not (Test-Path -Path Registry::HKEY_CLASSES_ROOT\.bmp\ShellNew)) {
			New-Item -Path Registry::HKEY_CLASSES_ROOT\.bmp\ShellNew -Force
		}
		New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\.bmp\ShellNew -Name ItemName -PropertyType ExpandString -Value "@%systemroot%\system32\mspaint.exe,-59414" -Force
		New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\.bmp\ShellNew -Name NullFile -PropertyType String -Value "" -Force
	}
	else {
		Get-WindowsCapability -Online -Name "Microsoft.Windows.MSPaint*" | Add-WindowsCapability -Online
	}
}

# Remove the "Rich Text Document" item from the "New" context menu
# Удалить пункт "Документ в формате RTF" из контекстного меню "Создать"
function RemoveRichTextDocumentNewContext {
	if ((Get-WindowsCapability -Online -Name "Microsoft.Windows.WordPad*").State -eq "Installed") {
		Remove-Item -Path Registry::HKEY_CLASSES_ROOT\.rtf\ShellNew -Force -ErrorAction Ignore
	}
}

# Restore the "Rich Text Document" item in the "New" context menu
# Восстановить пункт "Документ в формате RTF" в контекстного меню "Создать"
function RestoreRichTextDocumentNewContext {
	if ((Get-WindowsCapability -Online -Name "Microsoft.Windows.WordPad*").State -eq "Installed") {
		if (-not (Test-Path -Path Registry::HKEY_CLASSES_ROOT\.rtf\ShellNew)) {
			New-Item -Path Registry::HKEY_CLASSES_ROOT\.rtf\ShellNew -Force
		}
		New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\.rtf\ShellNew -Name Data -PropertyType String -Value "{\rtf1}" -Force
		New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\.rtf\ShellNew -Name ItemName -PropertyType ExpandString -Value "@%ProgramFiles%\Windows NT\Accessories\WORDPAD.EXE,-213" -Force
	}
	else {
		Get-WindowsCapability -Online -Name "Microsoft.Windows.WordPad*" | Add-WindowsCapability -Online
	}
}

# Remove the "Compressed (zipped) Folder" item from the "New" context menu
# Удалить пункт "Сжатая ZIP-папка" из контекстного меню "Создать"
function RemoveCompressedFolderNewContext {
	Remove-Item -Path Registry::HKEY_CLASSES_ROOT\.zip\CompressedFolder\ShellNew -Force -ErrorAction Ignore
}

# Restore the "Compressed (zipped) Folder" item from the "New" context menu
# Восстановить пункт "Сжатая ZIP-папка" в контекстном меню "Создать"
function RestoreCompressedFolderNewContext {
	if (-not (Test-Path -Path Registry::HKEY_CLASSES_ROOT\.zip\CompressedFolder\ShellNew)) {
		New-Item -Path Registry::HKEY_CLASSES_ROOT\.zip\CompressedFolder\ShellNew -Force
	}
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\.zip\CompressedFolder\ShellNew -Name Data -PropertyType Binary -Value ([byte[]](80, 75, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)) -Force
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\.zip\CompressedFolder\ShellNew -Name ItemName -PropertyType ExpandString -Value "@%SystemRoot%\system32\zipfldr.dll,-10194" -Force
}

# Make the "Open", "Print", and "Edit" context menu items available, when more than 15 items selected
# Сделать доступными элементы контекстного меню "Открыть", "Изменить" и "Печать" при выделении более 15 элементов
function EnableMultipleInvokeContext {
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name MultipleInvokePromptMinimum -PropertyType DWord -Value 300 -Force
}

# Disable the "Open", "Print", and "Edit" context menu items for more than 15 items selected
# Отключить элементы контекстного меню "Открыть", "Изменить" и "Печать" при выделении более 15 элементов
function DisableMultipleInvokeContext {
	Remove-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name MultipleInvokePromptMinimum -Force -ErrorAction SilentlyContinue
}

# Hide the "Look for an app in the Microsoft Store" item in the "Open with" dialog
# Скрыть пункт "Поиск приложения в Microsoft Store" в диалоге "Открыть с помощью"
function DisableUseStoreOpenWith {
	if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer)) {
		New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Force
	}
	New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name NoUseStoreOpenWith -PropertyType DWord -Value 1 -Force
}

# Show the "Look for an app in the Microsoft Store" item in the "Open with" dialog
# Отображать пункт "Поиск приложения в Microsoft Store" в диалоге "Открыть с помощью"
function EnableUseStoreOpenWith {
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name NoUseStoreOpenWith -Force -ErrorAction SilentlyContinue
}

# Hide the "Previous Versions" tab from files and folders context menu and also the "Restore previous versions" context menu item
# Скрыть вкладку "Предыдущие версии" в свойствах файлов и папок, а также пункт контекстного меню "Восстановить прежнюю версию"
function DisablePreviousVersionsPage {
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name NoPreviousVersionsPage -PropertyType DWord -Value 1 -Force
}

# Show the "Previous Versions" tab from files and folders context menu and also the "Restore previous versions" context menu item
# Отображать вкладку "Предыдущие версии" в свойствах файлов и папок, а также пункт контекстного меню "Восстановить прежнюю версию"
function EnablePreviousVersionsPage {
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name NoPreviousVersionsPage -Force -ErrorAction SilentlyContinue
}
#endregion Context menu
#region WSL
<#
	Install the Windows Subsystem for Linux (WSL)
	Установить подсистему Windows для Linux (WSL)

	https://github.com/microsoft/WSL/issues/5437
#>
function InstallWSL {
    $WSLFeatures = @(
		# Windows Subsystem for Linux
		# Подсистема Windows для Linux
		"Microsoft-Windows-Subsystem-Linux",

		# Virtual Machine Platform
		# Поддержка платформы для виртуальных машин
		"VirtualMachinePlatform"
	)
	Enable-WindowsOptionalFeature -Online -FeatureName $WSLFeatures -NoRestart
}

<#
	Download and install the Linux kernel update package
	Set WSL 2 as the default version when installing a new Linux distribution
	Run the function only after WSL installed and PC restart

	Скачать и установить пакет обновления ядра Linux
	Установить WSL 2 как версию по умолчанию при установке нового дистрибутива Linux
	Выполните функцию только после установки WSL и перезагрузки ПК

	https://github.com/microsoft/WSL/issues/5437
#>
function OptInWSL {
	if ((Get-Package -Name "Windows Subsystem for Linux Update" -ProviderName msi -Force -ErrorAction Ignore).Status -ne "Installed") {
		try {
			if ((Invoke-WebRequest -Uri https://www.google.com -UseBasicParsing -DisableKeepAlive -Method Head).StatusDescription) {
				Write-Verbose $Localization.WSLUpdateDownloading -Verbose

				[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
				$DownloadsFolder = Get-ItemPropertyValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{374DE290-123F-4565-9164-39C4925E467B}"
				$Parameters = @{
					Uri     = "https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi"
					OutFile = "$DownloadsFolder\wsl_update_x64.msi"
					Verbose = [switch]::Present
				}
				Invoke-WebRequest @Parameters

				Write-Verbose $Localization.WSLUpdateInstalling -Verbose
				Start-Process -FilePath "$DownloadsFolder\wsl_update_x64.msi" -ArgumentList "/passive" -Wait
				Remove-Item -Path "$DownloadsFolder\wsl_update_x64.msi" -Force
			}
		}
		catch [System.Net.WebException] {
			Write-Warning -Message $Localization.NoInternetConnection
		}
	}

	<#
		Set WSL 2 as the default architecture when installing a new Linux distribution
		To receive kernel updates, enable the Windows Update setting: 'Receive updates for other Microsoft products when you update Windows'

		Установить WSL 2 как архитектуру по умолчанию при установке нового дистрибутива Linux
		Чтобы получать обновления ядра, включите параметр Центра обновления Windows: "Получение обновлений для других продуктов Майкрософт при обновлении Windows"
	#>
	if ((Get-Package -Name "Windows Subsystem for Linux Update" -ProviderName msi -Force -ErrorAction Ignore).Status -eq "Installed") {
		wsl --set-default-version 2
	}
}

# Uninstall the Windows Subsystem for Linux (WSL2)
# Удалить подсистему Windows для Linux (WSL2)
function UninstallWSL {
	$WSLFeatures = @(
		# Windows Subsystem for Linux
		# Подсистему Windows для Linux
		"Microsoft-Windows-Subsystem-Linux",

		# Virtual Machine Platform
		# Поддержка платформы для виртуальных машин
		"VirtualMachinePlatform"
	)
	Disable-WindowsOptionalFeature -Online -FeatureName $WSLFeatures -NoRestart

	Uninstall-Package -Name "Windows Subsystem for Linux Update" -Force
	Remove-Item -Path "$env:USERPROFILE\.wslconfig" -Force -ErrorAction Ignore
}
#endregion WSL
#region chocolatey
# Install chocolatey package manager and pre-installs as well
function ChocolateyPackageManager {
	Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
	choco install -y --allow-empty-checksums drivereasyfree chocolatey-windowsupdate.extension notepadplusplus.install 7zip.install chocolatey-core.extension transmission-qt jpegview mpc-hc k-litecodecpackfull chocolatey-dotnetfx.extension directx vcredist-all bleachbit.install
	Write-Warning -Message $Localization.OOShutup
	Import-Module BitsTransfer
	Start-BitsTransfer -Source "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -Destination OOSU10.exe
	./OOSU10.exe ooshutup.cfg /quiet
}
#endregion chocolatey
#region Refresh
function Refresh {
	$UpdateExplorer = @{
		Namespace        = "WinAPI"
		Name             = "UpdateExplorer"
		Language         = "CSharp"
		MemberDefinition = @"
private static readonly IntPtr HWND_BROADCAST = new IntPtr(0xffff);
private const int WM_SETTINGCHANGE = 0x1a;
private const int SMTO_ABORTIFHUNG = 0x0002;

[DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = false)]
static extern bool SendNotifyMessage(IntPtr hWnd, uint Msg, IntPtr wParam, string lParam);
[DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = false)]
private static extern IntPtr SendMessageTimeout(IntPtr hWnd, int Msg, IntPtr wParam, string lParam, int fuFlags, int uTimeout, IntPtr lpdwResult);
[DllImport("shell32.dll", CharSet = CharSet.Auto, SetLastError = false)]
private static extern int SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);
public static void Refresh()
{
	// Update desktop icons
	// Обновить иконки рабочего стола
	SHChangeNotify(0x8000000, 0x1000, IntPtr.Zero, IntPtr.Zero);
	// Update environment variables
	// Обновить переменные среды
	SendMessageTimeout(HWND_BROADCAST, WM_SETTINGCHANGE, IntPtr.Zero, null, SMTO_ABORTIFHUNG, 100, IntPtr.Zero);
	// Update taskbar
	// Обновить панель задач
	SendNotifyMessage(HWND_BROADCAST, WM_SETTINGCHANGE, IntPtr.Zero, "TraySettings");
}

private static readonly IntPtr hWnd = new IntPtr(65535);
private const int Msg = 273;
// Virtual key ID of the F5 in File Explorer
// Виртуальный код клавиши F5 в проводнике
private static readonly UIntPtr UIntPtr = new UIntPtr(41504);

[DllImport("user32.dll", SetLastError=true)]
public static extern int PostMessageW(IntPtr hWnd, uint Msg, UIntPtr wParam, IntPtr lParam);
public static void PostMessage()
{
	// Simulate pressing F5 to refresh the desktop
	// Симулировать нажатие F5 для обновления рабочего стола
	PostMessageW(hWnd, Msg, UIntPtr, IntPtr.Zero);
}
"@
	}
	if (-not ("WinAPI.UpdateExplorer" -as [type])) {
		Add-Type @UpdateExplorer
	}

	# Simulate pressing F5 to refresh the desktop
	# Симулировать нажатие F5 для обновления рабочего стола
	[WinAPI.UpdateExplorer]::PostMessage()

	# Refresh desktop icons, environment variables, taskbar
	# Обновить иконки рабочего стола, переменные среды, панель задач
	[WinAPI.UpdateExplorer]::Refresh()

	# Restart the Start menu
	# Перезапустить меню "Пуск"
	Stop-Process -Name StartMenuExperienceHost -Force -ErrorAction Ignore

	Write-Warning -Message $Localization.RestartWarning
}
#endregion Refresh
# Errors output
# Вывод ошибок
function Errors {
	if ($Global:Error) {
		($Global:Error | ForEach-Object -Process {
				[PSCustomObject] @{
					$Localization.ErrorsLine    = $_.InvocationInfo.ScriptLineNumber
					$Localization.ErrorsFile    = Split-Path -Path $PSCommandPath -Leaf
					$Localization.ErrorsMessage = $_.Exception.Message
				}
			} | Sort-Object -Property Line | Format-Table -AutoSize -Wrap | Out-String).Trim()
	}
}
