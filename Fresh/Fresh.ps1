#Requires -RunAsAdministrator
#Requires -Version 5.1

Clear-Host

Remove-Module -Name Fresh -Force -ErrorAction Ignore
Import-Module -Name $PSScriptRoot\Fresh.psd1 -PassThru -Force

Import-LocalizedData -BindingVariable Global:Localization  -FileName Fresh

# Checking
# Проверка
Check

#region Start menu
# Unpin all the Start tiles
# Открепить все ярлыки от начального экрана
UnpinAllStartTiles

# Do not show recently added apps in the Start menu
# Не показывать недавно добавленные приложения в меню "Пуск"
HideRecentlyAddedApps

# Show recently added apps in the Start menu
# Показывать недавно добавленные приложения в меню "Пуск"
# ShowRecentlyAddedApps

# Do not show app suggestions in the Start menu
# Не показывать рекомендации в меню "Пуск"
HideAppSuggestions

# Show app suggestions in the Start menu
# Показывать рекомендации в меню "Пуск"
# ShowAppSuggestions

# Hide live tiles
HideLiveTiles
#endregion Start menu
#region UI & Personalization
# Do not use check boxes to select items (current user only)
# Не использовать флажки для выбора элементов (только для текущего пользователя)
DisableCheckBoxes

# Use check boxes to select items (current user only)
# Использовать флажки для выбора элементов (только для текущего пользователя)
# EnableCheckBoxes

# Show hidden files, folders, and drives (current user only)
# Показывать скрытые файлы, папки и диски (только для текущего пользователя)
ShowHiddenItems

# Do not show hidden files, folders, and drives (current user only)
# Не показывать скрытые файлы, папки и диски (только для текущего пользователя)
# HideHiddenItems

# Show file name extensions (current user only)
# Показывать расширения имён файлов (только для текущего пользователя)
ShowFileExtensions

# Do not show file name extensions (current user only)
# Не показывать расширения имён файлов файлов (только для текущего пользователя)
# HideFileExtensions

# Do not hide folder merge conflicts (current user only)
# Не скрывать конфликт слияния папок (только для текущего пользователя)
ShowMergeConflicts

# Hide folder merge conflicts (current user only)
# Скрывать конфликт слияния папок (только для текущего пользователя)
# HideMergeConflicts

# Open File Explorer to: "This PC" (current user only)
# Открывать проводник для: "Этот компьютер" (только для текущего пользователя)
OpenFileExplorerToThisPC

# Open File Explorer to: "Quick access" (current user only)
# Открывать проводник для: "Быстрый доступ" (только для текущего пользователя)
# OpenFileExplorerToQuickAccess

# Do not show Cortana button on the taskbar (current user only)
# Не показывать кнопку Кортаны на панели задач (только для текущего пользователя)
HideCortanaButton

# Show Cortana button on the taskbar (current user only)
# Показывать кнопку Кортаны на панели задач (только для текущего пользователя)
# ShowCortanaButton

# Do not show Task View button on the taskbar (current user only)
# Не показывать кнопку Просмотра задач (только для текущего пользователя)
HideTaskViewButton

# Show Task View button on the taskbar (current user only)
# Показывать кнопку Просмотра задач (только для текущего пользователя)
# ShowTaskViewButton

# Do not show People button on the taskbar (current user only)
# Не показывать панель "Люди" на панели задач (только для текущего пользователя)
HidePeopleTaskbar

# Show People button on the taskbar (current user only)
# Показывать панель "Люди" на панели задач (только для текущего пользователя)
# ShowPeopleTaskbar

# Show seconds on the taskbar clock (current user only)
# Отображать секунды в системных часах на панели задач (только для текущего пользователя)
# ShowSecondsInSystemClock

# Do not show seconds on the taskbar clock (current user only)
# не отображать секунды в системных часах на панели задач (только для текущего пользователя)
HideSecondsInSystemClock

# Do not show when snapping a window, what can be attached next to it (current user only)
# Не показывать при прикреплении окна, что можно прикрепить рядом с ним (только для текущего пользователя)
DisableSnapAssist

# Show when snapping a window, what can be attached next to it (current user only)
# Показывать при прикреплении окна, что можно прикрепить рядом с ним (только для текущего пользователя)
# EnableSnapAssist

# Always open the file transfer dialog box in the detailed mode (current user only)
# Всегда открывать диалоговое окно передачи файлов в развернутом виде (только для текущего пользователя)
FileTransferDialogDetailed

# Always open the file transfer dialog box in the compact mode (current user only)
# Всегда открывать диалоговое окно передачи файлов в свернутом виде (только для текущего пользователя)
# FileTransferDialogCompact

# Show the ribbon expanded in File Explorer (current user only)
# Отображать ленту проводника в развернутом виде (только для текущего пользователя)
FileExplorerRibbonExpanded

# Do not show the ribbon expanded in File Explorer (current user only)
# Не отображать ленту проводника в развернутом виде (только для текущего пользователя)
# FileExplorerRibbonMinimized

# Display recycle bin files delete confirmation
# Запрашивать подтверждение на удаление файлов в корзину
EnableRecycleBinDeleteConfirmation

# Do not display recycle bin files delete confirmation
# Не запрашивать подтверждение на удаление файлов в корзину
# DisableRecycleBinDeleteConfirmation

# Hide the "3D Objects" folder from "This PC" and "Quick access" (current user only)
# Скрыть папку "Объемные объекты" из "Этот компьютер" и из панели быстрого доступа (только для текущего пользователя)
Hide3DObjects

# Show the "3D Objects" folder from "This PC" and "Quick access" (current user only)
# Отобразить папку "Объемные объекты" из "Этот компьютер" и из панели быстрого доступа (только для текущего пользователя)
# Show3DObjects

# Do not show frequently used folders in "Quick access" (current user only)
# Не показывать недавно используемые папки на панели быстрого доступа (только для текущего пользователя)
HideQuickAccessFrequentFolders

# Show frequently used folders in "Quick access" (current user only)
# Показывать недавно используемые папки на панели быстрого доступа (только для текущего пользователя)
# ShowQuickAccessFrequentFolders

# Do not show recently used files in Quick access (current user only)
# Не показывать недавно использовавшиеся файлы на панели быстрого доступа (только для текущего пользователя)
HideQuickAccessRecentFiles

# Show recently used files in Quick access (current user only)
# Показывать недавно использовавшиеся файлы на панели быстрого доступа (только для текущего пользователя)
# ShowQuickAccessShowRecentFiles

# Hide the search box or the search icon from the taskbar (current user only)
# Скрыть поле или значок поиска на панели задач (только для текущего пользователя)
HideTaskbarSearch

# Show the search box from the taskbar (current user only)
# Показать поле поиска на панели задач (только для текущего пользователя)
# ShowTaskbarSearch

# Do not show the "Windows Ink Workspace" button on the taskbar (current user only)
# Не показывать кнопку Windows Ink Workspace на панели задач (current user only)
HideWindowsInkWorkspace

# Show the "Windows Ink Workspace" button in taskbar (current user only)
# Показывать кнопку Windows Ink Workspace на панели задач (current user only)
# ShowWindowsInkWorkspace

# Always show all icons in the notification area (current user only)
# Всегда отображать все значки в области уведомлений (только для текущего пользователя)
ShowTrayIcons

# Do not show all icons in the notification area (current user only)
# Не отображать все значки в области уведомлений (только для текущего пользователя)
# HideTrayIcons

# Unpin all taskbar icons
UnpinAllTaskbarIcons

# View the Control Panel icons by: large icons (current user only)
# Просмотр иконок Панели управления как: крупные значки (только для текущего пользователя)
ControlPanelLargeIcons

# View the Control Panel icons by: category (current user only)
# Просмотр значки Панели управления как "категория" (только для текущего пользователя)
# ControlPanelCategoryIcons

# Set the Windows mode color scheme to the light (current user only)
# Установить режим цвета для Windows на светлый (только для текущего пользователя)
# WindowsColorSchemeLight

# Set the Windows mode color scheme to the dark (current user only)
# Установить цвет режима Windows по умолчанию на темный (только для текущего пользователя)
WindowsColorSchemeDark

# Set the default app mode color scheme to the light (current user only)
# Установить цвет режима приложений по умолчанию на светлый (только для текущего пользователя)
# AppModeLight

# Set the default app mode color scheme to the dark (current user only)
# Установить цвет режима приложений по умолчанию на темный (только для текущего пользователя)
AppModeDark

# Do not show the "New App Installed" indicator
# Не показывать уведомление "Установлено новое приложение"
DisableNewAppInstalledNotification

# Show the "New App Installed" indicator
# Показывать уведомление "Установлено новое приложение"
# EnableNewAppInstalledNotification

# Do not show user first sign-in animation after the upgrade
# Не показывать анимацию при первом входе в систему после обновления
HideFirstSigninAnimation

# Show user first sign-in animation the upgrade
# Показывать анимацию при первом входе в систему после обновления
# ShowFirstSigninAnimation

# Set the quality factor of the JPEG desktop wallpapers to default (current user only)
# Установить коэффициент качества обоев рабочего стола в формате JPEG по умолчанию (только для текущего пользователя)
JPEGWallpapersQualityDefault

# Start Task Manager in expanded mode (current user only)
# Запускать Диспетчера задач в развернутом виде (только для текущего пользователя)
TaskManagerWindowExpanded

# Show a notification when your PC requires a restart to finish updating
# Показывать уведомление, когда компьютеру требуется перезагрузка для завершения обновления
ShowRestartNotification

# Do not show a notification when your PC requires a restart to finish updating
# Не показывать уведомление, когда компьютеру требуется перезагрузка для завершения обновления
# HideRestartNotification

# Do not add the "- Shortcut" suffix to the file name of created shortcuts (current user only)
# Нe дoбaвлять "- яpлык" к имени coздaвaeмых яpлыков (только для текущего пользователя)
DisableShortcutsSuffix

# Add the "- Shortcut" suffix to the file name of created shortcuts (current user only)
# Дoбaвлять "- яpлык" к имени coздaвaeмых яpлыков (только для текущего пользователя)
# EnableShortcutsSuffix

# Use the PrtScn button to open screen snipping (current user only)
# Использовать кнопку PRINT SCREEN, чтобы запустить функцию создания фрагмента экрана (только для текущего пользователя)
EnablePrtScnSnippingTool

# Do not use the PrtScn button to open screen snipping (current user only)
# Не использовать кнопку PRINT SCREEN, чтобы запустить функцию создания фрагмента экрана (только для текущего пользователя)
# DisablePrtScnSnippingTool

# Change desktop background
ChangeDesktopBackground

# Small taskbar icons
SmallTaskbarIcons

# Smaller min max close window button
MinMaxCloseWindowButton

# Turn off action center
TurnOffActionCenter
#endregion UI & Personalization
#region Context menu
# Add the "Extract all" item to Windows Installer (.msi) context menu
# Добавить пункт "Извлечь все" в контекстное меню Windows Installer (.msi)
AddMSIExtractContext

# Remove the "Extract all" item from Windows Installer (.msi) context menu
# Удалить пункт "Извлечь все" из контекстного меню Windows Installer (.msi)
# RemoveMSIExtractContext

# Add the "Install" item to the .cab archives context menu
# Добавить пункт "Установить" в контекстное меню .cab архивов
AddCABInstallContext

# Remove the "Install" item from the .cab archives context menu
# Удалить пункт "Установить" из контекстного меню .cab архивов
# RemoveCABInstallContext

# Add the "Run as different user" item to the .exe files types context menu
# Добавить пункт "Запуск от имени другого пользователя" в контекстного меню .exe файлов
AddExeRunAsDifferentUserContext

# Remove the "Run as different user" item from the .exe files types context menu
# Удалить пункт "Запуск от имени другого пользователя" из контекстное меню .exe файлов
# RemoveExeRunAsDifferentUserContext

# Hide the "Cast to Device" item from the context menu
# Скрыть пункт "Передать на устройство" из контекстного меню
HideCastToDeviceContext

# Show the "Cast to Device" item in the context menu
# Показывать пункт "Передать на устройство" в контекстном меню
# ShowCastToDeviceContext

# Hide the "Share" item from the context menu
# Скрыть пункт "Отправить" (поделиться) из контекстного меню
HideShareContext

# Show the "Share" item in the context menu
# Показывать пункт "Отправить" (поделиться) в контекстном меню
# ShowShareContext

# Hide the "Edit with Paint 3D" item from the context menu
# Скрыть пункт "Изменить с помощью Paint 3D" из контекстного меню
HideEditWithPaint3DContext

# Show the "Edit with Paint 3D" item in the context menu
# Показывать пункт "Изменить с помощью Paint 3D" в контекстном меню
# ShowEditWithPaint3DContext

# Hide the "Edit with Photos" item from the context menu
# Скрыть пункт "Изменить с помощью приложения "Фотографии"" из контекстного меню
HideEditWithPhotosContext

# Show the "Edit with Photos" item in the context menu
# Показывать пункт "Изменить с помощью приложения "Фотографии"" в контекстном меню
# ShowEditWithPhotosContext

# Hide the "Create a new video" item from the context menu
# Скрыть пункт "Создать новое видео" из контекстного меню
HideCreateANewVideoContext

# Show the "Create a new video" item in the context menu
# Показывать пункт "Создать новое видео" в контекстном меню
# ShowCreateANewVideoContext

# Hide the "Edit" item from the images context menu
# Скрыть пункт "Изменить" из контекстного меню изображений
HideImagesEditContext

# Show the "Edit" item from in images context menu
# Показывать пункт "Изменить" в контекстном меню изображений
# ShowImagesEditContext

# Hide the "Print" item from the .bat and .cmd context menu
# Скрыть пункт "Печать" из контекстного меню .bat и .cmd файлов
HidePrintCMDContext

# Show the "Print" item in the .bat and .cmd context menu
# Показывать пункт "Печать" в контекстном меню .bat и .cmd файлов
# ShowPrintCMDContext

# Hide the "Include in Library" item from the context menu
# Скрыть пункт "Добавить в библиотеку" из контекстного меню
HideIncludeInLibraryContext

# Show the "Include in Library" item in the context menu
# Показывать пункт "Добавить в библиотеку" в контекстном меню
# ShowIncludeInLibraryContext

# Hide the "Send to" item from the folders context menu
# Скрыть пункт "Отправить" из контекстного меню папок
HideSendToContext

# Show the "Send to" item in the folders context menu
# Показывать пункт "Отправить" в контекстном меню папок
# ShowSendToContext

# Hide the "Turn on BitLocker" item from the context menu
# Скрыть пункт "Включить BitLocker" из контекстного меню
HideBitLockerContext

# Show the "Turn on BitLocker" item in the context menu
# Показывать пункт "Включить BitLocker" в контекстном меню
# ShowBitLockerContext

# Remove the "Bitmap image" item from the "New" context menu
# Удалить пункт "Точечный рисунок" из контекстного меню "Создать"
RemoveBitmapImageNewContext

# Restore the "Bitmap image" item in the "New" context menu
# Восстановить пункт "Точечный рисунок" в контекстного меню "Создать"
# RestoreBitmapImageNewContext

# Remove the "Rich Text Document" item from the "New" context menu
# Удалить пункт "Документ в формате RTF" из контекстного меню "Создать"
RemoveRichTextDocumentNewContext

# Restore the "Rich Text Document" item in the "New" context menu
# Восстановить пункт "Документ в формате RTF" в контекстного меню "Создать"
# RestoreRichTextDocumentNewContext

# Remove the "Compressed (zipped) Folder" item from the "New" context menu
# Удалить пункт "Сжатая ZIP-папка" из контекстного меню "Создать"
RemoveCompressedFolderNewContext

# Restore the "Compressed (zipped) Folder" item from the "New" context menu
# Восстановить пункт "Сжатая ZIP-папка" в контекстном меню "Создать"
# RestoreCompressedFolderNewContext

# Make the "Open", "Print", and "Edit" context menu items available, when more than 15 items selected
# Сделать доступными элементы контекстного меню "Открыть", "Изменить" и "Печать" при выделении более 15 элементов
EnableMultipleInvokeContext

# Disable the "Open", "Print", and "Edit" context menu items for more than 15 items selected
# Отключить элементы контекстного меню "Открыть", "Изменить" и "Печать" при выделении более 15 элементов
# DisableMultipleInvokeContext

# Hide the "Look for an app in the Microsoft Store" item in the "Open with" dialog
# Скрыть пункт "Поиск приложения в Microsoft Store" в диалоге "Открыть с помощью"
DisableUseStoreOpenWith

# Show the "Look for an app in the Microsoft Store" item in the "Open with" dialog
# Отображать пункт "Поиск приложения в Microsoft Store" в диалоге "Открыть с помощью"
# EnableUseStoreOpenWith

# Hide the "Previous Versions" tab from files and folders context menu and also the "Restore previous versions" context menu item
# Скрыть вкладку "Предыдущие версии" в свойствах файлов и папок, а также пункт контекстного меню "Восстановить прежнюю версию"
DisablePreviousVersionsPage

# Show the "Previous Versions" tab from files and folders context menu and also the "Restore previous versions" context menu item
# Отображать вкладку "Предыдущие версии" в свойствах файлов и папок, а также пункт контекстного меню "Восстановить прежнюю версию"
# EnablePreviousVersionsPage
#endregion Context menu
#region Chocolatey
# Install Chocolatey package manager and pre-installs as well
ChocolateyPackageManager
#endregion Chocolatey
#region Microsoft Defender & Security
# Turn on Microsoft Defender Exploit Guard network protection
# Включить защиту сети в Microsoft Defender Exploit Guard
# EnableNetworkProtection

# Turn off Microsoft Defender Exploit Guard network protection
# Выключить защиту сети в Microsoft Defender Exploit Guard
DisableNetworkProtection

# Turn on detection for potentially unwanted applications and block them
# Включить обнаружение потенциально нежелательных приложений и блокировать их
# EnablePUAppsDetection

# Turn off detection for potentially unwanted applications and block them
# Выключить обнаружение потенциально нежелательных приложений и блокировать их
DisabledPUAppsDetection

# Run Microsoft Defender within a sandbox
# Запускать Microsoft Defender в песочнице
EnableDefenderSandbox

# Do not run Microsoft Defender within a sandbox
# Не запускать Microsoft Defender в песочнице
# DisableDefenderSandbox

# Dismiss Microsoft Defender offer in the Windows Security about signing in Microsoft account
# Отклонить предложение Microsoft Defender в "Безопасность Windows" о входе в аккаунт Microsoft
DismissMSAccount

# Dismiss Microsoft Defender offer in the Windows Security about turning on the SmartScreen filter for Microsoft Edge
# Отклонить предложение Microsoft Defender в "Безопасность Windows" включить фильтр SmartScreen для Microsoft Edge
DismissSmartScreenFilter

<#
	Include command line in process creation events
	In order this feature to work events auditing must be enabled ("EnableAuditProcess" function)

	Включать командную строку в событиях создания процесса
	Необходимо включить аудит событий, чтобы работала данная опция (функция "EnableAuditProcess")
#>
# EnableAuditProcess

# Turn off events auditing generated when a process is created or starts
# Выключить аудит событий, возникающих при создании или запуске процесса
DisableAuditProcess

# Turn on events auditing generated when a process is created or starts
# Включить аудит событий, возникающих при создании или запуске процесса
# EnableAuditCommandLineProcess

# Do not include command line in process creation events
# Не включать командную строку в событиях создания процесса
DisableAuditCommandLineProcess

# Do not check apps and files within Microsofot Defender SmartScreen
# Не проверять приложения и файлы фильтром SmartScreen в Microsoft Defender
DisableAppsSmartScreen

# Check apps and files within Microsofot Defender SmartScreen
# Проверять приложения и файлы фильтром SmartScreen в Microsoft Defender
# EnableAppsSmartScreen

# Prevent SmartScreen from marking files that have been downloaded from the Internet as unsafe (current user only)
# Не позволять SmartScreen отмечать файлы, скачанные из интернета, как небезопасные (только для текущего пользователя)
DisableSaveZoneInformation

# Mark files that have been downloaded from the Internet as unsafe within SmartScreen (current user only)
# Отмечать файлы, скачанные из интернета, как небезопасные с помощью SmartScreen (только для текущего пользователя)
# EnableSaveZoneInformation

# Disable activity history
DisableActivityHistory

# Disable automatic map updates
DisableMapUpdates

# Disable wap push service
DisableWAPPush

# Enable strong cryptography for .NET Framework(version 4 and above)
EnableDotNetStrongCrypto

<#
Enable Meltdown (CVE-2017-5754) compatibility flag(required for january 2018 and all subsequent windows updates)
This flag is normally automatically enabled by compatible antivirus software (such as Windows Defender).
Use the tweak only if you have confirmed that your AV is compatible but unable to set the flag automatically or if you don't use any AV at all
#>
EnableMeltdownCompatFlag

# Disable password complexity and maximum age requirements
DisablePasswordPolicy

# Schedule automatic maintenance hours
AutomaticMaintenanceHours

# Turn off memory integry(virtualization based security)
TurnOffMemoryIntegry

# Disable implicit administrative shares
DisableAdminShares

# Disable obsolete SMB protocol(disabled by default since 1709)
DisableSMB

# Disable link-local multicast name resolution(LLMNR) protocol
DisableLLMNR

# Set unknown networks profile to public(deny file sharing, device discovery, etc.)
SetUnknownNetworksPublic

# Disable automatic installation of network devices
DisableNetDevicesAutoInst

# Hide tray icon
HideTrayIcon

# Disable defender cloud
DisableDefenderCloud

# Disable ntfs refs mitigations
DisableNTFSREFSMitigations

# Disable weak TLS
DisableWeakTLS
#endregion Microsoft Defender & Security
#region O&OShutup
OOShutup
#endregion O&OShutup
#region Privacy & Telemetry
# Disable the "Connected User Experiences and Telemetry" service (DiagTrack)
# Отключить службу "Функциональные возможности для подключенных пользователей и телеметрия" (DiagTrack)
DisableTelemetryServices

# Set the OS level of diagnostic data gathering to minimum
# Установить уровень сбора диагностических сведений ОС на минимальный
SetMinimalDiagnosticDataLevel

# Set the default OS level of diagnostic data gathering
# Установить уровень сбора диагностических сведений ОС по умолчанию
# SetDefaultDiagnosticDataLevel

# Turn off Windows Error Reporting for the current user
# Отключить отчеты об ошибках Windows для текущего пользователя
DisableWindowsErrorReporting

# Turn on Windows Error Reporting for the current user
# Включить отчеты об ошибках Windows для текущего пользователя
# EnableWindowsErrorReporting

# Change Windows feedback frequency to "Never" for the current user
# Изменить частоту формирования отзывов на "Никогда" для текущего пользователя
DisableWindowsFeedback

# Change Windows Feedback frequency to "Automatically" for the current user
# Изменить частоту формирования отзывов на "Автоматически" для текущего пользователя
# EnableWindowsFeedback

# Turn off tracking apps launch event
TurnOffAppLaunchTracking

# Turn off diagnostics tracking scheduled tasks
# Отключить задачи диагностического отслеживания
DisableScheduledTasks

# Turn on diagnostics tracking scheduled tasks
# Включить задачи диагностического отслеживания
# EnableScheduledTasks

# Do not use sign-in info to automatically finish setting up device and reopen apps after an update or restart (current user only)
# Не использовать данные для входа для автоматического завершения настройки устройства и открытия приложений после перезапуска или обновления (только для текущего пользователя)
DisableSigninInfo

# Use sign-in info to automatically finish setting up device and reopen apps after an update or restart (current user only)
# Использовать данные для входа для автоматического завершения настройки устройства и открытия приложений после перезапуска или обновления (только для текущего пользователя)
# EnableSigninInfo

# Do not let websites provide locally relevant content by accessing language list (current user only)
# Не позволять веб-сайтам предоставлять местную информацию за счет доступа к списку языков (только для текущего пользователя)
DisableLanguageListAccess

# Let websites provide locally relevant content by accessing language list (current user only)
# Позволять веб-сайтам предоставлять местную информацию за счет доступа к списку языков (только для текущего пользователя)
# EnableLanguageListAccess

# Do not allow apps to use advertising ID (current user only)
# Не разрешать приложениям использовать идентификатор рекламы (только для текущего пользователя)
DisableAdvertisingID

# Allow apps to use advertising ID (current user only)
# Разрешать приложениям использовать идентификатор рекламы (только для текущего пользователя)
# EnableAdvertisingID

# Do not let apps on other devices open and message apps on this device, and vice versa (current user only)
# Не разрешать приложениям на других устройствах запускать приложения и отправлять сообщения на этом устройстве и наоборот (только для текущего пользователя)
DisableShareAcrossDevices

# Let apps on other devices open and message apps on this device, and vice versa (current user only)
# Разрешать приложениям на других устройствах запускать приложения и отправлять сообщения на этом устройстве и наоборот (только для текущего пользователя)
# EnableShareAcrossDevices

# Do not show the Windows welcome experiences after updates and occasionally when I sign in to highlight what's new and suggested (current user only)
# Не показывать экран приветствия Windows после обновлений и иногда при входе, чтобы сообщить о новых функциях и предложениях (только для текущего пользователя)
DisableWindowsWelcomeExperience

# Show the Windows welcome experiences after updates and occasionally when I sign in to highlight what's new and suggested (current user only)
# Показывать экран приветствия Windows после обновлений и иногда при входе, чтобы сообщить о новых функциях и предложениях (только для текущего пользователя)
# EnableWindowsWelcomeExperience

# Get tip, trick, and suggestions as you use Windows (current user only)
# Получать советы, подсказки и рекомендации при использованию Windows (только для текущего пользователя)
#EnableWindowsTips

# Do not get tip, trick, and suggestions as you use Windows (current user only)
# Не получать советы, подсказки и рекомендации при использованию Windows (только для текущего пользователя)
DisableWindowsTips

# Do not show suggested content in the Settings app (current user only)
# Не показывать рекомендуемое содержимое в приложении "Параметры" (только для текущего пользователя)
DisableSuggestedContent

# Show suggested content in the Settings app (current user only)
# Показывать рекомендуемое содержимое в приложении "Параметры" (только для текущего пользователя)
# EnableSuggestedContent

# Turn off automatic installing suggested apps (current user only)
# Отключить автоматическую установку рекомендованных приложений (только для текущего пользователя)
DisableAppsSilentInstalling

# Turn on automatic installing suggested apps (current user only)
# Включить автоматическую установку рекомендованных приложений (только для текущего пользователя)
# EnableAppsSilentInstalling

# Do not suggest ways I can finish setting up my device to get the most out of Windows (current user only)
# Не предлагать способы завершения настройки устройства для максимально эффективного использования Windows (только для текущего пользователя)
DisableWhatsNewInWindows

# Suggest ways I can finish setting up my device to get the most out of Windows
# Предлагать способы завершения настройки устройства для максимально эффективного использования Windows
# EnableWhatsNewInWindows

# Do not offer tailored experiences based on the diagnostic data setting (current user only)
# Не предлагать персонализированные возможности, основанные на выбранном параметре диагностических данных (только для текущего пользователя)
DisableTailoredExperiences

# Offer tailored experiences based on the diagnostic data setting
# Предлагать персонализированные возможности, основанные на выбранном параметре диагностических данных
# EnableTailoredExperiences

# Disable Bing search in the Start Menu
# Отключить в меню "Пуск" поиск через Bing
DisableBingSearch

# Enable Bing search in the Start Menu
# Включить поиск через Bing в меню "Пуск"
# EnableBingSearch

# Disable find my device
DisableFindMyDevice

# Disable apps suggestions, tips, welcome experience
DisableAppsSuggestionsTipsWelcomeExperience

# Disable news feeds
DisableNewsFeeds

# Disable edge update
DisableEdgeUpdate
#endregion Privacy & Telemetry
#region Gaming
# Turn off Xbox Game Bar tips
# Отключить советы Xbox Game Bar
DisableXboxGameTips

# Turn on Xbox Game Bar tips
# Включить советы Xbox Game Bar
# EnableXboxGameTips

# Adjust best performance for all programs and also foreground services
BestPriorityForeground

# Disable mouse feedback
DisableMouseFeedback

# Enable full-screen optimization
EnableFullScreenOptimization
#endregion Gaming
#region UWP apps
<#
	Uninstall UWP apps
	A dialog box that enables the user to select packages to remove
	App packages will not be installed for new users if "Uninstall for All Users" is checked

	Удалить UWP-приложения
	Диалоговое окно, позволяющее пользователю отметить пакеты на удаление
	Приложения не будут установлены для новых пользователе, если отмечено "Удалять для всех пользователей"
#>
UninstallUWPApps

# Do not let UWP apps run in the background, except the followings... (current user only)
# Не разрешать UWP-приложениям работать в фоновом режиме, кроме следующих... (только для текущего пользователя)
DisableBackgroundUWPApps

# Disable the following Windows features
# Отключить следующие компоненты Windows
DisableWindowsFeatures

# Disable certain Feature On Demand v2 (FODv2) capabilities
# Отключить определенные компоненты "Функции по требованию" (FODv2)
DisableWindowsCapabilities

# Turn off Cortana autostarting
# Удалить Кортана из автозагрузки
DisableCortanaAutostart
#endregion UWP apps
#region System
# Uninstall OneDrive
# Удалить OneDrive
UninstallOneDrive

# Do not show sync provider notification within File Explorer (current user only)
# Не показывать уведомления поставщика синхронизации в проводнике (только для текущего пользователя)
HideOneDriveFileExplorerAd

# Turn on Storage Sense (current user only)
# Включить Контроль памяти (только для текущего пользователя)
EnableStorageSense

# Disable hibernation if the device is not a laptop
# Отключить режим гибернации, если устройство не является ноутбуком
DisableHibernate

# Turn on hibernate
# Включить режим гибернации
# EnableHibernate

# Change the %TEMP% environment variable path to the %SystemDrive%\Temp (both machine-wide, and for the current user)
# Изменить путь переменной среды для %TEMP% на %SystemDrive%\Temp (для всех пользователей)
SetTempPath

# Enable Windows 260 character path limit
# Включить ограничение Windows на 260 символов в пути
EnableWin32LongPaths

# Disable Windows 260 character path limit
# Отключить ограничение Windows на 260 символов в пути
# DisableWin32LongPaths

# Display the Stop error information on the BSoD
# Отображать Stop-ошибку при появлении BSoD
EnableBSoDStopError

# Do not display the Stop error information on the BSoD
# Не отображать Stop-ошибку при появлении BSoD
# DisableBSoDStopError

# Change "Behavior of the elevation prompt for administrators in Admin Approval Mode" to "Elevate without prompting"
# Изменить "Поведение запроса на повышение прав для администраторов в режиме одобрения администратором" на "Повышение прав без запроса"
DisableAdminApprovalMode

# Change "Behavior of the elevation prompt for administrators in Admin Approval Mode" to "Prompt for consent for non-Windows binaries" (default value)
# Изменить "Поведение запроса на повышение прав для администраторов в режиме одобрения администратором" на "Запрос согласия для исполняемых файлов, отличных от Windows" (значение по умолчанию)
# EnableAdminApprovalMode

# Turn on access to mapped drives from app running with elevated permissions with Admin Approval Mode enabled
# Включить доступ к сетевым дискам при включенном режиме одобрения администратором при доступе из программ, запущенных с повышенными правами
EnableMappedDrivesAppElevatedAccess

# Turn off access to mapped drives from app running with elevated permissions with Admin Approval Mode enabled
# Выключить доступ к сетевым дискам при включенном режиме одобрения администратором при доступе из программ, запущенных с повышенными правами
# DisableMappedDrivesAppElevatedAccess

# Opt out of the Delivery Optimization-assisted updates downloading
# Отказаться от загрузки обновлений с помощью оптимизации доставки
DisableDeliveryOptimization

# Opt-in to the Delivery Optimization-assisted updates downloading
# Включить загрузку обновлений с помощью оптимизации доставки
# EnableDeliveryOptimization

# Always wait for the network at computer startup and logon for workgroup networks
# Всегда ждать сеть при запуске и входе в систему для рабочих групп
# AlwaysWaitNetworkStartup

# Never wait for the network at computer startup and logon for workgroup networks
# Никогда ждать сеть при запуске и входе в систему для рабочих групп
NeverWaitNetworkStartup

# Use latest installed .NET runtime for all apps
# Использовать последнюю установленную среду выполнения .NET для всех приложений
EnableLatestInstalled.NET

# Do not use latest installed .NET runtime for all apps
# Не использовать последнюю установленную версию .NET для всех приложений
# DisableLatestInstalled.NET

# Save screenshots by pressing Win+PrtScr to the Desktop folder (current user only)
# Сохранять скриншоты по нажатию Win+PrtScr в папку "рабочий стол" (только для текущего пользователя)
# WinPrtScrDesktopFolder

# Hide annoying Troubleshooting
HideTroubleshooting

# Launch folder windows in a separate process (current user only)
# Запускать окна с папками в отдельном процессе (только для текущего пользователя)
# EnableFoldersLaunchSeparateProcess

# Do not folder windows in a separate process (current user only)
# Не запускать окна с папками в отдельном процессе (только для текущего пользователя)
DisableFoldersLaunchSeparateProcess

# Turn on Num Lock at startup
# Включить Num Lock при загрузке
# EnableNumLock

# Turn off Num Lock at startup
# Выключить Num Lock при загрузке
DisableNumLock

# Do not activate StickyKey after tapping the Shift key 5 times (current user only)
# Не включать залипание клавиши Shift после 5 нажатий (только для текущего пользователя)
DisableStickyShift

# Activate StickyKey after tapping the Shift key 5 times (current user only)
# Включать залипание клавиши Shift после 5 нажатий (только для текущего пользователя)
# EnableStickyShift

# Do not use AutoPlay for all media and devices (current user only)
# Не использовать автозапуск для всех носителей и устройств (только для текущего пользователя)
DisableAutoplay

# Use AutoPlay for all media and devices (current user only)
# Использовать автозапуск для всех носителей и устройств (только для текущего пользователя)
# EnableAutoplay

# Disable thumbnail cache removal
# Отключить удаление кэша миниатюр
DisableThumbnailCacheRemoval

# Enable thumbnail cache removal
# Включить удаление кэша миниатюр
# EnableThumbnailCacheRemoval

# Automatically save my restartable apps when signing out and restart them after signing in (current user only)
# Автоматически сохранять мои перезапускаемые приложения при выходе из системы и перезапускать их после выхода (только для текущего пользователя)
EnableSaveRestartableApps

# Do not automatically save my restartable apps when signing out and restart them after signing in
# Не сохранять автоматически мои перезапускаемые приложения при выходе из системы и перезапускать их после выхода
# DisableSaveRestartableApps

# Enable "Network Discovery" and "File and Printers Sharing" for workgroup networks
# Включить сетевое обнаружение и общий доступ к файлам и принтерам для рабочих групп
EnableNetworkDiscovery

# Disable "Network Discovery" and "File and Printers Sharing" for workgroup networks
# Выключить сетевое обнаружение и общий доступ к файлам и принтерам для рабочих групп
# DisableNetworkDiscovery

# This option must be Enabled by default, otherwise set it so.
OnlySecurityUpdates

# Do not automatically adjust active hours for me based on daily usage
# Не изменять автоматически период активности для этого устройства на основе действий
DisableSmartActiveHours

# Automatically adjust active hours for me based on daily usage
# Автоматически изменять период активности для этого устройства на основе действий
SetActiveHours

# Не перезапускать это устройство как можно быстрее, если для установки обновления требуется перезагрузка
# Do not restart this device as soon as possible when a restart is required to install an update
DisableDeviceRestartAfterUpdate

# Set data execution prevention (DEP) policy to optout
SetDEPOptOut

# Disable remote assistance
DisableRemoteAssistance

# Stop and disable superfetch service
DisableSuperfetch

<#
Disable offering of drivers through Windows Update
Note: This doesn't work properly if you use a driver intended for another hardware model. E.g. Intel I219-V on WinServer works only with I219-LM driver.
Therefore Windows update will repeatedly try and fail to install I219-V driver indefinitely even if you use the tweak.
#>
DisableAutoUpdateDriver

# SvcHost split threshold in KB
SvcHostSplitThresholdInKB

# Function discovery resource publication
FDResPub

# Disable microsoft edge services
DisableMSEdgeServices

# Turn off lock screen background
TurnOffLockScreenBackground

# Disable license manager
DisableLicenseManager

# Disable network connection status indicator
NetworkConnectionStatusIndicator

# Fix timers
FixTimers

# Don't use firmware pci settings
DontUseFirmwarePciSettings

# Disable hyper virtualization
DisableHyperVirtualization

# Enable pae
EnablePae

# Disable au power management
DisableAUPowerManagement

# Prioritize csrss.exe service
PrioritizeCSRSSService

# Disable lock screen
DisableLockScreen

# Auto enhance during playback
AutoEnhanceDuringPlayback

# Disable windows auto upgrade
DisableWindowsAutoUpgrade

# Fix windows DPI
FixWindowsDPI

# Disable automatic maintenance
DisableAutomaticMaintenance

# Disable sleep study
DisableSleepStudy

# Disable system energy saving
DisableSystemEnergySaving

# Disable hiberboot
DisableHiberboot

# Disable warning sounds
DisableWarningSounds
#endregion System
#region Performance
# Adjust best performance(that would able to increase the overall performance)
AdjustBestPerformance

# Prevent battery saver
PreventBatterySaver

# Disable default disk defragmenter
DisableDefaultDiskDefragmenter

# Let personalize power plan, neither switch it off so
LetPersonalizePowerPlan

# Prevent require sign-in when after sleep
PreventRequireSignInWhenAfterSleep

# Disable indexing
DisableIndexing

# Set current boot timeout value to 0
SetBootTimeoutValue

# Ntfs allow extended character 8dot3 rename
NtfsAllowExtendedCharacter8dot3Rename

# Ntfs disable 8dot3 name creation
NtfsDisable8dot3NameCreation

# Auto end tasks
AutoEndTasks

# Hung app timeout
HungAppTimeout

# Wait to kill app timeout
WaitToKillAppTimeout

# Low-level hooks timeout
LowLevelHooksTimeout

# Foreground lock timeout
ForegroundLockTimeout

# No low disk space checks
NoLowDiskSpaceChecks

# Link resolve ignore link info
LinkResolveIgnoreLinkInfo

# No resolve search
NoResolveSearch

# No resolve track
NoResolveTrack

# No internet open with
NoInternetOpenWith

# Wait to kill service timeout
WaitToKillServiceTimeout

# Disable paging executive
DisablePagingExecutive

# Large system cache
LargeSystemCache

# IO page lock limit
IoPageLockLimit

# Paging files
PagingFiles

# Second-level data cache
SecondLevelDataCache

# Existing page files
ExistingPageFiles

# Enable prefetcher
EnablePrefetcher

# Wait to kill service timeout
WaitToKillServiceTimeout1

# Disable paging executive
DisablePagingExecutive1

# Enable boot optimization function
EnableBootOptimizationFunction

# Ntfs disable last access update
NtfsDisableLastAccessUpdate

# Max connections per 1_0 server
MaxConnectionsPer1_0Server

# Max connections per server
MaxConnectionsPerServer

# Non best effort limit
NonBestEffortLimit

# Double click height width
DoubleClickHeightWidth

# Value max
ValueMax

# Debloat microsoft services
DebloatMicrosoftServices

# Disable boot splash animations
DisableBootSplashAnimations

# Disable trusted platform module
DisableTrustedPlatformModule

# Disable integrity checks
DisableIntegrityChecks

# Disable last access
DisableLastAccess

# Set memory usage
SetMemoryUsage

# Disable boot logging
DisableBootLogging

# Increase default size buffer
IncreaseDefaultSizeBuffer

# IRP stack size
IRPStackSize

# Size
Size

# Max work items
MaxWorkItems

# Maxmpxct
MaxMpxCt

# Max cmds
MaxCmds

# Disable strict name checking
DisableStrictNameChecking

# Enable dynamic backlog
EnableDynamicBacklog

# Minimum dynamic backlog
MinimumDynamicBacklog

# Maximum dynamic backlog
MaximumDynamicBacklog

# Dynamic backlog growth delta
DynamicBacklogGrowthDelta

# Increase mft zone
IncreaseMFTZone

# Enable memory allocation in graphics driver
EnableMemoryAllocationInGraphicsDriver

# Disable realtime monitoring
DisableRealtimeMonitoring

# Enable hardware accelerated GPU scheduling
EnableHardwareAcceleratedGPUScheduling

# Indexer respect power modes
IndexerRespectPowerModes

# Enable TRIM
EnableTRIM

# Disable power throttling
DisablePowerThrottling

# Disable wpp software tracing logs
DisableWPPSoftwareTracingLogs

# Cpu rate limit
CpuRateLimit

# Disable search history
DisableSearchHistory

# Thread priority
ThreadPriority
#endregion Performance
Errors
