@ECHO OFF
SET __COMPAT_LAYER=RunAsInvoker
SETLOCAL EnableDelayedExpansion
CLS 

:: Command Line Param
SET SELECTED_OPTION=%1

SET ARCHITECTURE_SUFFIX=64
SET ARCHITECTURE_SUFFIX_X=64
IF "%PROCESSOR_ARCHITECTURE%" EQU "AMD64" (
SET ARCHITECTURE_SUFFIX=64
) ELSE (
SET ARCHITECTURE_SUFFIX=32
SET ARCHITECTURE_SUFFIX_X=86
)

:: BatchGotAdmin
:: Source: https://stackoverflow.com/a/10052222
:-------------------------------------
:: Check for permissions
IF "%PROCESSOR_ARCHITECTURE%" EQU "amd64" (
>nul 2>&1 "%SYSTEMROOT%\SysWOW64\cacls.exe" "%SYSTEMROOT%\SysWOW64\config\system"
) ELSE (
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
)

:: Not Admin
:: If error flag set, we do not have admin.
IF '%errorlevel%' NEQ '0' (
    ECHO Requesting administrative privileges...
    GOTO UACPrompt
) ELSE ( GOTO gotAdmin )

:: UAC Prompt
:UACPrompt
    ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    SET params= %*
    ECHO UAC.ShellExecute "cmd.exe", "/c ""%~s0"" %params:"=""%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    DEL "%temp%\getadmin.vbs"
    EXIT /B

:: Actual Script
:gotAdmin
    PUSHD "%CD%"
    CD /D "%~dp0"

:: Check Architecture and set postfix
SET ARCH=
IF "%PROCESSOR_ARCHITECTURE%" EQU "x86" (
    ECHO Detected x86 architecture
    SET ARCH=_x86
)

:MENU
CLS
ECHO.
ECHO ..............................................................................
:::     ___               _         
:::    / _ \___ _________(_)__  ___ 
:::   / , _/ _ `/ __/ __/ / _ \/ -_)
:::  /_/|_|\_,_/\__/\__/_/_//_/\__/ 
:::
for /f "delims=: tokens=*" %%A in ('findstr /b ::: "%~f0"') do @echo(%%A
ECHO   A Simple Ransomware and Emotet Vaccine
ECHO   Installer by Florian Roth, October 2020  
ECHO.                       
ECHO ------------------------------------------------------------------------------
ECHO   WARNING! Raccine could break your backup solution 
ECHO ..............................................................................
ECHO.
ECHO   1 - Install Raccine for all possible methods
ECHO   2 - Install Raccine for all possible methods (simulation mode, logging only)
ECHO   3 - Install Raccine interception for less often used executables only (soft)
ECHO   4 - Disable GUI elements (alert window, settings tray icon)
ECHO   5 - Disable automatic rule updates
ECHo   6 - Run Windows Hardening Script
ECHO   U - Uninstall Raccine
ECHO   E - EXIT
ECHO.

:: Option set via ENV variables
IF "%SELECTED_OPTION%"=="FULL" GOTO FULL
IF "%SELECTED_OPTION%"=="SOFT" GOTO SOFT
IF "%SELECTED_OPTION%"=="FULL_SIMU" GOTO FULL_SIMU
IF "%SELECTED_OPTION%"=="UNINSTALL" GOTO UNINSTALL

:: Options set by user
SET /P M=" Select an option and then press ENTER: "
IF %M%==1 GOTO FULL
IF %M%==2 GOTO FULL_SIMU
IF %M%==3 GOTO SOFT
IF %M%==4 GOTO DISABLEGUI
IF %M%==5 GOTO DISABLEUPDATES
IF %M%==6 GOTO HARDENING
IF %M%==U GOTO UNINSTALL
IF %M%==u GOTO UNINSTALL
IF %M%==E GOTO EOF
IF %M%==e GOTO EOF
GOTO MENU

:: Installer actions

:: Actions to run in all modes
:INSTALL
ECHO.
:: Requirements
:: Visual C++ Runtime
IF NOT EXIST C:\Windows\System32\vcruntime140.dll (
    ECHO Installing Visual C++ Redistributable Package ...
    start /wait preqeq\vc_redist.x%ARCHITECTURE_SUFFIX_X%.exe /q /norestart
)
:: .NET Framework
REG QUERY "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319\SKUs\.NETFramework,Version=v4.5" 2>nul
IF ERRORLEVEL 1 (
    ECHO Installing .NET Framework ...
    start /wait preqeq\NDP462-KB3151800-x86-x64-AllOS-ENU.exe /q /norestart
)
:: Cleanup existing elements
TASKKILL /F /IM Raccine.exe
TASKKILL /F /IM RaccineSettings.exe
TASKKILL /F /IM RaccineRulesSync.exe
:: Raccine GUI Elements
ECHO Creating data directory "%ProgramFiles%\Raccine" ...
MKDIR "%ProgramFiles%\Raccine"
COPY RaccineElevatedCfg.exe "%ProgramFiles%\Raccine\"
COPY RaccineSettings.exe "%ProgramFiles%\Raccine\"
COPY RaccineRulesSync.exe "%ProgramFiles%\Raccine\"
:: Raccine Program Files
COPY Raccine%ARCH%.exe "%ProgramFiles%\Raccine\Raccine.exe"
COPY yara\yara%ARCHITECTURE_SUFFIX%.exe "%ProgramFiles%\Raccine\"
COPY yara\yarac%ARCHITECTURE_SUFFIX%.exe "%ProgramFiles%\Raccine\"
:: YARA Rules
MKDIR "%ProgramFiles%\Raccine\yara"
MKDIR "%ProgramFiles%\Raccine\yara\in-memory"
ECHO Copying YARA rules to the directory ...
COPY yara\*.yar "%ProgramFiles%\Raccine\yara"
COPY yara\in-memory\*.yar "%ProgramFiles%\Raccine\yara\in-memory"
:: Setting the Path
SETX /M Path "%PATH%;%ProgramFiles%\Raccine"
:: Raccine Data
ECHO Creating data directory "%ProgramData%\Raccine" ...
MKDIR "%ProgramData%\Raccine"
ECHO Creating empty log file ...
echo. 2>"%ProgramData%\Raccine\Raccine_log.txt"
icacls "%ProgramData%\Raccine\Raccine_log.txt" /grant Users:F
ECHO Registering Eventlog Events
eventcreate.exe /L Application /T Information /id 1 /so Raccine /d "Raccine Setup: Registration of Event ID 1 - Used for Informational Messages" 2> nul
eventcreate.exe /L Application /T Information /id 2 /so Raccine /d "Raccine Setup: Registration of Event ID 2 - Used for Malicious Actitivty" 2> nul
eventcreate.exe /L Application /T Information /id 3 /so Raccine /d "Raccine Setup: Registration of Event ID 3 - Used for Benign Activity" 2> nul
:: Registry Settings
REG.EXE ADD HKLM\Software\Raccine /v ShowGui /t REG_DWORD /d 1 /F
REG.EXE ADD HKLM\Software\Raccine /v ScanMemory /t REG_DWORD /d 1 /F
REG.EXE ADD HKLM\Software\Raccine /v RulesDir /t REG_SZ /d "%ProgramFiles%\Raccine\yara" /F
:: Registering and starting the GUI elements
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Raccine Tray" /t REG_SZ /F /D "%ProgramFiles%\Raccine\RaccineSettings.exe"
START "" "%ProgramFiles%\Raccine\RaccineSettings.exe"
:: Scheduled Task
ECHO Adding scheduled task for rule updates
SCHTASKS /create /tn "Raccine Rules Updater" /tr "\"%PROGRAMFILES%\Raccine\RaccineRulesSync.exe\"" /sc DAILY /mo 1 /f /RL highest /RU "NT AUTHORITY\SYSTEM" /NP
SCHTASKS /RUN /TN "Raccine Rules Updater"
:: in case of automation, directly got to EOF
IF NOT "%SELECTED_OPTION%"=="" GOTO EOF
TIMEOUT /t 30
GOTO MENU

:: Full
:FULL
ECHO.
:: Registry Patches
ECHO Installing Registry patches ...
REGEDIT.EXE /S reg-patches\raccine-reg-patch-vssadmin.reg
IF '%errorlevel%' NEQ '0' (
    ECHO Something went wrong. Sorry. Installation failed.
    GOTO MENU
)
REGEDIT.EXE /S reg-patches\raccine-reg-patch-wmic.reg 
REGEDIT.EXE /S reg-patches\raccine-reg-patch-wbadmin.reg
REGEDIT.EXE /S reg-patches\raccine-reg-patch-bcdedit.reg
REGEDIT.EXE /S reg-patches\raccine-reg-patch-powershell.reg
REGEDIT.EXE /S reg-patches\raccine-reg-patch-diskshadow.reg
REGEDIT.EXE /S reg-patches\raccine-reg-patch-net.reg
:: Simulation only
REG.EXE ADD HKLM\Software\Raccine /v LogOnly /t REG_DWORD /d 0 /F
GOTO INSTALL

:: Simulation Mode
:FULL_SIMU
ECHO.
:: Registry Patches
ECHO Installing Registry patches ...
REGEDIT.EXE /S reg-patches\raccine-reg-patch-vssadmin.reg
IF '%errorlevel%' NEQ '0' (
    ECHO Something went wrong. Sorry. Installation failed.
    GOTO MENU
)
REGEDIT.EXE /S reg-patches\raccine-reg-patch-wmic.reg 
REGEDIT.EXE /S reg-patches\raccine-reg-patch-wbadmin.reg
REGEDIT.EXE /S reg-patches\raccine-reg-patch-bcdedit.reg
REGEDIT.EXE /S reg-patches\raccine-reg-patch-powershell.reg
REGEDIT.EXE /S reg-patches\raccine-reg-patch-diskshadow.reg
REGEDIT.EXE /S reg-patches\raccine-reg-patch-net.reg
:: Simulation only
REG.EXE ADD HKLM\Software\Raccine /v LogOnly /t REG_DWORD /d 1 /F
GOTO INSTALL

:: Soft
:SOFT 
ECHO.
:: Registry Patches
ECHO Installing Registry patches ...
REGEDIT.EXE /S reg-patches\raccine-reg-patch-vssadmin.reg
IF '%errorlevel%' NEQ '0' (
    ECHO Something went wrong. Sorry. Installation failed.
    GOTO MENU
)
REGEDIT.EXE /S reg-patches\raccine-reg-patch-wbadmin.reg
REGEDIT.EXE /S reg-patches\raccine-reg-patch-bcdedit.reg
REGEDIT.EXE /S reg-patches\raccine-reg-patch-diskshadow.reg
:: Simulation only
REG.EXE ADD HKLM\Software\Raccine /v LogOnly /t REG_DWORD /d 0 /F
GOTO INSTALL

:: Disable GUI Elements
:DISABLEGUI 
ECHO.
ECHO Disabling the GUI elements ...
ECHO.
REG.EXE ADD HKLM\Software\Raccine /v ShowGui /t REG_DWORD /d 1 /F
TASKKILL /F /IM RaccineSettings.exe
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Raccine Tray" /F
IF '%errorlevel%' NEQ '0' (
    ECHO Something went wrong. Sorry.
    GOTO MENU
)
TIMEOUT /t 30
GOTO MENU

:: Disable Updates
:DISABLEUPDATES 
ECHO.
ECHO Disabling automatic updates ...
ECHO.
SCHTASKS /DELETE /TN "Raccine Rules Updater" /F
IF '%errorlevel%' NEQ '0' (
    ECHO Something went wrong. Sorry.
    GOTO MENU
)
TIMEOUT /t 30
GOTO MENU

:: Run Hardening Script
:HARDENING 
ECHO.
ECHO Running the Hardening script ...
ECHO.
CALL scripts\windows-hardening.bat
IF '%errorlevel%' NEQ '0' (
    ECHO Something went wrong. Sorry.
    GOTO MENU
)
TIMEOUT /t 30
GOTO MENU

:: Uninstall
:UNINSTALL
ECHO.
TASKKILL /F /IM Raccine.exe
TASKKILL /F /IM RaccineSettings.exe
TASKKILL /F /IM RaccineRulesSync.exe
ECHO Removing Raccine folders ...
@RD /S /Q "%ProgramData%\Raccine"
@RD /S /Q "%ProgramFiles%\Raccine"
ECHO LEGACY: Removing Raccine.exe from the Windows folder (succeeds only if previously installed) ...
DEL /Q C:\Windows\Raccine.exe
ECHO Uninstalling Registry patches ...
REGEDIT.EXE /S reg-patches\raccine-reg-patch-uninstall.reg
IF '%errorlevel%' NEQ '0' (
    ECHO Something went wrong. Sorry.
) ELSE (
    ECHO.
    ECHO Successfully uninstalled!
)
TASKKILL /F /IM RaccineSettings.exe
TASKKILL /F /IM RaccineRulesSync.exe
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Raccine Tray" /F
:: Uninstall update task
SCHTASKS /DELETE /TN "Raccine Rules Updater" /F
:: in case of automation, directly got to EOF
IF NOT "%SELECTED_OPTION%"=="" GOTO EOF
TIMEOUT /t 30
GOTO MENU

:EOF
EXIT /B %ERRORLEVEL%
