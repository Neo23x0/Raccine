@ECHO OFF
SET __COMPAT_LAYER=RunAsInvoker
SETLOCAL EnableDelayedExpansion
CLS 

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
ECHO   3 - Install Raccine for Vssadmin and BcdEdit only
ECHo   4 - Run Windows Hardening Script (select 4 for more information)
ECHO   U - Uninstall Raccine
ECHO   E - EXIT
ECHO.

SET /P M=" Select an option and then press ENTER: "
IF %M%==1 GOTO FULL
IF %M%==2 GOTO FULL_SIMU
IF %M%==3 GOTO SOFT
IF %M%==4 GOTO HARDENING
IF %M%==U GOTO UNINSTALL
IF %M%==u GOTO UNINSTALL
IF %M%==E GOTO EOF
IF %M%==e GOTO EOF
GOTO MENU

:: Installer actions

:: Full
:FULL
ECHO.
ECHO Creating data directory %ProgramData%\Raccine ...
MKDIR "%ProgramData%\Raccine"
MKDIR "%ProgramData%\Raccine\yara"
ECHO Copying YARA rules to the directory ...
COPY *.yar "%ProgramData%\Raccine\yara"
COPY runyara.bat "%ProgramData%\Raccine"
ECHO Installing Registry patches ...
REGEDIT.EXE /S raccine-reg-patch-vssadmin.reg
IF '%errorlevel%' NEQ '0' (
    ECHO Something went wrong. Sorry.
    GOTO MENU
)
REGEDIT.EXE /S raccine-reg-patch-wmic.reg 
REGEDIT.EXE /S raccine-reg-patch-wbadmin.reg
REGEDIT.EXE /S raccine-reg-patch-bcdedit.reg
REGEDIT.EXE /S raccine-reg-patch-powershell.reg
REGEDIT.EXE /S raccine-reg-patch-diskshadow.reg
ECHO Registering Eventlog Events
eventcreate.exe /L Application /T Information /id 1 /so Raccine /d "Raccine event message" 2> nul
eventcreate.exe /L Application /T Information /id 2 /so Raccine /d "Raccine event message" 2> nul
REG.EXE ADD HKLM\Software\Raccine /v Logging /t REG_DWORD /d 2 /F
REG.EXE ADD HKLM\Software\Raccine /v LogOnly /t REG_DWORD /d 0 /F
REG.EXE ADD HKLM\Software\Raccine /v RulesDir /t REG_SZ /d %ProgramData%\Raccine\yara /F
ECHO Copying Raccine%ARCH%.exe to C:\Windows\Raccine.exe ...
COPY Raccine%ARCH%.exe C:\Windows\Raccine.exe
IF '%errorlevel%' NEQ '0' (
    ECHO Something went wrong. Sorry.
) ELSE (
    ECHO.
    ECHO Successfully installed. Your system has been raccinated.
)
TIMEOUT /t 30
GOTO MENU

:: Full (Simulation Mode)
:FULL_SIMU
ECHO.
ECHO Creating data directory %ProgramData%\Raccine ...
MKDIR "%ProgramData%\Raccine"
MKDIR "%ProgramData%\Raccine\yara"
ECHO Copying YARA rules to the directory ...
COPY *.yar "%ProgramData%\Raccine\yara"
COPY runyara.bat "%ProgramData%\Raccine"
ECHO Installing Registry patches ...
REGEDIT.EXE /S raccine-reg-patch-vssadmin.reg
IF '%errorlevel%' NEQ '0' (
    ECHO Something went wrong. Sorry.
    GOTO MENU
)
REGEDIT.EXE /S raccine-reg-patch-wmic.reg 
REGEDIT.EXE /S raccine-reg-patch-wbadmin.reg
REGEDIT.EXE /S raccine-reg-patch-bcdedit.reg
REGEDIT.EXE /S raccine-reg-patch-powershell.reg
REGEDIT.EXE /S raccine-reg-patch-diskshadow.reg
REGEDIT.EXE /S raccine-reg-patch-ransomware.reg
ECHO Registering Eventlog Events
eventcreate.exe /L Application /T Information /id 1 /so Raccine /d "Raccine event message" 2> nul
eventcreate.exe /L Application /T Information /id 2 /so Raccine /d "Raccine event message" 2> nul
REG.EXE ADD HKLM\Software\Raccine /v Logging /t REG_DWORD /d 2 /F
REG.EXE ADD HKLM\Software\Raccine /v LogOnly /t REG_DWORD /d 2 /F
REG.EXE ADD HKLM\Software\Raccine /v RulesDir /t REG_SZ /d %ProgramData%\Raccine\yara /F
ECHO Copying Raccine%ARCH%.exe to C:\Windows\Raccine.exe ...
COPY Raccine%ARCH%.exe C:\Windows\Raccine.exe
IF '%errorlevel%' NEQ '0' (
    ECHO Something went wrong. Sorry.
) ELSE (
    ECHO.
    ECHO Successfully installed. Your system has been raccinated.
    ECHO Warning: Simulation mode only! 
)
TIMEOUT /t 30
GOTO MENU

:: Soft
:SOFT 
ECHO.
ECHO Creating data directory %ProgramData%\Raccine ...
MKDIR "%ProgramData%\Raccine"
MKDIR "%ProgramData%\Raccine\yara"
ECHO Copying YARA rules to the directory ...
COPY *.yar "%ProgramData%\Raccine\yara"
COPY runyara.bat "%ProgramData%\Raccine"
ECHO Installing Registry patches ...
REGEDIT.EXE /S raccine-reg-patch-vssadmin.reg
IF '%errorlevel%' NEQ '0' (
    ECHO Something went wrong. Sorry.
    GOTO MENU
)
REGEDIT.EXE /S raccine-reg-patch-bcdedit.reg
ECHO Registering Eventlog Events
eventcreate.exe /L Application /T Information /id 1 /so Raccine /d "Raccine event message" 2> nul
eventcreate.exe /L Application /T Information /id 2 /so Raccine /d "Raccine event message" 2> nul
REG.EXE ADD HKLM\Software\Raccine /v GUI /t REG_DWORD /d 1 /F
REG.EXE ADD HKLM\Software\Raccine /v Logging /t REG_DWORD /d 2 /F
REG.EXE ADD HKLM\Software\Raccine /v LogOnly /t REG_DWORD /d 0 /F
REG.EXE ADD HKLM\Software\Raccine /v RulesDir /t REG_SZ /d "%ProgramData%\Raccine\yara" /F
ECHO Copying Raccine%ARCH%.exe to C:\Windows\Raccine.exe ...
COPY Raccine%ARCH%.exe C:\Windows\Raccine.exe
IF '%errorlevel%' NEQ '0' (
    ECHO Something went wrong. Sorry.
) ELSE (
    ECHO.
    ECHO Successfully installed. Your system has been raccinated.
)
TIMEOUT /t 30
GOTO MENU


:: Run Hardening Script
:HARDENING 
ECHO.
ECHO Running the Hardening script ...
ECHO.
CALL windows-hardening.bat
IF '%errorlevel%' NEQ '0' (
    ECHO Something went wrong. Sorry.
    GOTO MENU
)
TIMEOUT /t 30
GOTO MENU


:: Uninstall
:UNINSTALL
ECHO.
ECHO Removing Raccine folder ...
@RD /S /Q "%ProgramData%\Raccine"
ECHO Uninstalling Registry patches ...
REGEDIT.EXE /S raccine-reg-patch-uninstall.reg
ECHO Removing Raccine.exe from the Windows folder ...
DEL /Q C:\Windows\Raccine.exe
IF '%errorlevel%' NEQ '0' (
    ECHO Something went wrong. Sorry.
) ELSE (
    ECHO.
    ECHO Successfully uninstalled!
)
TIMEOUT /t 30
GOTO MENU

:EOF
