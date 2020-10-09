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
ECHO ..........................................................
:::     ___               _         
:::    / _ \___ _________(_)__  ___ 
:::   / , _/ _ `/ __/ __/ / _ \/ -_)
:::  /_/|_|\_,_/\__/\__/_/_//_/\__/ 
:::
for /f "delims=: tokens=*" %%A in ('findstr /b ::: "%~f0"') do @echo(%%A
ECHO   A Simple Ransomware Vaccine
ECHO   Installer by Florian Roth, October 2020  
ECHO.                       
ECHO ----------------------------------------------------------
ECHO   WARNING! Raccine could break your backup solution 
ECHO ..........................................................
ECHO.
ECHO   1 - Install Raccine for all possible methods (radical)
ECHO   2 - Install Raccine for Vssadmin only (relatively safe)
ECHO   3 - Uninstall Raccine
ECHO   E - EXIT
ECHO.

SET /P M=" Select 1, 2, 3, or E then press ENTER: "
IF %M%==1 GOTO FULL
IF %M%==2 GOTO SOFT
IF %M%==3 GOTO UNINSTALL
IF %M%==E GOTO EOF
IF %M%==e GOTO EOF

:: Installer actions

:: Full
:FULL
ECHO.
ECHO Installing Registry patches ...
REGEDIT.EXE /S raccine-reg-patch-vssadmin.reg
IF '%errorlevel%' NEQ '0' (
    ECHO Something went wrong. Sorry.
    GOTO MENU
)
REGEDIT.EXE /S raccine-reg-patch-wmic.reg 
REGEDIT.EXE /S raccine-reg-patch-wbadmin.reg
ECHO Copying Raccine%ARCH%.exe to C:\Windows\Raccine.exe ...
COPY Raccine%ARCH%.exe C:\Windows\Raccine.exe
IF '%errorlevel%' NEQ '0' (
    ECHO Something went wrong. Sorry.
) ELSE (
    ECHO.
    ECHO Successfully installed. Your system has been raccinated.
)
TIMEOUT /t 5
GOTO MENU

:: Soft
:SOFT 
ECHO.
ECHO Installing Registry patches ...
REGEDIT.EXE /S raccine-reg-patch-vssadmin.reg
IF '%errorlevel%' NEQ '0' (
    ECHO Something went wrong. Sorry.
    GOTO MENU
)
ECHO Copying Raccine%ARCH%.exe to C:\Windows\Raccine.exe ...
COPY Raccine%ARCH%.exe C:\Windows\Raccine.exe
IF '%errorlevel%' NEQ '0' (
    ECHO Something went wrong. Sorry.
) ELSE (
    ECHO.
    ECHO Successfully installed. Your system has been raccinated.
)
TIMEOUT /t 5
GOTO MENU

:: Uninstall
:UNINSTALL
ECHO.
ECHO Uninstalling Registry patch ...
REGEDIT.EXE /S raccine-reg-patch-uninstall.reg
ECHO Removing Raccine.exe from the Windows folder ...
DEL /Q C:\Windows\Raccine.exe
IF '%errorlevel%' NEQ '0' (
    ECHO Something went wrong. Sorry.
) ELSE (
    ECHO.
    ECHO Successfully uninstalled!
)
TIMEOUT /t 5
GOTO MENU

:EOF