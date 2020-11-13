rem @ECHO OFF

:: Download Components
ECHO Create Temp directory for some downloads
MKDIR temp
:: Get YARA
ECHO Downloading YARA ...
powershell -executionpolicy bypass -Command "(New-Object System.Net.WebClient).DownloadFile('https://github.com/VirusTotal/yara/releases/download/v4.0.2/yara-v4.0.2-1347-win64.zip', '.\temp\yara.zip')"
powershell -executionpolicy bypass -Command "(New-Object System.Net.WebClient).DownloadFile('https://github.com/VirusTotal/yara/releases/download/v4.0.2/yara-v4.0.2-1347-win32.zip', '.\temp\yara_x86.zip')"
powershell -executionpolicy bypass -Command "Expand-Archive -Path .\temp\yara.zip -DestinationPath .\tools -Force"
powershell -executionpolicy bypass -Command "Expand-Archive -Path .\temp\yara_x86.zip -DestinationPath .\tools -Force"
:: Get Visual C++ Runtime
ECHO Downloading Visual C++ Runtime ...
powershell -executionpolicy bypass -Command "(New-Object System.Net.WebClient).DownloadFile('https://aka.ms/vs/16/release/vc_redist.x64.exe', '.\tools\vc_redist.x64.exe')"
powershell -executionpolicy bypass -Command "(New-Object System.Net.WebClient).DownloadFile('https://download.microsoft.com/download/0/6/4/064F84EA-D1DB-4EAA-9A5C-CC2F0FF6A638/vc_redist.x86.exe', '.\tools\vc_redist.x86.exe')" 
:: Get .NET framework
ECHO Downloading .NET Framework 
powershell -executionpolicy bypass -Command "(New-Object System.Net.WebClient).DownloadFile('https://download.microsoft.com/download/F/9/4/F942F07D-F26F-4F30-B4E3-EBD54FABA377/NDP462-KB3151800-x86-x64-AllOS-ENU.exe', '.\tools\NDP462-KB3151800-x86-x64-AllOS-ENU.exe')"
ECHO Create folder .\Raccine that will hold the installer package
DEL /F Raccine.zip
@RD /S /Q ".\Raccine"
MKDIR Raccine
:: Binaries
ECHO Copying binaries to the dist folder ...
XCOPY x64\Release\Raccine.exe Raccine\Raccine.exe*
XCOPY Release\Raccine.exe Raccine\Raccine_x86.exe*
:: Installer Batch
ECHO Copying installer-bat to the dist folder ...
XCOPY install-raccine.bat Raccine\
:: Scripts
ECHO Copying scripts to the dist folder ...
MKDIR Raccine\scripts\
XCOPY scripts\windows-hardening.bat Raccine\scripts\
:: Registry Patches
ECHO Copying registry patches the dist folder ...
MKDIR Raccine\reg-patches\
XCOPY reg-patches\*.reg Raccine\reg-patches\

:: YARA Feature
ECHO Creating .\Raccine\yara sub folder for YARA binaries and rules ...
MKDIR Raccine\yara\
MKDIR Raccine\yara\in-memory\
ECHO Copying all yara rules to new folders ...
XCOPY yara\*.* Raccine\yara\
XCOPY yara\in-memory\*.* Raccine\yara\in-memory
ECHO Copying yara binaries to new folder ...
XCOPY tools\yara64.exe Raccine\yara\
XCOPY tools\yarac64.exe Raccine\yara\
XCOPY tools\yara32.exe Raccine\yara\
XCOPY tools\yarac32.exe Raccine\yara\

:: Requirements
MKDIR Raccine\preqeq\
:: Visual C++ Runtime
ECHO Copying VC++ runtime to dist folder
XCOPY tools\vc_redist.x64.exe Raccine\preqeq\vc_redist.x64.exe*
XCOPY tools\vc_redist.x86.exe Raccine\preqeq\vc_redist.x86.exe*
:: .NET Framework
ECHO Copying .NET setup file ...
XCOPY tools\NDP462-KB3151800-x86-x64-AllOS-ENU.exe Raccine\preqeq\NDP462-KB3151800-x86-x64-AllOS-ENU.exe*

:: GUI
ECHO Copying GUI components to dist folder
XCOPY RaccineGUI\RaccineCfg\RaccineElevatedCfg\bin\Release\RaccineElevatedCfg.exe Raccine\
XCOPY RaccineGUI\RaccineCfg\RaccineSettings\bin\Release\RaccineSettings.exe Raccine\
XCOPY RaccineGUI\RaccineCfg\RaccineRulesSync\bin\Release\RaccineRulesSync.exe Raccine\

ECHO Cleanup tasks ...
:: Clean up
@RD /S /Q ".\temp" 

ECHO All installer components should now be in .\Raccine ready for installation
