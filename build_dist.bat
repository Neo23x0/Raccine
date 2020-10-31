@ECHO OFF

:: Download Components
ECHO Create Temp directory for some downloads
MKDIR temp
:: Get YARA
ECHO Downloading YARA ...
powershell -executionpolicy bypass -Command "(New-Object System.Net.WebClient).DownloadFile('https://github.com/VirusTotal/yara/releases/download/v4.0.2/yara-v4.0.2-1347-win64.zip', '.\temp\yara.zip')"
powershell -executionpolicy bypass -Command "Expand-Archive -Path .\temp\yara.zip -DestinationPath .\tools -Force"
DEL /F .\tools\yarac64.exe
:: Get Visual C++ Runtime
ECHO Downloading Visual C++ Runtime ...
powershell -executionpolicy bypass -Command "(New-Object System.Net.WebClient).DownloadFile('https://aka.ms/vs/16/release/vc_redist.x64.exe', '.\tools\vc_redist.x64.exe')"

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
ECHO Crating .\Raccine\yara sub folder for YARA binaries and rules ...
MKDIR Raccine\yara\
MKDIR Raccine\yara\in-memory\
ECHO Copying all yara rules to new folders ...
XCOPY yara\*.* Raccine\yara\
XCOPY yara\in-memory\*.* Raccine\yara\in-memory
ECHO Copying yara binaries to new folder ...
XCOPY tools\yara64.exe Raccine\yara\

:: Visual C++ Runtime
ECHO Copying VC++ runtimt to dist folder
XCOPY tools\yara64.exe Raccine\vc_redist.x64.exe*

:: GUI
ECHO Copying GUI components to dist folder
XCOPY RaccineGUI\RaccineCfg\RaccineElevatedCfg\bin\Release\RaccineElevatedCfg.exe Raccine\
XCOPY RaccineGUI\RaccineCfg\RaccineSettings\bin\Release\RaccineSettings.exe Raccine\
XCOPY RaccineGUI\RaccineCfg\RaccineRulesSync\bin\Release\RaccineRulesSync.exe Raccine\

ECHO Cleanup tasks ...
:: Clean up
@RD /S /Q ".\temp" 

ECHO All installer components should now be in .\Raccine ready for installation
