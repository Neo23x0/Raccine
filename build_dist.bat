@ECHO OFF

DEL /F Raccine.zip
@RD /S /Q ".\Raccine"
MKDIR Raccine
:: Binaries
XCOPY x64\Release\Raccine.exe Raccine\Raccine.exe*
XCOPY Release\Raccine.exe Raccine\Raccine_x86.exe*
:: Installer Batch
XCOPY install-raccine.bat Raccine\
:: Scripts
MKDIR Raccine\scripts\
XCOPY scripts\windows-hardening.bat Raccine\scripts\
:: Registry Patches
MKDIR Raccine\reg-patches\
XCOPY reg-patches\*.reg Raccine\reg-patches\

:: YARA Feature
MKDIR Raccine\yara\
XCOPY yara\*.* Raccine\yara\
XCOPY tools\yara86.exe Raccine\yara\
XCOPY tools\yara64.exe Raccine\yara\

:: GUI
XCOPY RaccineGUI\RaccineCfg\RaccineElevatedCfg\bin\Release\RaccineElevatedCfg.exe Raccine\
XCOPY RaccineGUI\RaccineCfg\RaccineSettings\bin\Release\RaccineSettings.exe Raccine\
