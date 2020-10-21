@ECHO OFF

MKDIR Raccine
:: Binaries
COPY x64\Release\Raccine.exe Raccine\Raccine.exe
COPY Release\Raccine.exe Raccine\Raccine_x86.exe
:: Installer Batch
COPY install-raccine.bat Raccine\
:: Scripts
COPY scripts\windows-hardening.bat Raccine\scripts
:: Registry Patches
COPY reg-patches\*.reg Raccine\reg-patches

:: YARA Feature
COPY yara\*.* Raccine\yara

:: GUI
COPY RaccineGUI\RaccineCfg\RaccineElevatedCfg\bin\Release\RaccineElevatedCfg.exe Raccine\
COPY RaccineGUI\RaccineCfg\RaccineSettings\bin\Release\RaccineSettings.exe Raccine\
