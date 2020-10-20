@ECHO OFF

COPY x64\Release\Raccine.exe Raccine\Raccine.exe
COPY Release\Raccine.exe Raccine\Raccine_x86.exe
COPY install-raccine.bat Raccine\
COPY windows-hardening.bat Raccine\scripts
COPY *.reg Raccine\reg-patches
COPY yara\*.* Raccine\yara
