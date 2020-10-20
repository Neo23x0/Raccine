@ECHO OFF

DEL /F Raccine.zip
COPY x64\Release\Raccine.exe Raccine\Raccine.exe
COPY Release\Raccine.exe Raccine\Raccine_x86.exe
COPY install-raccine.bat Raccine\
COPY windows-hardening.bat Raccine\
COPY *.reg Raccine\
COPY yara\*.* Raccine\
zip Raccine