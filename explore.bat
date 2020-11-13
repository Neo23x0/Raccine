rem @ECHO OFF

:: Download Components
ECHO Create Temp directory for some downloads
MKDIR bin
:: Get YARA
ECHO Downloading YARA ...
powershell -executionpolicy bypass -Command "(New-Object System.Net.WebClient).DownloadFile('https://live.sysinternals.com/psloggedon.exe', '.\bin\psloggedon.exe')"
powershell -executionpolicy bypass -Command "(New-Object System.Net.WebClient).DownloadFile('https://live.sysinternals.com/du.exe', '.\bin\du.exe')"
powershell -executionpolicy bypass -Command "(New-Object System.Net.WebClient).DownloadFile('https://live.sysinternals.com/psinfo.exe', '.\bin\psinfo.exe')"
set MYBIN=.\bin
set
whoami /groups
tasklist /m
dir %USERPROFILE%
dir %TEMP%
net localgroup administrators
%MYBIN%\psloggedon /accepteula
%MYBIN%\psinfo -d /accepteula
dir  > "c:\Program Files\foo.txt"
dir "c:\Program Files\"
%MYBIN%\du -l 2 c:\ /accepteula
