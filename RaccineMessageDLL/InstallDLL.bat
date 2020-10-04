@echo off
echo Installing message file
copy RaccineMessageDLL.dll c:\Windows\System32\RaccineMessageDLL.dll
reg add HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\Raccine
reg add HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\Raccine /v EventMessageFile /t REG_EXPAND_SZ /d "C:\Windows\System32\RaccineMessageDLL.dll"