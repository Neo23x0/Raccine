:: Source: https://gist.github.com/sjas/2d7a9b9c976bb2aa410757044d4282c9
:: Modified to be less intrusive by Florian Roth in October 2020
:: I've disabled some of the original actions with REM statements

:MENU
CLS
ECHO.
ECHO ..............................................................................
:::     ___               _         
:::    / _ \___ _________(_)__  ___ 
:::   / , _/ _ `/ __/ __/ / _ \/ -_)
:::  /_/|_|\_,_/\__/\__/_/_//_/\__/ Hardening Script
:::
for /f "delims=: tokens=*" %%A in ('findstr /b ::: "%~f0"') do @echo(%%A
ECHO   Composed by Florian Roth, October 2020
ECHO   Source: https://gist.github.com/sjas/2d7a9b9c976bb2aa410757044d4282c9
ECHO.                       
ECHO ------------------------------------------------------------------------------
ECHO   WARNING! 
ECHO   This scripts performs some actions on your system that cannot be undone.
ECHO   The actions include:
ECHO     - Show extensions of known file extensions
ECHO     - Change the default application for .hta and .wsh files to notepad.exe 
ECHO     - Configure Win 10 1709 ExploitGuard to mitigate Office malspam
ECHO     - Harden MS Office itself against malspam attacks (VBA, Macro warnings)
ECHO     - Harden MS Office itself against DDE malspam attacks
ECHO     - Adds firewall rules to block network connections by
ECHO       notepad.exe, regsvr32.exe, mshta.exe, wscript.exe, cscript.exe and 
ECHO       runscripthelper.exe
ECHO ..............................................................................
ECHO.
ECHO   1 - Run Hardening Script
ECHO   E - EXIT
ECHO.

SET /P M=" Select 1 or E then press ENTER: "
IF %M%==1 GOTO HARDEN
IF %M%==E GOTO EOF
IF %M%==e GOTO EOF

:HARDEN 
::
::#######################################################################
::
:: My Own Addition (Florian Roth)
:: Show extensions of known file types (makes double extensions like .doc.exe visible to the user)
REG.EXE ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v HideFileExt /t REG_DWORD /d 0 /f

:: Disable OLE
:: https://twitter.com/keydet89/status/1318150271919288321
reg add "HKCU\Software\Policies\Microsoft\Office\12.0\Word\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\Software\Policies\Microsoft\Office\14.0\Word\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Word\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Excel\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\PowerPoint\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Publisher\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Word\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Excel\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\PowerPoint\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Publisher\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f

::
::#######################################################################
::
:: Change file associations to protect against common ransomware attacks
:: Note that if you legitimately use these extensions, like .bat, you will now need to execute them manually from cmd or powershell
:: Alternatively, you can right-click on them and hit 'Run as Administrator' but ensure it's a script you want to run :) 
:: ---------------------
ftype htafile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
ftype WSHFile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
REM ftype batfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"

::
::#######################################################################
::
:: Enable ASR rules in Win10 1709 ExploitGuard to mitigate Offic malspam
:: Blocks Office childprocs, Office proc injection, Office win32 api calls & executable content creation
:: Note these only work when Defender is your primary AV
:: Source: https://www.darkoperator.com/blog/2017/11/11/windows-defender-exploit-guard-asr-rules-for-office
:: ---------------------
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions enable
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions enable
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids '3B576869-A4EC-4529-8536-B80A7769E899' -AttackSurfaceReductionRules_Actions enable
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
::
::#######################################################################
::
:: Harden all version of MS Office itself against common malspam attacks
:: Disables Macros, enables ProtectedView
:: Source: https://decentsecurity.com/block-office-macros/
:: ---------------------
reg add "HKCU\Software\Policies\Microsoft\Office\12.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\12.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\14.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\14.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Outlook\Security" /v markinternalasunsafe /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Word\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Excel\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\PowerPoint\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Outlook\Security" /v markinternalasunsafe /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Word\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Excel\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\PowerPoint\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
::
::#######################################################################
::
:: Harden all version of MS Office itself against DDE malspam attacks
:: Disables Macros, enables ProtectedView
:: Source: https://gist.github.com/wdormann/732bb88d9b5dd5a66c9f1e1498f31a1b
:: ---------------------
::
reg add "HKCU\Software\Microsoft\Office\14.0\Word\Options" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\14.0\Word\Options\WordMail" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\15.0\Word\Options" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\15.0\Word\Options\WordMail" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\16.0\Word\Options" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\16.0\Word\Options\WordMail" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
::#######################################################################
::
:: General OS hardening
:: Disables DNS multicast, smbv1, netbios, powershellv2
:: Enables UAC
:: ---------------------
REM reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 1 /f
REM reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f
REM reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
REM wmic /interactive:off nicconfig where TcpipNetbiosOptions=1 call SetTcpipNetbios 2
REM powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol
REM powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2
REM powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
::
::#######################################################################
::
:: Harden lsass to help protect against credential dumping (mimikatz)
:: Configures lsass.exe as a protected process and disabled wdigest
:: Source: https://technet.microsoft.com/en-us/library/dn408187(v=ws.11).aspx
:: ---------------------
REM reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f
REM reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 00000001 /f
REM reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
::
::#######################################################################
::
:: Enable Windows Firewall and configure some advanced options
:: ---------------------
NetSh Advfirewall set allrprofiles state on
Netsh.exe advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\system32\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\system32\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
REM Netsh.exe advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\system32\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\system32\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\system32\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\system32\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\system32\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any

:: Other sections have been removed

ECHO Successfully applied harding script. The system is now less susceptible to phishing attacks.

:EOF