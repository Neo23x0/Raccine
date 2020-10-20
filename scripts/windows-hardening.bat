:: Source: https://gist.github.com/mackwage/08604751462126599d7e52f233490efe
:: Modified to be less intrusive by Florian Roth in October 2020
:: I've disabled some of the original actions with REM statements
@ECHO OFF
SET __COMPAT_LAYER=RunAsInvoker
SETLOCAL EnableDelayedExpansion
CLS 
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
ECHO   Modified Hardening Script by Florian Roth, October 2020
ECHO   Source: https://gist.github.com/mackwage/08604751462126599d7e52f233490efe
ECHO.                       
ECHO ------------------------------------------------------------------------------
ECHO   WARNING! USE AT YOUR OWN RISK! 
ECHO   This scripts performs actions on your system that cannot be automatically 
ECHO   undone. 
ECHO   Don't use this hardening script in environments controlled by GPOs.
ECHO.
ECHO   FULL - Apply all harding options (best for private computers)
ECHO   SOFT - Apply only the safest harding options (some basic security tweaks)
ECHO ..............................................................................
ECHO.
ECHO   1 - Run Hardening Script (Full)
ECHO   2 - Run Harding Script (Soft)
ECHO   E - EXIT
ECHO.

SET /P M=" Select one of the options and  then press ENTER: "
IF %M%==1 GOTO HARD 
IF %M%==2 GOTO SOFT 
IF %M%==E GOTO EOF
IF %M%==e GOTO EOF

:HARD
::#######################################################################
:: Hard Changes 
::#######################################################################

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

:: Change file associations to protect against common ransomware attacks
:: Note that if you legitimately use these extensions, like .bat, you will now need to execute them manually from cmd or powershel
:: Alternatively, you can right-click on them and hit 'Run as Administrator' but ensure it's a script you want to run :) 
:: https://support.microsoft.com/en-us/help/883260/information-about-the-attachment-manager-in-microsoft-windows
:: ---------------------
ftype wshfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
ftype wsffile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
@REM ftype batfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
ftype vbefile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
ftype vbsfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"

::#######################################################################
:: Enable and configure Windows Defender and advanced settings
::#######################################################################
::
:: Reset Defender to defaults. Commented out but available for reference
::"%programfiles%"\"Windows Defender"\MpCmdRun.exe -RestoreDefaults
:: https://docs.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#defender-submitsamplesconsent
:: https://docs.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=win10-ps
::
@REM :: Start Defender Service
@REM sc start WinDefend
@REM ::Enable Windows Defender sandboxing
@REM setx /M MP_FORCE_USE_SANDBOX 1
@REM :: Update signatures
@REM "%ProgramFiles%"\"Windows Defender"\MpCmdRun.exe -SignatureUpdate
@REM :: Enable Defender signatures for Potentially Unwanted Applications (PUA)
@REM powershell.exe Set-MpPreference -PUAProtection enable
@REM :: Enable Defender periodic scanning
@REM reg add "HKCU\SOFTWARE\Microsoft\Windows Defender" /v PassiveMode /t REG_DWORD /d 2 /f
@REM :: Enable Cloud functionality of Windows Defender
@REM powershell.exe Set-MpPreference -MAPSReporting Advanced
@REM powershell.exe Set-MpPreference -SubmitSamplesConsent 0
::
:: Enable early launch antimalware driver for scan of boot-start drivers
:: 3 is the default which allows good, unknown and 'bad but critical'. Recommend trying 1 for 'good and unknown' or 8 which is 'good only'
reg add "HKCU\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" /v DriverLoadPolicy /t REG_DWORD /d 3 /f
::
:: Enable ASR rules in Win10 1903 ExploitGuard to mitigate Office malspam
:: Blocks Office childprocs, Office proc injection, Office win32 api calls & executable content creation
:: Note these only work when Defender is your primary AV
::

:: Block Win32 API calls in macros
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled
:: Block execution of potentially obfuscated scripts
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
:: Block lsass cred theft
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled
:: Block untrusted and unsigned processes that run from USB
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions Enabled
:: Block process creations originating from PSExec and WMI commands
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions Enabled
::
:: Enable Defender exploit system-wide protection
:: The commented line includes CFG which can cause issues with apps like Discord & Mouse Without Borders
:: powershell.exe Set-Processmitigation -System -Enable DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,SEHOPTelemetry,TerminateOnError,CFG
powershell.exe Set-Processmitigation -System -Enable DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,SEHOPTelemetry,TerminateOnError

::
:: Enable and Configure General Windows Security Settings
:: Disables DNS multicast, smart mutli-homed resolution, netbios, powershellv2, printer driver download and printing over http, icmp redirect
:: Enables UAC and sets to always notify, Safe DLL loading (DLL Hijacking prevention), saving zone information, explorer DEP, explorer shell protocol protected mode
:: ---------------------
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DisableSmartNameResolution /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v DisableParallelAandAAAA /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v IGMPLevel /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableICMPRedirect /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableVirtualization /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v SafeDLLSearchMode /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v ProtectionMode /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v SaveZoneInformation /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoDataExecutionPrevention /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoHeapTerminationOnCorruption /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v PreXPSP2ShellProtocolBehavior /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableWebPnPDownload /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableHTTPPrinting /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v AutoConnectAllowedOEM /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v fMinimizeConnections /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" /v NoNameReleaseOnDemand /t REG_DWORD /d 1 /f
wmic /interactive:off nicconfig where (TcpipNetbiosOptions=0 OR TcpipNetbiosOptions=1) call SetTcpipNetbios 2
powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -norestart
powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -norestart
::
:: Prioritize ECC Curves with longer keys
::reg add "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" /v EccCurves /t REG_MULTI_SZ /d NistP384,NistP256 /f
:: Prevent Kerberos from using DES or RC4
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v SupportedEncryptionTypes /t REG_DWORD /d 2147483640 /f
:: Encrypt and sign outgoing secure channel traffic when possible
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f
::
:: Enable SmartScreen
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v ShellSmartScreenLevel /t REG_SZ /d Block /f
::
:: Enforce device driver signing
BCDEDIT /set nointegritychecks OFF

::
:: Windows Sharing/SMB Settings
:: Disable smb1, anonymous access to named pipes/shared, anonymous enumeration of SAM accounts, non-admin remote access to SAM
:: Enable optional SMB client signing
powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -norestart
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v RestrictNullSessAccess /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v EveryoneIncludesAnonymous /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictRemoteSAM /t REG_SZ /d "O:BAG:BAD:(A;;RC;;;BA)" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v UseMachineId /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" /v allownullsessionfallback /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f
:: Force SMB server signing
:: This could cause impact if the Windows computer this is run on is hosting a file share and the other computers connecting to it do not have SMB client signing enabled.
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f
::
:: Harden lsass to help protect against credential dumping (mimikatz) and audit lsass access requests
:: Configures lsass.exe as a protected process and disables wdigest
:: Enables delegation of non-exported credentials which enables support for Restricted Admin Mode or Remote Credential Guard
:: ---------------------
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v AllowProtectedCreds /t REG_DWORD /d 1 /f
::
:: Windows RPC and WinRM settings
:: Stop WinRM
net stop WinRM
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" /v AllowUnencryptedTraffic /t REG_DWORD /d 0 /f
:: Disable WinRM Client Digiest authentication
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v AllowDigest /t REG_DWORD /d 0 /f
:: Disabling RPC usage from a remote asset interacting with scheduled tasks
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule" /v DisableRpcOverTcp /t REG_DWORD /d 1 /f
:: Disabling RPC usage from a remote asset interacting with services
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v DisableRemoteScmEndpoints /t REG_DWORD /d 1 /f

::#######################################################################
:: Enable and configure Windows Firewall
::#######################################################################
::
NetSh Advfirewall set allprofiles state on
::
:: Enable Firewall Logging
netsh advfirewall set currentprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log
netsh advfirewall set currentprofile logging maxfilesize 4096
netsh advfirewall set currentprofile logging droppedconnections enable
::
:: Block all inbound connections on Public profile
netsh advfirewall set publicprofile firewallpolicy blockinboundalways,allowoutbound
:: Enable Windows Defender Network Protection
powershell.exe Set-MpPreference -EnableNetworkProtection Enabled


::
:: Block Win32 binaries from making netconns when they shouldn't - specifically targeting native processes known to be abused by bad actors
:: ---------------------
:: Note: in hard mode we'll also make sure that the firewall is running
::       in softmode, we just add the rules - if the firewall is disabled, this has no (negative) effect
Netsh.exe advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\system32\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\system32\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any

::#######################################################################
:: Enable Advanced Windows Logging
::#######################################################################
::
:: Enlarge Windows Event Security Log Size
@REM wevtutil sl Security /ms:1024000 /f
@REM wevtutil sl Application /ms:1024000 /f
@REM wevtutil sl System /ms:1024000 /f
@REM wevtutil sl "Windows Powershell" /ms:1024000 /f
@REM wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:1024000 /f
:: Record command line data in process creation events eventid 4688
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
::
:: Enabled Advanced Settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f
:: Enable PowerShell Logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
::
:: Enable Windows Event Detailed Logging
:: This is intentionally meant to be a subset of expected enterprise logging as this script may be used on consumer devices.
:: For more extensive Windows logging, I recommend https://www.malwarearchaeology.com/cheat-sheets
Auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
Auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
Auditpol /set /subcategory:"Logon" /success:enable /failure:enable 
Auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:disable
Auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
Auditpol /set /subcategory:"SAM" /success:disable /failure:disable
Auditpol /set /subcategory:"Filtering Platform Policy Change" /success:disable /failure:disable
Auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable
Auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
Auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable

::#######################################################################
:: Extra settings commented out but worth considering
::#######################################################################
::
:: Enforce NTLMv2 and LM authentication
:: This is commented out by default as it could impact access to consumer-grade file shares but it's a recommended setting
:: reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f
::
:: Prevent unencrypted passwords being sent to third-party SMB servers
:: This is commented out by default as it could impact access to consumer-grade file shares but it's a recommended setting
:: reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
::
:: Prevent guest logons to SMB servers
:: This is commented out by default as it could impact access to consumer-grade file shares but it's a recommended setting
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f
::
:: Force SMB server signing
:: This is commented out by default as it could impact access to consumer-grade file shares but it's a recommended setting
:: reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f
::
:: Enable Windows Defender Application Guard
:: This setting is commented out as it enables subset of DC/CG which renders other virtualization products unsuable. Can be enabled if you don't use those
:: powershell.exe Enable-WindowsOptionalFeature -online -FeatureName Windows-Defender-ApplicationGuard -norestart
::
:: Enable Windows Defender Credential Guard
:: This setting is commented out as it enables subset of DC/CG which renders other virtualization products unsuable. Can be enabled if you don't use those
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v RequirePlatformSecurityFeatures /t REG_DWORD /d 3 /f
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v LsaCfgFlags /t REG_DWORD /d 1 /f
::
:: The following variant also enables forced ASLR and CFG but causes issues with several third party apps
:: powershell.exe Set-Processmitigation -System -Enable DEP,CFG,ForceRelocateImages,BottomUp,SEHOP
::
:: Block executable files from running unless they meet a prevalence, age, or trusted list criterion
:: This one is commented out for now as I need to research and test more to determine potential impact
:: powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions Enabled
::
:: Enable Windows Defender real time monitoring
:: Commented out given consumers often run third party anti-virus. You can run either. 
:: powershell.exe -command "Set-MpPreference -DisableRealtimeMonitoring $false"
:: reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 0 /f
::
:: Disable internet connection sharing
:: Commented out as it's not enabled by default and if it is enabled, may be for a reason
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v NC_ShowSharedAccessUI /t REG_DWORD /d 0 /f
::
:: Always re-process Group Policy even if no changes
:: Commented out as consumers don't typically use GPO
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" /v NoGPOListChanges /t REG_DWORD /d 0 /f
::
:: Force logoff if smart card removed
:: Set to "2" for logoff, set to "1" for lock
:: Commented out as consumers don't typically use smart cards
:: reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v SCRemoveOption /t REG_DWORD /d 2 /f
::
:: Restrict privileged local admin tokens being used from network 
:: Commented out as it only works on domain-joined assets
:: reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f
::
:: Ensure outgoing secure channel traffic is encrytped
:: Commented out as it only works on domain-joined assets
:: reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v RequireSignOrSeal /t REG_DWORD /d 1 /f
::
:: Enforce LDAP client signing
:: Commented out as most consumers don't use LDAP auth
:: reg add "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" /v LDAPClientIntegrity /t REG_DWORD /d 1 /f
::
:: Prevent unauthenticated RPC connections
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" /v RestrictRemoteClients /t REG_DWORD /d 1 /f
::
::#######################################################################
:: References
::#######################################################################
::
:: LLMNR
:: https://www.blackhillsinfosec.com/how-to-disable-llmnr-why-you-want-to/
:: 
:: Windows Defender References
:: ASR Rules https://www.darkoperator.com/blog/2017/11/11/windows-defender-exploit-guard-asr-rules-for-office
:: ASR and Exploit Guard https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/attack-surface-reduction-exploit-guard
:: ASR Rules https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction
:: Easy methods to test rules https://demo.wd.microsoft.com/?ocid=cx-wddocs-testground
:: Resource on the rules and associated event IDs https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/event-views
:: Defender sandboxing https://cloudblogs.microsoft.com/microsoftsecure/2018/10/26/windows-defender-antivirus-can-now-run-in-a-sandbox/
:: Defender exploit protection https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/customize-exploit-protection
:: Application Guard https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-guard/install-wd-app-guard 
:: Defender cmdline https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/command-line-arguments-windows-defender-antivirus
::
:: General hardening references
:: LSA Protection https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn408187(v=ws.11)?redirectedfrom=MSDN
::
:: Microsoft Office References: 
:: Disable DDE https://gist.github.com/wdormann/732bb88d9b5dd5a66c9f1e1498f31a1b
:: Disable macros https://decentsecurity.com/block-office-macros/
::
:: Debloating
:: https://blog.danic.net/how-windows-10-pro-installs-unwanted-apps-candy-crush-and-how-you-stop-it/

:: Frameworks and benchmarks
:: STIG https://www.stigviewer.com/stig/windows_10/

:: After the HARD Setting, apply the SOFT settings
GOTO SOFT

:SOFT 
::#######################################################################
:: Soft Changes 
::#######################################################################
::
:: My Own Addition (Florian Roth)
:: Show extensions of known file types (makes double extensions like .doc.exe visible to the user)
REG.EXE ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v HideFileExt /t REG_DWORD /d 0 /f

:: Change file associations to protect against common ransomware attacks
:: Note that if you legitimately use these extensions, like .bat, you will now need to execute them manually from cmd or powershel
:: Alternatively, you can right-click on them and hit 'Run as Administrator' but ensure it's a script you want to run :) 
:: https://support.microsoft.com/en-us/help/883260/information-about-the-attachment-manager-in-microsoft-windows
:: ---------------------
ftype htafile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
ftype jsfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
ftype jsefile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"

::
:: Enable ASR rules in Win10 1903 ExploitGuard to mitigate Office malspam
:: Blocks Office childprocs, Office proc injection, Office win32 api calls & executable content creation
:: Note these only work when Defender is your primary AV
::
:: Block Office Child Process Creation 
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
:: Block Process Injection
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled
:: Block Office from creating executables
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled
:: Block executable content from email client and webmail
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
:: Block JavaScript or VBScript from launching downloaded executable content
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
:: Block Adobe Reader from creating child processes
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Enabled
:: Block persistence through WMI event subscription
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled

::
:: Enable and Configure Internet Browser Settings
::
:: Enable SmartScreen for Edge
reg add "HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f
:: Enable Notifications in IE when a site attempts to install software
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v SafeForScripting /t REG_DWORD /d 0 /f

::#######################################################################
:: Enable and Configure Microsoft Office Security Settings
::#######################################################################
::
:: Harden all version of MS Office itself against common malspam attacks
:: Disables Macros, enables ProtectedView
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
:: Harden all version of MS Office itself against DDE malspam attacks
:: Disables Macros, enables ProtectedView
:: ---------------------
reg add "HKCU\Software\Microsoft\Office\14.0\Word\Options" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\14.0\Word\Options\WordMail" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\15.0\Word\Options" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\15.0\Word\Options\WordMail" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\16.0\Word\Options" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\16.0\Word\Options\WordMail" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f

::
:: Block Win32 binaries from making netconns when they shouldn't - specifically targeting native processes known to be abused by bad actors
:: ---------------------
:: Note: in hard mode we'll also make sure that the firewall is running
::       in softmode, we just add the rules - if the firewall is disabled, this has no (negative) effect
Netsh.exe advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\system32\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\system32\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\system32\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\system32\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\system32\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\system32\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any

GOTO EOF

:EOF
:: Other sections have been removed
ECHO Successfully applied harding script. The system is now less susceptible to phishing attacks.