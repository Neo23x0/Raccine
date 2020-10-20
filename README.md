![Raccine](https://raw.githubusercontent.com/Neo23x0/Raccine/main/images/raccine_logo.png)

# Raccine

A Simple Ransomware Protection 

## Why

We see ransomware delete all shadow copies using `vssadmin` pretty often. What if we could just intercept that request and kill the invoking process? Let's try to create a simple vaccine.

![Ransomware Process Tree](https://raw.githubusercontent.com/Neo23x0/Raccine/main/images/screen4.png)

## How it works

We [register a debugger](https://attack.mitre.org/techniques/T1546/012/) for `vssadmin.exe` (and `wmic.exe`), which is our compiled `raccine.exe`. Raccine is a binary, that first collects all PIDs of the parent processes and then tries to kill all parent processes. 

Avantages:

- The method is rather generic
- We don't have to replace a system file (`vssadmin.exe` or `wmic.exe`), which could lead to integrity problems and could break our raccination on each patch day 
- The changes are easy to undo
- Should work on all Windows versions from Windows 2000 onwards
- No running executable or additional service required (agent-less)

Disadvantages / Blind Spots:

- The legitimate use of `vssadmin.exe delete shadows` (or any other blacklisted combination) isn't possible anymore
- It even kills the processes that tried to invoke `vssadmin.exe delete shadows`, which could be a backup process
- This won't catch methods in which the malicious process isn't one of the processes in the tree that has invoked `vssadmin.exe` (e.g. via `schtasks`)

### The Process

1. Invocation of `vssadmin.exe` (and `wmic.exe`) gets intercepted and passed to `raccine.exe` as debugger (`vssadmin.exe delete shadows` becomes `raccine.xe vssadmin.exe delete shadows`)
2. We then process the command line arguments and look for malicious combinations. 
3. If no malicious combination could be found, we create a new process with the original command line parameters. 
4. If a malicious combination could be found, we collect all PIDs of parent processes and the start killing them (this should be the malware processes as shown in the screenshots above). Raccine shows a command line window with the killed PIDs for 5 seconds and then exits itself. 

Malicious combinations:

- `delete` and `shadows` (vssadmin, diskshadow)
- `resize` and `shadowstorage` (vssadmin)
- `delete` and `shadowstorage` (vssadmin)
- `delete` and `shadowcopy` (wmic)
- `delete` and `catalog` and `-quiet` (wbadmin)
- `win32_shadowcopy` or element from a list of encoded commands (powershell)
- `recoveryenabled` (bcedit)
- `ignoreallfailures` (bcedit)

Powershell list of encoded commands: `JAB`, `SQBFAF`, `SQBuAH`, `SUVYI`, `cwBhA`, `aWV4I`, `aQBlAHgA`

## Example

Emotet without Raccine - [Link](https://app.any.run/tasks/b12f8ee2-f6cc-4571-bcc2-51e34c19941f/)

![Emotet wihtout Raccine](https://raw.githubusercontent.com/Neo23x0/Raccine/main/images/emotet-wo-raccine.png)

Emotet with Raccine - [Link](https://app.any.run/tasks/057ff7f5-43c1-4e51-93c3-a702c6fb0d75/) (ignore the process activity that is related to the Raccine installation)

![Emotet wihtout Raccine](https://raw.githubusercontent.com/Neo23x0/Raccine/main/images/emotet-with-raccine.png)

The infection gets nipped in the bud. 

## Warning !!!

USE IT AT YOUR OWN RISK!

You won't be able to run commands that use the blacklisted commands on a raccinated machine anymore until your apply the uninstall patch `raccine-reg-patch-uninstall.reg`. This could break various backup solutions that run that specific command during their work. It will not only block that request but kills all processes in that tree including the backup solution and its invoking process.

If you have a solid security monitoring that logs all process executions, you could check your logs to see if `vssadmin.exe delete shadows`, `vssadmin.exe resize shadowstorage ...` or the other blocked command lines are frequently or sporadically used for legitimate purposes in which case you should refrain from using Raccine.

## Version History

- 0.1.0 - Initial version that intercepted & blocked all vssadmin.exe executions
- 0.2.0 - Version that blocks only vssadmin.exe executions that contain `delete` and `shadows` in their command line and otherwise pass all parameters to a new process that invokes vssadmin with its original parameters
- 0.2.1 - Removed `explorer.exe` from the whitelist
- 0.3.0 - Supports the `wmic` method calling `delete shadowcopy`, no outputs for whitelisted process starts (avoids problems with wmic output processing)
- 0.4.0 - Supports logging to the Windows Eventlog for each blocked attempt, looks for more malicious parameter combinations
- 0.4.1 - Statically linked binaries
- 0.4.2 - Bugfixes provided by John Lambert
- 0.5.0 - Removed Eventlog logging (basic info was unnecessary; cuased higher complexity; can be achieved by process creation logging as well), support for wbadmin filtering
- 0.5.1 - Improvements by @JohnLaTwC
- 0.5.2 - Additional check for `delete shadowstorage` by @JohnLaTwC, code review by @_hillu, application icon 
- 0.5.3 - Batch installer 
- 0.6.0 - Additional checks for `bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures` and `bcdedit.exe /set {default} recoveryenabled no`
- 0.7.0 - Additional checks for `powershell.exe` and `win32_shadowcopy` or a list of encoded commands
- 0.7.1 - Improvements by @JohnLaTwC
- 0.7.2 - Using abolsute paths in registry patches
- 0.8.0 - Creates a log file with all intercepted requests and actions performed `C:\ProgramData\Raccine_log.txt`
- 0.9.0 - Logs to Windows Eventlog by @JohnLaTwC
- 0.10.0 - Simulation mode only
- 0.10.1 - Fix for Simulation mode
- 0.10.2 - Includes `diskshadow.exe delete shadows` command

## Installation

### Automatic Installation

1. Download `Raccine.zip` from the [Release](https://github.com/Neo23x0/Raccine/releases/) section
2. Extract it
3. Run `raccine-installer.bat`

![Windows Batch Installer](https://raw.githubusercontent.com/Neo23x0/Raccine/main/images/raccine-installer.png)

The batch installer includes an "uninstall" option.

### Manual Installation

1. Apply Registry Patch `raccine-reg-patch-vssadmin.reg` to intercept invocations of `vssadmin.exe`
2. Apply all other registry patches of applications that you'd like to intercept
3. Place `Raccine.exe` from the [release section](https://github.com/Neo23x0/Raccine/releases/) into `C:\Windows`
4. Create a folder `%ProgramData%\Raccine` for the log file
5. Run the following command to register Raccine as Eventlog source and set logging to enabled

```bat
eventcreate.exe /L Application /T Information /id 1 /so Raccine /d "Raccine event message"
eventcreate.exe /L Application /T Information /id 2 /so Raccine /d "Raccine event message"
REG.EXE ADD HKCU\Software\Raccine /v Logging /t REG_DWORD /d 2 /F
```

(For systems with i386 architecture use `Raccine_x86.exe` and rename it to `Raccine.exe`)

### Manual Uninstall 

1. Run `raccine-reg-patch-uninstall.reg` 
2. Remove `Raccine.exe` from the `C:\Windows` folder
3. Run `REG.EXE DELETE HKCU\Software\Raccine /F`

### Upgrade

We recommend an uninstall and reinstall to upgrade. An uninstall removes all registry keys with configurations. 

## Deploy Configuration via GPO

The folder `GPO` includes `Raccine.ADMX` and `Raccine.ADML`. In deployment the `Raccine.ADMX` file goes in `C:\Windows\PolicyDefinitions`. The accompanying `Raccine.ADML` files goes in `C:\Windows\PolicyDefinitions\en-US`. 

To use: Open `GPEDIT.MSC` > Computer Configuration > Administrative Templates > System > Raccine

After configuring the changes, you may need to bump gpo by running `gpupdate.exe`.

## Logfile

A logfile with all interceptions and actions taken is written to `C:\ProgramData\Raccine_log.txt` 

![Log File](https://raw.githubusercontent.com/Neo23x0/Raccine/main/images/logfile.png)

## Windows Eventlog

An entry is generated by every blocking event in the `Application` eventlog. 

![Eventlog](https://raw.githubusercontent.com/Neo23x0/Raccine/main/images/eventlog2.png)

## Simulation Mode

Since version 0.10.0, Raccine can be installed in "simulation mode", which activates all triggers, logs all actions but doesn't kill anything. This mode should be used in environments in which backup solutions or other legitimate software for a reasonable amount of time to check if Raccine would interfere with other software. The idea is to install Raccine in simulation mode, let it log for a week or month and then check the logs to see if it would have blocked legitimate software used in the organisation. 

![Kill Run](https://raw.githubusercontent.com/Neo23x0/Raccine/main/images/raccine-simulation.png)

## Screenshot

Run `raccine.exe` and watch the parent process tree die (screenshot of v0.1)

![Kill Run](https://raw.githubusercontent.com/Neo23x0/Raccine/main/images/screen1.png)

## Pivot

In case that the Ransomware that your're currently handling uses a certain process name, e.g. `taskdl.exe`, you could just change the `.reg` patch to intercept calls to that name and let Raccine kill all parent processes of the invoking process tree.

## Help Wanted

I'd like to extend Raccine but lack the C++ coding skills, especially o the Windows platform.

1. Show process image name and not just PID for killed processes
2. Add (optional) message box to indicate a blocked program for the working user
3. Extend coverage according to [this](https://github.com/Neo23x0/sigma/blob/master/rules/windows/process_creation/win_office_shell.yml) sigma rule comparing a list of child process names with their parents' to block many office droppers
4. Add MD5/SHA1/SHA256 hash values to log (I fear the OpenSSl ... maybe we don't include a hash)

## Other Info

The right pronounciation is "Rax-Een".

## Credits

- Florian Roth [@cyb3rops](https://twitter.com/cyb3rops)
- Ollie Whitehouse [@ollieatnccgroup](https://twitter.com/ollieatnccgroup)
- John Lambert [@JohnLaTwC](https://twitter.com/JohnLaTwC)
- Branislav Đalić [@LordOfThePies4](https://twitter.com/LordOfThePies4)
- Hilko Bengen [@_hillu_](https://twitter.com/_hillu_)
