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

- `delete` and `shadows` (vssadmin)
- `resize` and `shadowstorage` (vssadmin)
- `delete` and `shadowstorage` (vssadmin)
- `delete` and `shadowcopy` (wmic)
- `delete` and `catalog` and `-quiet` (wbadmin)
- `win32_shadowcopy` or element from a list of encoded commands (powershell)
- `recoveryenabled` (bcedit)
- `ignoreallfailures` (bcedit)

## Warning !!!

USE IT AT YOUR OWN RISK!

You won't be able to run commands that use the blacklisted commands on a raccinated machine anymore until your apply the uninstall patch `raccine-reg-patch-uninstall.reg`. This could break various backup solutions that run that specific command during their work. It will not only block that request but kills all processes in that tree including the backup solution and its invoking process.

If you have a solid security monitoring that logs all process executions, you could check your logs to see if `vssadmin.exe delete shadows` or `vssadmin.exe resize shadowstorage ...` is frequently or sporadically used for legitimate purposes in which case you should refrain from using Raccine.

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

## Installation

### Automatic

1. Download `Raccine.zip` from the [Release](https://github.com/Neo23x0/Raccine/releases/) section
2. Extract it
3. Run `raccine-installer.bat`

![Windows Batch Installer](https://raw.githubusercontent.com/Neo23x0/Raccine/main/images/batch-installer.png)

### Manual

1. Apply Registry Patch `raccine-reg-patch-vssadmin.reg` to intercept invocations of `vssadmin.exe`
2. Place `Raccine.exe` from the [release section](https://github.com/Neo23x0/Raccine/releases/) in the `PATH`, e.g. into `C:\Windows`

(For i386 architecture systems use `Raccine_x86.exe` and rename it to `Raccine.exe`)

### Wmic Addon (Optional)

About 10-30% of Ransomware samples use `wmic` to delete the local shadowcopies. However, `wmic` is used for administrative activity far more often than `vssadmin`. The output of wmic often gets processed by automated scripts. It is unknown how a proxied execution through Raccine affects these scripts and programs. We've removed all outputs for cases in which no malicious parameter combination gets detected, but who knows?

3. Apply the `raccine-reg-patch-wmic.reg` patch to intercept invocations of `wmic.exe`

![Kill Run](https://raw.githubusercontent.com/Neo23x0/Raccine/main/images/screen5.png)

### Wbadmin Addon (Optional)

Ransomware [often](https://www.google.com/search?q=%22wbadmin+delete+catalog+-quiet%22) uses the command `wbadmin delete catalog -quiet` to delete the backup catalog of the local computer. 

4. Apply the `raccine-reg-patch-wbadmin.reg` patch to intercept invocations of `wbadmin.exe`

## Uninstall 

1. Run `raccine-reg-patch-uninstall.reg` 
2. Remove `Raccine.exe` (optional)

## Logfile

A logfile with all interceptions and actions taken is written to `C:\ProgramData\Raccine_log.txt` 

![Log File](https://raw.githubusercontent.com/Neo23x0/Raccine/main/images/logfile.png)

## Screenshot

Run `raccine.exe` and watch the parent process tree die (screenshot of v0.1)

![Kill Run](https://raw.githubusercontent.com/Neo23x0/Raccine/main/images/screen1.png)

## Pivot

In case that the Ransomware that your're currently handling uses a certain process name, e.g. `taskdl.exe`, you could just change the `.reg` patch to intercept calls to that name and let Raccine kill all parent processes of the invoking process tree.

## Help Wanted

I'd like to extend Raccine but lack the C++ coding skills, especially o the Windows platform.

### ~~1. Allow Certain Vssadmin Executions~~

***implemented by Ollie Whitehouse in v0.2.0***

Since Raccine is registered as a debugger for `vssadmin.exe` the actual command line that starts raccine.exe looks like

```bash
raccine.exe vssadmin.exe ... [params]
```

![raccine as debugger](https://raw.githubusercontent.com/Neo23x0/Raccine/main/images/screen3.png)

If we were able to process the command line options and apply filters to them, we could provide the following features: 

- Only block the execution in cases in which the parameters contains `delete shadows`
- Allow all other executions by passing the original parameters to a newly created process of `vssadmin.exe` (transparent pass-through)

### 2. Whitelist Certain Parents

We could provide a config file that contains white-listed parents for `vssadmin.exe`. If such a parent is detected, it would also pass the parameters to a new process and skip killing the process tree.

### 3. Create Shim Instead of Image File Execution Options Hack

The solution is outlined in this [tweet](https://twitter.com/cyb3rops/status/1312982510746374144?s=20) and related [talk](https://www.youtube.com/watch?v=LOsesi3QkXY&feature=youtu.be).

![raccine as debugger](https://raw.githubusercontent.com/Neo23x0/Raccine/main/images/screen-tweet1.png)

## FAQs

### Why did it even kill explorer.exe during its run?

Since malware tends to inject into `explorer.exe`, we thought it would be a good idea to kill even `explorer.exe` in order to avoid malicious code performing other operations on the system. What happens in real world examples is that a user that executed the Ransomware process would loose its windows task bar and desktop, while other programs like Microsoft Word or Outlook would still be running and the user would be able to save his work and close the respective programs before calling the helpdesk or simpy reboot the system. An expericend user could bring up task manager using `CTRL+ALT+Del` and start a new `explorer.exe` or just log off.

![raccine as debugger](https://raw.githubusercontent.com/Neo23x0/Raccine/main/images/screen-explorer-injection.png)

## Other Info

The right pronounciation is "Rax-Een".

## Credits

- Florian Roth [@cyb3rops](https://twitter.com/cyb3rops)
- Ollie Whitehouse [@ollieatnccgroup](https://twitter.com/ollieatnccgroup)
- John Lambert [@JohnLaTwC](https://twitter.com/JohnLaTwC)
- Hilko Bengen [@_hillu_](https://twitter.com/_hillu_)
- Branislav Đalić [@LordOfThePies4](https://twitter.com/LordOfThePies4)
