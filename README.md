# Raccine

A Simple Ransomware Vaccine

## Why

We see ransomware delete all shadow copies using `vssadmin` pretty often. What if we could just intercept that request and kill the invoking process? Let's try to create a simple vaccine.

![Ransomware Process Tree](https://raw.githubusercontent.com/Neo23x0/Raccine/main/images/screen2.png)

## How it works

We [register a debugger](https://attack.mitre.org/techniques/T1546/012/) for `vssadmin.exe` which is our compiled `raccine.exe`. Raccine is a binary, that first collects all PIDs of the parent processes and then tries to kill all parent processes. I've whitelisted `explorer.exe` in order to avoid unwanted problems with the Windows desktop. I don't know if this was a good idea.  

Avantages:

- The method is rather generic
- We don't have to replace a system file (`vssadmin.exe`), which could lead to integrity problems and could break our raccination on each patch day 
- The changes are easy to undo

Disadvantages / Blind Spots:

- The legitimate use of `vssadmin.exe` isn't possble anymore
- It even kills the processes that tried to invoke `vssadmin.exe`, which could be a backup process
- This won't catch methods in which the malicious process isn't one of the processes in the tree that has invoked `vssadmin.exe` (e.g. via `schtasks`)

Note: If you have a solid security monitoring that logs all process executions, you could check your logs to see if `vssadmin.exe` is frequently or sporadically used for legitimate purposes and refrain from using Raccine.  

## Pivot

In case that the Ransomware that your're currently handling uses a certain process name, e.g. `taskdl.exe`, you could just change the `.reg` patch to intercept calls to that name and let Raccine kill all parent processes of the invoking process tree.

## Warning

You won't be able to run `vssadmin.exe` on a raccinated machine anymore until your apply the uninstall patch `raccine-reg-patch-uninstall.reg`.

## Installation

1. Apply Registry Patch `raccine-reg-patch.reg`
2. Place `raccine.exe` from the [release section](https://github.com/Neo23x0/Raccine/releases/) in the `PATH`, e.g. into `C:\Windows`

## Screenshot

Run `raccine.exe` and watch the parent process tree die. 

![Kill Run](https://raw.githubusercontent.com/Neo23x0/Raccine/main/images/screen1.png)
