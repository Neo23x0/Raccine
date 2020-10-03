# Raccine

A Simple Ransomware Vaccine

## How it works

We register a debugger for `vssadmin.exe` which is our compiled `raccine.exe`. Raccine is a binary, that first collects all PIDs of the parent processes and then tries to kill all parent processes. I've whitelisted `explorer.exe` in order to avoid unwanted problems with the Windows desktop. I don't know if this was a good idea.  

Avantages:

- The method is rather generic
- We don't have to replace a system file (`vssadmin.exe`), which could lead to integrity problems and could break our raccination on each patch day 
- The changes are easy to undo

Disadvantages / Blind Spots:

- The legitimate use of `vssadmin.exe` isn't possble anymore
- It even kills the processes that tried to invoke `vssadmin.exe`, which could be a backup process
- This won't catch methods in which the malicious process isn't one of the processes in the tree that has invoked `vssadmin.exe` (e.g. via `schtasks`)

## Warning

You won't be able to run `vssadmin.exe` on this system anymore until your apply the uninstall patch `raccine-reg-patch-uninstall.reg`.

## Installation

1. Apply Registry Patch `raccine-reg-patch.reg`
2. Place `raccine.exe` in the `PATH`, e.g. into `C:\Windows`

## Screenshot

Run `raccine.exe` and watch the parent process tree die. 

![Kill Run](https://raw.githubusercontent.com/Neo23x0/Raccine/main/images/screen1.png)
