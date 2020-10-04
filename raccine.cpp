//
//
//
//

#include <tchar.h>
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <chrono>
#include <thread>
#include <locale.h>
#include <string>
#include <vector>

#define arraysize(ar)  (sizeof(ar) / sizeof(ar[0]))

DWORD getppid(DWORD pid) {
    PROCESSENTRY32 pe32;
    HANDLE hSnapshot;
    DWORD ppid = 0;
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    __try {
        if(hSnapshot == INVALID_HANDLE_VALUE) __leave;
        ZeroMemory(&pe32, sizeof(pe32));
        pe32.dwSize = sizeof(pe32);
        if (!Process32First(hSnapshot, &pe32)) __leave;
        do {
            if (pe32.th32ProcessID == pid){
                ppid = pe32.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    __finally {
        if (hSnapshot != INVALID_HANDLE_VALUE) CloseHandle(hSnapshot);
    }
    return ppid;
}

BOOL isdenylisted(DWORD pid) {
    TCHAR denylist[3][MAX_PATH] = {TEXT("explorer.exe"), TEXT("wininit.exe"), TEXT("winlogon.exe")}; 
    PROCESSENTRY32 pe32;
    HANDLE hSnapshot;
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    __try {
        if(hSnapshot == INVALID_HANDLE_VALUE) __leave;
        ZeroMemory(&pe32, sizeof(pe32));
        pe32.dwSize = sizeof(pe32);
        if (!Process32First(hSnapshot, &pe32)) __leave;
        do {
            if (pe32.th32ProcessID == pid){
                for (uint8_t i = 0; i < arraysize(denylist); i++) {
                    if (!_tcscmp((TCHAR*)pe32.szExeFile, denylist[i])) {
                        return TRUE;
                    } 
                }
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    __finally {
        if (hSnapshot != INVALID_HANDLE_VALUE) CloseHandle(hSnapshot);
    }
    return FALSE;
}

BOOL killprocess(DWORD dwProcessId, UINT uExitCode) {
    DWORD dwDesiredAccess = PROCESS_TERMINATE;
    BOOL  bInheritHandle  = FALSE;
    HANDLE hProcess = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    if (hProcess == NULL)
        return FALSE;

    BOOL result = TerminateProcess(hProcess, uExitCode);
    CloseHandle(hProcess);
    return result;
}

int _tmain(int argc, _TCHAR* argv[])
{

    DWORD pids[1024];
    uint8_t c = 0;
    DWORD pid = GetCurrentProcessId();

    fprintf(stdout,"Raccine PID is %d\n", pid);

    setlocale(LC_ALL, "");

    bool bDelete = false;
    bool bShadow = false;

    // check if delete and shadow are in any of the
    // the arguments and in any combination
    for (DWORD iCount = 0; iCount < argc; iCount++)
    {
        if (_tcsicmp(TEXT("delete"), argv[iCount])) {
            bDelete = true;
        }
        else if (_tcsicmp(TEXT("shadow"), argv[iCount])) {
            bShadow = true;
        }
    }


    // OK this is not want we want 
    // we want to kill the process responsible
    if (bDelete && bShadow) {
        // Collect PIDs to kill
        while (true) {
            try {
                pid = getppid(pid);
                if (pid == 0) {
                    break;
                }
                if (!isdenylisted(pid)) {
                    printf("Collecting PID %d for a kill\n", pid);
                    pids[c] = pid;
                    c++;
                }
                else {
                    printf("Process with PID %d is on whitelist\n", pid);
                }
            }
            catch (...) {
                printf("Couldn't kill PID %d\n", pid);
                break;
            }
        }

        //std::this_thread::sleep_for(std::chrono::milliseconds(5000));
        // Loop over collected PIDs and try to kill the processes
        for (uint8_t i = c; i > 0; --i) {
            printf("Kill PID %d\n", pids[i - 1]);
            killprocess(pids[i - 1], 1);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    }
    //
    // Otherwise launch it
    //
    else {
        
        fprintf(stdout, "Raccine is allowing a launch\n");
        std::wstring commandLineStr = TEXT("");

        for (int i = 1; i < argc; i++) commandLineStr.append(std::wstring(argv[i]).append(TEXT(" ")));

        STARTUPINFO info = { sizeof(info) };
        PROCESS_INFORMATION processInfo;

        if (CreateProcess(NULL, (LPWSTR)commandLineStr.c_str(), NULL, NULL, TRUE, 0, NULL, NULL, &info, &processInfo))
        {
            WaitForSingleObject(processInfo.hProcess, INFINITE);
            CloseHandle(processInfo.hProcess);
            CloseHandle(processInfo.hThread);
        }

    }


    printf("Raccine v0.1.2 finished its cleanup.\n");

    return 0;
}