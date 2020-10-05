// Raccine 
// A Simple Ransomware Vaccine
// https://github.com/Neo23x0/Raccine
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
#include <psapi.h>
#include <string>
#include <vector>
#include "RaccineMessageDLL/Message.h"

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

DWORD IntegrityLevel(HANDLE hProcess) {

    HANDLE hToken = INVALID_HANDLE_VALUE;
    DWORD dwIntegrityLevel = 0;
    PTOKEN_MANDATORY_LABEL pTIL;
    DWORD dwLengthNeeded = sizeof(pTIL);

    OpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
    
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLengthNeeded);
    pTIL = (PTOKEN_MANDATORY_LABEL) LocalAlloc(0, dwLengthNeeded);

    if (GetTokenInformation(hToken, TokenIntegrityLevel,
        pTIL, dwLengthNeeded, &dwLengthNeeded))
    {
        dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid,
            (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

        LocalFree(pTIL);

        if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
        {
            // Low Integrity
            return 1;
        }
        else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID &&
            dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
        {
            // Medium Integrity
            return 2;
        }
        else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID)
        {
            // High Integrity
            return 3;
        }
        else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
        {
            // System Integrity
            return 4;
        }
        else
        {
            return 0;
        }
    }
    else {
        return 0;
    }


    return 0;
}

BOOL isallowlisted(DWORD pid) {
    TCHAR allowlist[3][MAX_PATH] = { TEXT("wininit.exe"), TEXT("winlogon.exe"), TEXT("explorer.exe") };
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
                for (uint8_t i = 0; i < arraysize(allowlist); i++) {
        
                    if (_tcsicmp((TCHAR*)pe32.szExeFile, allowlist[i]) == 0 ) {                

                        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
                        if (hProcess != NULL)
                        {
                            wchar_t filePath[MAX_PATH];
                            if (GetModuleFileNameEx(hProcess, NULL, filePath, MAX_PATH))
                            {

                                DWORD dwInLevel = IntegrityLevel(hProcess);                              

                                // Are they in the Windows directory?
                                if (_tcsnicmp(filePath, TEXT("C:\\Windows\\System32\\"), _tcslen(TEXT("C:\\Windows\\System32\\"))) == 0) {
                                    
                                    // Is the process running as SYSTEM
                                    if (IntegrityLevel(hProcess) == 4) {
                                        CloseHandle(hProcess);
                                        return TRUE;
                                    }
                                    
                                }

                                // Are you explorer running in the Windows dir
                                if (_tcsnicmp(filePath, TEXT("C:\\Windows\\Explorer.exe"), _tcslen(TEXT("C:\\Windows\\Explorer.exe"))) == 0) {
                                    
                                    // Is the process running as MEDIUM (which Explorer does)
                                    if (IntegrityLevel(hProcess) == 2) {
                                        CloseHandle(hProcess);
                                        return TRUE;
                                    }
                                }
                            }
                            else {
                                CloseHandle(hProcess);
                            }
                        }
                    } // _tcsicmp
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

int _tmain(int argc, _TCHAR* argv[]) {

    DWORD pids[1024];
    uint8_t c = 0;
    DWORD pid = GetCurrentProcessId();

    setlocale(LC_ALL, "");

    bool bDelete = false;
    bool bShadow = false;
    bool bResize = false;
    bool bShadowStorage = false;
    bool bShadowCopy = false;

    // check for keywords in command line parameters
    for (DWORD iCount = 0; iCount < argc; iCount++)
    {
        if (_tcsicmp(TEXT("delete"), argv[iCount]) == 0) {
            bDelete = true;
        }
        else if (_tcsicmp(TEXT("shadows"), argv[iCount]) == 0) {
            bShadow = true;
        }
        else if (_tcsicmp(TEXT("shadowstorage"), argv[iCount]) == 0) {
            bShadowStorage = true;
        }
        else if (_tcsicmp(TEXT("resize"), argv[iCount]) == 0) {
            bResize = true;
        }
        else if (_tcsicmp(TEXT("shadowcopy"), argv[iCount]) ==0 ) {
            bShadowCopy = true;
        }
    }

    // OK this is not want we want 
    // we want to kill the process responsible
    if ((bDelete && bShadow) || (bResize && bShadowStorage) || (bDelete && bShadowCopy)) {

        printf("Raccine detected malicious activity\n");

        // Collect PIDs to kill
        while (true) {
            try {
                pid = getppid(pid);
                if (pid == 0) {
                    break;
                }
                if (!isallowlisted(pid)) {
                    printf("Collecting PID %d for a kill\n", pid);
                    pids[c] = pid;
                    c++;
                }
                else {
                    printf("Process with PID %d is on allowlist\n", pid);
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

        // Log an event
        HANDLE hReg = RegisterEventSource(NULL, TEXT("Raccine"));
        ReportEvent(hReg, EVENTLOG_INFORMATION_TYPE, RaccineAlert, Alert_1337, NULL, 0, 0, NULL, NULL);

        printf("Raccine v0.4.0 finished\n");
        std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    }
    //
    // Otherwise launch it
    //
    else {
        DEBUG_EVENT debugEvent = { 0 };
        std::wstring commandLineStr = TEXT("");

        for (int i = 1; i < argc; i++) commandLineStr.append(std::wstring(argv[i]).append(TEXT(" ")));

        STARTUPINFO info = { sizeof(info) };
        PROCESS_INFORMATION processInfo;

        if (CreateProcess(NULL, (LPWSTR)commandLineStr.c_str(), NULL, NULL, TRUE, DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &info, &processInfo))
        {
            DebugActiveProcessStop(processInfo.dwProcessId);

            WaitForSingleObject(processInfo.hProcess, INFINITE);
            CloseHandle(processInfo.hProcess);
            CloseHandle(processInfo.hThread);
        }
    }
    return 0;
}