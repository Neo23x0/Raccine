#include    <windows.h>
#include    <tlhelp32.h>
#include    <stdio.h>
#include    <chrono>
#include    <thread>

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

BOOL iswhitelisted(DWORD pid) {
    char* whitelist[] = {"explorer.exe"}; 
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
                for (uint8_t i = 0; i < arraysize(whitelist); i++) {
                    if (!strcmp((char*)pe32.szExeFile, whitelist[i])) {
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

int main(){
    DWORD pids[1024];
    uint8_t c = 0;
    DWORD pid = GetCurrentProcessId();
    printf("Raccine PID is %d\n", pid);
    // Collect PIDs to kill
    while (true) {
        try {
            pid = getppid(pid);
            if (pid == 0) {
                break;
            }
            if (!iswhitelisted(pid)) {
                printf("Collecting PID %d for a kill\n", pid);
                pids[c] = pid;
                c++;
            } else {
                printf("Process with PID %d is on whitelist\n", pid);
            }
        } catch(...) {
            printf("Couldn't kill PID %d\n", pid);
            break;
        }
    }
    //std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    // Loop over collected PIDs and try to kill the processes
    for (uint8_t i = c; i > 0; --i) {
        printf("Kill PID %d\n", pids[i-1]);
        killprocess(pids[i-1], 1);
    }
    printf("Raccine finished its cleanup.\n", pid);
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    return 0;
}