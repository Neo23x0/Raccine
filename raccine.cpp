// Raccine 
// A Simple Ransomware Vaccine
// https://github.com/Neo23x0/Raccine
//
// Florian Roth, Ollie Whitehouse, Branislav Dalic, John Lambert
// with help of Hilko Bengen

#include <wchar.h>
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <locale.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <strsafe.h>

#include <shellapi.h>

#pragma comment(lib,"advapi32.lib")

// Version
#define VERSION "0.10.3"

// Log Config and Flags
BOOL g_fLogToEventLog = FALSE;
BOOL g_fLogOnly = FALSE;
#define RACCINE_REG_CONFIG  L"SOFTWARE\\Raccine"
#define RACCINE_REG_POICY_CONFIG  L"SOFTWARE\\Policies\\Raccine"
#define MAX_MESSAGE 1000
#define RACCINE_DEFAULT_EVENTID  1
#define RACCINE_EVENTID_MALICIOUS_ACTIVITY  2

#define RACCINE_DIRECTORY  L"%PROGRAMDATA%\\Raccine"
WCHAR g_wRaccineDirectory[MAX_PATH] = { 0 };  // ENV expanded RACCINE_DIRECTORY

// YARA Matching
WCHAR g_wYaraRulesDir[MAX_PATH] = { 0 };
LPWSTR* g_aszRuleFiles = { 0 };
int g_cRuleCount = 0;
#define YARA_INSTANCE  L"runyara.bat"
#define YARA_RESULTS_SUFFIX L".out"
#define TIMEOUT  1000*5

#define MAX_YARA_RULE_FILES 200
#define RACCINE_REG_CONFIG  L"SOFTWARE\\Raccine"
#define RACCINE_REG_POICY_CONFIG  L"SOFTWARE\\Policies\\Raccine"
#define RACCINE_YARA_RULES_PATH L"RulesDir"
#define MAX_MESSAGE 1000
#define RACCINE_DEFAULT_EVENTID  1
#define RACCINE_EVENTID_MALICIOUS_ACTIVITY  2


//
// By default it looks in %PROGRAMDATA%\Raccine, unless overridden by RulesDir in the registry
//

/// <summary>
/// Initialize the set of Yara rules. Look in the configured directory (which can be overridden in the registry).
/// </summary>
/// <returns></returns>
BOOL InitializeYaraRules()
{
    BOOL fRetVal = FALSE;
    WCHAR wYaraPattern[MAX_PATH] = { 0 };
    WIN32_FIND_DATA FindFileData = { 0 };
    HANDLE hFind = INVALID_HANDLE_VALUE;
    
    //wprintf(L"Checking dir: %s\n", g_wYaraRulesDir);
    if (FAILED(StringCchCat(wYaraPattern, ARRAYSIZE(wYaraPattern) - 1, g_wYaraRulesDir)))
        return FALSE;

    if (FAILED(StringCchCat(wYaraPattern, ARRAYSIZE(wYaraPattern) - 1, L"\\*.yar")))
        return FALSE;

    //allocate array to hold paths to yara rule files
    g_aszRuleFiles = (LPWSTR*)LocalAlloc(LPTR, MAX_YARA_RULE_FILES * sizeof LPWSTR);
    if (!g_aszRuleFiles)
        return FALSE;  

    hFind = FindFirstFile(wYaraPattern, &FindFileData);
    if (hFind != INVALID_HANDLE_VALUE)
    {
        do
        {
            DWORD nSize = MAX_PATH;
            LPWSTR szRulePath = (LPWSTR)LocalAlloc(LPTR, (nSize + 1) * sizeof WCHAR );
            if (!szRulePath)
                goto cleanup;

            //wprintf(L"The file found is %s\n", FindFileData.cFileName);
            StringCchPrintf(szRulePath, nSize, L"%s\\%s", g_wYaraRulesDir, FindFileData.cFileName);
            g_aszRuleFiles[g_cRuleCount++] = szRulePath;
            //wprintf(L"Rule count %d\n", g_cRuleCount);
            
        } while (FindNextFile(hFind, &FindFileData));
        fRetVal = TRUE;
    }

cleanup:
    if (hFind != INVALID_HANDLE_VALUE)
        FindClose(hFind);
    return fRetVal;
}

/// <summary>
/// This function tests the Yara rules in Raccine's config directory on the launched command line.
/// </summary>
/// <param name="szTestFile">The temp file containing the command line to test</param>
/// <param name="ppszYaraOutput">Output parameter.  A string containing the Yara match text. If not NULL, call LocalFree to release the memory</param>
/// <param name="lpCommandLine">The input command line</param>
/// <returns></returns>

BOOL TestYaraRulesOnFile(LPWSTR szTestFile, _Outptr_opt_ LPWSTR* ppszYaraOutput, LPWSTR lpCommandLine)
{
    BOOL fRetVal = FALSE;
    WCHAR wYaraCommandLine[1000] = { 0 };
    WCHAR wYaraOutputFile[MAX_PATH] = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFO si = { 0 };
    LPWSTR szFinalString = NULL;
    DWORD cchFinalStringMaxSize = 2000;

    //wprintf(L"Rule Count: %d\n", g_cRuleCount);
    for (int i = 0; i < g_cRuleCount; i++)
    {
        LPWSTR szYaraRule = g_aszRuleFiles[i];
        //wprintf(L"Running: %s\\%s %s %s\n", g_wRaccineDirectory, YARA_INSTANCE, szYaraRule, szTestFile);
        StringCchPrintf(wYaraCommandLine, ARRAYSIZE(wYaraCommandLine), L"%s\\%s %s %s", g_wRaccineDirectory, YARA_INSTANCE, szYaraRule, szTestFile);

        if (!CreateProcess(
            NULL,
            wYaraCommandLine,
            NULL,
            NULL,
            FALSE,
            0,
            NULL,
            NULL,
            &si,
            &pi
        ))
        {
            DWORD err = GetLastError();
            goto cleanup;
        }

        if (WaitForSingleObject(pi.hProcess, TIMEOUT) == WAIT_TIMEOUT)
        {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            goto cleanup;
        }

        if (SUCCEEDED(StringCchPrintf(wYaraOutputFile, ARRAYSIZE(wYaraOutputFile), L"%s%s", szTestFile, YARA_RESULTS_SUFFIX)))
        {
            HANDLE hOutputFile = CreateFile(wYaraOutputFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (hOutputFile != INVALID_HANDLE_VALUE)
            {
                DWORD dwSize = 0;
                DWORD dwHighSize = 0;
                dwSize = GetFileSize(
                    hOutputFile,
                    &dwHighSize
                );
                if (dwSize > 2)  //did we get a match?  allow for an empty newline or two . 
                {
                    fRetVal = TRUE;

                    if (!szFinalString)
                    {
                        szFinalString = (LPWSTR)LocalAlloc(LPTR, cchFinalStringMaxSize * sizeof WCHAR);
                    }
                    if (szFinalString)
                    {
                        LPSTR szYaraOutput = (LPSTR)LocalAlloc(LPTR, (dwSize + 1) * sizeof CHAR);
                        LPWSTR szYaraOutputWide = (LPWSTR)LocalAlloc(LPTR, (dwSize + 1) * sizeof WCHAR);
                        DWORD cbRead = 0;
                        if (szYaraOutput && szYaraOutputWide)
                        {
                            if (ReadFile(hOutputFile, szYaraOutput, dwSize, &cbRead, NULL))
                            {
                                if (MultiByteToWideChar(
                                    CP_ACP,
                                    0,
                                    szYaraOutput,
                                    -1,
                                    szYaraOutputWide,
                                    dwSize + 1
                                ))
                                {
                                    if (SUCCEEDED(StringCchCat(szFinalString, cchFinalStringMaxSize, L"Rule file: ")) &&
                                        SUCCEEDED(StringCchCat(szFinalString, cchFinalStringMaxSize, szYaraRule)) &&
                                        SUCCEEDED(StringCchCat(szFinalString, cchFinalStringMaxSize, L"\n")) &&
                                        SUCCEEDED(StringCchCat(szFinalString, cchFinalStringMaxSize, szYaraOutputWide)) &&
                                        SUCCEEDED(StringCchCat(szFinalString, cchFinalStringMaxSize, L"\n")) &&
                                        SUCCEEDED(StringCchCat(szFinalString, cchFinalStringMaxSize, L"Command line:\n")) &&
                                        SUCCEEDED(StringCchCat(szFinalString, cchFinalStringMaxSize, lpCommandLine)) &&
                                        SUCCEEDED(StringCchCat(szFinalString, cchFinalStringMaxSize, L"\n\n")))
                                    {
                                        *ppszYaraOutput = szFinalString;
                                    }
                                    LocalFree(szYaraOutputWide);
                                }
                            }
                        }
                        if (szYaraOutput)
                            LocalFree(szYaraOutput);
                    }
         
                }

                CloseHandle(hOutputFile);
            }

            DeleteFile(wYaraOutputFile);
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

cleanup:
    return fRetVal;
}

/// <summary>
/// Evaluate a set of yara rules on a command line
/// </summary>
/// <param name="lpCommandLine">The command line to test</param>
/// <param name="ppszYaraOutput">if non-NULL, an output string containing match results is written to this parameter. Use LocalFree to free the memory.</param>
/// <returns>TRUE if at least one match result was found</returns>
BOOL EvaluateYaraRules(LPWSTR lpCommandLine, _Outptr_opt_ LPWSTR* ppszYaraOutput)
{
    BOOL fRetVal = FALSE;
    WCHAR wTestFilename[MAX_PATH] = { 0 };
    size_t len = wcslen(lpCommandLine) + 1;
    HANDLE hTempFile = INVALID_HANDLE_VALUE;
    LPSTR lpAnsiCmdLine = (LPSTR)LocalAlloc(LPTR, len);
    if (!lpAnsiCmdLine)
    {
        return FALSE;
    }
    ExpandEnvironmentStrings(RACCINE_DIRECTORY, wTestFilename, ARRAYSIZE(wTestFilename) - 1);

    int c = GetTempFileName(wTestFilename, L"Raccine", 0, wTestFilename);
    if (c != 0)
    {
        //  Creates the new file to write to for the upper-case version.
        hTempFile = CreateFile(wTestFilename, // file name 
            GENERIC_WRITE,        // open for write 
            0,                    // do not share 
            NULL,                 // default security 
            CREATE_ALWAYS,        // overwrite existing
            FILE_ATTRIBUTE_NORMAL,// normal file 
            NULL);                // no template 
        if (hTempFile == INVALID_HANDLE_VALUE)
        {
            return FALSE;
        }
        DWORD dwWritten = 0;

        if (WideCharToMultiByte(
            CP_ACP,
            0,
            lpCommandLine,
            wcslen(lpCommandLine),
            lpAnsiCmdLine,
            len + 1,
            NULL,
            NULL
        ))
        {
            if (!WriteFile(hTempFile, lpAnsiCmdLine, lstrlenA(lpAnsiCmdLine) + 1, &dwWritten, NULL))
            {
                CloseHandle(hTempFile);
                goto cleanup;
            }
        }
        CloseHandle(hTempFile);

        fRetVal = TestYaraRulesOnFile(wTestFilename, ppszYaraOutput, lpCommandLine);

        DeleteFile(wTestFilename);
    }
    cleanup:
    return fRetVal;        
}

/// This function will optionally log messages to the eventlog
void WriteEventLogEntryWithId(LPWSTR  pszMessage, DWORD dwEventId)
{
    if (g_fLogToEventLog)
    {
        HANDLE hEventSource = NULL;
        LPCWSTR lpszStrings[2] = { NULL, NULL };

        hEventSource = RegisterEventSource(NULL, L"Raccine");
        if (hEventSource)
        {
            lpszStrings[0] = pszMessage;
            lpszStrings[1] = NULL;


            ReportEvent(hEventSource,  // Event log handle
                EVENTLOG_INFORMATION_TYPE,                 // Event type
                0,                     // Event category
                dwEventId,                     // Event identifier
                NULL,                  // No security identifier
                1,  // Size of lpszStrings array
                0,                     // No binary data
                lpszStrings,           // Array of strings
                NULL                   // No binary data
            );

            DeregisterEventSource(hEventSource);
        }
    }
    // always print the message to the console
    wprintf(pszMessage);
}

void WriteEventLogEntry(LPWSTR  pszMessage)
{
    WriteEventLogEntryWithId(pszMessage, RACCINE_DEFAULT_EVENTID);
}

// Get Parent Process ID
DWORD getParentPid(DWORD pid) {
    PROCESSENTRY32 pe32;
    HANDLE hSnapshot;
    DWORD ppid = 0;
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        goto out;
    }
    ZeroMemory(&pe32, sizeof(pe32));
    pe32.dwSize = sizeof(pe32);
    if (!Process32First(hSnapshot, &pe32)) {
        goto out;
    }
    do {
        if (pe32.th32ProcessID == pid) {
            ppid = pe32.th32ParentProcessID;
            break;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
out:
    return ppid;
}

// Get integrity level of process
DWORD getIntegrityLevel(HANDLE hProcess) {

    HANDLE hToken = INVALID_HANDLE_VALUE;
    DWORD dwIntegrityLevel = 0;
    PTOKEN_MANDATORY_LABEL pTIL;
    DWORD dwLengthNeeded = sizeof(pTIL);

    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
        return 0;
    
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLengthNeeded);
    pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, dwLengthNeeded);
    if (!pTIL) {
        return 0;
    }

    if (GetTokenInformation(hToken, TokenIntegrityLevel,
        pTIL, dwLengthNeeded, &dwLengthNeeded)) {
        dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid,
            (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

        LocalFree(pTIL);

        if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID) {
            // Low Integrity
            return 1;
        }
        else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID &&
            dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID) {
            // Medium Integrity
            return 2;
        }
        else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID &&
            dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID) {
            // High Integrity
            return 3;
        }
        else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) {
            // System Integrity
            return 4;
        }
        else {
            return 0;
        }
    }
    else {
        LocalFree(pTIL);
        return 0;
    }
    return 0;
}

// Get the image name of the process
std::wstring getImageName(DWORD pid) {
    PROCESSENTRY32 pe32 = { 0 };
    HANDLE hSnapshot;
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        goto out;
    }

    ZeroMemory(&pe32, sizeof(pe32));
    pe32.dwSize = sizeof(pe32);

    if (!Process32First(hSnapshot, &pe32)) {
        goto out;
    }

    do {
        if (pe32.th32ProcessID == pid) {
            std::wstring imageName = std::wstring((wchar_t*)pe32.szExeFile);
            return imageName;
        }
    } while (Process32Next(hSnapshot, &pe32));

out:
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        CloseHandle(hSnapshot);
    }
    return L"(unavailable)";
}


// Check if process is in allowed list
BOOL isallowlisted(DWORD pid) {
    WCHAR allowlist[3][MAX_PATH] = { L"wininit.exe", L"winlogon.exe", L"explorer.exe" };
    PROCESSENTRY32 pe32 = { 0 };
    HANDLE hSnapshot;
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        goto out;
    }

    ZeroMemory(&pe32, sizeof(pe32));
    pe32.dwSize = sizeof(pe32);

    if (!Process32First(hSnapshot, &pe32)) {
        goto out;
    }

    do {
        if (pe32.th32ProcessID == pid) {
            for (uint8_t i = 0; i < ARRAYSIZE(allowlist); i++) {

                if (_wcsicmp((wchar_t*)pe32.szExeFile, allowlist[i]) == 0) {

                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);

                    if (hProcess != NULL) {
                        wchar_t filePath[MAX_PATH] = { 0 };
                        if (GetModuleFileNameEx(hProcess, NULL, filePath, MAX_PATH)) {
                            DWORD dwInLevel = getIntegrityLevel(hProcess);

                            // Are they in the Windows directory?
                            if (_wcsnicmp(filePath, L"C:\\Windows\\System32\\", wcslen(L"C:\\Windows\\System32\\")) == 0) {

                                // Is the process running as SYSTEM
                                if (getIntegrityLevel(hProcess) == 4) {
                                    CloseHandle(hProcess);
                                    CloseHandle(hSnapshot);
                                    return TRUE;
                                }
                            }

                            // Are you explorer running in the Windows dir
                            if (_wcsnicmp(filePath, L"C:\\Windows\\Explorer.exe", wcslen(L"C:\\Windows\\Explorer.exe")) == 0) {

                                // Is the process running as MEDIUM (which Explorer does)
                                if (getIntegrityLevel(hProcess) == 2) {
                                    CloseHandle(hProcess);
                                    CloseHandle(hSnapshot);
                                    return TRUE;
                                }
                            }
                        }
                        else {
                            CloseHandle(hProcess);
                        }
                    }
                } // _wcsicmp
            }
            break;
        }
    } while (Process32Next(hSnapshot, &pe32));

out:
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        CloseHandle(hSnapshot);
    }
    return FALSE;
}

// Kill a process
BOOL killProcess(DWORD dwProcessId, UINT uExitCode) {
    DWORD dwDesiredAccess = PROCESS_TERMINATE;
    BOOL  bInheritHandle = FALSE;
    HANDLE hProcess = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    if (hProcess == NULL)
        return FALSE;

    BOOL result = TerminateProcess(hProcess, uExitCode);
    CloseHandle(hProcess);
    return result;
}

// Get timestamp
std::string getTimeStamp() {
    struct tm buf;
    auto time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now() - std::chrono::hours(24));
    localtime_s(&buf, &time);
    std::stringstream ss;
    ss << std::put_time(&buf, "%F %T");
    auto timestamp = ss.str();
    return timestamp;
}

// Fomat a log lines
std::wstring logFormat(const std::wstring cmdLine, const std::wstring comment = L"done") {
    std::string timeString = getTimeStamp();
    std::wstring timeStringW(timeString.begin(), timeString.end());
    std::wstring logLine = timeStringW + L" DETECTED_CMD: '" + cmdLine + L" COMMENT: " + comment + L"\n";
    return logLine;
}

std::wstring logFormatLine(const std::wstring line = L"") {
    std::string timeString = getTimeStamp();
    std::wstring timeStringW(timeString.begin(), timeString.end());
    std::wstring logLine = timeStringW + L" " + line + L"\n";
    return logLine;
}

// Format the activity log lines
std::wstring logFormatAction(int pid, const std::wstring imageName, const std::wstring cmdLine, const std::wstring comment = L"done") {
    std::string timeString = getTimeStamp();
    std::wstring timeStringW(timeString.begin(), timeString.end());
    std::wstring logLine = timeStringW + L" DETECTED_CMD: '" + cmdLine + L"' IMAGE: '" + imageName + L"' PID: " + std::to_wstring(pid) + L" ACTION: " + comment + L"\n";
    return logLine;
}

// Log to file
void logSend(const std::wstring logStr) {
    static FILE* logFile = 0;
    if (logFile == 0) 
    {
        errno_t err = _wfopen_s(&logFile, L"C:\\ProgramData\\Raccine\\Raccine_log.txt", L"at");
        if (err != 0) 
            err = _wfopen_s(&logFile, L"C:\\ProgramData\\Raccine\\Raccine_log.txt", L"wt");
            
        if (err != 0) {
            wprintf(L"\nCan not open C:\\ProgramData\\Raccine\\Raccine_log.txt for writing.\n");
            return;   // bail out if we can't log
        }
    }
    //transform(logStr.begin(), logStr.end(), logStr.begin(), ::tolower);
    if (logFile != 0)
    {
        fwprintf(logFile, L"%s", logStr.c_str());
        fflush(logFile);
        fclose(logFile);
        logFile = 0;
    }
}

//
//  Query for config in HKLM and HKLM\Software\Policies override by GPO
//
void InitializeLoggingSettings()
{
    // Registry Settings
    // Query for logging level. A value of 1 or more indicates to log key events to the event log
    // Query for logging only mode. A value of 1 or more indicates to suppress process kills

    StringCchCopy(g_wYaraRulesDir, ARRAYSIZE(g_wYaraRulesDir), g_wRaccineDirectory);

    const wchar_t* LoggingKeys[] = { RACCINE_REG_CONFIG , RACCINE_REG_POICY_CONFIG };

    HKEY hKey = NULL;
    for (int i = 0; i < ARRAYSIZE(LoggingKeys); i++)
    {
        if (ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE, LoggingKeys[i], 0, KEY_READ, &hKey))
        {
            // Log Level
            DWORD dwLoggingLevel = 0;
            DWORD cbData = sizeof(dwLoggingLevel);
            if (ERROR_SUCCESS == RegQueryValueExW(hKey, L"Logging", NULL, NULL, (LPBYTE)&dwLoggingLevel, &cbData))
            {
                if (dwLoggingLevel > 0)
                {
                    g_fLogToEventLog = TRUE;
                }
            }
            // Log Only
            DWORD dwLoggingOnly = 0;
            DWORD cbDataLO = sizeof(dwLoggingOnly);
            if (ERROR_SUCCESS == RegQueryValueExW(hKey, L"LogOnly", NULL, NULL, (LPBYTE)&dwLoggingOnly, &cbDataLO))
            {
                if (dwLoggingOnly > 0)
                {
                    g_fLogOnly = TRUE;
                }
            }
            // Yara rules dir
            cbData = sizeof(g_wYaraRulesDir);
            if (ERROR_SUCCESS == RegQueryValueExW(hKey, RACCINE_YARA_RULES_PATH, NULL, NULL, (LPBYTE)g_wYaraRulesDir, &cbData))
            {
                ;
            }
            RegCloseKey(hKey);
        }
    }
}


int wmain(int argc, WCHAR* argv[]) {

    DWORD pids[1024] = { 0 };
    uint8_t c = 0;
    DWORD pid = GetCurrentProcessId();

    setlocale(LC_ALL, "");

    // Block marker
    bool bBlock = false;

    // Main programs to monitor
    bool bVssadmin = false;
    bool bWmic = false;
    bool bWbadmin = false;
    bool bcdEdit = false;
    bool bPowerShell = false;
    bool bDiskShadow = false;

    // Command line params
    bool bDelete = false;
    bool bShadows = false;
    bool bResize = false;
    bool bShadowStorage = false;
    bool bShadowCopy = false;
    bool bCatalog = false;
    bool bQuiet = false;
    bool bRecoveryEnabled = false;
    bool bIgnoreallFailures = false;
    bool bwin32ShadowCopy = false;
    bool bEncodedCommand = false;

    // Encoded Command List (Base64)
    WCHAR encodedCommands[10][9] = { L"JAB", L"SQBFAF", L"SQBuAH", L"SUVYI", L"cwBhA", L"aWV4I", L"aQBlAHgA", L"cwB", L"IAA", L"UWB" };

    // Log
    std::wstring sCommandLine = L"";
    std::wstring sListLogs(L"");
    WCHAR wMessage[MAX_MESSAGE] = { 0 };

    // Append all original command line parameters to a string for later log messages
    for (int i = 1; i < argc; i++) sCommandLine.append(std::wstring(argv[i]).append(L" "));

    if (argc > 1)
    {
        // Check for invoked program 
        if ((_wcsicmp(L"vssadmin.exe", argv[1]) == 0) ||
            (_wcsicmp(L"vssadmin", argv[1]) == 0)) {
            bVssadmin = true;
        }
        else if ((_wcsicmp(L"wmic.exe", argv[1]) == 0) ||
            (_wcsicmp(L"wmic", argv[1]) == 0)) {
            bWmic = true;
        }
        else if ((_wcsicmp(L"wbadmin.exe", argv[1]) == 0) ||
            (_wcsicmp(L"wbadmin", argv[1]) == 0)) {
            bWbadmin = true;
        }
        else if ((_wcsicmp(L"bcdedit.exe", argv[1]) == 0) ||
            (_wcsicmp(L"bcdedit", argv[1]) == 0)) {
            bcdEdit = true;
        }
        else if ((_wcsicmp(L"powershell.exe", argv[1]) == 0) ||
            (_wcsicmp(L"powershell", argv[1]) == 0)) {
            bPowerShell = true;
        }
        else if ((_wcsicmp(L"diskshadow.exe", argv[1]) == 0) ||
            (_wcsicmp(L"diskshadow", argv[1]) == 0)) {
            bDiskShadow = true;
        }
    }

    InitializeLoggingSettings();

    ExpandEnvironmentStrings(RACCINE_DIRECTORY, g_wRaccineDirectory, ARRAYSIZE(g_wRaccineDirectory) - 1);

    // YARA
    if (!InitializeYaraRules())
    {
        wprintf(L"Fatal error during InitializeYaraRules(). Yara rules will not be used.");
    }

    LPWSTR szYaraOutput = NULL;  // if assigned, call LocalFree on it.
    BOOL fYaraRuleMatched = EvaluateYaraRules((LPWSTR)sCommandLine.c_str(), &szYaraOutput);
    if (fYaraRuleMatched)
    {
        bBlock = true;
    }

    // Check for keywords in command line parameters
    for (int iCount = 1; iCount < argc; iCount++) {

        // Convert wchar to wide string so we can perform contains/find command
        wchar_t* convertedCh = argv[iCount];
        wchar_t* convertedChOrig = argv[iCount];    // original parameter (no tolower)
        wchar_t* convertedChPrev = argv[iCount - 1];  // previous parameter
        // Convert them to wide strings
        std::wstring convertedArg(convertedCh);
        std::wstring convertedArgOrig(convertedChOrig);
        std::wstring convertedArgPrev(convertedChPrev);

        // Convert args to lowercase for case-insensitive comparisons
        transform(convertedArg.begin(), convertedArg.end(), convertedArg.begin(), ::tolower);
        transform(convertedArgPrev.begin(), convertedArgPrev.end(), convertedArgPrev.begin(), ::tolower);

        // Simple flag checks
        if (_wcsicmp(L"delete", argv[iCount]) == 0) {
            bDelete = true;
        }
        else if (_wcsicmp(L"shadows", argv[iCount]) == 0) {
            bShadows = true;
        }
        else if (_wcsicmp(L"shadowstorage", argv[iCount]) == 0) {
            bShadowStorage = true;
        }
        else if (_wcsicmp(L"resize", argv[iCount]) == 0) {
            bResize = true;
        }
        else if (_wcsicmp(L"shadowcopy", argv[iCount]) == 0) {
            bShadowCopy = true;
        }
        else if (_wcsicmp(L"catalog", argv[iCount]) == 0) {
            bCatalog = true;
        }
        else if (_wcsicmp(L"-quiet", argv[iCount]) == 0 || _wcsicmp(L"/quiet", argv[iCount]) == 0) {
            bQuiet = true;
        }
        else if (_wcsicmp(L"recoveryenabled", argv[iCount]) == 0) {
            bRecoveryEnabled = true;
        }
        else if (_wcsicmp(L"ignoreallfailures", argv[iCount]) == 0) {
            bIgnoreallFailures = true;
        }
        else if (convertedArg.find(L"win32_shadowcopy") != std::string::npos) {
            bwin32ShadowCopy = true;
        }
        // Special comparison of current argument with previous argument
        // allows to check for e.g. -encodedCommand JABbaTheHuttandotherBase64characters
        else if (convertedArgPrev.find(L"-e") != std::string::npos || convertedArgPrev.find(L"/e") != std::string::npos) {
            for (uint8_t i = 0; i < ARRAYSIZE(encodedCommands); i++) {
                if (convertedArgOrig.find(encodedCommands[i]) != std::string::npos) {
                    bEncodedCommand = true;
                }
            }
        }
    }

    // Check all combinations (our blocklist)
    if ((bVssadmin && bDelete && bShadows) ||             // vssadmin.exe
        (bVssadmin && bDelete && bShadowStorage) ||      // vssadmin.exe
        (bVssadmin && bResize && bShadowStorage) ||      // vssadmin.exe
        (bWmic && bDelete && bShadowCopy) ||             // wmic.exe
        (bWbadmin && bDelete && bCatalog && bQuiet) || 	 // wbadmin.exe 
        (bcdEdit && bIgnoreallFailures) ||               // bcdedit.exe
        (bcdEdit && bRecoveryEnabled) ||                 // bcdedit.exe
        (bDiskShadow && bDelete && bShadows) ||          // diskshadow.exe
        (bPowerShell && bwin32ShadowCopy) ||             // powershell.exe
        (bPowerShell && bEncodedCommand) ||              // powershell.exe
        (bDiskShadow && bDelete && bShadows)) {          // diskshadow.exe

        // Activate blocking
        bBlock = TRUE;
    }

    // If activity that should be block has been registered (always log)
    if (bBlock) {
        // Log to the windows Eventlog
        LPCWSTR lpMessage = sCommandLine.c_str();
        if (!g_fLogOnly) {
            // Eventlog
            StringCchPrintf(wMessage, ARRAYSIZE(wMessage), L"Raccine detected malicious activity:\n%s\n", lpMessage);
            // Log to the text log file
            sListLogs.append(logFormat(sCommandLine, L"Raccine detected malicious activity"));
        }
        else {
            // Eventlog
            StringCchPrintf(wMessage, ARRAYSIZE(wMessage), L"Raccine detected malicious activity:\n%s\n(simulation mode)", lpMessage);
            // Log to the text log file
            sListLogs.append(logFormat(sCommandLine, L"Raccine detected malicious activity (simulation mode)"));
        }
        if (fYaraRuleMatched)
        {
            if (szYaraOutput != NULL)
            {

                StringCchPrintf(wMessage, ARRAYSIZE(wMessage), L"\r\nYara matches:\r\n%s", szYaraOutput);
                WriteEventLogEntryWithId((LPWSTR)wMessage, RACCINE_EVENTID_MALICIOUS_ACTIVITY);
                sListLogs.append(logFormatLine(szYaraOutput));
                sListLogs.append(L"\r\n");

                LocalFree(szYaraOutput);
                szYaraOutput = NULL;
            }
        }
        WriteEventLogEntryWithId((LPWSTR)wMessage, RACCINE_EVENTID_MALICIOUS_ACTIVITY);
    }

    // If block and not simulation mode
    if (bBlock && !g_fLogOnly) {
        // Collect PIDs to kill
        while (c < 1024) {
            pid = getParentPid(pid);
            std::wstring imageName = L"(unavailable)";
            imageName = getImageName(pid);
            if (pid == 0) {
                break;
            }     
            if (!isallowlisted(pid)) {
                wprintf(L"\nCollecting IMAGE %s with PID %d for a kill\n", imageName.c_str(), pid);
                pids[c] = pid;
                c++;
            }
            else {
                wprintf(L"\nProcess IMAGE %s with PID %d is on allowlist\n", imageName.c_str(), pid);
                sListLogs.append(logFormatAction(pid, imageName, sCommandLine, L"Whitelisted"));
            }
        }

        // Loop over collected PIDs and try to kill the processes
        for (uint8_t i = c; i > 0; --i) {
            std::wstring imageName = L"(unavailable)";
            imageName = getImageName(pids[i - 1]);
            // If no simulation flag is set
            if (!g_fLogOnly) {
                // Kill
                wprintf(L"Kill process IMAGE %s with PID %d\n", imageName.c_str(), pids[i - 1]);
                killProcess(pids[i - 1], 1);
                sListLogs.append(logFormatAction(pids[i - 1], imageName, sCommandLine, L"Terminated"));
            }
            else {
                // Simulated kill
                wprintf(L"Simulated Kill IMAGE %s with PID %d\n", imageName.c_str(), pids[i - 1]);
                sListLogs.append(logFormatAction(pids[i - 1], imageName, sCommandLine, L"Terminated (Simulated)"));
            }
        }
        // Finish message
        printf("\nRaccine v%s finished\n", VERSION);
        Sleep(5000);
    }
    
    // Otherwise launch the process with its original parameters
    // Conditions:
    // a.) not block or
    // b.) simulation mode
    if ( !bBlock || g_fLogOnly ) {
        DEBUG_EVENT debugEvent = { 0 };
        std::wstring sCommandLineStr = L"";

        for (int i = 1; i < argc; i++) sCommandLineStr.append(std::wstring(argv[i]).append(L" "));

        STARTUPINFO info = { sizeof(info) };
        PROCESS_INFORMATION processInfo = { 0 };

        if (CreateProcess(NULL, (LPWSTR)sCommandLineStr.c_str(), NULL, NULL, TRUE, DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &info, &processInfo))
        {
            DebugActiveProcessStop(processInfo.dwProcessId);
            WaitForSingleObject(processInfo.hProcess, INFINITE);
            CloseHandle(processInfo.hProcess);
            CloseHandle(processInfo.hThread);
        }
    }

    // Log events
    logSend(sListLogs);

    return 0;
}
