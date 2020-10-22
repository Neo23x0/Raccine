// Raccine 
// A Simple Ransomware Vaccine
// https://github.com/Neo23x0/Raccine
//
// Florian Roth, Ollie Whitehouse, Branislav Djalic, John Lambert
// with help of Hilko Bengen

#include <cwchar>
#include <Windows.h>
#include <TlHelp32.h>
#include <cstdio>
#include <cstring>
#include <clocale>
#include <Psapi.h>
#include <string>
#include <array>
#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <strsafe.h>

#include "HandleWrapper.h"
#include "Utils.h"

#pragma comment(lib,"advapi32.lib")

// Version
#define VERSION "1.0 BETA"

// Log Config and Flags
BOOL g_fLogOnly = FALSE;
BOOL g_fShowGui = FALSE;
#define RACCINE_REG_CONFIG  L"SOFTWARE\\Raccine"
#define RACCINE_REG_POICY_CONFIG  L"SOFTWARE\\Policies\\Raccine"
constexpr UINT MAX_MESSAGE = 1000;
#define RACCINE_DEFAULT_EVENTID  1
#define RACCINE_EVENTID_MALICIOUS_ACTIVITY  2

#define RACCINE_DATA_DIRECTORY  L"%PROGRAMDATA%\\Raccine"
#define RACCINE_PROGRAM_DIRECTORY  L"%PROGRAMFILES%\\Raccine"
WCHAR g_wRaccineDataDirectory[MAX_PATH] = { 0 };  // ENV expanded RACCINE_DATA_DIRECTORY
WCHAR g_wRaccineProgramDirectory[MAX_PATH] = { 0 };  // ENV expanded RACCINE_PROGRAM_DIRECTORY

// YARA Matching
WCHAR g_wYaraRulesDir[MAX_PATH] = { 0 };
LPWSTR* g_aszRuleFiles = { 0 };
int g_cRuleCount = 0;
#define YARA_INSTANCE  L"runyara.bat"
#define YARA_RESULTS_SUFFIX L".out"
constexpr UINT TIMEOUT = 5000;

constexpr UINT MAX_YARA_RULE_FILES = 200;
#define RACCINE_REG_CONFIG  L"SOFTWARE\\Raccine"
#define RACCINE_REG_POICY_CONFIG  L"SOFTWARE\\Policies\\Raccine"
#define RACCINE_YARA_RULES_PATH L"RulesDir"
#define RACCINE_DEFAULT_EVENTID  1
#define RACCINE_EVENTID_MALICIOUS_ACTIVITY  2

enum class Integrity
{
    Error = 0, // Indicates integrity level could not be found
    Low = 1,
    Medium = 2,
    High = 3,
    System = 4,

};

/// <summary>
/// Initialize the set of Yara rules. Look in the configured directory (which can be overridden in the registry).
///
/// By default it looks in %PROGRAMDATA%\Raccine, unless overridden by RulesDir in the registry
///
/// </summary>
/// <returns></returns>
BOOL InitializeYaraRules()
{
    WCHAR wYaraPattern[MAX_PATH] = { 0 };

    //wprintf(L"Checking dir: %s\n", g_wYaraRulesDir);
    if (FAILED(StringCchCat(wYaraPattern, ARRAYSIZE(wYaraPattern) - 1, g_wYaraRulesDir)))
        return FALSE;

    if (FAILED(StringCchCat(wYaraPattern, ARRAYSIZE(wYaraPattern) - 1, L"\\*.yar")))
        return FALSE;

    //allocate array to hold paths to yara rule files
    g_aszRuleFiles = (LPWSTR*)LocalAlloc(LPTR, MAX_YARA_RULE_FILES * sizeof LPWSTR);
    if (!g_aszRuleFiles) {
        return FALSE;
    }

    WIN32_FIND_DATA FindFileData{};
    FindFileHandleWrapper hFind = FindFirstFileW(wYaraPattern, &FindFileData);
    if (!hFind) {
        return FALSE;
    }

    do
    {
        if (g_cRuleCount >= MAX_YARA_RULE_FILES) {
            wprintf(L"Yara rule count has exceeded max of %d rules\n", MAX_YARA_RULE_FILES);
            break;
        }

        constexpr DWORD nSize = MAX_PATH;
        LPWSTR szRulePath = static_cast<LPWSTR>(LocalAlloc(LPTR, (nSize + 1) * sizeof WCHAR));
        if (!szRulePath) {
            return FALSE;
        }

        StringCchPrintfW(szRulePath, nSize, L"%s\\%s", g_wYaraRulesDir, FindFileData.cFileName);
        g_aszRuleFiles[g_cRuleCount++] = szRulePath;

    } while (FindNextFileW(hFind, &FindFileData));

    return TRUE;
}

/// <summary>
/// This function tests the Yara rules in Raccine's config directory on the launched command line.
/// </summary>
/// <param name="szTestFile">The temp file containing the command line to test</param>
/// <param name="ppszYaraOutput">Output parameter.  A string containing the Yara match text. If not NULL, call LocalFree to release the memory</param>
/// <param name="lpCommandLine">The input command line</param>
/// <returns>TRUE if at least one Yara rule matched</returns>
BOOL TestYaraRulesOnFile(LPWSTR szTestFile, LPWSTR* ppszYaraOutput, LPWSTR lpCommandLine)
{

    BOOL fRetVal = FALSE;
    WCHAR wYaraCommandLine[1000] = { 0 };
    WCHAR wYaraOutputFile[MAX_PATH] = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFO si = { 0 };
    LPWSTR szFinalString = NULL;
    constexpr DWORD cchFinalStringMaxSize = 2000;

    for (int i = 0; i < g_cRuleCount; i++)
    {
        LPWSTR szYaraRule = g_aszRuleFiles[i];
        StringCchPrintf(wYaraCommandLine, ARRAYSIZE(wYaraCommandLine), L"%s\\%s %s %s", g_wRaccineProgramDirectory, YARA_INSTANCE, szYaraRule, szTestFile);

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
            HANDLE hOutputFile = CreateFileW(wYaraOutputFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (hOutputFile != INVALID_HANDLE_VALUE)
            {
                DWORD dwHighSize = 0;
                const DWORD dwSize = GetFileSize(hOutputFile,
                                                 &dwHighSize
                );
                if (dwSize > 2)  //did we get a match?  allow for an empty newline or two . 
                {
                    fRetVal = TRUE;

                    if (!szFinalString)
                    {
                        szFinalString = static_cast<LPWSTR>(LocalAlloc(LPTR, cchFinalStringMaxSize * sizeof WCHAR));
                    }
                    if (szFinalString)
                    {
                        LPSTR szYaraOutput = static_cast<LPSTR>(LocalAlloc(LPTR, (dwSize + 1) * sizeof CHAR));
                        LPWSTR szYaraOutputWide = static_cast<LPWSTR>(LocalAlloc(LPTR, (dwSize + 1) * sizeof WCHAR));
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

            DeleteFileW(wYaraOutputFile);
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
    int len = static_cast<int>(wcslen(lpCommandLine));
    HANDLE hTempFile = INVALID_HANDLE_VALUE;
    LPSTR lpAnsiCmdLine = static_cast<LPSTR>(LocalAlloc(LPTR, len + 1));
    if (!lpAnsiCmdLine)
    {
        return FALSE;
    }
    ExpandEnvironmentStrings(RACCINE_DATA_DIRECTORY, wTestFilename, ARRAYSIZE(wTestFilename) - 1);

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
            len,
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
void WriteEventLogEntryWithId(LPWSTR pszMessage, DWORD dwEventId)
{
    EventSourceHandleWrapper hEventSource = RegisterEventSourceW(NULL, L"Raccine");
    if (!hEventSource) {
        return;
    }

    LPCWSTR lpszStrings[2] = { NULL, NULL };

    lpszStrings[0] = pszMessage;
    lpszStrings[1] = NULL;


    ReportEventW(hEventSource,      // Event log handle
                 EVENTLOG_INFORMATION_TYPE,  // Event type
                 0,                          // Event category
                 dwEventId,                  // Event identifier
                 NULL,                       // No security identifier
                 1,                          // Size of lpszStrings array
                 0,                          // No binary data
                 lpszStrings,                // Array of strings
                 NULL                        // No binary data
    );
}

void WriteEventLogEntry(LPWSTR  pszMessage)
{
    WriteEventLogEntryWithId(pszMessage, RACCINE_DEFAULT_EVENTID);
}

// Get Parent Process ID
DWORD getParentPid(DWORD pid)
{
    SnapshotHandleWrapper hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (!hSnapshot) {
        return 0;
    }

    PROCESSENTRY32W pe32{};
    ZeroMemory(&pe32, sizeof(pe32));
    pe32.dwSize = sizeof(pe32);
    if (!Process32FirstW(hSnapshot, &pe32)) {
        return 0;
    }

    do {
        if (pe32.th32ProcessID == pid) {
            return pe32.th32ParentProcessID;
        }
    } while (Process32NextW(hSnapshot, &pe32));

    return 0;
}

// Get integrity level of process
Integrity getIntegrityLevel(HANDLE hProcess)
{

    HANDLE hToken = INVALID_HANDLE_VALUE;

    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        return Integrity::Error;
    }

    PTOKEN_MANDATORY_LABEL pTIL;
    DWORD dwLengthNeeded = sizeof pTIL;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLengthNeeded);
    pTIL = static_cast<PTOKEN_MANDATORY_LABEL>(LocalAlloc(0, dwLengthNeeded));
    if (!pTIL) {
        return Integrity::Error;
    }

    if (GetTokenInformation(hToken, TokenIntegrityLevel,
                            pTIL, dwLengthNeeded, &dwLengthNeeded)) {
        const DWORD dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid,
                                                           static_cast<DWORD>(static_cast<UCHAR>(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1)));

        LocalFree(pTIL);

        if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID) {
            return Integrity::Low;
        }

        if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID &&
            dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID) {
            return Integrity::Medium;
        }

        if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID &&
            dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID) {
            return Integrity::High;
        }

        if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) {
            return Integrity::System;
        }

        return Integrity::Error;
    }

    LocalFree(pTIL);
    return Integrity::Error;
}

// Get the image name of the process
std::wstring getImageName(DWORD pid)
{
    PROCESSENTRY32W pe32{};
    SnapshotHandleWrapper hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (!hSnapshot) {
        return L"(unavailable)";
    }

    ZeroMemory(&pe32, sizeof(pe32));
    pe32.dwSize = sizeof(pe32);

    if (!Process32FirstW(hSnapshot, &pe32)) {
        return L"(unavailable)";
    }

    do {
        if (pe32.th32ProcessID == pid) {
            return std::wstring(static_cast<wchar_t*>(pe32.szExeFile));
        }
    } while (Process32NextW(hSnapshot, &pe32));

    return L"(unavailable)";
}

// Helper for isAllowListed, checks if a specific process is allowed
bool isProcessAllowed(const PROCESSENTRY32W& pe32)
{
    ProcessHandleWrapper hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
    if (!hProcess) {
        return false;
    }

    const std::array<std::wstring, 3> allow_list{ L"wininit.exe", L"winlogon.exe", L"explorer.exe" };
    for (const std::wstring& allowed_name : allow_list) {
        if (_wcsicmp(static_cast<const wchar_t*>(pe32.szExeFile), allowed_name.c_str()) != 0) {
            continue;
        }

        wchar_t filePath[MAX_PATH] = { 0 };
        if (GetModuleFileNameEx(hProcess, NULL, filePath, MAX_PATH)) {
            // Are they in the Windows directory?
            const std::wstring system32_path = L"C:\\Windows\\System32\\";
            if (_wcsnicmp(filePath, system32_path.c_str(), system32_path.length()) == 0) {
                // Is the process running as SYSTEM
                return getIntegrityLevel(hProcess) == Integrity::System;
            }

            // Are you explorer running in the Windows dir
            const std::wstring explorer_path = L"C:\\Windows\\Explorer.exe";
            if (_wcsnicmp(filePath, explorer_path.c_str(), explorer_path.length()) == 0) {
                // Is the process running as MEDIUM (which Explorer does)
                return getIntegrityLevel(hProcess) == Integrity::Medium;
            }
        }
    }

    return false;
}

// Check if process is in allowed list
bool isAllowListed(DWORD pid)
{
    SnapshotHandleWrapper hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (!hSnapshot) {
        return false;
    }

    PROCESSENTRY32W pe32{};
    pe32.dwSize = sizeof pe32;

    if (!Process32FirstW(hSnapshot, &pe32)) {
        return false;
    }

    do {
        if (pe32.th32ProcessID != pid) {
            continue;
        }

        return isProcessAllowed(pe32);
    } while (Process32NextW(hSnapshot, &pe32));

    return false;
}

// Kill a process
BOOL killProcess(DWORD dwProcessId, UINT uExitCode) {
    constexpr DWORD dwDesiredAccess = PROCESS_TERMINATE;
    constexpr BOOL  bInheritHandle = FALSE;
    ProcessHandleWrapper hProcess = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    if (!hProcess) {
        return FALSE;
    }

    return TerminateProcess(hProcess, uExitCode);
}

// Get timestamp
std::string getTimeStamp() {
    struct tm buf {};
    auto time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now() - std::chrono::hours(24));
    localtime_s(&buf, &time);
    std::stringstream ss;
    ss << std::put_time(&buf, "%F %T");
    auto timestamp = ss.str();
    return timestamp;
}

// Format a log lines
std::wstring logFormat(const std::wstring& cmdLine, const std::wstring& comment = L"done") {
    const std::string timeString = getTimeStamp();
    const std::wstring timeStringW(timeString.cbegin(), timeString.cend());
    std::wstring logLine = timeStringW + L" DETECTED_CMD: '" + cmdLine + L" COMMENT: " + comment + L"\n";
    return logLine;
}

std::wstring logFormatLine(const std::wstring& line = L"") {
    const std::string timeString = getTimeStamp();
    const std::wstring timeStringW(timeString.cbegin(), timeString.cend());
    std::wstring logLine = timeStringW + L" " + line + L"\n";
    return logLine;
}

// Format the activity log lines
std::wstring logFormatAction(DWORD pid, const std::wstring& imageName, const std::wstring& cmdLine, const std::wstring& comment = L"done") {
    const std::string timeString = getTimeStamp();
    const std::wstring timeStringW(timeString.cbegin(), timeString.cend());
    std::wstring logLine = timeStringW + L" DETECTED_CMD: '" + cmdLine + L"' IMAGE: '" + imageName + L"' PID: " + std::to_wstring(pid) + L" ACTION: " + comment + L"\n";
    return logLine;
}

// Log to file
void logSend(const std::wstring& logStr) {
    static FILE* logFile = nullptr;
    if (logFile == nullptr) {
        errno_t err = _wfopen_s(&logFile, L"C:\\ProgramData\\Raccine\\Raccine_log.txt", L"at");

        if (err != 0) {
            err = _wfopen_s(&logFile, L"C:\\ProgramData\\Raccine\\Raccine_log.txt", L"wt");
        }

        if (err != 0) {
            wprintf(L"\nCan not open C:\\ProgramData\\Raccine\\Raccine_log.txt for writing.\n");
            return;   // bail out if we can't log
        }
    }
    //transform(logStr.begin(), logStr.end(), logStr.begin(), ::tolower);
    if (logFile != nullptr)
    {
        fwprintf(logFile, L"%s", logStr.c_str());
        fflush(logFile);
        fclose(logFile);
        logFile = nullptr;
    }
}

//
//  Query for config in HKLM and HKLM\Software\Policies override by GPO
//
void InitializeSettings()
{
    // Registry Settings
    // Query for logging level. A value of 1 or more indicates to log key events to the event log
    // Query for logging only mode. A value of 1 or more indicates to suppress process kills

    ExpandEnvironmentStrings(RACCINE_DATA_DIRECTORY, g_wRaccineDataDirectory, ARRAYSIZE(g_wRaccineDataDirectory) - 1);
    ExpandEnvironmentStrings(RACCINE_PROGRAM_DIRECTORY, g_wRaccineProgramDirectory, ARRAYSIZE(g_wRaccineProgramDirectory) - 1);

    StringCchCopy(g_wYaraRulesDir, ARRAYSIZE(g_wYaraRulesDir), g_wRaccineDataDirectory);

    const wchar_t* LoggingKeys[] = { RACCINE_REG_CONFIG , RACCINE_REG_POICY_CONFIG };

    HKEY hKey = NULL;
    for (int i = 0; i < ARRAYSIZE(LoggingKeys); i++)
    {
        if (ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE, LoggingKeys[i], 0, KEY_READ, &hKey))
        {
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
            // Show Gui
            DWORD dwShowGui = 0;
            DWORD cbDataGUI = sizeof(dwShowGui);
            if (ERROR_SUCCESS == RegQueryValueExW(hKey, L"ShowGui", NULL, NULL, (LPBYTE)&dwShowGui, &cbDataGUI))
            {
                if (dwShowGui > 0)
                {
                    g_fShowGui = TRUE;
                }
            }
            // Yara rules dir
            DWORD cbData = sizeof(g_wYaraRulesDir);
            if (ERROR_SUCCESS == RegQueryValueExW(hKey, RACCINE_YARA_RULES_PATH, NULL, NULL, (LPBYTE)g_wYaraRulesDir, &cbData))
            {
                ;
            }
            RegCloseKey(hKey);
        }
    }
}

void createChildProcessWithDebugger(std::wstring command_line)
{
    STARTUPINFO info = { sizeof(info) };
    PROCESS_INFORMATION processInfo{};

    constexpr LPCWSTR NO_APPLICATION_NAME = nullptr;
    constexpr LPSECURITY_ATTRIBUTES DEFAULT_SECURITY_ATTRIBUTES = nullptr;
    constexpr BOOL INHERIT_HANDLES = TRUE;
    constexpr LPVOID USE_CALLER_ENVIRONMENT = nullptr;
    constexpr LPCWSTR USE_CALLER_WORKING_DIRECTORY = nullptr;
    const BOOL res = CreateProcessW(NO_APPLICATION_NAME,
                                    static_cast<LPWSTR>(command_line.data()),
                                    DEFAULT_SECURITY_ATTRIBUTES,
                                    DEFAULT_SECURITY_ATTRIBUTES,
                                    INHERIT_HANDLES,
                                    DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS,
                                    USE_CALLER_ENVIRONMENT,
                                    USE_CALLER_WORKING_DIRECTORY,
                                    &info,
                                    &processInfo);
    if (res == 0) {
        return;
    }

    DebugActiveProcessStop(processInfo.dwProcessId);
    WaitForSingleObject(processInfo.hProcess, INFINITE);
    CloseHandle(processInfo.hProcess);
    CloseHandle(processInfo.hThread);
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
    bool bVersion = false;

    // Encoded Command List (Base64)
    WCHAR encodedCommands[11][9] = { L"JAB", L"SQBFAF", L"SQBuAH", L"SUVYI", L"cwBhA", L"aWV4I", L"aQBlAHgA",
                                     L"cwB", L"IAA", L"IAB", L"UwB" };

    // Log
    std::wstring sCommandLine;
    std::wstring sListLogs;
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

    InitializeSettings();


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
        convertedArg = utils::to_lower(convertedArg);
        convertedArgPrev = utils::to_lower(convertedArgPrev);

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
        else if (_wcsicmp(L"-version", argv[iCount]) == 0 || _wcsicmp(L"/version", argv[iCount]) == 0) {
            bVersion = true;
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
    if ((bVssadmin && bDelete && bShadows) ||            // vssadmin.exe
        (bVssadmin && bDelete && bShadowStorage) ||      // vssadmin.exe
        (bVssadmin && bResize && bShadowStorage) ||      // vssadmin.exe
        (bWmic && bDelete && bShadowCopy) ||             // wmic.exe
        (bWbadmin && bDelete && bCatalog && bQuiet) || 	 // wbadmin.exe 
        (bcdEdit && bIgnoreallFailures) ||               // bcdedit.exe
        (bcdEdit && bRecoveryEnabled) ||                 // bcdedit.exe
        (bPowerShell && bVersion) ||                     // powershell.exe
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
            WriteEventLogEntryWithId((LPWSTR)wMessage, RACCINE_EVENTID_MALICIOUS_ACTIVITY);
        }
        else {
            // Eventlog
            StringCchPrintf(wMessage, ARRAYSIZE(wMessage), L"Raccine detected malicious activity:\n%s\n(simulation mode)", lpMessage);
            // Log to the text log file
            sListLogs.append(logFormat(sCommandLine, L"Raccine detected malicious activity (simulation mode)"));
            WriteEventLogEntryWithId((LPWSTR)wMessage, RACCINE_EVENTID_MALICIOUS_ACTIVITY);
        }

        // YARA Matches Detected
        if (fYaraRuleMatched)
        {
            if (szYaraOutput != NULL)
            {

                StringCchPrintf(wMessage, ARRAYSIZE(wMessage), L"\r\nYara matches:\r\n%s", szYaraOutput);
                WriteEventLogEntryWithId((LPWSTR)wMessage, RACCINE_EVENTID_MALICIOUS_ACTIVITY);
                sListLogs.append(logFormatLine(szYaraOutput));
                LocalFree(szYaraOutput);
                szYaraOutput = NULL;
            }
        }

        // signal Event for UI to know an alert happened.  If no UI is running, this has no effect.
        if (g_fShowGui) {
            HANDLE hEvent = OpenEvent(EVENT_MODIFY_STATE, FALSE, L"RaccineAlertEvent");
            if (hEvent != NULL)
            {
                if (!SetEvent(hEvent))
                {
                    ;//didn't go through
                }
                CloseHandle(hEvent);
            }
        }
    }

    // If block and not simulation mode
    if (bBlock && !g_fLogOnly) {
        // Collect PIDs to kill
        while (c < 1024) {
            pid = getParentPid(pid);
            if (pid == 0) {
                break;
            }

            std::wstring imageName = getImageName(pid);

            if (!isAllowListed(pid)) {
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
            std::wstring imageName = getImageName(pids[i - 1]);
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
    if (!bBlock || g_fLogOnly) {
        std::wstring sCommandLineStr;

        for (int i = 1; i < argc; i++) {
            sCommandLineStr.append(std::wstring(argv[i]).append(L" "));
        }

        createChildProcessWithDebugger(sCommandLineStr);
    }

    // Log events
    logSend(sListLogs);

    return 0;
}
