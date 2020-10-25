// Raccine 
// A Simple Ransomware Vaccine
// https://github.com/Neo23x0/Raccine
//
// Florian Roth, Ollie Whitehouse, Branislav Djalic, John Lambert
// with help of Hilko Bengen

#include <cwchar>
#include <Windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <array>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <strsafe.h>
#include <Shlwapi.h>
#include <vector>

#include "Raccine.h"


#include "HandleWrapper.h"
#include "YaraRuleRunner.h"

#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"shlwapi.lib")
#pragma comment(lib,"Wbemuuid.lib")


/// <summary>
/// Evaluate a set of yara rules on a command line
/// </summary>
/// <param name="lpCommandLine">The command line to test</param>
/// <param name="outYaraOutput">if not empty, an output string containing match results is written to this parameter.</param>
/// <returns>TRUE if at least one match result was found</returns>
BOOL EvaluateYaraRules(LPWSTR lpCommandLine, std::wstring& outYaraOutput, DWORD dwChildPid, DWORD dwParentPid)
{
    if (g_fDebug) {
        wprintf(L"Running YARA on: %s\n", lpCommandLine);
    }
    BOOL fRetVal = FALSE;
    WCHAR wTestFilename[MAX_PATH] = { 0 };
    const int len = static_cast<int>(wcslen(lpCommandLine));
    LPSTR lpAnsiCmdLine = static_cast<LPSTR>(LocalAlloc(LPTR, len + 1));
    if (!lpAnsiCmdLine)
    {
        return FALSE;
    }
    ExpandEnvironmentStringsW(RACCINE_YARA_DIRECTORY, wTestFilename, ARRAYSIZE(wTestFilename) - 1);
    YaraRuleRunner rule_runner(wTestFilename, g_wRaccineProgramDirectory);

    int c = GetTempFileNameW(wTestFilename, L"Raccine", 0, wTestFilename);
    if (c != 0)
    {
        //  Creates the new file to write to for the upper-case version.
        HANDLE hTempFile = CreateFileW(wTestFilename, // file name 
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

        BOOL fSuccess = TRUE;

        DWORD dwCurrPid = dwChildPid;
        DWORD dwCurrParentPid = dwParentPid;
        DWORD dwCurrSessionId = 0;
        if (!ProcessIdToSessionId(dwCurrPid, &dwCurrSessionId))
        {
            fSuccess = FALSE;
        }

        DWORD dwParentParentPid = utils::getParentPid(dwParentPid);
        DWORD dwParentSessionId = 0;
        if (!ProcessIdToSessionId(dwParentPid, &dwParentSessionId))
        {
            fSuccess = FALSE;
        }

        std::wstring AdditionalYaraDefines = L" " + std::to_wstring(dwCurrSessionId) + L" " + std::to_wstring(dwCurrPid) + L" " + std::to_wstring(dwCurrParentPid) +
            L" " + std::to_wstring(dwParentSessionId) + L" " + std::to_wstring(dwParentPid) + L" " + std::to_wstring(dwParentParentPid) + L" ";

        if (g_fDebug) {
            wprintf(L"Composed test-string is: %s\n", AdditionalYaraDefines.c_str());
            wprintf(L"Everything OK? %d\n", fSuccess);
        }

        CreateContextFileForProgram(dwCurrPid, dwCurrSessionId, dwCurrParentPid, false);

        CreateContextFileForProgram(dwParentPid, dwParentSessionId, dwParentParentPid, true);

        // BUGBUG clean up after files

        if (fSuccess)
        {
            fRetVal = rule_runner.run_yara_rules_on_file(wTestFilename, lpCommandLine, outYaraOutput, AdditionalYaraDefines);
        }
        DeleteFileW(wTestFilename);
    }
cleanup:
    return fRetVal;
}

void CreateContextFileForProgram(DWORD pid, DWORD sessionid, DWORD parentPid, bool fParent)
{
    utils::ProcessDetail details = utils::ProcessDetail(pid);

    std::wstring strDetails;

    if (fParent)
    {
        strDetails = details.ToString(L"Parent");
    }
    else
    {
        strDetails = details.ToString(L"");;
    }

    LPSTR lpDetails = static_cast<LPSTR>(LocalAlloc(LPTR, strDetails.length() + 1));
    if (!lpDetails)
    {
        return;
    }

    WCHAR wContextPath[MAX_PATH] = { 0 };
    ExpandEnvironmentStringsW(RACCINE_USER_CONTEXT_DIRECTORY, wContextPath, ARRAYSIZE(wContextPath) - 1);
    WCHAR wContextFileName[100] = { 0 };
    if (FAILED(StringCchPrintf(wContextFileName, ARRAYSIZE(wContextFileName), L"\\RaccineYaraContext-%d-%d-%d.txt", sessionid, pid, parentPid)))
        return;

    if (SUCCEEDED(StringCchCat(wContextPath, ARRAYSIZE(wContextPath), wContextFileName)))
    {
        //  Creates the new file to write to for the upper-case version.
        HANDLE hTempFile = CreateFileW(wContextPath, // file name 
            GENERIC_WRITE,        // open for write 
            0,                    // do not share 
            NULL,                 // default security 
            CREATE_ALWAYS,        // overwrite existing
            FILE_ATTRIBUTE_NORMAL,// normal file 
            NULL);                // no template 
        if (hTempFile == INVALID_HANDLE_VALUE)
        {
            return;
        }
        DWORD dwWritten = 0;

        if (WideCharToMultiByte(
            CP_ACP,
            0,
            strDetails.c_str(),
            (int)strDetails.length(),
            lpDetails,
            (int)strDetails.length() + 1,
            NULL,
            NULL
        ))
        {
            if (!WriteFile(hTempFile, lpDetails, lstrlenA(lpDetails) + 1, &dwWritten, NULL))
            {
                ;
            }
        }
        CloseHandle(hTempFile);
    }
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


// Get timestamp
std::string getTimeStamp()
{
    struct tm buf {};
    auto time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now() - std::chrono::hours(24));
    localtime_s(&buf, &time);
    std::stringstream ss;
    ss << std::put_time(&buf, "%F %T");
    auto timestamp = ss.str();
    return timestamp;
}

// Format a log lines
std::wstring logFormat(const std::wstring& cmdLine, const std::wstring& comment)
{
    const std::string timeString = getTimeStamp();
    const std::wstring timeStringW(timeString.cbegin(), timeString.cend());
    std::wstring logLine = timeStringW + L" DETECTED_CMD: '" + cmdLine + L" COMMENT: " + comment + L"\n";
    return logLine;
}

std::wstring logFormatLine(const std::wstring& line) {
    const std::string timeString = getTimeStamp();
    const std::wstring timeStringW(timeString.cbegin(), timeString.cend());
    std::wstring logLine = timeStringW + L" " + line + L"\n";
    return logLine;
}

// Format the activity log lines
std::wstring logFormatAction(DWORD pid, const std::wstring& imageName, const std::wstring& cmdLine, const std::wstring& comment) {
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

    ExpandEnvironmentStringsW(RACCINE_DATA_DIRECTORY, g_wRaccineDataDirectory, ARRAYSIZE(g_wRaccineDataDirectory) - 1);
    ExpandEnvironmentStringsW(RACCINE_PROGRAM_DIRECTORY, g_wRaccineProgramDirectory, ARRAYSIZE(g_wRaccineProgramDirectory) - 1);

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
            // Debug
            DWORD dwDebug = 0;
            DWORD cbDataDebug = sizeof(dwDebug);
            if (ERROR_SUCCESS == RegQueryValueExW(hKey, L"Debug", NULL, NULL, (LPBYTE)&dwDebug, &cbDataDebug))
            {
                if (dwDebug > 0)
                {
                    g_fDebug = TRUE;
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

void createChildProcessWithDebugger(std::wstring command_line, DWORD dwAdditionalCreateParams, PDWORD pdwChildPid, PHANDLE phProcess, PHANDLE phThread)
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
                                    DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | dwAdditionalCreateParams,
                                    USE_CALLER_ENVIRONMENT,
                                    USE_CALLER_WORKING_DIRECTORY,
                                    &info,
                                    &processInfo);
    if (res == 0) {
        return;
    }

    DebugActiveProcessStop(processInfo.dwProcessId);

    if (phProcess != NULL)
    {
        *phProcess = processInfo.hProcess;  // Caller responsible for closing
    }
    if (phThread != NULL)
    {
        *phThread = processInfo.hThread;  // Caller responsible for closing
    }
    if (pdwChildPid != NULL)
    {
        *pdwChildPid = processInfo.dwProcessId;
    }
}

// Find all parent processes and kill them
void find_and_kill_processes(const std::wstring& sCommandLine, std::wstring& sListLogs)
{
    std::vector<DWORD> pids;
    // Collect PIDs to kill
    DWORD pid = GetCurrentProcessId();

    while (true) {
        pid = utils::getParentPid(pid);
        if (pid == 0) {
            break;
        }

        std::wstring imageName = utils::getImageName(pid);

        if (!isAllowListed(pid)) {
            wprintf(L"\nCollecting IMAGE %s with PID %d for a kill\n", imageName.c_str(), pid);
            pids.push_back(pid);
        }
        else {
            wprintf(L"\nProcess IMAGE %s with PID %d is on allowlist\n", imageName.c_str(), pid);
            sListLogs.append(logFormatAction(pid, imageName, sCommandLine, L"Whitelisted"));
        }
    }

    // Loop over collected PIDs and try to kill the processes
    for (DWORD process_id : pids) {
        std::wstring imageName = utils::getImageName(process_id);
        // If no simulation flag is set
        if (!g_fLogOnly) {
            // Kill
            wprintf(L"Kill process IMAGE %s with PID %d\n", imageName.c_str(), process_id);
            utils::killProcess(process_id, 1);
            sListLogs.append(logFormatAction(process_id, imageName, sCommandLine, L"Terminated"));
        }
        else {
            // Simulated kill
            wprintf(L"Simulated Kill IMAGE %s with PID %d\n", imageName.c_str(), process_id);
            sListLogs.append(logFormatAction(process_id, imageName, sCommandLine, L"Terminated (Simulated)"));
        }
    }

    // Finish message
    printf("\nRaccine v%s finished\n", VERSION);
    Sleep(1000);
}
