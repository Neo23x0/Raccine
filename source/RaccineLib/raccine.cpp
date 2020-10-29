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
#include <thread>

#include "Raccine.h"

#include "HandleWrapper.h"
#include "Utils.h"
#include "YaraRuleRunner.h"

#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"shlwapi.lib")
#pragma comment(lib,"Wbemuuid.lib")


bool EvaluateYaraRules(const RaccineConfig& raccine_config,
    const std::wstring& lpCommandLine,
    std::wstring& outYaraOutput,
    DWORD dwChildPid,
    DWORD dwParentPid)
{
    if (raccine_config.is_debug_mode()) {
        wprintf(L"Running YARA on: %s\n", lpCommandLine.c_str());
    }

    WCHAR wTestFilename[MAX_PATH] = { 0 };

    ExpandEnvironmentStringsW(RACCINE_USER_CONTEXT_DIRECTORY, wTestFilename, ARRAYSIZE(wTestFilename) - 1);

    const int c = GetTempFileNameW(wTestFilename, L"Raccine", 0, wTestFilename);
    if (c == 0) {
        return false;
    }
    utils::write_string_to_file(wTestFilename, lpCommandLine);

    BOOL fSuccess = TRUE;

    const DWORD dwCurrPid = dwChildPid;
    const DWORD dwCurrParentPid = dwParentPid;
    DWORD dwCurrSessionId = 0;
    if (!ProcessIdToSessionId(dwCurrPid, &dwCurrSessionId)) {
        fSuccess = FALSE;
    }

    const DWORD dwParentParentPid = utils::getParentPid(dwParentPid);
    DWORD dwParentSessionId = 0;
    if (!ProcessIdToSessionId(dwParentPid, &dwParentSessionId)) {
        fSuccess = FALSE;
    }

    std::wstring AdditionalYaraDefines = L" " + std::to_wstring(dwCurrSessionId) + L" " + std::to_wstring(dwCurrPid) + L" " + std::to_wstring(dwCurrParentPid) +
        L" " + std::to_wstring(dwParentSessionId) + L" " + std::to_wstring(dwParentPid) + L" " + std::to_wstring(dwParentParentPid) + L" ";

    if (raccine_config.is_debug_mode()) {
        wprintf(L"Composed test-string is: %s\n", AdditionalYaraDefines.c_str());
        wprintf(L"Everything OK? %d\n", fSuccess);
    }

    CreateContextFileForProgram(dwCurrPid, dwCurrSessionId, dwCurrParentPid, false);

    CreateContextFileForProgram(dwParentPid, dwParentSessionId, dwParentParentPid, true);

    // BUGBUG clean up after files

    bool fRetVal = false;

    if (fSuccess) {
        //wprintf(L"Checking rule dir: %s", raccine_config.yara_rules_directory().c_str());
        YaraRuleRunner rule_runner(raccine_config.yara_rules_directory(),
            utils::expand_environment_strings(RACCINE_PROGRAM_DIRECTORY));
        fRetVal = rule_runner.run_yara_rules_on_file(wTestFilename, lpCommandLine, outYaraOutput, AdditionalYaraDefines);
    }
    DeleteFileW(wTestFilename);

    return fRetVal;
}

void CreateContextFileForProgram(DWORD pid, DWORD session_id, DWORD parentPid, bool fParent)
{
    const utils::ProcessDetail details(pid);

    std::wstring strDetails;
    if (fParent) {
        strDetails = details.ToString(L"Parent");
    }
    else {
        strDetails = details.ToString(L"");
    }

    std::wstring context_path = utils::expand_environment_strings(RACCINE_USER_CONTEXT_DIRECTORY);
    context_path += L"\\RaccineYaraContext-" + std::to_wstring(session_id) +
        L"-" + std::to_wstring(pid) +
        L"-" + std::to_wstring(parentPid) + L".txt";

    utils::write_string_to_file(context_path, strDetails);
}

void WriteEventLogEntryWithId(const std::wstring& pszMessage, DWORD dwEventId)
{
    constexpr LPCWSTR LOCAL_COMPUTER = nullptr;
    EventSourceHandleWrapper hEventSource = RegisterEventSourceW(LOCAL_COMPUTER,
        L"Raccine");
    if (!hEventSource) {
        return;
    }

    LPCWSTR lpszStrings[2] = { pszMessage.c_str() , nullptr };

    constexpr PSID NO_USER_SID = nullptr;
    constexpr LPVOID NO_BINARY_DATA = nullptr;
    ReportEventW(hEventSource,               // Event log handle
        EVENTLOG_INFORMATION_TYPE,  // Event type
        0,                          // Event category
        dwEventId,                  // Event identifier
        NO_USER_SID,                // No security identifier
        1,                          // Size of lpszStrings array
        0,                          // No binary data
        lpszStrings,                // Array of strings
        NO_BINARY_DATA              // No binary data
    );
}

void WriteEventLogEntry(const std::wstring& pszMessage)
{
    WriteEventLogEntryWithId(pszMessage, RACCINE_DEFAULT_EVENTID);
}

bool is_malicious_command_line(const std::vector<std::wstring>& command_line)
{
    if (command_line.empty()) {
        return false;
    }

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
    bool bWin32ShadowCopy = false;
    const bool bEncodedCommand = does_command_line_contain_base64(command_line);
    bool bVersion = false;

    const std::wstring program = utils::to_lower(command_line[0]);
    // Check for invoked program
    if (program == L"vssadmin.exe" || program == L"vssadmin") {
        bVssadmin = true;
    }

    if (program == L"wmic.exe" || program == L"wmic") {
        bWmic = true;
    }

    if (program == L"wbadmin.exe" || program == L"wbadmin") {
        bWbadmin = true;
    }

    if (program == L"bcdedit.exe" || program == L"bcdedit") {
        bcdEdit = true;
    }

    if (program == L"powershell.exe" || program == L"powershell") {
        bPowerShell = true;
    }

    if (program == L"diskshadow.exe" || program == L"diskshadow") {
        bDiskShadow = true;
    }

    // Check for keywords in command line parameters
    std::vector<std::wstring> command_line_parameters(command_line.begin() + 1,
        command_line.end());
    for (const std::wstring& parameter : command_line_parameters) {
        // Convert wchar to wide string so we can perform contains/find command
        const std::wstring convertedArg(utils::to_lower(parameter));

        // Simple flag checks
        if (convertedArg == L"delete") {
            bDelete = true;
        }
        else if (convertedArg == L"shadows") {
            bShadows = true;
        }
        else if (convertedArg == L"shadowstorage") {
            bShadowStorage = true;
        }
        else if (convertedArg == L"resize") {
            bResize = true;
        }
        else if (convertedArg == L"shadowcopy") {
            bShadowCopy = true;
        }
        else if (convertedArg == L"catalog") {
            bCatalog = true;
        }
        else if (convertedArg == L"-quiet" || convertedArg == L"/quiet") {
            bQuiet = true;
        }
        else if (convertedArg == L"recoveryenabled") {
            bRecoveryEnabled = true;
        }
        else if (convertedArg == L"ignoreallfailures") {
            bIgnoreallFailures = true;
        }
        else if (convertedArg.find(L"win32_shadowcopy") != std::string::npos) {
            bWin32ShadowCopy = true;
        }
        else if (convertedArg == L"-version" || convertedArg == L"/version") {
            bVersion = true;
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
        (bPowerShell && bWin32ShadowCopy) ||             // powershell.exe
        (bPowerShell && bEncodedCommand) ||              // powershell.exe
        (bDiskShadow && bDelete && bShadows)) {          // diskshadow.exe

        // Activate blocking
        return true;
    }

    return false;
}

bool does_command_line_contain_base64(const std::vector<std::wstring>& command_line)
{
    // Encoded Command List (Base64)
    std::vector<std::wstring> encodedCommands = { L"JAB", L"SQBFAF", L"SQBuAH", L"SUVYI",
                                                  L"cwBhA", L"aWV4I", L"aQBlAHgA",
                                                  L"cwB", L"IAA", L"IAB", L"UwB" };

    // Check for keywords in command line parameters
    for (size_t iCount = 1; iCount < command_line.size(); iCount++) {

        // Convert wchar to wide string so we can perform contains/find command
        std::wstring convertedArg(utils::to_lower(command_line[iCount]));
        std::wstring convertedArgOrig(command_line[iCount]);                        // original parameter (no tolower)
        std::wstring convertedArgPrev(utils::to_lower(command_line[iCount - 1]));   // previous parameter

        // Special comparison of current argument with previous argument
        // allows to check for e.g. -encodedCommand JABbaTheHuttandotherBase64characters
        if (convertedArgPrev.find(L"-e") == std::string::npos && convertedArgPrev.find(L"/e") == std::string::npos) {
            continue;
        }

        for (const std::wstring& command : encodedCommands) {
            if (convertedArgOrig.find(command) != std::string::npos) {
                return true;
            }
        }
    }

    return false;
}

bool needs_powershell_workaround(const std::wstring& command_line)
{
    if (command_line.find(L"-File ") != std::wstring::npos &&
        command_line.find(L".ps") != std::wstring::npos &&
        command_line.find(L"powershell") == std::wstring::npos) {
        return true;
    }

    return false;
}

void trigger_gui_event()
{
    constexpr BOOL DO_NOT_INHERIT = FALSE;
    EventHandleWrapper hEvent = OpenEventW(EVENT_MODIFY_STATE,
        DO_NOT_INHERIT,
        L"RaccineAlertEvent");
    if (hEvent) {
        SetEvent(hEvent);
    }
}

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

        return utils::isProcessAllowed(pe32);
    } while (Process32NextW(hSnapshot, &pe32));

    return false;
}

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

std::wstring logFormat(const std::wstring& cmdLine, const std::wstring& comment)
{
    const std::string timeString = getTimeStamp();
    const std::wstring timeStringW(timeString.cbegin(), timeString.cend());
    std::wstring logLine = timeStringW + L" DETECTED_CMD: '" + cmdLine + L" COMMENT: " + comment + L"\n";
    return logLine;
}

std::wstring logFormatLine(const std::wstring& line)
{
    const std::string timeString = getTimeStamp();
    const std::wstring timeStringW(timeString.cbegin(), timeString.cend());
    std::wstring logLine = timeStringW + L" " + line + L"\n";
    return logLine;
}

std::wstring logFormatAction(DWORD pid, const std::wstring& imageName, const std::wstring& cmdLine, const std::wstring& comment)
{
    const std::string timeString = getTimeStamp();
    const std::wstring timeStringW(timeString.cbegin(), timeString.cend());
    std::wstring logLine = timeStringW + L" DETECTED_CMD: '" + cmdLine + L"' IMAGE: '" + imageName + L"' PID: " + std::to_wstring(pid) + L" ACTION: " + comment + L"\n";
    return logLine;
}

void logSend(const std::wstring& logStr)
{
    static FILE* logFile = nullptr;
    if (logFile == nullptr) {
        const std::filesystem::path raccine_data_directory = utils::expand_environment_strings(RACCINE_DATA_DIRECTORY);
        const std::filesystem::path raccine_log_file_path = raccine_data_directory / L"Raccine_log.txt";
        errno_t err = _wfopen_s(&logFile, raccine_log_file_path.c_str(), L"at");

        if (err != 0) {
            err = _wfopen_s(&logFile, raccine_log_file_path.c_str(), L"wt");
        }

        if (err != 0) {
            wprintf(L"\nCan not open %s for writing.\n", raccine_log_file_path.c_str());
            return;   // bail out if we can't log
        }
    }

    if (logFile != nullptr) {
        fwprintf(logFile, L"%s", logStr.c_str());
        fflush(logFile);
        fclose(logFile);
        logFile = nullptr;
    }
}

std::tuple<DWORD, ProcessHandleWrapper, ThreadHandleWrapper> createChildProcessWithDebugger(LPWSTR lpzchildCommandLine,
    DWORD dwAdditionalCreateParams)
{

    STARTUPINFO info = { sizeof(info) };
    PROCESS_INFORMATION processInfo{};

    constexpr LPCWSTR NO_APPLICATION_NAME = nullptr;
    constexpr LPSECURITY_ATTRIBUTES DEFAULT_SECURITY_ATTRIBUTES = nullptr;
    constexpr BOOL INHERIT_HANDLES = TRUE;
    constexpr LPVOID USE_CALLER_ENVIRONMENT = nullptr;
    constexpr LPCWSTR USE_CALLER_WORKING_DIRECTORY = nullptr;


    const BOOL res = CreateProcessW(NO_APPLICATION_NAME,
        lpzchildCommandLine,
        DEFAULT_SECURITY_ATTRIBUTES,
        DEFAULT_SECURITY_ATTRIBUTES,
        INHERIT_HANDLES,
        DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | dwAdditionalCreateParams,
        USE_CALLER_ENVIRONMENT,
        USE_CALLER_WORKING_DIRECTORY,
        &info,
        &processInfo);
    if (res == 0) {
        return { 0, INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE };
    }

    DebugActiveProcessStop(processInfo.dwProcessId);

    return { processInfo.dwProcessId, processInfo.hProcess, processInfo.hThread };
}

std::set<DWORD> find_processes_to_kill(const std::wstring& sCommandLine, std::wstring& sListLogs)
{
    std::set<DWORD> pids;
    DWORD pid = GetCurrentProcessId();

    while (true) {
        pid = utils::getParentPid(pid);
        if (pid == 0) {
            break;
        }

        const std::wstring imageName = utils::getImageName(pid);

        if (!isAllowListed(pid)) {
            wprintf(L"\nCollecting IMAGE %s with PID %d for a kill\n", imageName.c_str(), pid);
            pids.insert(pid);
        }
        else {
            wprintf(L"\nProcess IMAGE %s with PID %d is on allowlist\n", imageName.c_str(), pid);
            sListLogs.append(logFormatAction(pid, imageName, sCommandLine, L"Whitelisted"));
        }
    }

    return pids;
}

void find_and_kill_processes(bool log_only, const std::wstring& sCommandLine, std::wstring& sListLogs)
{
    const std::set<DWORD> pids = find_processes_to_kill(sCommandLine, sListLogs);

    for (DWORD process_id : pids) {
        const std::wstring imageName = utils::getImageName(process_id);
        // If no simulation flag is set
        if (!log_only) {
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

    printf("\nRaccine v%s finished\n", VERSION);
    //std::this_thread::sleep_for(std::chrono::seconds(5));
}