// Raccine 
// A Simple Ransomware Vaccine
// https://github.com/Neo23x0/Raccine
//
// Florian Roth, Ollie Whitehouse, Branislav Dalic, John Lambert
// with help of Hilko Bengen

#include <cwchar>
#include <Windows.h>
#include <TlHelp32.h>
#include <cstdio>
#include <cstring>
#include <clocale>
#include <Psapi.h>
#include <string>
#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <strsafe.h>
#include <shellapi.h>
#include <array>

#include "HandleWrapper.h"
#include "resource.h"

#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"shell32.lib")
#pragma comment(lib,"user32.lib")
#pragma comment(lib,"gdi32.lib")

// Version
#define VERSION L"0.10.3"

// Log Config and Flags
int g_fGuiSettings = 0;
BOOL g_fSimulationOnly = FALSE;
BOOL g_fLogging = TRUE;
WCHAR g_wYaraRulesDir[MAX_PATH] = { 0 };
LPWSTR* g_aszRuleFiles = { 0 };
int g_cRuleCount = 0;
#define YARA_INSTANCE  L"runyara.bat"
#define YARA_RESULTS_SUFFIX L".out"
#define TIMEOUT  1000*5

#define RACCINE_DIRECTORY  L"%PROGRAMDATA%\\Raccine"
WCHAR g_wRaccineDirectory[MAX_PATH] = { 0 };  // ENV expanded RACCINE_DIRECTORY


#define MAX_YARA_RULE_FILES 200
#define RACCINE_REG_CONFIG  L"SOFTWARE\\Raccine"
#define RACCINE_REG_POICY_CONFIG  L"SOFTWARE\\Policies\\Raccine"
#define RACCINE_YARA_RULES_PATH L"RulesDir"
#define MAX_MESSAGE 1000
#define RACCINE_DEFAULT_EVENTID  1
#define RACCINE_EVENTID_MALICIOUS_ACTIVITY  2

#define RACCINE_SHOW_ALERT 0x1
#define RACCINE_SHOW_CONSOLE 0x2

std::wstring sListLogs;

// UX defines and globals
#define RACCINE_TOOLTIP L"Raccine Notification"
#define APPWM_ICONNOTIFY (WM_APP + 1)
#define APPWM_ALERT (WM_APP + 2)
#define APPWM_WORKERDONE (WM_APP + 3)

wchar_t const szWindowClass[] = L"RaccineNotificationIcon";

HWND g_Hwnd = 0;
HINSTANCE g_hInst = 0;
HBITMAP g_hBitmap = NULL;
#define ID_EDITCHILD 100

#define DEFAULT_HEIGHT 400
#define DEFAULT_WIDTH  400

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
            LPWSTR szRulePath = (LPWSTR)LocalAlloc(LPTR, (nSize + 1) * sizeof WCHAR);
            if (!szRulePath)
                goto cleanup;

            //wprintf(L"The file found is %s\n", FindFileData.cFileName);
            StringCchPrintf(szRulePath, nSize, L"%s\\%s", g_wYaraRulesDir, FindFileData.cFileName);
            g_aszRuleFiles[g_cRuleCount++] = szRulePath;

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

    for (int i = 0; i < g_cRuleCount; i++)
    {
        LPWSTR szYaraRule = g_aszRuleFiles[i];
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

LRESULT CALLBACK WndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{

    HWND static hwndEdit = 0;
    BITMAP static bitmap = { 0 };

    switch (uMsg)
    {
        case WM_CREATE:
        {
            g_hBitmap = (HBITMAP)LoadBitmap(g_hInst, MAKEINTRESOURCE(IDCLOGO));

            if (!g_hBitmap)
                return 0;
            GetObject(g_hBitmap, sizeof(bitmap), &bitmap);

            RECT rc = { 0 };
            GetWindowRect(hwnd, &rc);
            int xPos = (GetSystemMetrics(SM_CXSCREEN) - rc.right) / 2;
            int yPos = (GetSystemMetrics(SM_CYSCREEN) - rc.bottom) / 2;

            hwndEdit = CreateWindowEx(
                0, L"EDIT",   // predefined class 
                NULL,         // no window title 
                WS_CHILD | WS_VISIBLE | WS_VSCROLL |
                ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL,
                0, 0, 0, 0,   // set size in WM_SIZE message 
                hwnd,         // parent window 
                (HMENU)ID_EDITCHILD,   // edit control ID 
                (HINSTANCE)GetWindowLongPtr(hwnd, GWLP_HINSTANCE),
                NULL);        // pointer not needed 

            int nHeight = -MulDiv(10, GetDeviceCaps(GetDC(hwnd), LOGPIXELSY), 72);

            HFONT hFont = CreateFont(nHeight, 0, 0, 0, FW_DONTCARE, FALSE, FALSE, FALSE, ANSI_CHARSET,
                OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                DEFAULT_PITCH | FF_DONTCARE, TEXT("Consolas"));
            SendMessage(hwndEdit, WM_SETFONT, (WPARAM)hFont, TRUE);

            SetWindowPos(hwnd, 0, xPos, yPos, bitmap.bmWidth + DEFAULT_WIDTH, bitmap.bmHeight + DEFAULT_HEIGHT, SWP_NOZORDER);

            break;
        }
        case WM_PAINT:
        {
            PAINTSTRUCT     ps = { 0 };
            HDC             hdc = NULL;
            HDC             hdcMem = NULL;
            HGDIOBJ         oldBitmap = NULL;

            hdc = BeginPaint(hwnd, &ps);

            hdcMem = CreateCompatibleDC(hdc);
            oldBitmap = SelectObject(hdcMem, g_hBitmap);

            BitBlt(hdc, 0, 0, bitmap.bmWidth, bitmap.bmHeight, hdcMem, 0, 0, SRCCOPY);

            SelectObject(hdcMem, oldBitmap);
            DeleteDC(hdcMem);

            EndPaint(hwnd, &ps);
            break;
        }
        case WM_APPCOMMAND:
        {
            if (lParam == APPWM_ALERT)
            {
                SendMessage(hwndEdit, WM_SETTEXT, 0, (LPARAM)sListLogs.c_str());
                return 0;
            }
        }
        case WM_SETFOCUS:
        {
            SetFocus(hwndEdit);
            return 0;
        }
        case APPWM_WORKERDONE:
        {
            //WINDOWPLACEMENT WindowPlacement = { 0 };
            //WindowPlacement.length = sizeof(WindowPlacement);
            //GetWindowPlacement(g_Hwnd, &WindowPlacement);
            //bool IsWindowHidden = (WindowPlacement.showCmd == SW_HIDE || WindowPlacement.showCmd == SW_SHOWNORMAL);

            if (!IsWindowVisible(g_Hwnd))
            {
                PostQuitMessage(0);
                return 0;
            }
            break;
        }
        case WM_CLOSE:
        {
            PostQuitMessage(0);
            return 0;
        }
        case WM_SIZE:
        {
            // Make the edit control the size of the window's client area. 

            MoveWindow(hwndEdit,
                0, bitmap.bmHeight,    // starting x- and y-coordinates 
                LOWORD(lParam),        // width of client area 
                HIWORD(lParam),        // height of client area 
                TRUE);                 // repaint window 
            return 0;
        }
        case APPWM_ICONNOTIFY:
        {
            switch (lParam)
            {
                case WM_LBUTTONUP:
                    //...
                    break;
                case WM_RBUTTONUP:
                    //...
                    break;
            }
            return 0;
        }
    }

    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

/// This function will optionally log messages to the eventlog
void WriteEventLogEntryWithId(LPWSTR pszMessage, DWORD dwEventId)
{
    // always print the message to the console
    wprintf(pszMessage);

    if (!g_fLogging) {
        return;
    }

    EventSourceHandleWrapper hEventSource = RegisterEventSourceW(NULL, L"Raccine");
    if (!hEventSource) {
        return;
    }

    LPCWSTR lpszStrings[2] = { NULL, NULL };

    lpszStrings[0] = pszMessage;
    lpszStrings[1] = NULL;


    ReportEventW(hEventSource,  // Event log handle
        EVENTLOG_INFORMATION_TYPE,                 // Event type
        0,                     // Event category
        dwEventId,                     // Event identifier
        NULL,                  // No security identifier
        1,  // Size of lpszStrings array
        0,                     // No binary data
        lpszStrings,           // Array of strings
        NULL                   // No binary data
    );
}

void WriteEventLogEntry(LPWSTR  pszMessage)
{
    WriteEventLogEntryWithId(pszMessage, RACCINE_DEFAULT_EVENTID);
}

// Get Parent Process ID
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
DWORD getIntegrityLevel(HANDLE hProcess) {

    HANDLE hToken = INVALID_HANDLE_VALUE;

    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        return 0;
    }

    PTOKEN_MANDATORY_LABEL pTIL;
    DWORD dwLengthNeeded = sizeof(pTIL);
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLengthNeeded);
    pTIL = static_cast<PTOKEN_MANDATORY_LABEL>(LocalAlloc(0, dwLengthNeeded));
    if (!pTIL) {
        return 0;
    }

    if (GetTokenInformation(hToken, TokenIntegrityLevel,
        pTIL, dwLengthNeeded, &dwLengthNeeded)) {
        const DWORD dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid,
            static_cast<DWORD>(static_cast<UCHAR>(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1)));

        LocalFree(pTIL);

        if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID) {
            // Low Integrity
            return 1;
        }

        if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID &&
            dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID) {
            // Medium Integrity
            return 2;
        }

        if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID &&
            dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID) {
            // High Integrity
            return 3;
        }

        if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) {
            // System Integrity
            return 4;
        }

        return 0;
    }

    LocalFree(pTIL);
    return 0;
}

// Check if process is in allowed list
bool isAllowListed(DWORD pid) {
    const std::array<std::wstring, 3> allowlist{ L"wininit.exe", L"winlogon.exe", L"explorer.exe" };

    PROCESSENTRY32W pe32{};
    SnapshotHandleWrapper hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (!hSnapshot) {
        return false;
    }

    ZeroMemory(&pe32, sizeof(pe32));
    pe32.dwSize = sizeof(pe32);

    if (!Process32FirstW(hSnapshot, &pe32)) {
        return false;
    }

    do {
        if (pe32.th32ProcessID == pid) {
            continue;
        }

        ProcessHandleWrapper hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
        if (!hProcess) {
            break;
        }

        for (const std::wstring& allowed_name : allowlist) {
            if (_wcsicmp(static_cast<wchar_t*>(pe32.szExeFile), allowed_name.c_str()) != 0) {
                continue;
            }

            wchar_t filePath[MAX_PATH] = { 0 };
            if (GetModuleFileNameEx(hProcess, NULL, filePath, MAX_PATH)) {
                // Are they in the Windows directory?
                const std::wstring system32_path = L"C:\\Windows\\System32\\";
                if (_wcsnicmp(filePath, system32_path.c_str(), system32_path.length()) == 0) {

                    // Is the process running as SYSTEM
                    if (getIntegrityLevel(hProcess) == 4) {
                        return true;
                    }
                }

                // Are you explorer running in the Windows dir
                const std::wstring explorer_path = L"C:\\Windows\\Explorer.exe";
                if (_wcsnicmp(filePath, explorer_path.c_str(), explorer_path.length()) == 0) {

                    // Is the process running as MEDIUM (which Explorer does)
                    if (getIntegrityLevel(hProcess) == 2) {
                        return true;
                    }
                }
            }
        }
        break;
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

// Format the activity log lines
std::wstring logFormatAction(DWORD pid, const std::wstring& imageName, const std::wstring& cmdLine, const std::wstring& comment = L"done") {
    const std::string timeString = getTimeStamp();
    const std::wstring timeStringW(timeString.cbegin(), timeString.cend());
    std::wstring logLine = timeStringW + L" DETECTED_CMD: '" + cmdLine + L"' IMAGE: '" + imageName + L"' PID: " + std::to_wstring(pid) + L" ACTION: " + comment + L"\n";
    return logLine;
}

std::wstring logFormatLine(const std::wstring& line = L"") {
    const std::string timeString = getTimeStamp();
    const std::wstring timeStringW(timeString.cbegin(), timeString.cend());
    std::wstring logLine = timeStringW + L" " + line + L"\n";
    return logLine;
}

// Log to file
void logSend(const std::wstring& logStr) {
    if (!g_fLogging) {
        return;
    }

    static FILE* logFile = nullptr;
    if (logFile == nullptr)
    {
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

    StringCchCopy(g_wYaraRulesDir, ARRAYSIZE(g_wYaraRulesDir), g_wRaccineDirectory);

    const wchar_t* LoggingKeys[] = { RACCINE_REG_CONFIG , RACCINE_REG_POICY_CONFIG };

    HKEY hKey = NULL;
    for (int i = 0; i < ARRAYSIZE(LoggingKeys); i++)
    {
        if (ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE, LoggingKeys[i], 0, KEY_READ, &hKey))
        {
            // GUI Settings
            DWORD dwGuiSettings = 0;
            DWORD cbDataGUI = sizeof(dwGuiSettings);
            if (ERROR_SUCCESS == RegQueryValueExW(hKey, L"GUI", NULL, NULL, (LPBYTE)&dwGuiSettings, &cbDataGUI))
            {
                g_fGuiSettings = dwGuiSettings;  // This can be a bitmask
            }
            // Logging Settings
            DWORD dwLoggingOnly = 0;
            DWORD cbDataLO = sizeof(dwLoggingOnly);
            if (ERROR_SUCCESS == RegQueryValueExW(hKey, L"Logging", NULL, NULL, (LPBYTE)&dwLoggingOnly, &cbDataLO))
            {
                if (dwLoggingOnly > 0)
                {
                    g_fLogging = TRUE;
                }
            }
            // Simulation Only
            DWORD dwSimulationOnly = 0;
            DWORD cbDataSIM = sizeof(dwSimulationOnly);
            if (ERROR_SUCCESS == RegQueryValueExW(hKey, L"SimulationOnly", NULL, NULL, (LPBYTE)&dwSimulationOnly, &cbDataSIM))
            {
                if (dwSimulationOnly > 0) {
                    // Yara rules dir
                    cbData = sizeof(g_wYaraRulesDir);
                }

                if (ERROR_SUCCESS == RegQueryValueExW(hKey, RACCINE_YARA_RULES_PATH, NULL, NULL, (LPBYTE)g_wYaraRulesDir, &cbData))
                {
                    g_fSimulationOnly = TRUE;
                }
                
            }
            RegCloseKey(hKey);
        }
    }
}

void RaccineAlert()
{
    SendMessage(g_Hwnd, WM_APPCOMMAND, 0, APPWM_ALERT);
    ShowWindow(g_Hwnd, SW_SHOW);
}

DWORD WINAPI WorkerThread(LPVOID lpParameter)
{
    DWORD pids[1024] = { 0 };
    uint8_t c = 0;
    DWORD pid = GetCurrentProcessId();
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    setlocale(LC_ALL, "");

    if (g_fGuiSettings & RACCINE_SHOW_CONSOLE)
    {
        // create the console
        if (AllocConsole())
        {
            FILE* pCout = nullptr;
            freopen_s(&pCout, "CONOUT$", "w", stdout);
            SetConsoleTitle(L"Racine Logging Console");
        }
    }

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
    WCHAR encodedCommands[7][9] = { L"JAB", L"SQBFAF", L"SQBuAH", L"SUVYI", L"cwBhA", L"aWV4I", L"aQBlAHgA" };

    // Log
    std::wstring sCommandLine;
    WCHAR wMessage[MAX_MESSAGE] = { 0 };

    // Append all original command line parameters to a string for later log messages
    for (int i = 1; i < argc; i++) sCommandLine.append(std::wstring(argv[i]).append(L" "));

    LPWSTR szYaraOutput = NULL;  // if assigned, call LocalFree on it.
    BOOL fYaraRuleMatched = EvaluateYaraRules((LPWSTR)sCommandLine.c_str(), &szYaraOutput);
    if (fYaraRuleMatched)
    {
        bBlock = true;
    }

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
        if (!g_fSimulationOnly) {
            // Eventlog
            StringCchPrintf(wMessage, ARRAYSIZE(wMessage), L"Raccine detected malicious activity:\n%s\r\n", lpMessage);
            WriteEventLogEntryWithId((LPWSTR)wMessage, RACCINE_EVENTID_MALICIOUS_ACTIVITY);
            // Log to the text log file
            sListLogs.append(logFormat(sCommandLine, L"Raccine detected malicious activity\r\n"));

        }
        else {
            // Eventlog
            StringCchPrintf(wMessage, ARRAYSIZE(wMessage), L"Raccine detected malicious activity:\n%s\n(simulation mode)\r\n", lpMessage);
            WriteEventLogEntryWithId((LPWSTR)wMessage, RACCINE_EVENTID_MALICIOUS_ACTIVITY);
            // Log to the text log file
            sListLogs.append(logFormat(sCommandLine, L"Raccine detected malicious activity (simulation mode)\r\n"));
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
        if (g_fGuiSettings & RACCINE_SHOW_ALERT) {
            RaccineAlert();
        }
    }

    // If block and not simulation mode
    if (bBlock && !g_fSimulationOnly) {
        // Collect PIDs to kill
        while (c < 1024) {
            pid = getParentPid(pid);
            if (pid == 0) {
                break;
            }
            if (!isAllowListed(pid)) {
                wprintf(L"\nCollecting PID %d for a kill\n", pid);
                pids[c] = pid;
                c++;
            }
            else {
                wprintf(L"\nProcess with PID %d is on allowlist\n", pid);
                sListLogs.append(logFormatAction(pid, sCommandLine, L"Whitelisted"));
            }
        }

        // Loop over collected PIDs and try to kill the processes
        for (uint8_t i = c; i > 0; --i) {
            // If no simulation flag is set
            if (!g_fSimulationOnly) {
                // Kill
                wprintf(L"Kill PID %d\n", pids[i - 1]);
                killProcess(pids[i - 1], 1);
                sListLogs.append(logFormatAction(pids[i - 1], sCommandLine, L"Terminated"));
            }
            else {
                // Simulated kill
                wprintf(L"Simulated Kill PID %d\n", pids[i - 1]);
                sListLogs.append(logFormatAction(pids[i - 1], sCommandLine, L"Terminated (Simulated)"));
            }
        }
        // Finish message
        wprintf(L"\nRaccine v%s finished\n", VERSION);
        Sleep(5000);
    }

    // Otherwise launch the process with its original parameters
    // Conditions:
    // a.) not block or
    // b.) simulation mode
    if (!bBlock || g_fSimulationOnly) {
        std::wstring sCommandLineStr;

        for (int i = 1; i < argc; i++) sCommandLineStr.append(std::wstring(argv[i]).append(L" "));

        STARTUPINFO info = { sizeof(info) };
        PROCESS_INFORMATION processInfo = { 0 };

        if (CreateProcessW(NULL, (LPWSTR)sCommandLineStr.c_str(), NULL, NULL, TRUE, DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &info, &processInfo))
        {
            DebugActiveProcessStop(processInfo.dwProcessId);
            WaitForSingleObject(processInfo.hProcess, INFINITE);
            CloseHandle(processInfo.hProcess);
            CloseHandle(processInfo.hThread);
        }
    }

    // Log events
    logSend(sListLogs);

    if (argv)
    {
        LocalFree(argv);
        argv = NULL;
    }
    PostMessage(g_Hwnd, APPWM_WORKERDONE, 0, 0);

    return 0;
}

int WINAPI wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nShowCmd)
{
    g_hInst = hInstance;

    InitializeSettings();

    WNDCLASSEX wcex = { sizeof(wcex) };
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDCICON));
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground = reinterpret_cast<HBRUSH>((COLOR_WINDOW + 1));
    wcex.lpszMenuName = NULL;
    wcex.lpszClassName = szWindowClass;
    RegisterClassEx(&wcex);

    const HWND hwnd = CreateWindow(szWindowClass, RACCINE_TOOLTIP, WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, 0, DEFAULT_WIDTH, DEFAULT_HEIGHT, NULL, NULL, hInstance, NULL);

    g_Hwnd = hwnd;
    SendMessageW(g_Hwnd, WM_APPCOMMAND, 0, APPWM_ALERT);

    DWORD dwThreadId = 0;
    const ThreadHandleWrapper hWorkerThread = CreateThread(
        NULL,
        0,
        WorkerThread,
        NULL,
        0,
        &dwThreadId);

    if (!hWorkerThread) {
        return 0;
    }

    if (hwnd)
    {
        ShowWindow(hwnd, SW_HIDE);

        // Main message loop:
        MSG msg{};
        while (GetMessage(&msg, NULL, 0, 0))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return 0;
}
