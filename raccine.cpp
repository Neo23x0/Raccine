// Raccine 
// A Simple Ransomware Vaccine
// https://github.com/Neo23x0/Raccine
//
// Florian Roth, Ollie Whitehouse, Branislav Djalic, John Lambert
// with help of Hilko Bengen

#include "source/RaccineLib/Raccine.h"
#include "source/RaccineLib/Utils.h"

#include <Shlwapi.h>
#include <strsafe.h>

int wmain(int argc, WCHAR* argv[])
{
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
    bool bPowerShellWorkaround = false;

    HANDLE hThread = INVALID_HANDLE_VALUE;
    HANDLE hProcess = INVALID_HANDLE_VALUE;
    DWORD dwChildPid = 0;

    // Encoded Command List (Base64)
    WCHAR encodedCommands[11][9] = { L"JAB", L"SQBFAF", L"SQBuAH", L"SUVYI", L"cwBhA", L"aWV4I", L"aQBlAHgA",
                                     L"cwB", L"IAA", L"IAB", L"UwB" };

    // Log
    std::wstring sCommandLine;
    std::wstring sListLogs;
    WCHAR wMessage[MAX_MESSAGE] = { 0 };

    // Append all original command line parameters to a string for later log messages
    for (int i = 1; i < argc; i++) {
        sCommandLine.append(std::wstring(argv[i]).append(L" "));
    }

    LPWSTR szCommandLine = (LPWSTR)sCommandLine.c_str();
    if (StrStrI(szCommandLine, L"-File ") != NULL
        && StrStrI(szCommandLine, L".ps") != NULL
        && StrStrI(szCommandLine, L"powershell") == NULL)
    {
        bPowerShellWorkaround = true;
    }

    // Launch the new child in a suspended state (CREATE_SUSPENDED)
    // this will allow yara rules to run against this process
    // if we should block, we will terminate it later
    std::wstring sCommandLineStr = sCommandLine;
    if (bPowerShellWorkaround) {
        sCommandLineStr = std::wstring(L"powershell.exe ").append(sCommandLine);
    }

    createChildProcessWithDebugger(sCommandLineStr, CREATE_SUSPENDED, &dwChildPid, &hProcess, &hThread);
    Sleep(300);

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

    std::wstring szYaraOutput;
    BOOL fYaraRuleMatched = EvaluateYaraRules(static_cast<LPWSTR>(sCommandLine.data()), szYaraOutput, dwChildPid);

    if (fYaraRuleMatched) {
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
            StringCchPrintfW(wMessage, ARRAYSIZE(wMessage), L"Raccine detected malicious activity:\n%s\n", lpMessage);
            // Log to the text log file
            sListLogs.append(logFormat(sCommandLine, L"Raccine detected malicious activity"));
        }
        else {
            // Eventlog
            StringCchPrintfW(wMessage, ARRAYSIZE(wMessage), L"Raccine detected malicious activity:\n%s\n(simulation mode)", lpMessage);
            // Log to the text log file
            sListLogs.append(logFormat(sCommandLine, L"Raccine detected malicious activity (simulation mode)"));
        }

        WriteEventLogEntryWithId(static_cast<LPWSTR>(wMessage), RACCINE_EVENTID_MALICIOUS_ACTIVITY);


        // YARA Matches Detected
        if (fYaraRuleMatched && !szYaraOutput.empty()) {
            StringCchPrintfW(wMessage, ARRAYSIZE(wMessage), L"\r\nYara matches:\r\n%s", szYaraOutput.c_str());
            WriteEventLogEntryWithId(static_cast<LPWSTR>(wMessage), RACCINE_EVENTID_MALICIOUS_ACTIVITY);
            sListLogs.append(logFormatLine(szYaraOutput));
        }

        // signal Event for UI to know an alert happened.  If no UI is running, this has no effect.
        if (g_fShowGui) {
            HANDLE hEvent = OpenEvent(EVENT_MODIFY_STATE, FALSE, L"RaccineAlertEvent");
            if (hEvent != NULL) {
                if (!SetEvent(hEvent)) {
                    //didn't go through
                }
                CloseHandle(hEvent);
            }
        }
    }

    // If block and not simulation mode
    if (bBlock && !g_fLogOnly) {
        find_and_kill_processes(sCommandLine, sListLogs);
    }


    // if we're in simulation mode or we didn't need to block the process, let it run
    if (g_fLogOnly || !bBlock)
    {
        if (hThread != INVALID_HANDLE_VALUE && hProcess != INVALID_HANDLE_VALUE)
        {

            ResumeThread(hThread);
            WaitForSingleObject(hProcess, INFINITE);
            CloseHandle(hThread);
            CloseHandle(hProcess);
        }
    }
    else
    {
        if (bBlock)
        {
            killProcess(dwChildPid, 1);
            CloseHandle(hThread);
            CloseHandle(hProcess);
        }
    }

    // Log events
    logSend(sListLogs);

    return 0;
}
