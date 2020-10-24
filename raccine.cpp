// Raccine 
// A Simple Ransomware Vaccine
// https://github.com/Neo23x0/Raccine
//
// Florian Roth, Ollie Whitehouse, Branislav Djalic, John Lambert
// with help of Hilko Bengen

#include "source/RaccineLib/Raccine.h"

#include <Shlwapi.h>
#include <strsafe.h>

int wmain(int argc, WCHAR* argv[])
{
    setlocale(LC_ALL, "");


    // Log
    std::vector<std::wstring> command_line;
    std::wstring sCommandLine;
    std::wstring sListLogs;
    WCHAR wMessage[MAX_MESSAGE] = { 0 };

    // Append all original command line parameters to a string for later log messages
    for (int i = 1; i < argc; i++) {
        sCommandLine.append(std::wstring(argv[i]).append(L" "));
        command_line.emplace_back(argv[i]);
    }

    InitializeSettings();

    bool bBlock = is_malicious_command_line(command_line);

    std::wstring szYaraOutput;
    const bool fYaraRuleMatched = EvaluateYaraRules(sCommandLine, szYaraOutput);

    if (fYaraRuleMatched) {
        bBlock = true;
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
        } else {
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

    // Otherwise launch the process with its original parameters
    // Conditions:
    // a.) not block or
    // b.) simulation mode
    if (!bBlock || g_fLogOnly) {
        std::wstring sCommandLineStr = sCommandLine;
        if (needs_powershell_workaround(sCommandLine)) {
            sCommandLineStr = std::wstring(L"powershell.exe ").append(sCommandLine);
        }

        createChildProcessWithDebugger(sCommandLineStr);
    }

    // Log events
    logSend(sListLogs);

    return 0;
}
