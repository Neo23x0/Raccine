// Raccine 
// A Simple Ransomware Vaccine
// https://github.com/Neo23x0/Raccine
//
// Florian Roth, Ollie Whitehouse, Branislav Djalic, John Lambert
// with help of Hilko Bengen

#include "RaccineLib/Raccine.h"

#include <Shlwapi.h>

#include "RaccineLib/RaccineConfig.h"
#include "RaccineLib/Utils.h"

int wmain(int argc, WCHAR* argv[])
{
    setlocale(LC_ALL, "");

    std::vector<std::wstring> command_line;
    std::wstring sCommandLine;

    // Append all original command line parameters to a string for later log messages
    for (int i = 1; i < argc; i++) {
        sCommandLine.append(std::wstring(argv[i]).append(L" "));
        command_line.emplace_back(argv[i]);
    }

    const RaccineConfig configuration;

    // Launch the new child in a suspended state (CREATE_SUSPENDED)
    // this will allow yara rules to run against this process
    // if we should block, we will terminate it later

    //skip argv[0] and create a new command line string from our argv,
    //if we get a quoted path for the exe back, adjust the command line to skip past that.
    LPWSTR lpzchildCommandLine = GetCommandLine() + (wcslen(argv[0]) + 1);
    const std::wstring originalCommandLine(GetCommandLine());
    if (originalCommandLine.starts_with(L"\"") && (wcslen(argv[0]) + 3) < originalCommandLine.length())
        lpzchildCommandLine = GetCommandLine() + (wcslen(argv[0]) + 3);
    if (needs_powershell_workaround(sCommandLine)) {
        lpzchildCommandLine = static_cast<LPWSTR>(std::wstring(L"powershell.exe ").append(sCommandLine).data());
    }

    auto [dwChildPid, hProcess, hThread] = createChildProcessWithDebugger(lpzchildCommandLine, CREATE_SUSPENDED);
    // TODO: What happens if the process isn't created?

    const DWORD dwParentPid = utils::getParentPid(GetCurrentProcessId());

    const DWORD dwGrandParentPid = utils::getParentPid(dwParentPid); // parent of parent of raccine.exe

    bool bBlock = is_malicious_command_line(command_line);

    std::wstring szYaraOutput;
    const bool fYaraRuleMatched = EvaluateYaraRules(configuration,
        sCommandLine,
        szYaraOutput,
        dwChildPid,
        dwParentPid,
        dwGrandParentPid);

    if (fYaraRuleMatched) {
        bBlock = true;
    }

    std::wstring sListLogs;

    // If activity that should be block has been registered (always log)
    if (bBlock) {
        std::wstring message;
        // Log to the windows Eventlog
        if (!configuration.log_only()) {
            // Eventlog
            message = L"Raccine detected malicious activity:\r\n" + sCommandLine + L"\r\n";
            // Log to the text log file
            sListLogs.append(logFormat(sCommandLine, L"Raccine detected malicious activity"));
        }
        else {
            // Eventlog
            message = L"Raccine detected malicious activity:\r\n" + sCommandLine + L"\r\n(simulation mode)";
            // Log to the text log file
            sListLogs.append(logFormat(sCommandLine, L"Raccine detected malicious activity (simulation mode)"));
        }


        // YARA Matches Detected
        if (fYaraRuleMatched && !szYaraOutput.empty()) {
              message += L"\r\n\r\nYara matches:\r\n" + szYaraOutput;
            sListLogs.append(logFormatLine(szYaraOutput));
        }

        const utils::ProcessDetail details(dwChildPid);
        std::wstring context = L"\r\n\r\nRaccine Context:\r\n" + details.ToPrintedString(L"Child");
        const utils::ProcessDetail detailsParent(dwParentPid);
        context += detailsParent.ToPrintedString(L"Parent");
        const utils::ProcessDetail detailsGrandParent(dwGrandParentPid);
        context += detailsGrandParent.ToPrintedString(L"GrandParent");
        message += context;
    
        WriteEventLogEntryWithId(message, RACCINE_EVENTID_MALICIOUS_ACTIVITY);

        // signal Event for UI to know an alert happened.  If no UI is running, this has no effect.
        if (configuration.show_gui()) {
            trigger_gui_event();
        }
    }

    // If block and not simulation mode
    if (bBlock && !configuration.log_only()) {
        find_and_kill_processes(configuration.log_only(), sCommandLine, sListLogs);
    }


    // if we're in simulation mode or we didn't need to block the process, let it run
    if (configuration.log_only() || !bBlock) {
        if (hThread != INVALID_HANDLE_VALUE && hProcess != INVALID_HANDLE_VALUE) {

            ResumeThread(hThread);
            WaitForSingleObject(hProcess, INFINITE);
        }
    }
    else {
        if (bBlock) {
            utils::killProcess(dwChildPid, 1);
        }
    }

    // Log events
    logSend(sListLogs);

    return 0;
}
