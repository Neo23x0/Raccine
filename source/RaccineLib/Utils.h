#pragma once
#include <string>
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include "HandleWrapper.h"
#include <array>
#include <StrSafe.h>
#include <wbemidl.h>
#include <comdef.h>

namespace utils
{

    class ProcessDetail final
    {
    public:
        ProcessDetail(DWORD dwPid);

        ~ProcessDetail() = default;

        std::wstring ToString(std::wstring szPrefix);

    private:
        struct PROCESS_DETAIL
        {
            DWORD dwPid;
            std::wstring ExeName;
            std::wstring ExePath;
            std::wstring CommandLine;
            UINT HandleCount;
            UINT Priority;
            UINT SecondsSinceExeCreation;
        };
        PROCESS_DETAIL ProcessDetailStruct;
    };

    enum class Integrity
    {
        Error = 0, // Indicates integrity level could not be found
        Low = 1,
        Medium = 2,
        High = 3,
        System = 4,

    };
    std::wstring to_lower(const std::wstring& input);

    bool isProcessAllowed(const PROCESSENTRY32W& pe32);

    std::wstring getImageName(DWORD pid);

    std::wstring getImageEXEPath(DWORD pid);

    Integrity getIntegrityLevel(HANDLE hProcess);

    DWORD getParentPid(DWORD pid);

    BOOL killProcess(DWORD dwProcessId, UINT uExitCode);

    std::wstring GetProcessCommandLine(DWORD pid);

    DWORD GetPriorityClassByPid( DWORD pid );

}
