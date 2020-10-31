#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>

namespace utils
{

class ProcessDetail final
{
public:
    ProcessDetail(DWORD pid);

    ~ProcessDetail() = default;

    [[nodiscard]] std::wstring ToString(const std::wstring szPrefix) const;

private:
    struct PROCESS_DETAIL
    {
        DWORD dwPid;
        std::wstring ExeName;
        std::wstring ExePath;
        std::wstring CommandLine;
        ULONG TimeSinceExeCreation;
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

DWORD GetPriorityClassByPid(DWORD pid);

std::wstring expand_environment_strings(const std::wstring& input);

bool write_string_to_file(const std::filesystem::path file_path, const std::wstring& string_to_write);

std::optional<std::string> convert_wstring_to_string(const std::wstring& input);

ULONG getLastWriteTime(std::wstring szFilePath);

}
