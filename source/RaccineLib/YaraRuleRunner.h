#pragma once
#include <filesystem>
#include <vector>
#include <Windows.h>
#include "HandleWrapper.h"

#define YARA_RESULTS_SUFFIX L".out"
#define YARA_INSTANCE  L"yara64.exe"
constexpr UINT TIMEOUT = 5000;

class YaraRuleRunner final
{
public:
    [[nodiscard]] YaraRuleRunner(const std::filesystem::path& yara_rules_dir,
                                 const std::filesystem::path& raccine_program_directory);

    ~YaraRuleRunner() = default;

    [[nodiscard]] bool run_yara_rules_on_file(const std::filesystem::path& target_file,
                                              const std::wstring& command_line,
                                              std::wstring& out_yara_output,
                                              std::wstring& yara_cmd_optional_defines);
    
    [[nodiscard]] bool run_yara_rules_on_process(const DWORD dwPid,
                                            const std::wstring& command_line,
                                            std::wstring& out_yara_output,
                                            std::wstring& yara_cmd_optional_defines);

    // Deleted functions
    YaraRuleRunner(const YaraRuleRunner&) = delete;
    YaraRuleRunner& operator=(const YaraRuleRunner&) = delete;
    YaraRuleRunner(YaraRuleRunner&&) = delete;
    YaraRuleRunner& operator=(YaraRuleRunner&&) = delete;

private:

    bool run_yara_rule_on_file(const std::filesystem::path& yara_rule,
                               const std::filesystem::path& target_file,
                               const std::wstring& command_line,
                               std::wstring& out_yara_output,
                               std::wstring& yara_cmd_optional_defines);

    bool run_yara_rule_on_process(const std::filesystem::path& yara_rule,
        const DWORD dwPid,
        const std::wstring& command_line,
        std::wstring& out_yara_output,
        std::wstring& yara_cmd_optional_defines);

    bool run_yara_process(std::wstring& command_line, HANDLE writepipe);

    std::wstring read_output_file(const std::filesystem::path& target_file);

    std::vector<std::filesystem::path> get_yara_rules(const std::filesystem::path& yara_rules_dir);

    bool CreateRedirectedOutput(PHANDLE phPipeRead, PHANDLE phPipeWrite);

    std::wstring ReadFromPipe(HANDLE readpipe);

    const std::filesystem::path m_raccine_program_directory;

    std::vector<std::filesystem::path> m_yara_rules;

    FileHandleWrapper m_std_output_read;
    FileHandleWrapper m_std_output_write;
};
