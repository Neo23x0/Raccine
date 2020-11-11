#pragma once
#include <filesystem>
#include <strsafe.h>
#include <optional>

#define RACCINE_REG_CONFIG  L"SOFTWARE\\Raccine"
#define RACCINE_REG_POLICY_CONFIG  L"SOFTWARE\\Policies\\Raccine"

constexpr wchar_t RACCINE_YARA_RULES_PATH[] = L"RulesDir";
constexpr wchar_t RACCINE_YARA_SCAN_MEMORY[] = L"ScanMemory";
constexpr wchar_t RACCINE_CONFIG_SHOW_GUI[] = L"ShowGui";
constexpr wchar_t RACCINE_CONFIG_LOG_ONLY[] = L"LogOnly";
constexpr wchar_t RACCINE_CONFIG_EVENTLOG_DATA_IN_RULES[] = L"EventlogRules";
constexpr wchar_t RACCINE_CONFIG_DEBUG[] = L"Debug";
constexpr wchar_t RACCINE_YARA_RULES_PATH_INMEMORY_PATH[] = L"in-memory";
//
//  Query for config in HKLM and HKLM\Software\Policies override by GPO
//
class 
    RaccineConfig final
{
public:

    RaccineConfig();

    ~RaccineConfig() = default;

    [[nodiscard]] bool log_only() const;
    [[nodiscard]] bool show_gui() const;
    [[nodiscard]] bool is_debug_mode() const;
    [[nodiscard]] bool use_eventlog_data_in_rules() const;
    [[nodiscard]] std::wstring yara_rules_directory() const;
    [[nodiscard]] std::wstring yara_in_memory_rules_directory() const;
    [[nodiscard]] bool scan_memory() const;

    RaccineConfig(const RaccineConfig&) = delete;
    RaccineConfig& operator=(const RaccineConfig&) = delete;
    RaccineConfig(RaccineConfig&&) = delete;
    RaccineConfig& operator=(RaccineConfig&&) = delete;

private:

    static std::vector<std::filesystem::path> get_raccine_registry_paths();
    static std::wstring get_yara_rules_directory();
    static std::wstring get_yara_in_memory_rules_directory();

    static bool read_flag_from_registry(const std::wstring& flag_name);
    static std::wstring read_string_from_registry(const std::wstring& string_name);

    static std::optional<DWORD> read_from_registry(const std::wstring& key_path,
                                                   const std::wstring& value_name);

    static std::optional<std::wstring> read_string_from_registry(const std::wstring& key_path,
                                                                 const std::wstring& value_name);

    const bool m_log_only;
    const bool m_show_gui;
    const bool m_is_debug_mode;
    const bool m_scan_memory;
    const bool m_use_eventlog_data_in_rules;
    std::wstring m_yara_rules_directory;
    std::wstring m_yara_in_memory_rules_directory;
};
