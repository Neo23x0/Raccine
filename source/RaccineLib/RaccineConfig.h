#pragma once
#include <filesystem>
#include <strsafe.h>
#include <optional>

#define RACCINE_REG_CONFIG  L"SOFTWARE\\Raccine"
#define RACCINE_REG_POLICY_CONFIG  L"SOFTWARE\\Policies\\Raccine"
#define RACCINE_YARA_RULES_PATH L"RulesDir"

//
//  Query for config in HKLM and HKLM\Software\Policies override by GPO
//
class RaccineConfig final
{
public:

    RaccineConfig();

    ~RaccineConfig() = default;

    [[nodiscard]] bool log_only() const;
    [[nodiscard]] bool show_gui() const;
    [[nodiscard]] std::wstring yara_rules_directory() const;

    RaccineConfig(const RaccineConfig&) = delete;
    RaccineConfig& operator=(const RaccineConfig&) = delete;
    RaccineConfig(RaccineConfig&&) = delete;
    RaccineConfig& operator=(RaccineConfig&&) = delete;

private:

    static std::vector<std::filesystem::path> get_raccine_registry_paths();
    static std::wstring get_yara_rules_directory();

    static bool read_flag_from_registry(const std::wstring& flag_name);
    static std::wstring read_string_from_registry(const std::wstring& string_name);

    static std::optional<DWORD> read_from_registry(const std::wstring& key_path,
                                                   const std::wstring& value_name);

    static std::optional<std::wstring> read_string_from_registry(const std::wstring& key_path,
                                                                 const std::wstring& value_name);

    const bool m_log_only;
    const bool m_show_gui;
    std::wstring m_yara_rules_directory;
};
