#pragma once
#include <filesystem>
#include <strsafe.h>
#include <optional>

#define RACCINE_REG_CONFIG  L"SOFTWARE\\Raccine"
#define RACCINE_REG_POLICY_CONFIG  L"SOFTWARE\\Policies\\Raccine"

class RaccineConfig final
{
public:

    RaccineConfig();

    ~RaccineConfig() = default;

    [[nodiscard]] bool log_only() const;
    [[nodiscard]] bool show_gui() const;

    RaccineConfig(const RaccineConfig&) = delete;
    RaccineConfig& operator=(const RaccineConfig&) = delete;
    RaccineConfig(RaccineConfig&&) = delete;
    RaccineConfig& operator=(RaccineConfig&&) = delete;

private:

    static std::vector<std::filesystem::path> get_raccine_registry_paths();

    static bool read_flag_from_registry(const std::wstring& flag_name);

    static std::optional<DWORD> read_from_registry(const std::wstring& key_path, 
                                                   const std::wstring& value_name);

    const bool m_log_only;
    const bool m_show_gui;
};
