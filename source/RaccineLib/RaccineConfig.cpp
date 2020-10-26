#include "RaccineConfig.h"

#include <Shlwapi.h>
#include <strsafe.h>


#include "Raccine.h"
#include "Utils.h"

RaccineConfig::RaccineConfig() :
    m_log_only(read_flag_from_registry(L"LogOnly")),
    m_show_gui(read_flag_from_registry(L"ShowGui")),
    m_yara_rules_directory(get_yara_rules_directory())
{
}

bool RaccineConfig::log_only() const
{
    return m_log_only;
}

bool RaccineConfig::show_gui() const
{
    return m_show_gui;
}

std::wstring RaccineConfig::yara_rules_directory() const
{
    return m_yara_rules_directory;
}

std::vector<std::filesystem::path> RaccineConfig::get_raccine_registry_paths()
{
    return { RACCINE_REG_CONFIG, RACCINE_REG_POLICY_CONFIG };
}

std::wstring RaccineConfig::get_yara_rules_directory()
{
    std::wstring yara_directory = read_string_from_registry(RACCINE_YARA_RULES_PATH);
    if (!yara_directory.empty()) {
        return yara_directory;
    }

    return utils::expand_environment_strings(RACCINE_DATA_DIRECTORY);
}

bool RaccineConfig::read_flag_from_registry(const std::wstring& flag_name)
{
    for (const std::filesystem::path& registry_path : get_raccine_registry_paths()) {
        std::optional<DWORD> value = read_from_registry(registry_path, flag_name);
        if (value.has_value()) {
            return value.value() > 0;
        }
    }

    return false;
}

std::wstring RaccineConfig::read_string_from_registry(const std::wstring& string_name)
{
    for (const std::filesystem::path& registry_path : get_raccine_registry_paths()) {
        std::optional<std::wstring> value = read_string_from_registry(registry_path, string_name);
        if (value.has_value()) {
            return value.value();
        }
    }

    return L"";
}

std::optional<DWORD> RaccineConfig::read_from_registry(const std::wstring& key_path,
                                                       const std::wstring& value_name)
{
    constexpr std::nullptr_t NO_TYPE = nullptr;
    DWORD result;
    DWORD size = sizeof result;

    const LSTATUS status = RegGetValueW(HKEY_LOCAL_MACHINE,
                                        key_path.c_str(),
                                        value_name.c_str(),
                                        RRF_RT_DWORD,
                                        NO_TYPE,
                                        &result,
                                        &size);
    if (status != ERROR_SUCCESS) {
        return std::nullopt;
    }

    return result;
}

std::optional<std::wstring> RaccineConfig::read_string_from_registry(const std::wstring& key_path,
                                                                     const std::wstring& value_name)
{
    constexpr std::nullptr_t NO_TYPE = nullptr;
    std::wstring result;
    DWORD size = 0;

    constexpr DWORD RESTRICT_TO_REG_SZ = RRF_RT_REG_SZ;

    LSTATUS status = RegGetValueW(HKEY_LOCAL_MACHINE,
                                  key_path.c_str(),
                                  value_name.c_str(),
                                  RESTRICT_TO_REG_SZ,
                                  NO_TYPE,
                                  result.data(),
                                  &size);
    if (status != ERROR_MORE_DATA) {
        return std::nullopt;
    }

    result.resize(size);

    status = RegGetValueW(HKEY_LOCAL_MACHINE,
                          key_path.c_str(),
                          value_name.c_str(),
                          RRF_RT_REG_SZ,
                          NO_TYPE,
                          result.data(),
                          &size);
    if (status != ERROR_SUCCESS) {
        return std::nullopt;
    }

    result.erase(std::find(result.begin(), result.end(), '\0'), result.end());

    return result;
}
