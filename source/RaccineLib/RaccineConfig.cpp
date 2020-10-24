#include "RaccineConfig.h"

#include <Shlwapi.h>
#include <strsafe.h>

#include "Utils.h"

RaccineConfig::RaccineConfig() :
    m_log_only(read_flag_from_registry(L"LogOnly")),
    m_show_gui(read_flag_from_registry(L"ShowGui"))
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

std::vector<std::filesystem::path> RaccineConfig::get_raccine_registry_paths()
{
    return { RACCINE_REG_CONFIG, RACCINE_REG_POLICY_CONFIG };
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
