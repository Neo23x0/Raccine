#pragma once
#include <string>

namespace utils
{
    std::wstring to_lower(const std::wstring& input);

    std::wstring expand_environment_strings(const std::wstring& input);
}
