#include "Utils.h"

#include <algorithm>
#include <Shlwapi.h>
#include <vector>

namespace utils
{

std::wstring to_lower(const std::wstring& input)
{
    std::wstring output = input;
    std::transform(output.begin(), output.end(), output.begin(),
                   [](wchar_t c)->wchar_t { return static_cast<wchar_t>(std::tolower(c)); });
    return output;
}

std::wstring expand_environment_strings(const std::wstring& input)
{
    constexpr size_t MAX_STRING_SIZE = 2 << 15;
    std::vector<wchar_t> output(MAX_STRING_SIZE, 0);
    const DWORD ret = ExpandEnvironmentStringsW(input.c_str(),
                                                output.data(),
                                                static_cast<DWORD>(output.size()));
    if(ret == 0) {
        return input;
    }

    return std::wstring(output.data());
}

}
