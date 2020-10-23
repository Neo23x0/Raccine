#include "Utils.h"

#include <algorithm>

std::wstring utils::to_lower(const std::wstring& input)
{
    std::wstring output = input;
    std::transform(output.begin(), output.end(), output.begin(),
                   [](wchar_t c)->wchar_t { return static_cast<wchar_t>(std::tolower(c)); });
    return output;
}
