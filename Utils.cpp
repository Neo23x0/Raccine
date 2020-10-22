#include "Utils.h"

#include <algorithm>

std::wstring utils::to_lower(const std::wstring& input)
{
    std::wstring output = input;
    std::transform(input.begin(), input.end(), output.begin(), ::tolower);
    return output;
}
