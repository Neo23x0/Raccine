#include "pch.h"

#include "../../source/RaccineLib/Utils.h"

TEST(TestUtils, ToLower)
{
    const std::wstring input = L"HellO WoRld";
    std::wstring excepted_output = L"hello world";
    EXPECT_EQ(excepted_output, utils::to_lower(input));
}