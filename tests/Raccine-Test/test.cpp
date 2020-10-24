#include "pch.h"



#include "../../source/RaccineLib/HandleWrapper.h"
#include "../../source/RaccineLib/Raccine.h"
#include "../../source/RaccineLib/Utils.h"

TEST(TestUtils, ToLower)
{
    const std::wstring input = L"HellO WoRld";
    std::wstring excepted_output = L"hello world";
    EXPECT_EQ(excepted_output, utils::to_lower(input));
}

TEST(TestGetImageName, System)
{
    std::wstring image_name = getImageName(4);
    ASSERT_EQ(image_name, L"System");
}

TEST(TestGetImageName, NonExistant)
{
    std::wstring image_name = getImageName(3);
    ASSERT_EQ(image_name, L"(unavailable)");
}

TEST(TestGetImageName, CurrentProcess)
{
    std::wstring image_name = getImageName(GetCurrentProcessId());
    ASSERT_EQ(image_name, L"Raccine-Test.exe");
}

TEST(TestGetParentPid, System)
{
    DWORD parent_pid = getParentPid(4);
    ASSERT_EQ(parent_pid, 0);
}

TEST(TestGetParentPid, NonExistant)
{
    DWORD parent_pid = getParentPid(3);
    ASSERT_EQ(parent_pid, 0);
}

TEST(TestGetIntegrityLevel, CurrentProcess)
{
    ProcessHandleWrapper hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 
                                                FALSE, 
                                                GetCurrentProcessId());
    if (!hProcess) {
        FAIL() << "Failed to open process";
    }

    Integrity integrity = getIntegrityLevel(hProcess);
    EXPECT_TRUE(integrity == Integrity::Medium || integrity == Integrity::High);
}
