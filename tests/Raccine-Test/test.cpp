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


TEST(TestIsMaliciousCommandLine, VssAdmin)
{
    EXPECT_FALSE(is_malicious_command_line({ L"vssadmin.exe"}));
    EXPECT_FALSE(is_malicious_command_line({ L"vssadmin.exe", L"delete"}));
    EXPECT_FALSE(is_malicious_command_line({ L"vssadmin.exe", L"shadows"}));
    EXPECT_FALSE(is_malicious_command_line({ L"vssadmin", L"resize", L"shadows" }));

    EXPECT_TRUE(is_malicious_command_line({ L"vssadmin.exe", L"delete", L"shadows" }));
    EXPECT_TRUE(is_malicious_command_line({ L"vssadmin", L"delete", L"shadows" }));
    EXPECT_TRUE(is_malicious_command_line({ L"Vssadmin", L"dElete", L"shAdows" }));
    EXPECT_TRUE(is_malicious_command_line({ L"vssadmin", L"shadows", L"delete" }));
    EXPECT_TRUE(is_malicious_command_line({ L"vssadmin", L"delete", L"shadowstorage" }));

    EXPECT_TRUE(is_malicious_command_line({ L"vssadmin", L"resize", L"shadowstorage" }));
}

TEST(TestIsMaliciousCommandLine, Empty)
{
    const std::vector<std::wstring> command_line;
    EXPECT_FALSE(is_malicious_command_line(command_line));
}