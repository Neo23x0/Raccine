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

    const Integrity integrity = getIntegrityLevel(hProcess);
    EXPECT_TRUE(integrity == Integrity::Medium || integrity == Integrity::High);
}

TEST(TestExpandEnvironmentStrings, RaccineDataDirectory)
{
    std::wstring result = utils::expand_environment_strings(RACCINE_DATA_DIRECTORY);
    EXPECT_EQ(result, L"C:\\ProgramData\\Raccine");
}

TEST(TestFindProcessesToKill, Parent)
{
    const std::wstring command_line = L"TEST_COMMAND_LINE";
    std::wstring logs;
    const std::set<DWORD> pids = find_processes_to_kill(command_line, logs);
    EXPECT_FALSE(pids.empty());

    const DWORD parent_pid = getParentPid(GetCurrentProcessId());
    EXPECT_TRUE(pids.contains(parent_pid));

    // TODO: test logs output
}

TEST(TestFindProcessesToKill, System)
{
    const std::wstring command_line = L"TEST_COMMAND_LINE";
    std::wstring logs;
    const std::set<DWORD> pids = find_processes_to_kill(command_line, logs);
    EXPECT_FALSE(pids.empty());

    EXPECT_FALSE(pids.contains(4));
}

TEST(TestFindProcessesToKill, NonExistant)
{
    const std::wstring command_line = L"TEST_COMMAND_LINE";
    std::wstring logs;
    const std::set<DWORD> pids = find_processes_to_kill(command_line, logs);
    EXPECT_FALSE(pids.empty());

    EXPECT_FALSE(pids.contains(3));
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