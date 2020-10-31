#include "YaraRuleRunner.h"

#include <fstream>
#include <Windows.h>
#include <string>

YaraRuleRunner::YaraRuleRunner(const std::filesystem::path& yara_rules_dir, const std::filesystem::path& raccine_program_directory) :
    m_raccine_program_directory(raccine_program_directory),
    m_yara_rules(get_yara_rules(yara_rules_dir))
{
    m_std_output_read = FileHandleWrapper(INVALID_HANDLE_VALUE);
    m_std_output_write = FileHandleWrapper(INVALID_HANDLE_VALUE);
}

bool YaraRuleRunner::run_yara_rules_on_process(const DWORD dwPid,
                                            const std::wstring& command_line,
                                            std::wstring& out_yara_output,
                                            std::wstring&  yara_cmd_optional_defines)
{
    bool fRetVal = false;
    // run all rules, don't bail out early

    for (const std::filesystem::path& yara_rule : m_yara_rules) 
    {
        //wprintf(L"Running with YARA rule: %s", yara_rule.c_str());
        bool fSuccess = run_yara_rule_on_process(yara_rule, dwPid, command_line, out_yara_output, yara_cmd_optional_defines); 
        if (fSuccess)
            fRetVal = true;
    }

    return fRetVal;
}
bool YaraRuleRunner::run_yara_rules_on_file(const std::filesystem::path& target_file,
                                            const std::wstring& command_line,
                                            std::wstring& out_yara_output,
                                            std::wstring&  yara_cmd_optional_defines)
{
    bool fRetVal = false;
    // run all rules, don't bail out early

    for (const std::filesystem::path& yara_rule : m_yara_rules) 
    {
        //wprintf(L"Running with YARA rule: %s", yara_rule.c_str());
        bool fSuccess = run_yara_rule_on_file(yara_rule, target_file, command_line, out_yara_output, yara_cmd_optional_defines); 
        if (fSuccess)
            fRetVal = true;
    }

    return fRetVal;
}

bool  YaraRuleRunner::CreateRedirectedOutput(PHANDLE phPipeRead, PHANDLE phPipeWrite)
{
    SECURITY_ATTRIBUTES saAttr = { 0 };
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    if (!CreatePipe(phPipeRead, phPipeWrite, &saAttr, 0))
    {
        return false;
    }

    //the read side of the pipe is just for this process, not to be inherited.
    if (!SetHandleInformation(*phPipeRead, HANDLE_FLAG_INHERIT, 0))
    {
        return false;
    }

    return true;
}


bool YaraRuleRunner::run_yara_rule_on_process(const std::filesystem::path& yara_rule,
    const DWORD dwPid,
    const std::wstring& command_line,
    std::wstring& out_yara_output,
    std::wstring& yara_cmd_optional_defines)
{
    std::wstring yara_command_line = L"\"" + m_raccine_program_directory.wstring() + L"\\"
        + YARA_INSTANCE + L"\" \"" + yara_rule.wstring() + L"\" " + std::to_wstring(dwPid) + L" -d MemoryScan=1 " + yara_cmd_optional_defines;


    HANDLE readpipe = INVALID_HANDLE_VALUE;
    HANDLE writepipe = INVALID_HANDLE_VALUE;

    if (!CreateRedirectedOutput(&readpipe, &writepipe))
    {
        return false;
    }

    const bool yara_succeeded = run_yara_process(yara_command_line, writepipe);
    if (!yara_succeeded) {
        return false;
    }

    std::wstring yara_output = ReadFromPipe(readpipe);

    if (yara_output.empty())
    {
        return false;
    }

    out_yara_output = L"Rule file: " + yara_rule.wstring() + L"\r\nYARA Output: " + yara_output + L"\r\n" + L"Command line: " + command_line + L"\r\n";
    return true;
}


bool YaraRuleRunner::run_yara_rule_on_file(const std::filesystem::path& yara_rule,
                                           const std::filesystem::path& target_file,
                                           const std::wstring& command_line,
                                           std::wstring& out_yara_output,
                                           std::wstring& yara_cmd_optional_defines) 
{
    std::wstring yara_command_line = L"\"" + m_raccine_program_directory.wstring() + L"\\"
        + YARA_INSTANCE + L"\" \"" + yara_rule.wstring() + L"\" " + target_file.wstring() + L" " + yara_cmd_optional_defines;


    HANDLE readpipe = INVALID_HANDLE_VALUE;
    HANDLE writepipe = INVALID_HANDLE_VALUE;

    if (!CreateRedirectedOutput(&readpipe, &writepipe))
    {
        return false;
    }

    const bool yara_succeeded = run_yara_process(yara_command_line, writepipe);
    if (!yara_succeeded) {
        return false;
    }

    std::wstring yara_output = ReadFromPipe(readpipe);

    if (yara_output.empty())
    {
        return false;
    }

    out_yara_output = L"Rule file: " + yara_rule.wstring() + L"\r\nYARA Output: " + yara_output + L"\r\n" + L"Command line: " + command_line + L"\r\n";
    return true;
}

bool YaraRuleRunner::run_yara_process(std::wstring& command_line, HANDLE writepipe)
{
    STARTUPINFO info{};
    info.cb = sizeof info;
    info.hStdOutput = writepipe;
    info.dwFlags |= STARTF_USESTDHANDLES;

    PROCESS_INFORMATION processInfo{};

    if (!CreateProcessW(
        NULL,
        command_line.data(),
        NULL,
        NULL,
        TRUE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &info,
        &processInfo)) {
        return false;
    }

    CloseHandle(processInfo.hThread);
    CloseHandle(writepipe); 

    const DWORD wait_result = WaitForSingleObject(processInfo.hProcess, TIMEOUT);

    CloseHandle(processInfo.hProcess);

    if (wait_result == WAIT_TIMEOUT) {
        return false;
    }

    return true;
}

std::wstring YaraRuleRunner::ReadFromPipe(HANDLE readpipe)
{
    DWORD dwRead;
    CHAR chBuf[1000] = { 0 };
    BOOL bSuccess = FALSE;
    for (;;)
    {

        bSuccess = ReadFile(readpipe, chBuf, sizeof(chBuf), &dwRead, NULL);
        if (!bSuccess || dwRead == 0) break;
    }
    CloseHandle(readpipe);

    if (strlen(chBuf) == 0)
    {
        return L"";
    }
    std::wstring output_string(&chBuf[0], &chBuf[ARRAYSIZE(chBuf)]);

    return output_string;
}
std::wstring YaraRuleRunner::read_output_file(const std::filesystem::path& target_file)
{
    std::ifstream file_stream(target_file);
    const std::string str((std::istreambuf_iterator<char>(file_stream)),
                          std::istreambuf_iterator<char>());
    return std::wstring(str.cbegin(), str.cend());
}

std::vector<std::filesystem::path> YaraRuleRunner::get_yara_rules(const std::filesystem::path& yara_rules_dir)
{
    std::vector<std::filesystem::path> yara_rules;
    //wprintf(L"Checking Rules Directory: %s\n", yara_rules_dir.c_str());
    const std::wstring ext(L".yar");
    for (const auto& p : std::filesystem::directory_iterator(yara_rules_dir.c_str())) {
        if (p.path().extension() == ext) {
            //wprintf(L"Found: %s\n", p.path().c_str());
            yara_rules.push_back(p.path());
        }
    }
    return yara_rules;
}
