#include "Utils.h"

#include <algorithm>
#include <Shlwapi.h>
#include <vector>

#include <Psapi.h>
#include "HandleWrapper.h"
#include <array>
#include <strsafe.h>
#include <wbemidl.h>
#include <comdef.h>

namespace utils
{

std::wstring to_lower(const std::wstring& input)
{
    std::wstring output = input;
    std::transform(output.begin(), output.end(), output.begin(),
                   [](wchar_t c)->wchar_t { return static_cast<wchar_t>(std::tolower(c)); });
    return output;
}

DWORD getParentPid(DWORD pid)
{
    SnapshotHandleWrapper hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (!hSnapshot) {
        return 0;
    }

    PROCESSENTRY32W pe32{};
    pe32.dwSize = sizeof pe32;

    if (!Process32FirstW(hSnapshot, &pe32)) {
        return 0;
    }

    do {
        if (pe32.th32ProcessID == pid) {
            return pe32.th32ParentProcessID;
        }
    } while (Process32NextW(hSnapshot, &pe32));

    return 0;
}

Integrity getIntegrityLevel(HANDLE hProcess)
{
    TokenHandleWrapper hToken = INVALID_HANDLE_VALUE;

    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        return Integrity::Error;
    }

    DWORD dwLengthNeeded = 0;
    GetTokenInformation(hToken,
                        TokenIntegrityLevel,
                        NULL,
                        0,
                        &dwLengthNeeded);
    std::vector<unsigned char> token_data(static_cast<size_t>(dwLengthNeeded), 0);

    const BOOL ret = GetTokenInformation(hToken,
                                         TokenIntegrityLevel,
                                         token_data.data(),
                                         dwLengthNeeded,
                                         &dwLengthNeeded);
    if (!ret) {
        return Integrity::Error;
    }

    auto* const pTIL = reinterpret_cast<PTOKEN_MANDATORY_LABEL>(token_data.data());
    const DWORD dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid,
                                                       static_cast<DWORD>(static_cast<UCHAR>(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1)));

    if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID) {
        return Integrity::Low;
    }

    if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID &&
        dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID) {
        return Integrity::Medium;
    }

    if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID &&
        dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID) {
        return Integrity::High;
    }

    if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) {
        return Integrity::System;
    }

    return Integrity::Error;
}

BOOL GetWin32FileName(const WCHAR* pszNativeFileName, WCHAR* pszWin32FileName)
{
    BOOL bFound = FALSE;

    // Translate path with device name to drive letters.
    WCHAR szTemp[MAX_PATH];
    szTemp[0] = '\0';

    if (GetLogicalDriveStrings(MAX_PATH - 1, szTemp)) {
        WCHAR szName[MAX_PATH];
        WCHAR szDrive[3] = TEXT(" :");
        WCHAR* p = szTemp;

        do {
            // Copy the drive letter to the template string
            *szDrive = *p;

            // Look up each device name
            if (QueryDosDevice(szDrive, szName, MAX_PATH)) {
                const size_t uNameLen = wcslen(szName);

                if (uNameLen < MAX_PATH) {
                    bFound = _wcsnicmp(pszNativeFileName, szName, uNameLen) == 0
                        && *(pszNativeFileName + uNameLen) == L'\\';

                    if (bFound) {
                        // Replace device path with DOS path
                        StringCchPrintf(pszWin32FileName,
                                        MAX_PATH,
                                        L"%s%s",
                                        szDrive,
                                        pszNativeFileName + uNameLen);
                    }
                }
            }
            // Go to the next NULL character.
            while (*p++);
        } while (!bFound && *p);
    }

    return(bFound);
}

DWORD GetPriorityClassByPid(DWORD pid)
{
    ProcessHandleWrapper hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                                FALSE, 
                                                pid);
    if (hProcess != NULL) {
        return GetPriorityClass(hProcess);
    }

    return NORMAL_PRIORITY_CLASS;
}

std::wstring getImageEXEPath(DWORD pid)
{
    WCHAR wEXEPath[MAX_PATH] = { 0 };

    ProcessHandleWrapper hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);

    //this API returned \\Device\\HardDisk1\\foo\\bar. We want a drive letter version.
    GetProcessImageFileName(hProcess, wEXEPath, ARRAYSIZE(wEXEPath) - 1);
    std::wstring ExePath(wEXEPath);

    //see if we need to convert it to C:
    if (to_lower(ExePath).rfind(L"\\device\\harddisk", 0) == 0) {
        WCHAR wWin32EXEPath[MAX_PATH] = { 0 };
        if (GetWin32FileName(ExePath.c_str(), wWin32EXEPath)) {
            return std::wstring(wWin32EXEPath);
        }
    }


    return ExePath;
}

std::wstring getImageName(DWORD pid)
{
    SnapshotHandleWrapper hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (!hSnapshot) {
        return L"(unavailable)";
    }

    PROCESSENTRY32W pe32{};
    pe32.dwSize = sizeof pe32;

    if (!Process32FirstW(hSnapshot, &pe32)) {
        return L"(unavailable)";
    }

    do {
        if (pe32.th32ProcessID == pid) {
            return std::wstring(static_cast<wchar_t*>(pe32.szExeFile));
        }
    } while (Process32NextW(hSnapshot, &pe32));

    return L"(unavailable)";
}

// Helper for isAllowListed, checks if a specific process is allowed
bool isProcessAllowed(const PROCESSENTRY32W& pe32)
{
    ProcessHandleWrapper hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
    if (!hProcess) {
        return false;
    }

    const std::array<std::wstring, 3> allow_list{ L"wininit.exe", L"winlogon.exe", L"explorer.exe" };
    for (const std::wstring& allowed_name : allow_list) {
        if (_wcsicmp(static_cast<const wchar_t*>(pe32.szExeFile), allowed_name.c_str()) != 0) {
            continue;
        }

        wchar_t filePath[MAX_PATH] = { 0 };
        if (GetModuleFileNameEx(hProcess, NULL, filePath, MAX_PATH)) {
            // Are they in the Windows directory?
            const std::wstring system32_path = L"C:\\Windows\\System32\\";
            if (_wcsnicmp(filePath, system32_path.c_str(), system32_path.length()) == 0) {
                // Is the process running as SYSTEM
                return getIntegrityLevel(hProcess) == Integrity::System;
            }

            // Are you explorer running in the Windows dir
            const std::wstring explorer_path = L"C:\\Windows\\Explorer.exe";
            if (_wcsnicmp(filePath, explorer_path.c_str(), explorer_path.length()) == 0) {
                // Is the process running as MEDIUM (which Explorer does)
                return getIntegrityLevel(hProcess) == Integrity::Medium;
            }
        }
    }

    return false;
}

std::wstring GetProcessCommandLine(DWORD pid)
{
    std::wstring CommandLine;
    HRESULT hr = 0;
    IWbemLocator* WbemLocator = NULL;
    IWbemServices* WbemServices = NULL;
    IEnumWbemClassObject* EnumWbem = NULL;
    std::wstring Query = L"SELECT CommandLine FROM Win32_Process WHERE ProcessID = " + std::to_wstring(pid);

    // initialize the Windows security
    hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);


    hr = CoCreateInstance(CLSID_WbemLocator,
                          0,
                          CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator, 
                          reinterpret_cast<LPVOID*>(&WbemLocator));
    //connect to the WMI
    hr = WbemLocator->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"), // WMI namespace
        NULL,                    // User name
        NULL,                    // User password
        0,                       // Locale
        NULL,                    // Security flags                 
        0,                       // Authority       
        0,                       // Context object
        &WbemServices                    // IWbemServices proxy
    );
    //Run the WQL Query
    hr = WbemServices->ExecQuery(_bstr_t(L"WQL"), _bstr_t(Query.c_str()), WBEM_FLAG_FORWARD_ONLY, NULL, &EnumWbem);

    // Iterate over the enumerator
    if (EnumWbem != NULL) {
        IWbemClassObject* result = NULL;
        ULONG returnedCount = 0;

        while ((hr = EnumWbem->Next(WBEM_INFINITE, 1, &result, &returnedCount)) == S_OK) {
            VARIANT procCommandLine;

            // access the properties
            hr = result->Get(L"CommandLine", 0, &procCommandLine, 0, 0);
            if (hr == S_OK) {
                if (!(procCommandLine.vt == VT_NULL))
                    CommandLine = std::wstring(procCommandLine.bstrVal);
            }

            result->Release();
        }
    }

    // Release the resources
    EnumWbem->Release();
    WbemServices->Release();
    WbemLocator->Release();

    CoUninitialize();
    return CommandLine;
}

// Kill a process
BOOL killProcess(DWORD dwProcessId, UINT uExitCode)
{
    constexpr DWORD dwDesiredAccess = PROCESS_TERMINATE;
    constexpr BOOL  bInheritHandle = FALSE;
    ProcessHandleWrapper hProcess = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    if (!hProcess) {
        return FALSE;
    }

    return TerminateProcess(hProcess, uExitCode);
}

// Check if process is in allowed list
bool isAllowListed(DWORD pid)
{
    SnapshotHandleWrapper hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (!hSnapshot) {
        return false;
    }

    PROCESSENTRY32W pe32{};
    pe32.dwSize = sizeof pe32;

    if (!Process32FirstW(hSnapshot, &pe32)) {
        return false;
    }

    do {
        if (pe32.th32ProcessID != pid) {
            continue;
        }

        return utils::isProcessAllowed(pe32);
    } while (Process32NextW(hSnapshot, &pe32));

    return false;
}

ProcessDetail::ProcessDetail(DWORD dwPid)
{
    ProcessDetailStruct = { 0 };
    ProcessDetailStruct.dwPid = dwPid;
}

std::wstring ProcessDetail::ToString(const std::wstring& szPrefix)
{
    const DWORD pid = ProcessDetailStruct.dwPid;

    const std::wstring YaraDef = L" -d ";

    ProcessDetailStruct.Priority = GetPriorityClassByPid(pid);

    ProcessDetailStruct.ExeName = utils::getImageName(pid);
    std::replace(ProcessDetailStruct.ExeName.begin(), ProcessDetailStruct.ExeName.end(), '"', '\'');

    ProcessDetailStruct.ExePath = utils::getImageEXEPath(pid);
    std::replace(ProcessDetailStruct.ExePath.begin(), ProcessDetailStruct.ExePath.end(), '"', '\'');

    ProcessDetailStruct.CommandLine = utils::GetProcessCommandLine(pid);
    std::replace(ProcessDetailStruct.CommandLine.begin(), ProcessDetailStruct.CommandLine.end(), '"', '\'');

    // need to replace any internal doublequotes in these strings.

    std::wstring full_string = YaraDef + L" FromRaccine=\"true\" " + YaraDef + L" " + szPrefix + L"Name=\"" + ProcessDetailStruct.ExeName + L"\""
        + YaraDef + L" " + szPrefix + L"ExecutablePath=\"" + ProcessDetailStruct.ExePath + L"\""
        + YaraDef + L" " + szPrefix + L"CommandLine=\"" + ProcessDetailStruct.CommandLine + L"\""
        + YaraDef + L" " + szPrefix + L"Priority=" + std::to_wstring(ProcessDetailStruct.Priority) + L"";

    return full_string;
}



std::wstring expand_environment_strings(const std::wstring& input)
{
    constexpr size_t MAX_STRING_SIZE = 2 << 15;
    std::vector<wchar_t> output(MAX_STRING_SIZE, 0);
    const DWORD ret = ExpandEnvironmentStringsW(input.c_str(),
                                                output.data(),
                                                static_cast<DWORD>(output.size()));
    if (ret == 0) {
        return input;
    }

    return std::wstring(output.data());
}

}
