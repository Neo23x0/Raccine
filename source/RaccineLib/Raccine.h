#pragma once

// Raccine 
// A Simple Ransomware Vaccine
// https://github.com/Neo23x0/Raccine
//
// Florian Roth, Ollie Whitehouse, Branislav Djalic, John Lambert
// with help of Hilko Bengen

#include <cwchar>
#include <Windows.h>
#include <string>
#include "YaraRuleRunner.h"
#include "utils.h"


// Version
#define VERSION "1.0.4 BETA"

// Log Config and Flags
inline BOOL g_fLogOnly = FALSE;
inline BOOL g_fShowGui = FALSE;
inline BOOL g_fDebug = FALSE;
#define RACCINE_REG_CONFIG  L"SOFTWARE\\Raccine"
#define RACCINE_REG_POICY_CONFIG  L"SOFTWARE\\Policies\\Raccine"
constexpr UINT MAX_MESSAGE = 1000;
#define RACCINE_DEFAULT_EVENTID  1
#define RACCINE_EVENTID_MALICIOUS_ACTIVITY  2

#define RACCINE_DATA_DIRECTORY  L"%PROGRAMDATA%\\Raccine"
#define RACCINE_YARA_DIRECTORY  L"%PROGRAMDATA%\\Raccine\\yara"
#define RACCINE_PROGRAM_DIRECTORY  L"%PROGRAMFILES%\\Raccine"
inline WCHAR g_wRaccineDataDirectory[MAX_PATH] = { 0 };  // ENV expanded RACCINE_DATA_DIRECTORY
inline WCHAR g_wRaccineProgramDirectory[MAX_PATH] = { 0 };  // ENV expanded RACCINE_PROGRAM_DIRECTORY
#define RACCINE_USER_CONTEXT_DIRECTORY  L"%TEMP%\\RaccineUserContext"

// YARA Matching
inline WCHAR g_wYaraRulesDir[MAX_PATH] = { 0 };

constexpr UINT MAX_YARA_RULE_FILES = 200;
#define RACCINE_REG_CONFIG  L"SOFTWARE\\Raccine"
#define RACCINE_REG_POICY_CONFIG  L"SOFTWARE\\Policies\\Raccine"
#define RACCINE_YARA_RULES_PATH L"RulesDir"
#define RACCINE_DEFAULT_EVENTID  1
#define RACCINE_EVENTID_MALICIOUS_ACTIVITY  2



/// <summary>
/// Evaluate a set of yara rules on a command line
/// </summary>
/// <param name="lpCommandLine">The command line to test</param>
/// <param name="outYaraOutput">if not empty, an output string containing match results is written to this parameter.</param>
/// <returns>TRUE if at least one match result was found</returns>
BOOL EvaluateYaraRules(LPWSTR lpCommandLine, std::wstring& outYaraOutput, DWORD dwChildPid, DWORD dwParentPid);

/// This function will optionally log messages to the eventlog
void WriteEventLogEntryWithId(LPWSTR pszMessage, DWORD dwEventId);

void WriteEventLogEntry(LPWSTR  pszMessage);

// Check if process is in allowed list
bool isAllowListed(DWORD pid);


// Get timestamp
std::string getTimeStamp();

// Format a log lines
std::wstring logFormat(const std::wstring& cmdLine, const std::wstring& comment = L"done");

std::wstring logFormatLine(const std::wstring& line = L"");

// Format the activity log lines
std::wstring logFormatAction(DWORD pid, const std::wstring& imageName, const std::wstring& cmdLine, const std::wstring& comment = L"done");

// Log to file
void logSend(const std::wstring& logStr);

//
//  Query for config in HKLM and HKLM\Software\Policies override by GPO
//
void InitializeSettings();

void createChildProcessWithDebugger(std::wstring command_line, DWORD dwAdditionalCreateParams, PDWORD pdwChildPid, PHANDLE phProcess, PHANDLE phThread);

// Find all parent processes and kill them
void find_and_kill_processes(const std::wstring& sCommandLine, std::wstring& sListLogs);

void CreateContextFileForProgram(DWORD pid, DWORD sessionid, DWORD parentPid, bool fParent);
