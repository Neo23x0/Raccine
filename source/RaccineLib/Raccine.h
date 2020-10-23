#pragma once

// Raccine 
// A Simple Ransomware Vaccine
// https://github.com/Neo23x0/Raccine
//
// Florian Roth, Ollie Whitehouse, Branislav Djalic, John Lambert
// with help of Hilko Bengen

#include <cwchar>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include "YaraRuleRunner.h"

// Version
#define VERSION "1.0.4 BETA"

// Log Config and Flags
inline BOOL g_fLogOnly = FALSE;
inline BOOL g_fShowGui = FALSE;
#define RACCINE_REG_CONFIG  L"SOFTWARE\\Raccine"
#define RACCINE_REG_POICY_CONFIG  L"SOFTWARE\\Policies\\Raccine"
constexpr UINT MAX_MESSAGE = 1000;
#define RACCINE_DEFAULT_EVENTID  1
#define RACCINE_EVENTID_MALICIOUS_ACTIVITY  2

#define RACCINE_DATA_DIRECTORY  L"%PROGRAMDATA%\\Raccine"
#define RACCINE_PROGRAM_DIRECTORY  L"%PROGRAMFILES%\\Raccine"
inline WCHAR g_wRaccineDataDirectory[MAX_PATH] = { 0 };  // ENV expanded RACCINE_DATA_DIRECTORY
inline WCHAR g_wRaccineProgramDirectory[MAX_PATH] = { 0 };  // ENV expanded RACCINE_PROGRAM_DIRECTORY

// YARA Matching
inline WCHAR g_wYaraRulesDir[MAX_PATH] = { 0 };

constexpr UINT MAX_YARA_RULE_FILES = 200;
#define RACCINE_REG_CONFIG  L"SOFTWARE\\Raccine"
#define RACCINE_REG_POICY_CONFIG  L"SOFTWARE\\Policies\\Raccine"
#define RACCINE_YARA_RULES_PATH L"RulesDir"
#define RACCINE_DEFAULT_EVENTID  1
#define RACCINE_EVENTID_MALICIOUS_ACTIVITY  2

enum class Integrity
{
    Error = 0, // Indicates integrity level could not be found
    Low = 1,
    Medium = 2,
    High = 3,
    System = 4,

};

/// <summary>
/// Evaluate a set of yara rules on a command line
/// </summary>
/// <param name="lpCommandLine">The command line to test</param>
/// <param name="outYaraOutput">if not empty, an output string containing match results is written to this parameter.</param>
/// <returns>TRUE if at least one match result was found</returns>
BOOL EvaluateYaraRules(LPWSTR lpCommandLine, std::wstring& outYaraOutput);

/// This function will optionally log messages to the eventlog
void WriteEventLogEntryWithId(LPWSTR pszMessage, DWORD dwEventId);

void WriteEventLogEntry(LPWSTR  pszMessage);

// Get Parent Process ID
DWORD getParentPid(DWORD pid);

// Get integrity level of process
Integrity getIntegrityLevel(HANDLE hProcess);

// Get the image name of the process
std::wstring getImageName(DWORD pid);

// Helper for isAllowListed, checks if a specific process is allowed
bool isProcessAllowed(const PROCESSENTRY32W& pe32);

// Check if process is in allowed list
bool isAllowListed(DWORD pid);

// Kill a process
BOOL killProcess(DWORD dwProcessId, UINT uExitCode);

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

void createChildProcessWithDebugger(std::wstring command_line);

// Find all parent processes and kill them
void find_and_kill_processes(const std::wstring& sCommandLine, std::wstring& sListLogs);
