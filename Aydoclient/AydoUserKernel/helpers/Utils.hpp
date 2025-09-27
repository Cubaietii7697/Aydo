#pragma once

#include <Windows.h>

#include <filesystem>
#include <set>
#include <string>
#include <TlHelp32.h>
#include <vector>

#include "../KernelCommunication/FailureInfo.hpp"
namespace Utils {

// Find all PIDs matching exe name
std::set<DWORD> findProcess(const std::filesystem::path &p);

// Print error with custom message
void PrintError(const std::wstring &custom);

// Print failures in a user-friendly way
void PrintFailures(const std::vector<FailureInfo> &failures);
} // namespace Utils
