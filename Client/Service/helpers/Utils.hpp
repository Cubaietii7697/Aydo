#pragma once

#include <Windows.h>

#include <filesystem>
#include <set>
#include <string>
#include <TlHelp32.h>
#include <vector>

#include "../KernelCommunication/FailureInfo.hpp"
#include "../KernelCommunication/KernelCommunication.hpp"
namespace Utils {

// Find all PIDs matching exe name
std::set<DWORD> findProcess(const std::filesystem::path &p);

//
std::vector<FailureInfo> killProcces(const std::set<DWORD> &ps, const KernelCommunication &);

// Print error with custom message
void PrintError(const std::wstring &custom);

// Print failures in a user-friendly way
void PrintFailures(const std::vector<FailureInfo> &failures);
} // namespace Utils
