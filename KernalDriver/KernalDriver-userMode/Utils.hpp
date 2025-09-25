#pragma once
#include <Windows.h>

#include <filesystem>
#include <memory>
#include <set>
#include <TlHelp32.h>

#include "../ioctl_defs.h"

namespace Errors {
inline std::wstring FailedToOpen(DWORD pid) {
  return std::format(L"[KillProcess] Failed to open PID {}", pid);
}
inline std::wstring FailedToTerminate(DWORD pid) {
  return std::format(L"[KillProcess] Failed to terminate PID {}", pid);
}
} // namespace Errors

namespace Utils {
bool UseKernelMode(const std::set<DWORD> &pids);
bool KillProcess(DWORD pid);
bool KillAllProcess(const std::set<DWORD> &pids);
void PrintError(const std::wstring &custom);
std::set<DWORD> findProcess(const std::filesystem::path &p);
bool SendKill(HANDLE hDev, DWORD pid);
} // namespace Utils
