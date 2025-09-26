#pragma once
#include <Windows.h>

#include <iostream>
#include <memory>

namespace Errors {
inline std::wstring FailedToOpen(DWORD pid) {
  return std::format(L"[KillProcess] Failed to open PID {}", pid);
}
inline std::wstring FailedToTerminate(DWORD pid) {
  return std::format(L"[KillProcess] Failed to terminate PID {}", pid);
}
inline std::wstring FailedToCreateFile(LPCWSTR FILE) {
  return std::format(LR"([kernel] CreateFile({}) failed, winerr=)", FILE);
}
inline std::wstring FailedDeviceIoControl(DWORD pid) {
  return std::format(
      L"[kernel] DeviceIoControl(IOCTL_KILL_PROCESS, pid={}) failed, winerr=",
      pid);
}

} // namespace Errors
