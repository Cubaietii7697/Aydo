#include "Utils.hpp"

#include <iostream>

bool Utils::KillAllProcess(const std::set<DWORD> &pids) {
  bool allSuccess = true;

  for (auto pid : pids) {
    if (!KillProcess(pid)) {
      allSuccess = false;
    }
  }
  return allSuccess;
}

void Utils::PrintError(const std::wstring &custom) {
  DWORD err = GetLastError();
  std::wcerr << custom << L", error " << err << std::endl;
}

bool Utils::SendKill(HANDLE hDev, DWORD pid) {
  constexpr DWORD K_IN_SIZE = sizeof(DWORD);
  constexpr DWORD K_OUT_SIZE = 0;
  constexpr LPVOID K_NO_OUT_BUFFER = nullptr;
  constexpr LPOVERLAPPED K_SYNC = nullptr;
  DWORD bytes = 0;
  bool ok = DeviceIoControl(hDev,
                            IOCTL_KILL_PROCESS,
                            &pid, K_IN_SIZE,
                            K_NO_OUT_BUFFER, K_OUT_SIZE,
                            &bytes,
                            K_SYNC);
  if (!ok) {
    std::cerr << "[kernel] DeviceIoControl(IOCTL_KILL_PROCESS, pid=" << pid
              << ") failed, winerr=" << GetLastError() << std::endl;
    return ok;
  }
  return ok;
}

bool Utils::UseKernelMode(const std::set<DWORD> &pids) {
  // Must match the symbolic link you created in Device.c:
  // RtlInitUnicodeString(&sym, L"\\DosDevices\\AydoKernelDriver");
  constexpr DWORD K_SHARE_FLAGS = FILE_SHARE_READ | FILE_SHARE_WRITE;
  HANDLE hDev = CreateFileW(LR"(\\.\AydoKernelDriver)",
                            GENERIC_READ | GENERIC_WRITE,
                            K_SHARE_FLAGS, nullptr, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
  if (hDev == INVALID_HANDLE_VALUE) {
    std::wcerr << LR"([kernel] CreateFile(\\.\AydoKernelDriver) failed, winerr=)"
               << GetLastError() << std::endl;
    return false;
  }

  bool allOk = true;
  for (DWORD pid : pids) {
    if (!SendKill(hDev, pid))
      allOk = false;
  }

  CloseHandle(hDev);
  return allOk;
}

bool Utils::KillProcess(DWORD pid) {
  HANDLE handle = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
  if (!handle) {
    PrintError(Errors::FailedToOpen(pid));
    return false;
  }

  bool res = TerminateProcess(handle, 1);
  if (!res) {
    PrintError(Errors::FailedToTerminate(pid));
  }

  CloseHandle(handle);
  return res;
}

std::set<DWORD> Utils::findProcess(const std::filesystem::path &p) {
  std::set<DWORD> pids;
  std::wstring exeName = p.filename().wstring();

  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE)
    return pids;

  PROCESSENTRY32W pe{};
  pe.dwSize = sizeof(pe);

  if (Process32FirstW(snap, &pe)) {
    do {
      if (_wcsicmp(pe.szExeFile, exeName.c_str()) == 0) {
        pids.insert(pe.th32ProcessID);
      }
    } while (Process32NextW(snap, &pe));
  }

  CloseHandle(snap);
  return pids;
}
