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

static bool SendKill(HANDLE hDev, DWORD pid) {
  DWORD bytes = 0;
  BOOL ok = DeviceIoControl(hDev,
                            IOCTL_KILL_PROCESS,
                            &pid, sizeof(pid),
                            nullptr, 0,
                            &bytes,
                            nullptr);
  if (!ok) {
    std::cerr << "[kernel] DeviceIoControl(IOCTL_KILL_PROCESS, pid=" << pid
              << ") failed, winerr=" << GetLastError() << "\n";
    return false;
  }
  return true;
}

bool Utils::UseKernelMode(const std::set<DWORD> &pids) {
  // Must match the symbolic link you created in Device.c:
  // RtlInitUnicodeString(&sym, L"\\DosDevices\\KernalDriver1");
  HANDLE hDev = CreateFileW(L"\\\\.\\KernalDriver1",
                            GENERIC_READ | GENERIC_WRITE,
                            0, nullptr, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
  if (hDev == INVALID_HANDLE_VALUE) {
    std::wcerr << L"[kernel] CreateFile(\\\\.\\KernalDriver1) failed, winerr="
               << GetLastError() << L"\n";
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
