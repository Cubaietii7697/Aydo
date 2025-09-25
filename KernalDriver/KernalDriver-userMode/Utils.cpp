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
