#include "Utils.hpp"

#include <iostream>

#include "Error.hpp"

namespace Utils {

std::set<DWORD> findProcess(const std::filesystem::path &p) {
  std::set<DWORD> pids;
  std::wstring exeName = p.filename().wstring();

  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) {
    return pids;
  }

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

void PrintError(const std::wstring &custom) {
  DWORD err = GetLastError();
  std::wcerr << custom << L", error " << err << std::endl;
}

void PrintFailures(const std::vector<FailureInfo> &failures) {
  if (failures.empty()) {
    return;
  }

  std::wcerr << L"=== Failed to terminate " << failures.size()
             << L" process(es) ===" << std::endl;

  for (const auto &f : failures) {
    std::wcerr << L"  PID " << f.pid << L": " << f.reason << std::endl;
  }

  std::wcerr << L"==============================================" << std::endl;
}
} // namespace Utils
