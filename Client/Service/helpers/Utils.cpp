#include "Utils.hpp"

#include <iostream>

#include "../KernelCommunication/Error.hpp"

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

std::vector<FailureInfo> killProcces(const std::set<DWORD> &pids, const KernelCommunication &km) {
  // Kill all found or newly started processes
  std::vector<FailureInfo> failures;
  for (DWORD pid : pids) {
    std::variant<KillProcessData, std::wstring> payload{KillProcessData{pid}};
    auto [status, base] = km.sendRequest(RequestType::KillProcess, payload);
    auto *res = static_cast<KillProcessResult *>(base.get());

    if (status != ResponseStatus::success) {
      std::wstring reason = std::format(
          L"DeviceIoControl failed. pid={}, winErr={}, driverStatus=0x{:08X}",
          pid,
          res->errorCode,
          res->driverStatus);
      failures.emplace_back(pid, reason);
      Utils::PrintError(reason);
      continue;
    }

    if (res->terminatedPid != pid) {
      std::wstring note = std::format(
          L"Driver reported terminatedPid={}, requested pid={}",
          res->terminatedPid,
          pid);
      Utils::PrintError(note);
    }
  }

  return failures;
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
