#include <filesystem>
#include <iostream>
#include <set>
#include <vector>

#include "FailureInfo.hpp"
#include "KernelCommunication.hpp"
#include "Utils.hpp"

int main(int argc, char *argv[]) {
  constexpr int FILE_ARG = 1;

  if (argc != 2) {
    std::cerr << "[usage] KernalDriver.exe <file-to-kill>" << std::endl;
    return EXIT_FAILURE;
  }

  const std::filesystem::path exePath = argv[FILE_ARG];
  std::set<DWORD> pids = Utils::findProcess(exePath);

  if (pids.empty()) {
    std::cerr << "No running process matches: "
              << exePath.filename().string() << std::endl;
    return EXIT_FAILURE;
  }

  // Initialize communication with driver
  auto &km = KernelCommunication::instance();
  if (!km.initKernel()) {
    std::wcerr << L"[kernel] Failed to open device" << std::endl;
    return EXIT_FAILURE;
  }

  std::vector<FailureInfo> failures;

  for (DWORD pid : pids) {
    if (!km.sendRequest(RequestType::KillProcess, KillProcessData{pid})) {
      DWORD err = GetLastError();
      std::wstring reason = std::format(L"DeviceIoControl failed with error: {} ", std::to_wstring(err));
      failures.emplace_back(pid, reason);
      Utils::PrintError(L"[kernel] KillProcess request failed");
    }
  }

  km.shutdown();

  if (!failures.empty()) {
    Utils::PrintFailures(failures);
    return EXIT_FAILURE;
  }

  std::cout << "Successfully sent terminate requests (kernel mode)" << std::endl;
  return EXIT_SUCCESS;
}
