#include <filesystem>
#include <iostream>
#include <set>
#include <vector>

#include "../AydoKernelRunner/helpers/Utils.hpp"
#include "../AydoKernelRunner/KernelCommunication/Error.hpp"
#include "../AydoKernelRunner/KernelCommunication/FailureInfo.hpp"
#include "../AydoKernelRunner/KernelCommunication/KernelCommunication.hpp"

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
    auto [status, res] = km.sendRequest(RequestType::KillProcess, KillProcessData{pid});

    if (status == ResponseStatus::failure) {
      std::wstring reason = std::format(
          L"DeviceIoControl failed. pid={}, winErr={}, driverStatus={}",
          std::to_wstring(pid),
          std::to_wstring(res.errorCode),
          std::to_wstring(res.driverStatus));
      failures.emplace_back(pid, reason);
      Utils::PrintError(reason);
      continue;
    }
    if (res.terminatedPid != pid) {
      std::wstring note = std::format(
          L"Driver reported terminatedPid={}, requested pid={}",
          std::to_wstring(res.terminatedPid),
          std::to_wstring(pid));
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
