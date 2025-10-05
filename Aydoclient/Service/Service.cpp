#include <filesystem>
#include <iostream>
#include <set>
#include <vector>

#include "helpers/Utils.hpp"
#include "KernelCommunication/Error.hpp"
#include "KernelCommunication/FailureInfo.hpp"
#include "KernelCommunication/KernelCommunication.hpp"

int main(int argc, char *argv[]) {
  constexpr int FILE_ARG = 1;

  if (argc != 2) {
    std::cerr << "[usage]" << argv[0] << "< file-to-kill > " << std::endl;

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
    std::variant<KillProcessData> payload{KillProcessData{pid}};
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
          std::to_wstring(res->terminatedPid),
          std::to_wstring(pid));
      Utils::PrintError(note);
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
