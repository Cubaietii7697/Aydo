#include <filesystem>
#include <iostream>
#include <set>
#include <vector>

#include "../KernelDriver/include/Public.hpp"
#include "helpers/Utils.hpp"
#include "KernelCommunication/Error.hpp"
#include "KernelCommunication/FailureInfo.hpp"
#include "KernelCommunication/KernelCommunication.hpp"

int wmain(int argc, wchar_t *argv[]) {
  constexpr int FILE_ARG = 1;

  if (argc != 2) {
    std::wcerr << L"[usage] " << argv[0] << L"<exe-to-watch>" << std::endl;
    return EXIT_FAILURE;
  }

  const std::filesystem::path exePath = argv[FILE_ARG];
  const std::wstring exeName = exePath.filename().wstring();

  std::set<DWORD> pids = Utils::findProcess(exePath);

  // Initialize communication with driver
  auto &km = KernelCommunication::instance();
  if (!km.initKernel()) {
    std::wcerr << L"[kernel] Failed to open device" << std::endl;
    return EXIT_FAILURE;
  }

  if (!pids.empty()) {
    std::wcerr << L"Process is already running: " << exeName << std::endl;
  } else {
    std::wcout << L"[kernel] Waiting for process start: " << exeName << std::endl;
    auto [status, result] = km.sendRequest(RequestType::WaitForProcessStart, exeName);

    if (status != ResponseStatus::success) {
      std::wcerr << L"[kernel] waitForProcessStart failed." << std::endl;
      km.shutdown();
      return EXIT_FAILURE;
    }

    auto const *info = dynamic_cast<PROCESS_NOTIFY_INFO *>(result.get());

    std::wcout << L"[+] Target process started! PID=" << info->ProcessId
               << L"  Image=" << info->ImageFileName << std::endl;

    pids.insert(info->ProcessId);
  }

  /* std::vector<FailureInfo> failures = Utils::killProcces(pids, km);
  KILL PART

  km.shutdown();

  if (!failures.empty()) {
    Utils::PrintFailures(failures);
    return EXIT_FAILURE;
  }*/

  std::wcout << L"Successfully sent terminate requests (kernel mode)" << std::endl;
  return EXIT_SUCCESS;
}
