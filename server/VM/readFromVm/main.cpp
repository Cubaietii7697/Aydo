#include <windows.h>

#include <atomic>
#include <evntrace.h>
#include <iostream>
#include <string>
#include <thread>

#include "readFromVm.hpp"

static std::string narrow(const std::wstring &w) {
  if (w.empty())
    return {};

  int size_needed = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
                                        nullptr, 0, nullptr, nullptr);
  std::string str(size_needed, 0);
  WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &str[0],
                      size_needed, nullptr, nullptr);
  return str;
}

int wmain(int argc, wchar_t *argv[]) {
  const int FAILURE_VAL = 1;
  const int WAIT_TIME = 500;
  if (argc != 2) {
    std::wcerr << "Usage: " << argv[0] << " <exefile>" << std::endl;
    return FAILURE_VAL;
  }

  std::cout << "Starting ETW Monitor..." << std::endl;

  const auto targetExe = std::wstring(argv[1]);

  std::cout << "Looking for process: " << narrow(targetExe) << std::endl;
  std::set<DWORD> pids = readFromVm::FindPidByName(targetExe);
  if (pids.empty()) {
    std::wcerr << "Could not find process: " << targetExe << std::endl;
    return FAILURE_VAL;
  }

  g_targetPids = pids;
  std::cout << "Found " << pids.size() << narrow(targetExe)
            << "'s processes:\n";
  for (DWORD pid : pids) {
    std::cout << "  PID: " << pid << std::endl;
    g_targetPids.insert(pid);
  }
  // Use the standard kernel logger session name
  const std::wstring sessionName = L"NTKernelLogger";
  std::cout << "Using session name: " << narrow(sessionName) << std::endl;

  if (ULONG status = 0; !readFromVm::StartKernelSession(sessionName, status)) {
    std::wcerr << "[ERROR] StartKernelSession failed: " << status << std::endl;
    std::cout << "Press Enter to exit..." << std::endl;
    std::wstring dummy;
    std::getline(std::wcin, dummy);
    return FAILURE_VAL;
  }

  std::cout << "Kernel session started successfully!" << std::endl;

  // Start worker thread
  std::atomic<bool> workerStarted{false};
  std::atomic<bool> workerResult{false};

  std::cout << "Starting worker thread..." << std::endl;
  std::jthread worker([&sessionName, &workerStarted, &workerResult]() {
    std::cout << "[WORKER] Thread started" << std::endl;
    workerStarted = true;
    workerResult = readFromVm::OpenAndProcessRealTime(sessionName);
    std::cout << "[WORKER] Thread finished with result: "
              << (workerResult ? "SUCCESS" : "FAILURE") << std::endl;
  });

  Sleep(WAIT_TIME);

  if (!workerStarted) {
    std::wcerr << "Worker thread did not start properly." << std::endl;
  } else {
    std::cout << "Worker thread started successfully!" << std::endl;
  }

  std::cout << std::endl
            << "=== ETW Monitor Active ===" << std::endl;
  std::cout << "Monitoring PIDs: [ ";
  for (DWORD pid : pids) {
    std::cout << "  PID: " << pid << std::endl;
    g_targetPids.insert(pid);
  }
  std::cout << "] (" << narrow(targetExe) << ")" << std::endl;
  std::cout << "You should see events within 15 seconds..." << std::endl;
  std::cout << "If you don't see any events, try:" << std::endl;
  std::cout << "1. Run as Administrator" << std::endl;
  std::cout << "2. Try with notepad.exe instead" << std::endl;
  std::cout << "3. Create some activity in the target process" << std::endl;
  std::cout << std::endl
            << "Press Enter to stop monitoring..." << std::endl;

  std::wstring dummy;
  std::getline(std::wcin, dummy);

  std::cout << "Stopping trace..." << std::endl;

  // Stop tracing
  if (g_hTrace != 0 && g_hTrace != INVALID_PROCESSTRACE_HANDLE) {
    std::cout << "Closing trace handle..." << std::endl;
    if (ULONG closeStatus = CloseTrace(g_hTrace); closeStatus != ERROR_SUCCESS &&
                                                  closeStatus != ERROR_CTX_CLOSE_PENDING) {
      std::wcerr << "CloseTrace failed: " << closeStatus << std::endl;
    } else {
      std::cout << "Trace handle closed successfully" << std::endl;
    }
    g_hTrace = 0;
  }

  readFromVm::StopKernelSession(sessionName);

  std::cout << "Waiting for worker thread to finish..." << std::endl;
  if (worker.joinable())
    worker.join();

  if (workerResult != 0) {
    std::wcerr << "Worker reported failure (code=" << (int)workerResult.load()
               << std::endl;
  } else {
    std::cout << "Worker completed successfully" << std::endl;
  }

  std::cout << "Shutdown complete." << std::endl;
  return 0;
}
