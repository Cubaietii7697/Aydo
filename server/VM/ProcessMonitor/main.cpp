#include <windows.h>

#include <atomic>
#include <evntrace.h>
#include <iostream>
#include <string>
#include <thread>

#include "processMonitor.hpp"

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
  const int TRACE_DURATION_MS = 60 * 1000; // 60 seconds

  if (argc != 2) {
    std::wcerr << "Usage: " << argv[0] << " <exefile>" << std::endl;
    return FAILURE_VAL;
  }

  std::cout << "Starting ETW Monitor..." << std::endl;

  const auto targetExe = std::wstring(argv[1]);
  std::cout << "Looking for process: " << narrow(targetExe) << std::endl;

  std::set<DWORD> pids = processMonitor::FindPidByName(targetExe);
  if (pids.empty()) {
    std::wcerr << "Could not find process: " << targetExe << std::endl;
    return FAILURE_VAL;
  }

  g_targetPids = pids;
  std::cout << "Found " << pids.size() << " process(es) for " << narrow(targetExe) << ":\n";
  for (DWORD pid : pids) {
    std::cout << "  PID: " << pid << std::endl;
    g_targetPids.insert(pid);
  }

  const std::wstring sessionName = L"NTKernelLogger";
  std::cout << "Using session name: " << narrow(sessionName) << std::endl;

  if (ULONG status = 0; !processMonitor::StartKernelSession(sessionName, status)) {
    std::wcerr << "[ERROR] StartKernelSession failed: " << status << std::endl;
    return FAILURE_VAL;
  }

  std::cout << "Kernel session started successfully!" << std::endl;

  // Worker thread
  std::atomic<bool> workerStarted{false};
  std::atomic<bool> workerResult{false};

  std::cout << "Starting worker thread..." << std::endl;
  std::jthread worker([&sessionName, &workerStarted, &workerResult]() {
    std::cout << "[WORKER] Thread started" << std::endl;
    workerStarted = true;
    workerResult = processMonitor::OpenAndProcessRealTime(sessionName);
    std::cout << "[WORKER] Thread finished with result: "
              << (workerResult ? "SUCCESS" : "FAILURE") << std::endl;
  });

  Sleep(WAIT_TIME);

  if (!workerStarted) {
    std::wcerr << "Worker thread did not start properly." << std::endl;
  } else {
    std::cout << "Worker thread started successfully!" << std::endl;
  }

  std::cout << "=== ETW Monitor Active ===" << std::endl;
  std::cout << "Monitoring PIDs: ";
  for (DWORD pid : pids) {
    std::cout << pid << " ";
  }
  std::cout << "(" << narrow(targetExe) << ")" << std::endl;

  std::cout << "Tracing for 60 seconds..." << std::endl;
  Sleep(TRACE_DURATION_MS);

  std::cout << "Stopping trace..." << std::endl;

  if (g_hTrace != 0 && g_hTrace != INVALID_PROCESSTRACE_HANDLE) {
    if (ULONG closeStatus = CloseTrace(g_hTrace);
        closeStatus != ERROR_SUCCESS && closeStatus != ERROR_CTX_CLOSE_PENDING) {
      std::wcerr << "CloseTrace failed: " << closeStatus << std::endl;
    } else {
      std::cout << "Trace handle closed successfully" << std::endl;
    }
    g_hTrace = 0;
  }

  processMonitor::StopKernelSession(sessionName);

  std::cout << "Waiting for worker thread to finish..." << std::endl;
  if (worker.joinable())
    worker.join();

  if (!workerResult) {
    std::wcerr << "Worker reported failure" << std::endl;
  } else {
    std::cout << "Worker completed successfully" << std::endl;
  }

  std::cout << "Shutdown complete." << std::endl;
  return 0;
}
