#include <windows.h>

#include <atomic>
#include <evntrace.h>
#include <fstream>
#include <iostream>
#include <set>
#include <string>
#include <thread>

#include "constants.hpp"
#include "logger.hpp"
#include "processMonitor.hpp"

static std::string narrow(const std::wstring &w) {
  if (w.empty())
    return {};
  int size_needed = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
                                        nullptr, 0, nullptr, nullptr);
  std::string str(size_needed, 0);
  WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
                      &str[0], size_needed, nullptr, nullptr);
  return str;
}

int wmain(int argc, wchar_t *argv[]) {
  if (argc < 3 || argc > 4) {
    std::wcerr << L"Usage: " << argv[0] << L" <exefile> <logFile> [TraceTime]" << std::endl;
    return EXIT_FAILURE;
  }
  const std::wstring targetExe = argv[1];
  try {
    Logger::Init(argv[2]);
  } catch (const std::exception &e) {
    std::wcerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }
  const int TRACE_DURATION_MS = (argc == 4) ? _wtoi(argv[3]) : Constants::DEFAULT_TIME;

  Logger::Info(L"Starting ETW Monitor...");
  Logger::Info(L"Looking for process: " + targetExe);

  std::set<DWORD> pids = processMonitor::FindPidByName(targetExe);
  if (pids.empty()) {
    Logger::Error(L"Could not find process: " + targetExe);
    return EXIT_FAILURE;
  }

  g_targetPids = pids;
  Logger::Info(std::format(L"Found {} process(es) for {}", std::to_wstring(pids.size()), targetExe));
  for (DWORD pid : pids) {
    Logger::Info(std::format(L"  PID: {}", std::to_wstring(pid)));
  }

  const std::wstring sessionName = L"NTKernelLogger";
  Logger::Info(L"Using session name: " + sessionName);

  if (ULONG status = 0; !processMonitor::StartKernelSession(sessionName, status)) {
    Logger::Error(std::format(L"StartKernelSession failed: {}", std::to_wstring(status)));
    return EXIT_FAILURE;
  }

  Logger::Info(L"Kernel session started successfully!");

  std::atomic<bool> workerStarted{false};
  std::atomic<bool> workerResult{false};

  Logger::Info(L"Starting worker thread...");
  std::jthread worker([&sessionName, &workerStarted, &workerResult]() {
    Logger::Info(L"[WORKER] Thread started");
    workerStarted = true;
    workerResult = processMonitor::OpenAndProcessRealTime(sessionName);
    Logger::Info(L"[WORKER] Thread finished with result: " +
                 std::wstring(workerResult ? L"SUCCESS" : L"FAILURE"));
  });

  Sleep(Constants::WAIT_TIME);

  if (!workerStarted) {
    Logger::Error(L"Worker thread did not start properly.");
  } else {
    Logger::Info(L"Worker thread started successfully!");
  }

  Logger::Info(L"=== ETW Monitor Active ===");
  std::wstring pidList;
  for (DWORD pid : pids) {
    pidList = std::format(L"{} {} ", pidList, std::to_wstring(pid));
  }
  Logger::Info(L"Monitoring PIDs: " + pidList + L"(" + targetExe + L")");

  Logger::Info(std::format(L"Tracing for {}  seconds... ", std::to_wstring(TRACE_DURATION_MS / Constants::MS_TO_S)));
  Sleep(TRACE_DURATION_MS);

  Logger::Info(L"Stopping trace...");

  if (g_hTrace != 0 && g_hTrace != INVALID_PROCESSTRACE_HANDLE) {
    if (ULONG closeStatus = CloseTrace(g_hTrace);
        closeStatus != ERROR_SUCCESS && closeStatus != ERROR_CTX_CLOSE_PENDING) {
      Logger::Error(std::format(L"CloseTrace failed: {}", std::to_wstring(closeStatus)));
    } else {
      Logger::Info(L"Trace handle closed successfully");
    }
    g_hTrace = 0;
  }

  processMonitor::StopKernelSession(sessionName);

  Logger::Info(L"Waiting for worker thread to finish...");
  if (worker.joinable())
    worker.join();

  if (!workerResult) {
    Logger::Error(L"Worker reported failure");
  } else {
    Logger::Info(L"Worker completed successfully");
  }

  Logger::Info(L"Shutdown complete.");
  Logger::Shutdown();
  return EXIT_SUCCESS;
}
