#include "pch.h"

#include <atomic>
#include <format>
#include <fstream>
#include <iostream>
#include <mutex>
#include <set>
#include <string>
#include <thread>

#include "Constants.hpp"
#include "Logger.hpp"
#include "ProcessMonitor.hpp"

static std::wstring widen_utf8(const std::string &s) {
  if (s.empty())
    return L"";
  int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
  std::wstring w(n, 0);
  MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), n);
  return w;
}

int wmain(int argc, wchar_t *argv[]) {
  if (argc < 3 || argc > 4) {
    std::wcerr << L"Usage: " << argv[0] << L" <exefile> <logFile> [TraceTime]" << std::endl;
    return EXIT_FAILURE;
  }

  const std::wstring targetExe = argv[1];
  if (!Logger::Init(argv[2])) {
    return EXIT_FAILURE;
  }

  const int TRACE_DURATION_MS = (argc == 4) ? _wtoi(argv[3]) : Constants::DEFAULT_TIME;

  ProcessMonitor pm;

  // Find and seed initial PIDs
  std::set<DWORD> initialPids = pm.FindPidByName(targetExe);
  if (initialPids.empty()) {
    Logger::Error(L"Could not find process: " + targetExe);
    Logger::Shutdown();
    return EXIT_FAILURE;
  }

  g_targetPids = initialPids;

  const std::wstring sessionName = L"NTKernelLogger";

  // Start monitor
  pm.start();

  // Run for the requested duration
  std::this_thread::sleep_for(std::chrono::milliseconds(TRACE_DURATION_MS));

  // Stop and clean up
  pm.stop();
  Logger::Info(L"Shutdown complete.");
  Logger::Shutdown();

  return EXIT_SUCCESS;
}
