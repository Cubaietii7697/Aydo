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
#include "ProcessMonitor.hpp"

int wmain(int argc, wchar_t *argv[]) {
  if (argc < 3 || argc > 4) {
    std::wcerr << L"Usage: " << argv[0] << L" <exefile> <logFile> [TraceTime]" << std::endl;

    return EXIT_FAILURE;
  }

  const std::wstring targetExe = argv[1];

  const int TRACE_DURATION_S = (argc == 4) ? _wtoi(argv[3]) : Constants::DEFAULT_TIME_S;
  const std::wstring sessionNameKernel = L"NTKernelLogger";
  const std::wstring sessionNameUser = L"NTUserLogger";
  try {
    auto pm = std::make_unique<ProcessMonitor>(targetExe, sessionNameKernel, sessionNameUser, argv[2]);
    // Start monitor
    pm->start();

    std::this_thread::sleep_for(std::chrono::seconds(TRACE_DURATION_S));

    pm->stop();
  } catch (...) {
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
