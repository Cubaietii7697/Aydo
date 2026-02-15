#include "pch.h"

#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <thread>

#include "Constants.hpp"
#include "ProcessMonitor.hpp"
#include "SelfTest.hpp"

namespace MainConstants {
static constexpr int s_selfTestArgCount = 2;
static constexpr int s_executableArgIndex = 1;
static constexpr int s_outputPathArgIndex = 2;
static constexpr int s_traceDurationArgIndex = 3;
static constexpr int s_minRunArgCount = 3;
static constexpr int s_maxRunArgCount = 4;

static constexpr std::wstring_view s_selfTestFlag = L"--self-test";
static constexpr std::wstring_view s_kernelSessionName = L"NTKernelLogger";
static constexpr std::wstring_view s_userSessionName = L"NTUserLogger";
} // namespace MainConstants

int wmain(int argc, wchar_t *argv[]) {
  if (argc == MainConstants::s_selfTestArgCount && _wcsicmp(argv[MainConstants::s_executableArgIndex], MainConstants::s_selfTestFlag.data()) == 0) {
    return RunProcessMonitorSelfTest();
  }

  if (argc < MainConstants::s_minRunArgCount || argc > MainConstants::s_maxRunArgCount) {
    std::wcerr << L"Usage: " << argv[0] << L" <exefile> <logFile> [TraceTime]" << std::endl;
    std::wcerr << L"       " << argv[0] << L" --self-test" << std::endl;

    return EXIT_FAILURE;
  }

  const std::wstring targetExe = argv[MainConstants::s_executableArgIndex];

  const int traceDurationSeconds =
      (argc == MainConstants::s_maxRunArgCount) ? _wtoi(argv[MainConstants::s_traceDurationArgIndex]) : Constants::g_defaultTraceDurationSeconds;

  try {
    auto pm = std::make_unique<ProcessMonitor>(
        targetExe,
        std::wstring(MainConstants::s_kernelSessionName),
        std::wstring(MainConstants::s_userSessionName),
        argv[MainConstants::s_outputPathArgIndex]);
    // Start monitor
    pm->start();

    std::this_thread::sleep_for(std::chrono::seconds(traceDurationSeconds));

    pm->stop();
  } catch (...) {
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
