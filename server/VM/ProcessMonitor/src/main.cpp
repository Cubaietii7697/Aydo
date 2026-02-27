#include "pch.h"

#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <windows.h>

#include "Constants.hpp"
#include "Deadline.hpp"
#include "ProcessMonitor.hpp"
#include "SelfTest.hpp"

namespace MainConstants {
static constexpr int s_selfTestArgCount = 2;
static constexpr int s_executableArgIndex = 1;
static constexpr int s_outputPathArgIndex = 2;
static constexpr int s_traceDurationArgIndex = 3;
static constexpr int s_minRunArgCount = 3;
static constexpr int s_maxRunArgCount = 4;
static constexpr int s_minTraceDurationSeconds = 1;
static constexpr int s_hardStopExitCode = EXIT_FAILURE;
inline constexpr auto s_targetPollInterval = std::chrono::milliseconds(250);
inline constexpr auto s_stopGracePeriod = std::chrono::seconds(5);

static constexpr std::wstring_view s_selfTestFlag = L"--self-test";
static constexpr std::wstring_view s_kernelSessionName = L"NTKernelLogger";
static constexpr std::wstring_view s_userSessionName = L"NTUserLogger";
static constexpr std::wstring_view s_startBannerPrefix = L"Starting ProcessMonitor";
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
  const std::wstring outputPath = argv[MainConstants::s_outputPathArgIndex];

  const int traceDurationSeconds =
      (argc == MainConstants::s_maxRunArgCount) ? _wtoi(argv[MainConstants::s_traceDurationArgIndex]) : Constants::g_defaultTraceDurationSeconds;
  if (traceDurationSeconds < MainConstants::s_minTraceDurationSeconds) {
    std::wcerr << L"TraceTime must be >= " << MainConstants::s_minTraceDurationSeconds << L" seconds" << std::endl;
    return EXIT_FAILURE;
  }

  try {
    std::wcout << MainConstants::s_startBannerPrefix
               << L": target='" << targetExe
               << L"', output='" << outputPath
               << L"', trace_seconds=" << traceDurationSeconds << std::endl;

    // Hard watchdog: enforce process lifetime upper bound regardless of stop/join behavior.
    std::thread([hardStopAfter = std::chrono::seconds(traceDurationSeconds)] {
      std::this_thread::sleep_for(hardStopAfter);
      OutputDebugStringA("ProcessMonitor: hard stop reached; terminating process\n");
      TerminateProcess(GetCurrentProcess(), MainConstants::s_hardStopExitCode);
    }).detach();

    const auto now = std::chrono::steady_clock::now();
    Deadline deadline(now + std::chrono::seconds(traceDurationSeconds));
    const Deadline stopDeadline(deadline.time_point() + MainConstants::s_stopGracePeriod); // grace

    auto pm = std::make_unique<ProcessMonitor>(
        targetExe,
        std::wstring(MainConstants::s_kernelSessionName),
        std::wstring(MainConstants::s_userSessionName),
        outputPath);

    if (!pm->waitForTarget(deadline, MainConstants::s_targetPollInterval)) {
      std::wcerr << L"Target process '" << targetExe << L"' not found before deadline" << std::endl;
      return EXIT_FAILURE;
    }
    // Start monitor
    pm->start();

    if (const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline.time_point() - std::chrono::steady_clock::now()); remaining.count() > 0) {
      std::this_thread::sleep_for(remaining);
    }

    if (!pm->stopWithDeadline(stopDeadline)) {
      std::wcerr << L"ProcessMonitor stop exceeded deadline; some events may be lost" << std::endl;
    }
  } catch (...) {
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
