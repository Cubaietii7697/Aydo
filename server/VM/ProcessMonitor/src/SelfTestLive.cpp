#include "pch.h"
#include "SelfTest.hpp"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>

#include "Deadline.hpp"
#include "UserBlock.hpp"

namespace SelfTestLiveConstants {
inline constexpr UCHAR s_TRACE_LEVEL = TRACE_LEVEL_INFORMATION;
inline constexpr ULONGLONG s_ANY_MASK = 0;
inline constexpr ULONGLONG s_ALL_MASK = 0;
inline constexpr auto s_CAPTURE_DURATION = std::chrono::seconds(2);
inline constexpr auto s_STOP_GRACE = std::chrono::seconds(3);
static constexpr std::wstring_view s_SESSION_NAME = L"NTUserLoggerLiveSelfTest";
} // namespace SelfTestLiveConstants

int RunProcessMonitorLiveSelfTest() {
  std::atomic_uint64_t eventCount{0};
  UserBlock userBlock{std::wstring(SelfTestLiveConstants::s_SESSION_NAME)};
  userBlock.addAnalystProviders(SelfTestLiveConstants::s_TRACE_LEVEL,
                                SelfTestLiveConstants::s_ANY_MASK,
                                SelfTestLiveConstants::s_ALL_MASK);

  const UserProviderEnableStats statsBeforeStart = userBlock.getProviderEnableStats();
  userBlock.start([&eventCount](const EVENT_RECORD &, const krabs::trace_context &) {
    eventCount.fetch_add(1, std::memory_order_relaxed);
  });

  std::this_thread::sleep_for(SelfTestLiveConstants::s_CAPTURE_DURATION);
  const auto stopDeadline = Deadline(std::chrono::steady_clock::now() + SelfTestLiveConstants::s_STOP_GRACE);
  const bool stoppedGracefully = userBlock.stopWithDeadline(stopDeadline);
  const UserProviderEnableStats statsAfterStart = userBlock.getProviderEnableStats();

  std::wcout << L"[self-test-live] providers requested=" << statsBeforeStart.requested
             << L" resolved=" << statsBeforeStart.resolved
             << L" unresolved=" << statsBeforeStart.unresolved
             << L" enabled=" << statsAfterStart.enabled
             << L" failed_enable=" << statsAfterStart.failed_enable
             << L" events=" << eventCount.load(std::memory_order_relaxed)
             << std::endl;

  if (!stoppedGracefully) {
    std::wcerr << L"[self-test-live] stopWithDeadline failed" << std::endl;
    return EXIT_FAILURE;
  }

  if (statsBeforeStart.requested == 0 || statsBeforeStart.resolved == 0 || statsAfterStart.enabled == 0) {
    std::wcerr << L"[self-test-live] insufficient provider enablement" << std::endl;
    return EXIT_FAILURE;
  }

  std::wcout << L"[self-test-live] PASS" << std::endl;
  return EXIT_SUCCESS;
}
