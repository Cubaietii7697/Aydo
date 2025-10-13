#pragma once
#include <windows.h>

#include <atomic>
#include <filesystem>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "../KernelDriver/include/Public.hpp"
#include "helpers/Utils.hpp"
#include "KernelCommunication/FailureInfo.hpp"
#include "KernelCommunication/KernelCommunication.hpp"

struct ProcessStartEvent {
  DWORD pid{};
  std::wstring image;
};

enum class KillStatus { Ok,
                        NotFound,
                        PartialFailure,
                        Error };

struct KillResult {
  KillStatus status{KillStatus::Error};
  std::vector<FailureInfo> failures;
};

class Service {
public:
  Service() = default;
  ~Service();

  // Open/close the kernel communication
  bool init();
  void shutdown();

  // Wait once for a target process to start (blocking). Returns nullopt on failure.
  std::optional<ProcessStartEvent> waitForStart(const std::wstring &exeName);

  // Continuous watch: calls onEvent for every new start until stopFlag becomes true.
  // Runs on the caller's thread; you decide where to run it.
  void watch(const std::wstring &exeName,
             std::atomic<bool> &stopFlag,
             const std::function<void(const ProcessStartEvent &)> &onEvent);

  // Kill helpers
  KillResult killByPid(DWORD pid);
  KillResult killByExe(const std::wstring &exeOrPath);

  // Discovery
  std::set<DWORD> findPids(const std::wstring &exeOrPath) const;

private:
  static std::wstring toExeName(const std::wstring &input);
  KernelCommunication *km_{nullptr};
};
