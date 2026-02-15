#pragma once
#include "pch.h"
#include <chrono>
#include <optional>
#include "CrossProcWindow.hpp"
#include "NormalizedEvent.hpp"
#include "ThreadState.hpp"

class ThreadCaches {
  static constexpr auto s_TID_TTL = std::chrono::minutes(30);
  static constexpr auto s_XPROC_TTL = std::chrono::minutes(10);

public:
  void update(const NormalizedEvent &normEvent);
  void cleanup(std::chrono::time_point<std::chrono::system_clock> now);

  bool hasRecentProcessAccess(DWORD sourcePid,
                              DWORD targetPid,
                              std::chrono::time_point<std::chrono::system_clock> now,
                              std::chrono::seconds window) const;

  std::optional<DWORD> findRecentSourceForTarget(
      DWORD targetPid,
      std::chrono::time_point<std::chrono::system_clock> now,
      std::chrono::seconds window) const;

  std::map<uint64_t, ThreadState> byTid;
  std::map<std::pair<DWORD, DWORD>, CrossProcWindow> crossProcWindows;
};
