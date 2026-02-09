#pragma once
#include "pch.h"
#include "NormalizedEvent.hpp"
#include "CrossProcWindow.hpp"
#include "ThreadState.hpp"
#include <chrono>
#include <optional>

class ThreadCaches {
public:
  static constexpr auto TID_TTL = std::chrono::minutes(30);
  static constexpr auto XPROC_TTL = std::chrono::minutes(10);

public:
  std::map<uint64_t, ThreadState> byTid;
  std::map<std::pair<DWORD, DWORD>, CrossProcWindow> crossProcWindows;

  void update(const NormalizedEvent& normEvent);
  bool hasRecentProcessAccess(DWORD sourcePid,
                              DWORD targetPid,
                              std::chrono::time_point<std::chrono::system_clock> now,
                              std::chrono::seconds window) const;
  std::optional<DWORD> findRecentSourceForTarget(
      DWORD targetPid,
      std::chrono::time_point<std::chrono::system_clock> now,
      std::chrono::seconds window) const;
  void cleanup(std::chrono::time_point<std::chrono::system_clock> now);
};
