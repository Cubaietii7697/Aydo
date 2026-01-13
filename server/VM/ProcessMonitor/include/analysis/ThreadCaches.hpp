#pragma once
#include "pch.h"
#include "NormalizedEvent.hpp"
#include "CrossProcWindow.hpp"
#include "ThreadState.hpp"

class ThreadCaches {
public:
  static constexpr auto TID_TTL = std::chrono::minutes(30);
  static constexpr auto XPROC_TTL = std::chrono::minutes(10);

public:
  std::map<uint64_t, ThreadState> byTid;
  std::map<std::pair<DWORD, DWORD>, CrossProcWindow> crossProcWindows;

  void update(const NormalizedEvent& normEvent);
  void cleanup(std::chrono::time_point<std::chrono::system_clock> now);
};