#pragma once
#include "pch.h"

struct ThreadState {
  DWORD ownerPid;
  std::chrono::time_point<std::chrono::system_clock> lastSuspend;
  std::chrono::time_point<std::chrono::system_clock> lastResume;
  std::chrono::time_point<std::chrono::system_clock> lastContextChange;
};