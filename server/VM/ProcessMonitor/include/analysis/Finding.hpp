#pragma once
#include "pch.h"
#include <string>

struct Finding {
  std::string type;
  int SEVERITY;
  int confidence;
  std::chrono::time_point<std::chrono::system_clock> ts;
  DWORD source_pid;
  DWORD target_pid;
  DWORD tid;
  std::string evidence_json;
};