#pragma once
#include <Windows.h>

#include <string>

struct FailureInfo {
  DWORD pid;
  std::wstring reason;
};
