#pragma once
#include <windows.h>
#include <chrono>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

struct DnsAnswer {
  std::wstring query;
  std::vector<std::wstring> answers;
  std::chrono::steady_clock::time_point ts;
};

struct Caches {
  std::unordered_map<uint64_t, std::wstring> fileObjectPath;
  std::unordered_multimap<DWORD, DnsAnswer> dnsCacheByPid;
};
