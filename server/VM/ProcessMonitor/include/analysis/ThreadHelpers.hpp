#pragma once
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>

#include "NormalizedEvent.hpp"
#include "Utils.hpp"

namespace ThreadHelpers {

static inline uint64_t packPids(uint32_t src, uint32_t tgt) {
  return (uint64_t(src) << 32) | uint64_t(tgt);
}

static inline std::optional<uint32_t> getU32(const NormalizedEvent &e, std::string_view key) {
  auto it = e.fields.find(std::string(key));
  if (it == e.fields.end())
    return std::nullopt;

  const FieldValue &v = it->second;

  if (const auto p = std::get_if<uint32_t>(&v))
    return *p;

  if (const auto p = std::get_if<uint64_t>(&v)) {
    if (*p > std::numeric_limits<uint32_t>::max())
      return std::nullopt;
    return static_cast<uint32_t>(*p);
  }

  if (const auto p = std::get_if<int32_t>(&v)) {
    if (*p < 0)
      return std::nullopt;
    return static_cast<uint32_t>(*p);
  }

  if (const auto p = std::get_if<int64_t>(&v)) {
    if (*p < 0 || *p > static_cast<int64_t>(std::numeric_limits<uint32_t>::max()))
      return std::nullopt;
    return static_cast<uint32_t>(*p);
  }

  if (const auto p = std::get_if<std::string>(&v)) {
    try {
      const unsigned long x = std::stoul(*p, nullptr, 0); // base 0 supports 0x...
      if (x > std::numeric_limits<uint32_t>::max())
        return std::nullopt;
      return static_cast<uint32_t>(x);
    } catch (...) {
      return std::nullopt;
    }
  }

  if (const auto p = std::get_if<std::wstring>(&v)) {
    try {
      const unsigned long x = std::stoul(*p, nullptr, 0);
      if (x > std::numeric_limits<uint32_t>::max())
        return std::nullopt;
      return static_cast<uint32_t>(x);
    } catch (...) {
      return std::nullopt;
    }
  }

  return std::nullopt;
}

static inline std::optional<std::string> getStr(const NormalizedEvent &e, std::string_view key) {
  auto it = e.fields.find(std::string(key));
  if (it == e.fields.end())
    return std::nullopt;

  const FieldValue &v = it->second;

  if (const auto *p = std::get_if<std::string>(&v))
    return *p;

  if (const auto *p = std::get_if<std::wstring>(&v))
    return Utils::narrow_utf8(*p);

  return std::nullopt;
}

static inline bool containsI(std::string_view hay, std::string_view needle) {
  auto lower = [](char c) { return char((c >= 'A' && c <= 'Z') ? (c - 'A' + 'a') : c); };
  if (needle.empty())
    return true;

  for (size_t i = 0; i + needle.size() <= hay.size(); ++i) {
    bool ok = true;
    for (size_t j = 0; j < needle.size(); ++j) {
      if (lower(hay[i + j]) != lower(needle[j])) {
        ok = false;
        break;
      }
    }
    if (ok)
      return true;
  }
  return false;
}

static inline std::string bestName(const NormalizedEvent &e) {
  if (auto v = getStr(e, "event"))
    return *v;
  if (auto v = getStr(e, "task_name"))
    return *v;
  if (auto v = getStr(e, "EventType"))
    return *v;
  return {};
}

static inline bool isSuspend(const NormalizedEvent &e) {
  const auto n = bestName(e);
  return containsI(n, "SuspendThread");
}
static inline bool isResume(const NormalizedEvent &e) {
  const auto n = bestName(e);
  return containsI(n, "ResumeThread");
}
static inline bool isContextChange(const NormalizedEvent &e) {
  const auto n = bestName(e);
  return containsI(n, "SetThreadContext") || containsI(n, "GetThreadContext");
}

static inline bool isProcessAccess(const NormalizedEvent &e) {
  const auto n = bestName(e);
  return containsI(n, "OpenProcess") || containsI(n, "NtOpenProcess") || containsI(n, "OpenThread") || containsI(n, "NtOpenThread");
}
static inline bool isRemoteThread(const NormalizedEvent &e) {
  const auto n = bestName(e);
  return containsI(n, "CreateRemoteThread") || containsI(n, "NtCreateThreadEx") || containsI(n, "RtlCreateUserThread");
}
static inline bool isApcQueue(const NormalizedEvent &e) {
  const auto n = bestName(e);
  return containsI(n, "QueueUserAPC") || containsI(n, "NtQueueApcThread");
}

} // namespace ThreadHelpers
