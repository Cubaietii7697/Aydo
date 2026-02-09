#pragma once
#include <chrono>
#include <cstdint>
#include <initializer_list>
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

static inline std::optional<uint64_t> getU64(const NormalizedEvent &e, std::string_view key) {
  auto it = e.fields.find(std::string(key));
  if (it == e.fields.end())
    return std::nullopt;

  const FieldValue &v = it->second;
  if (const auto p = std::get_if<uint64_t>(&v))
    return *p;
  if (const auto p = std::get_if<uint32_t>(&v))
    return static_cast<uint64_t>(*p);
  if (const auto p = std::get_if<int64_t>(&v)) {
    if (*p < 0)
      return std::nullopt;
    return static_cast<uint64_t>(*p);
  }
  if (const auto p = std::get_if<int32_t>(&v)) {
    if (*p < 0)
      return std::nullopt;
    return static_cast<uint64_t>(*p);
  }
  if (const auto p = std::get_if<std::string>(&v)) {
    try {
      return static_cast<uint64_t>(std::stoull(*p, nullptr, 0));
    } catch (...) {
      return std::nullopt;
    }
  }
  if (const auto p = std::get_if<std::wstring>(&v)) {
    try {
      return static_cast<uint64_t>(std::stoull(*p, nullptr, 0));
    } catch (...) {
      return std::nullopt;
    }
  }

  return std::nullopt;
}

static inline std::optional<uint32_t> getFirstU32(
    const NormalizedEvent &e,
    std::initializer_list<std::string_view> keys) {
  for (const auto key : keys) {
    if (auto v = getU32(e, key))
      return v;
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

static inline bool hasFieldNamedLike(const NormalizedEvent &e, std::string_view token) {
  for (const auto &[k, _] : e.fields) {
    if (containsI(k, token))
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

static inline std::optional<uint32_t> getSourcePid(const NormalizedEvent &e) {
  if (auto v = getFirstU32(e, {"SourcePid", "SourceProcessId"}))
    return v;
  if (e.pid != 0)
    return static_cast<uint32_t>(e.pid);
  return std::nullopt;
}

static inline std::optional<uint32_t> getTargetPid(const NormalizedEvent &e) {
  return getFirstU32(e, {"TargetPid", "TargetProcessId", "ProcessId"});
}

static inline std::optional<uint32_t> getTargetTid(const NormalizedEvent &e) {
  return getFirstU32(e, {"TargetTid", "TargetThreadId", "TargetThreatId", "TThreadId"});
}

static inline uint32_t actorPidOrFallback(const NormalizedEvent &e) {
  if (auto src = getSourcePid(e))
    return *src;
  return static_cast<uint32_t>(e.pid);
}

static inline bool isKernelAuditApiProvider(const NormalizedEvent &e) {
  return containsI(e.provider, "Microsoft-Windows-Kernel-Audit-API-Calls");
}

static inline bool hasSuccessfulReturnCode(const NormalizedEvent &e) {
  if (auto v = getU32(e, "ReturnCode"))
    return *v == 0;
  if (auto v = getU32(e, "ReturnValue"))
    return *v == 0;
  return false;
}

static inline bool isThreadStart(const NormalizedEvent &e) {
  const auto n = bestName(e);
  if (containsI(n, "Thread/Start"))
    return true;

  if (containsI(n, "Start") && containsI(n, "Thread"))
    return true;

  if (auto task = getStr(e, "task_name"); task && containsI(*task, "Thread")) {
    if (getU32(e, "ProcessId") && getTargetTid(e))
      return true;
  }

  return false;
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
  if (containsI(n, "OpenProcess") || containsI(n, "NtOpenProcess") || containsI(n, "OpenThread") || containsI(n, "NtOpenThread")) {
    return true;
  }

  // Provider-level fallback when schema names are generic "Info".
  if (isKernelAuditApiProvider(e) &&
      (e.eventId == 5 || e.eventId == 6) &&
      hasSuccessfulReturnCode(e)) {
    return true;
  }

  return false;
}

static inline bool isRemoteThread(const NormalizedEvent &e) {
  const auto n = bestName(e);
  if (containsI(n, "CreateRemoteThread") || containsI(n, "NtCreateThreadEx") || containsI(n, "RtlCreateUserThread"))
    return true;

  return hasFieldNamedLike(e, "RemoteThread");
}

static inline bool isApcQueue(const NormalizedEvent &e) {
  const auto n = bestName(e);
  if (containsI(n, "QueueUserAPC") || containsI(n, "NtQueueApcThread"))
    return true;

  return hasFieldNamedLike(e, "Apc");
}

static inline std::chrono::time_point<std::chrono::system_clock> eventTsOrNow(const NormalizedEvent &e) {
  if (e.ts.time_since_epoch().count() == 0)
    return std::chrono::system_clock::now();
  return e.ts;
}

} // namespace ThreadHelpers
