#include "ProcessMonitor.hpp"
#include <initializer_list>
#include <optional>
#include <string_view>
#include <thread>
#include <windows.h>
#include <algorithm>
#include <iostream>

#include "Deadline.hpp"
#include "SafeKrabsParser.hpp"
#include "Utils.hpp"

namespace ProcessMonitorConstants {
inline constexpr DWORD s_invalidPid = 0;
inline constexpr DWORD s_allProcessesSnapshot = 0;
inline constexpr ULONGLONG s_defaultAnyMask = 0;
inline constexpr ULONGLONG s_defaultAllMask = 0;
inline constexpr long long s_minWaitMs = 0;
inline constexpr long long s_maxWaitMs = 0x7fffffff;
inline constexpr std::wstring_view s_pidSeparator = L", ";
} // namespace ProcessMonitorConstants

static std::wstring s_joinPids(const std::set<DWORD> &pids) {
  std::wstring out;
  bool first = true;
  for (const DWORD pid : pids) {
    if (!first) {
      out += ProcessMonitorConstants::s_pidSeparator;
    }
    out += std::to_wstring(pid);
    first = false;
  }
  return out;
}

ProcessMonitor::ProcessMonitor(const std::wstring &exeName, const std::wstring &sessionNameKernel, const std::wstring &sessionNameUser, const std::wstring &outPath) noexcept
    : m_user{sessionNameUser}
    , m_kernel{sessionNameKernel}
    , m_threads{}
    , m_caches{}
    , m_writer(std::make_unique<EventWriter>(outPath, EventWriter::WireFormat::Sqlite, false, true))
    , m_threadAnalysis(&m_caches.thread, m_writer.get())
    , m_targetExeName(exeName) {
  m_targetPids = findPidsByName(exeName);
}
ProcessMonitor::ProcessMonitor(const std::set<DWORD> &initialPids, const std::wstring &sessionNameKernel, const std::wstring &sessionNameUser, std::wstring outPath) noexcept
    : m_user{sessionNameUser}
    , m_kernel{sessionNameKernel}
    , m_threads{}
    , m_caches{}
    , m_writer(std::make_unique<EventWriter>(outPath, EventWriter::WireFormat::Sqlite, false, true))
    , m_threadAnalysis(&m_caches.thread, m_writer.get())
    , m_targetExeName(std::nullopt) {
  m_targetPids = initialPids;
}

bool ProcessMonitor::_pidAllowed(const EVENT_RECORD &record,
                                 const krabs::trace_context &ctx) const {
  if (m_targetPids.empty()) {
    return true;
  }

  auto inTargets = [this](DWORD pid) {
    return pid != ProcessMonitorConstants::s_invalidPid && m_targetPids.contains(pid);
  };

  if (inTargets(record.EventHeader.ProcessId)) {
    return true;
  }

  try {
    krabs::schema schema(record, ctx.schema_locator);
    SafeKrabsParserSession parser(schema);

    auto tryU32 = [&](const wchar_t *name) -> std::optional<uint32_t> {
      return parser.tryParse<uint32_t>(name);
    };

    for (const auto *field : {L"SourcePid", L"SourceProcessId", L"TargetPid", L"TargetProcessId", L"ProcessId"}) {
      if (auto v = tryU32(field); v && inTargets(static_cast<DWORD>(*v))) {
        return true;
      }
      if (parser.isPoisoned()) {
        break;
      }
    }
  } catch (...) {
  }

  return false;
}

void ProcessMonitor::_analyzeRecord(const EVENT_RECORD &record,
                                    const krabs::trace_context &ctx) {
  std::scoped_lock lk(m_analysisMtx);

  NormalizedEvent ne{};
  ne.ts = std::chrono::system_clock::now();
  ne.pid = record.EventHeader.ProcessId;
  ne.tid = record.EventHeader.ThreadId;
  ne.eventId = static_cast<int>(record.EventHeader.EventDescriptor.Id);
  ne.fields["SourcePid"] = static_cast<uint32_t>(ne.pid);

  try {
    krabs::schema schema(record, ctx.schema_locator);

    try {
      ne.provider = Utils::narrow_utf8(schema.provider_name());
    } catch (...) {
      ne.provider = "<unknown_provider>";
    }

    try {
      const auto evW = Utils::composeEvent(schema);
      ne.fields["event"] = Utils::narrow_utf8(evW);
    } catch (...) {
    }

    try {
      ne.fields["task_name"] = Utils::narrow_utf8(schema.task_name());
    } catch (...) {
    }

    SafeKrabsParserSession parser(schema);

    auto tryU32 = [&](const wchar_t *name) -> std::optional<uint32_t> {
      return parser.tryParse<uint32_t>(name);
    };

    auto tryU64 = [&](const wchar_t *name) -> std::optional<uint64_t> {
      return parser.tryParse<uint64_t>(name);
    };

    auto setFirstU32 = [&](std::string_view dst, std::initializer_list<const wchar_t *> aliases) {
      for (const auto *a : aliases) {
        if (auto v = tryU32(a)) {
          ne.fields[std::string(dst)] = *v;
          return true;
        }
        if (parser.isPoisoned()) {
          return false;
        }
      }
      return false;
    };

    const bool hasSourcePid = setFirstU32("SourcePid", {L"SourcePid", L"SourceProcessId"});
    (void)hasSourcePid;
    if (!parser.isPoisoned()) {
      setFirstU32("TargetPid", {L"TargetPid", L"TargetProcessId", L"ProcessId"});
    }
    if (!parser.isPoisoned()) {
      // Keep TargetThreatId for compatibility with malformed legacy event payloads.
      setFirstU32("TargetTid", {L"TargetTid", L"TargetThreadId", L"TargetThreatId", L"TThreadId"});
    }
    if (!parser.isPoisoned()) {
      setFirstU32("ProcessId", {L"ProcessId"});
    }
    if (!parser.isPoisoned()) {
      setFirstU32("TThreadId", {L"TThreadId"});
    }
    if (!parser.isPoisoned()) {
      setFirstU32("DesiredAccess", {L"DesiredAccess"});
    }
    if (!parser.isPoisoned()) {
      setFirstU32("ReturnCode", {L"ReturnCode", L"ReturnValue"});
    }

    if (!parser.isPoisoned()) {
      if (auto v = tryU64(L"TargetProcessStartKey")) {
        ne.fields["TargetProcessStartKey"] = *v;
      }
    }
    if (!parser.isPoisoned()) {
      if (auto v = tryU64(L"TargetProcessCreationTime")) {
        ne.fields["TargetProcessCreationTime"] = *v;
      }
    }
  } catch (...) {
    ne.provider = "<no_schema>";
  }

  if (!ne.fields.contains("SourcePid")) {
    ne.fields["SourcePid"] = static_cast<uint32_t>(ne.pid);
  }

  m_threadAnalysis.onEvent(ne);
}

void ProcessMonitor::_onKernelEvent(const EVENT_RECORD &record,
                                    const krabs::trace_context &ctx) {
  if (!_pidAllowed(record, ctx)) {
    return;
  }

  logEvent(record, ctx);
}

void ProcessMonitor::_onUserEvent(const EVENT_RECORD &record,
                                  const krabs::trace_context &ctx) {
  if (!_pidAllowed(record, ctx)) {
    return;
  }

  logEvent(record, ctx);
}

std::set<DWORD> ProcessMonitor::findPidsByName(const std::wstring &exeName) const {
  std::set<DWORD> pids;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, ProcessMonitorConstants::s_allProcessesSnapshot);
  if (snap == INVALID_HANDLE_VALUE) {
    return pids;
  }

  PROCESSENTRY32W pe{};
  pe.dwSize = sizeof(pe);

  if (Process32FirstW(snap, &pe)) {
    do {
      if (_wcsicmp(pe.szExeFile, exeName.c_str()) == 0) {
        pids.insert(pe.th32ProcessID);
      }
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
  return pids;
}

void ProcessMonitor::start() {
  m_threads.kernel = std::jthread([this] { _enableKernelProviders(); });
  m_threads.user = std::jthread([this] { _enableUserProviders(); });
}

void ProcessMonitor::stop() {
  m_kernel.stop();
  m_user.stop();
  if (m_threads.kernel.joinable()) {
    m_threads.kernel.join();
  }

  if (m_threads.user.joinable()) {
    m_threads.user.join();
  }
}

static bool s_joinWithDeadline(std::jthread &t, const Deadline &deadline, const char *tag) {
  if (!t.joinable()) {
    return true;
  }

  const auto rem = deadline.remaining_ms();
  const DWORD waitMs = static_cast<DWORD>(std::clamp<long long>(rem.count(), ProcessMonitorConstants::s_minWaitMs, ProcessMonitorConstants::s_maxWaitMs));
  const HANDLE h = reinterpret_cast<HANDLE>(t.native_handle());
  const DWORD res = WaitForSingleObject(h, waitMs);
  if (res == WAIT_OBJECT_0) {
    t.join();
    return true;
  }

  std::string msg = std::string("ProcessMonitor: thread '") + (tag ? tag : "unknown") + "' join timed out; detaching\n";
  OutputDebugStringA(msg.c_str());
  t.detach();
  return false;
}

bool ProcessMonitor::waitForTarget(const Deadline &deadline,
                                   std::chrono::milliseconds pollInterval) {
  if (!m_targetExeName.has_value()) {
    return true; // explicit PID list supplied
  }

  while (!deadline.expired()) {
    m_targetPids = findPidsByName(*m_targetExeName);
    if (!m_targetPids.empty()) {
      std::wcout << L"Matched target '" << *m_targetExeName
                 << L"' (count=" << m_targetPids.size()
                 << L"): " << s_joinPids(m_targetPids) << std::endl;
      return true;
    }
    std::this_thread::sleep_for(pollInterval);
  }

  OutputDebugStringA("ProcessMonitor: target process not found before deadline\n");
  return false;
}

bool ProcessMonitor::stopWithDeadline(const Deadline &deadline) {
  bool ok = true;
  ok &= m_kernel.stopWithDeadline(deadline);
  ok &= m_user.stopWithDeadline(deadline);
  ok &= s_joinWithDeadline(m_threads.kernel, deadline, "kernel_thread");
  ok &= s_joinWithDeadline(m_threads.user, deadline, "user_thread");
  return ok;
}

void ProcessMonitor::_enableKernelProviders() {
  m_kernel.addDefaultKernelProviders();
  m_kernel.start([this](const EVENT_RECORD &rec, const krabs::trace_context &ctx) {
    _onKernelEvent(rec, ctx);
  });
}

void ProcessMonitor::_enableUserProviders() {
  m_user.addApiCallsProvider(TRACE_LEVEL_INFORMATION,
                             ProcessMonitorConstants::s_defaultAnyMask,
                             ProcessMonitorConstants::s_defaultAllMask);
  m_user.start([this](const EVENT_RECORD &rec, const krabs::trace_context &ctx) {
    _onUserEvent(rec, ctx);
  });
}

void ProcessMonitor::logEvent(const EVENT_RECORD &record,
                              const krabs::trace_context &ctx) {
  (*m_writer)(record, ctx);
  _analyzeRecord(record, ctx);
}
