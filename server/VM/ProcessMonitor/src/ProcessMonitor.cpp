#include "ProcessMonitor.hpp"
#include <initializer_list>
#include <optional>
#include <string_view>
#include <thread>
#include <windows.h>
#include <algorithm>
#include <iostream>
#include <sstream>

#include "Deadline.hpp"
#include "ProcessMonitorConstants.hpp"
#include "SafeKrabsParser.hpp"
#include "Utils.hpp"

static std::wstring s_joinPids(const std::set<DWORD> &pids) {
  std::wstring out;
  bool first = true;
  for (const DWORD pid : pids) {
    if (!first) {
      out += ProcessMonitorConstants::PID_SEPARATOR;
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

std::set<DWORD> ProcessMonitor::_targetPidsSnapshot() const {
  std::scoped_lock lk(m_targetPidsMtx);
  return m_targetPids;
}

void ProcessMonitor::_refreshTargetPidsIfNeeded(bool forceRefresh,
                                                bool announceChanges) {
  if (!m_targetExeName.has_value()) {
    return;
  }

  const auto now = std::chrono::steady_clock::now();
  {
    std::scoped_lock lk(m_targetPidsMtx);
    if (!forceRefresh &&
        m_lastTargetPidRefresh.time_since_epoch().count() != 0 &&
        (now - m_lastTargetPidRefresh) < ProcessMonitorConstants::TARGET_PID_REFRESH_INTERVAL) {
      return;
    }
    m_lastTargetPidRefresh = now;
  }

  const auto latest = findPidsByName(*m_targetExeName);
  std::set<DWORD> previous;
  bool changed = false;
  {
    std::scoped_lock lk(m_targetPidsMtx);
    previous = m_targetPids;
    if (latest != m_targetPids) {
      m_targetPids = latest;
      changed = true;
    }
  }

  if (announceChanges && changed) {
    std::wcout << ProcessMonitorConstants::PROCESS_LIST_PREFIX
               << (latest.empty() ? std::wstring(ProcessMonitorConstants::PROCESS_NONE_VALUE)
                                  : s_joinPids(latest))
               << std::endl;

    for (const DWORD pid : previous) {
      if (!latest.contains(pid)) {
        std::wcout << L"process <" << pid << ProcessMonitorConstants::PROCESS_STOPPED_SUFFIX << std::endl;
      }
    }

    for (const DWORD pid : latest) {
      if (!previous.contains(pid)) {
        std::wcout << L"process <" << pid << ProcessMonitorConstants::PROCESS_STARTED_SUFFIX << std::endl;
      }
    }
  }
}

static std::string s_guidToString(const GUID &g) {
  wchar_t buf[64] = {};
  const int n = StringFromGUID2(g, buf, static_cast<int>(std::size(buf)));
  if (n <= 0) {
    return "<guid_error>";
  }
  return Utils::narrow_utf8(buf);
}

void ProcessMonitor::_recordProviderCount(const GUID &provider) {
  std::scoped_lock lk(m_providerCountsMtx);
  m_providerCounts[provider] += 1;
}

void ProcessMonitor::_emitProviderSummary() const {
  std::scoped_lock lk(m_providerCountsMtx);
  if (m_providerCounts.empty()) {
    return;
  }
  std::ostringstream oss;
  oss << "ProcessMonitor provider summary:";
  for (const auto &[gid, cnt] : m_providerCounts) {
    oss << " [" << s_guidToString(gid) << "]=" << cnt;
  }
  oss << "\n";
  OutputDebugStringA(oss.str().c_str());
  std::cout << oss.str();
}

bool ProcessMonitor::_pidAllowed(const EVENT_RECORD &record,
                                 const krabs::trace_context &ctx) {
  _refreshTargetPidsIfNeeded(false, false);

  // Policy: ingest all Sysmon events when Sysmon provider is active.
  if (InlineIsEqualGUID(record.EventHeader.ProviderId, ProcessMonitorConstants::SYSMON_PROVIDER_GUID)) {
    return true;
  }

  // Fallback by provider name if GUID match is unavailable.
  try {
    krabs::schema schema(record, ctx.schema_locator);
    try {
      const auto providerName = schema.provider_name();
      if (providerName != nullptr &&
          _wcsicmp(providerName, ProcessMonitorConstants::SYSMON_PROVIDER_NAME.data()) == 0) {
        return true;
      }
    } catch (...) {
    }
  } catch (...) {
  }

  const auto targetPids = _targetPidsSnapshot();

  if (targetPids.empty()) {
    // When matching by executable name, never fall back to "allow all" if no live match exists.
    return !m_targetExeName.has_value();
  }

  auto inTargets = [&targetPids](DWORD pid) {
    return pid != ProcessMonitorConstants::INVALID_PID && targetPids.contains(pid);
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
    auto tryWStr = [&](const wchar_t *name) -> std::optional<std::wstring> {
      return parser.tryParse<std::wstring>(name);
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
    auto setFirstU64 = [&](std::string_view dst, std::initializer_list<const wchar_t *> aliases) {
      for (const auto *a : aliases) {
        if (auto v = tryU64(a)) {
          ne.fields[std::string(dst)] = *v;
          return true;
        }
        if (parser.isPoisoned()) {
          return false;
        }
      }
      return false;
    };
    auto setFirstStr = [&](std::string_view dst, std::initializer_list<const wchar_t *> aliases) {
      for (const auto *a : aliases) {
        if (auto v = tryWStr(a)) {
          ne.fields[std::string(dst)] = Utils::narrow_utf8(*v);
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
      if (!setFirstU64("DesiredAccess", {L"DesiredAccess", L"GrantedAccess"})) {
        setFirstU32("DesiredAccess", {L"DesiredAccess", L"GrantedAccess"});
      }
    }
    if (!parser.isPoisoned()) {
      if (!setFirstU64("GrantedAccess", {L"GrantedAccess", L"DesiredAccess"})) {
        setFirstU32("GrantedAccess", {L"GrantedAccess", L"DesiredAccess"});
      }
    }
    if (!parser.isPoisoned()) {
      setFirstU32("ReturnCode", {L"ReturnCode", L"ReturnValue"});
    }
    if (!parser.isPoisoned()) {
      setFirstStr("Image", {L"Image", L"ImagePath", L"ProcessPath", L"ProcessName", L"ImageFileName", L"NewProcessName"});
    }
    if (!parser.isPoisoned()) {
      setFirstStr("SourceImage", {L"SourceImage", L"CallerProcessName", L"SourceProcessName"});
    }
    if (!parser.isPoisoned()) {
      setFirstStr("TargetImage", {L"TargetImage", L"TargetProcessName", L"TargetProcessPath"});
    }
    if (!parser.isPoisoned()) {
      setFirstStr("ObjectName", {L"ObjectName", L"TargetObject", L"RegName", L"KeyName", L"Path"});
    }
    if (!parser.isPoisoned()) {
      setFirstStr("TaskName", {L"TaskName"});
    }
    if (!parser.isPoisoned()) {
      setFirstStr("ServiceName", {L"ServiceName"});
    }
    if (!parser.isPoisoned()) {
      setFirstStr("EventType", {L"EventType"});
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
  _refreshTargetPidsIfNeeded(false, true);
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
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, ProcessMonitorConstants::ALL_PROCESSES_SNAPSHOT);
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
  const DWORD waitMs = static_cast<DWORD>(std::clamp<long long>(rem.count(), ProcessMonitorConstants::MIN_WAIT_MS, ProcessMonitorConstants::MAX_WAIT_MS));
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
    _refreshTargetPidsIfNeeded(true, true);
    if (!_targetPidsSnapshot().empty()) {
      return true;
    }

    const auto remaining = deadline.remaining_ms();
    const auto sleepFor = (pollInterval < remaining) ? pollInterval : remaining;
    if (sleepFor.count() > 0) {
      std::this_thread::sleep_for(sleepFor);
    }
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
  _emitProviderSummary();
  return ok;
}

void ProcessMonitor::_enableKernelProviders() {
  m_kernel.addDefaultKernelProviders();
  m_kernel.start([this](const EVENT_RECORD &rec, const krabs::trace_context &ctx) {
    _onKernelEvent(rec, ctx);
  });
}

void ProcessMonitor::_enableUserProviders() {
  m_user.addAnalystProviders(TRACE_LEVEL_INFORMATION,
                             ProcessMonitorConstants::DEFAULT_ANY_MASK,
                             ProcessMonitorConstants::DEFAULT_ALL_MASK);
  const bool sysmonEnabled = m_user.addSysmonProvider(TRACE_LEVEL_INFORMATION,
                                                      ProcessMonitorConstants::SYSMON_KEYWORD,
                                                      ProcessMonitorConstants::DEFAULT_ALL_MASK);
  std::wcout << (sysmonEnabled ? ProcessMonitorConstants::SYSMON_ENABLED_CONSOLE_MSG
                               : ProcessMonitorConstants::SYSMON_DISABLED_CONSOLE_MSG)
             << std::endl;
  if (!sysmonEnabled) {
    OutputDebugStringA(ProcessMonitorConstants::SYSMON_UNAVAILABLE_MSG);
  }
  m_user.start([this](const EVENT_RECORD &rec, const krabs::trace_context &ctx) {
    _onUserEvent(rec, ctx);
  });
}

void ProcessMonitor::logEvent(const EVENT_RECORD &record,
                              const krabs::trace_context &ctx) {
  _recordProviderCount(record.EventHeader.ProviderId);

  if (InlineIsEqualGUID(record.EventHeader.ProviderId, ProcessMonitorConstants::SYSMON_PROVIDER_GUID)) {
    const auto prev = m_sysmonDebugLogged.fetch_add(1, std::memory_order_relaxed);
    if (prev < ProcessMonitorConstants::MAX_SYSMON_DEBUG_LOGS) {
      const auto providerStr = s_guidToString(record.EventHeader.ProviderId);
      const auto evtId = static_cast<unsigned>(record.EventHeader.EventDescriptor.Id);
      const std::string msg = std::string("Sysmon event: provider=") + providerStr + " id=" + std::to_string(evtId) + "\n";
      OutputDebugStringA(msg.c_str());
    }
  }

  (*m_writer)(record, ctx);
  _analyzeRecord(record, ctx);
}
