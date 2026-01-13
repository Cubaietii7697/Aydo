#include "ProcessMonitor.hpp"
#include <algorithm>
#include <cstring>
#include <format>
#include <iostream>
#include <mutex>
#include <sstream>
#include <vector>
#include "Utils.hpp"

std::set<DWORD> g_targetPids;
TRACEHANDLE g_hTrace = 0;
TRACEHANDLE g_hSession = 0;

ProcessMonitor::ProcessMonitor(const std::wstring &exeName, const std::wstring &sessionNameKernel, const std::wstring &sessionNameUser, const std::wstring &outPath) noexcept
    : m_user{sessionNameUser}
    , m_kernel{sessionNameKernel}
    , m_threads{}
    , m_caches{}
    , m_writer(std::make_unique<EventWriter>(outPath, EventWriter::WireFormat::Sqlite, false, true))
    , m_threadAnalysis(&m_caches.thread, m_writer.get()) {
  g_hTrace = 0;
  g_hSession = 0;
  g_targetPids = FindPidByName(exeName);
}
ProcessMonitor::ProcessMonitor(const std::set<DWORD> &initialPids, const std::wstring &sessionNameKernel, const std::wstring &sessionNameUser, std::wstring outPath) noexcept
    : m_user{sessionNameUser}
    , m_kernel{sessionNameKernel}
    , m_threads{}
    , m_caches{}
    , m_writer(std::make_unique<EventWriter>(outPath, EventWriter::WireFormat::Sqlite, false, true)) 
    , m_threadAnalysis(&m_caches.thread, m_writer.get()) {
  g_hTrace = 0;
  g_hSession = 0;
  g_targetPids = initialPids;
}

bool ProcessMonitor::pidAllowed(DWORD pid) const {
  return g_targetPids.empty() || g_targetPids.contains(pid);
}

void ProcessMonitor::analysisRecord(const EVENT_RECORD &record,
                                    const krabs::trace_context &ctx) {
  std::scoped_lock lk(m_analysisMtx);

  NormalizedEvent ne{};
  ne.ts = std::chrono::system_clock::now(); 
  ne.pid = record.EventHeader.ProcessId;
  ne.tid = record.EventHeader.ThreadId;
  ne.eventId = static_cast<int>(record.EventHeader.EventDescriptor.Id);

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

    krabs::parser parser(schema);

    auto tryU32 = [&](const wchar_t *name) -> std::optional<uint32_t> {
      try {
        return parser.parse<uint32_t>(name);
      } catch (...) {
        return std::nullopt;
      }
    };

    if (auto v = tryU32(L"SourcePid"))
      ne.fields["SourcePid"] = *v;
    if (auto v = tryU32(L"TargetPid"))
      ne.fields["TargetPid"] = *v;
    if (auto v = tryU32(L"SourceProcessId"))
      ne.fields["SourcePid"] = *v;
    if (auto v = tryU32(L"TargetProcessId"))
      ne.fields["TargetPid"] = *v;

    if (auto v = tryU32(L"TargetTid"))
      ne.fields["TargetTid"] = *v;
    if (auto v = tryU32(L"TargetThreadId"))
      ne.fields["TargetTid"] = *v;

  } catch (...) {
    ne.provider = "<no_schema>";
  }

  m_threadAnalysis.onEvent(ne);
}

void ProcessMonitor::onKernelEvent(const EVENT_RECORD &record,
                                   const krabs::trace_context &ctx) {
  if (!pidAllowed(record.EventHeader.ProcessId)) {
    return;
  }

  LogEvent(record, ctx);
}

void ProcessMonitor::onUserEvent(const EVENT_RECORD &record,
                                 const krabs::trace_context &ctx) {
  if (!pidAllowed(record.EventHeader.ProcessId)) {
    return;
  }

  LogEvent(record, ctx);
}

std::set<DWORD> ProcessMonitor::FindPidByName(const std::wstring &exeName) const {
  std::set<DWORD> pids;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
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
  m_threads.kernel = std::jthread([this] { enableKernelProviders(); });
  m_threads.user = std::jthread([this] { enableUserProviders(); });
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

void ProcessMonitor::enableKernelProviders() {
  m_kernel.addDefaultKernelProviders();
  m_kernel.start([this](const EVENT_RECORD &rec, const krabs::trace_context &ctx) {
    onKernelEvent(rec, ctx);
  });
}

void ProcessMonitor::enableUserProviders() {
  m_user.addApiCallsProvider(TRACE_LEVEL_INFORMATION, 0, 0);
  m_user.start([this](const EVENT_RECORD &rec, const krabs::trace_context &ctx) {
    onUserEvent(rec, ctx);
  });
}

void ProcessMonitor::onThreadEvent(const EVENT_RECORD &record, const krabs::trace_context &ctx) {
  LogEvent(record, ctx);
}

void ProcessMonitor::LogEvent(const EVENT_RECORD &record,
                              const krabs::trace_context &ctx) {
  (*m_writer)(record, ctx);
  analysisRecord(record, ctx);
}
