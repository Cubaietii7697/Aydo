#include "ProcessMonitor.hpp"
#include <algorithm>
#include <cstring>
#include <format>
#include <iostream>
#include <mutex>
#include <sstream>
#include <vector>

std::set<DWORD> g_targetPids;
TRACEHANDLE g_hTrace = 0;
TRACEHANDLE g_hSession = 0;

ProcessMonitor::ProcessMonitor(const std::wstring &exeName, const std::wstring &sessionNameKernel, const std::wstring &sessionNameUser, const std::wstring &outPath) noexcept
    : m_kernel{sessionNameKernel}
    , m_user{sessionNameUser}
    , m_caches{}
    , m_threads{}
    , m_writer(std::make_unique<EventWriter>(outPath, EventWriter::WireFormat::Msgpack, false, true)) {
  g_hTrace = 0;
  g_hSession = 0;
  g_targetPids = FindPidByName(exeName);
}
ProcessMonitor::ProcessMonitor(const std::set<DWORD> &initialPids, const std::wstring &sessionNameKernel, const std::wstring &sessionNameUser, std::wstring outPath) noexcept
    : m_kernel{sessionNameKernel}
    , m_user{sessionNameUser}
    , m_caches{}
    , m_threads{}
    , m_writer(std::make_unique<EventWriter>(outPath, EventWriter::WireFormat::Msgpack, false, true)) {
  g_hTrace = 0;
  g_hSession = 0;
  g_targetPids = initialPids;
}

bool ProcessMonitor::pidAllowed(DWORD pid) const {
  return g_targetPids.empty() || g_targetPids.contains(pid);
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
  m_kernel.add_default_kernel_providers();
  m_kernel.start([this](const EVENT_RECORD &rec, const krabs::trace_context &ctx) {
    this->onKernelEvent(rec, ctx);
  });
}

void ProcessMonitor::enableUserProviders() {
  m_user.add_api_calls_provider(TRACE_LEVEL_INFORMATION, 0, 0);
  m_user.start([this](const EVENT_RECORD &rec, const krabs::trace_context &ctx) {
    this->onUserEvent(rec, ctx);
  });
}

void ProcessMonitor::LogEvent(const EVENT_RECORD &record,
                              const krabs::trace_context &ctx) {
  (*m_writer)(record, ctx);
}
