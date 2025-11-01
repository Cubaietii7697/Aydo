#include "pch.h"
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

ProcessMonitor::ProcessMonitor(const std::wstring &exeName) noexcept
    : m_kernel{}
    , m_user{}
    , m_caches{}
    , m_threads{} {
  g_hTrace = 0;
  g_hSession = 0;
  g_targetPids = FindPidByName(exeName);
}
ProcessMonitor::ProcessMonitor(const std::set<DWORD> &initialPids) noexcept
    : m_kernel{}
    , m_user{}
    , m_caches{}
    , m_threads{} {
  g_hTrace = 0;
  g_hSession = 0;
  g_targetPids = initialPids;
}

bool ProcessMonitor::pid_allowed(DWORD pid) {
  return g_targetPids.empty() || g_targetPids.contains(pid);
}

void ProcessMonitor::onKernelEvent(const EVENT_RECORD &record,
                                   const krabs::trace_context &ctx) {
  if (!pid_allowed(record.EventHeader.ProcessId))
    return;
  LogEvent(record, ctx);
}

void ProcessMonitor::onUserEvent(const EVENT_RECORD &record,
                                 const krabs::trace_context &ctx) {
  if (!pid_allowed(record.EventHeader.ProcessId))
    return;
  LogEvent(record, ctx);
}

std::set<DWORD> ProcessMonitor::FindPidByName(const std::wstring &exeName) const {
  std::set<DWORD> pids;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE)
    return pids;

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
  m_threads.kernel = std::jthread([this] { runKernel(); });
  m_threads.user = std::jthread([this] { runUser(); });
}

void ProcessMonitor::stop() {
  m_kernel.trace.stop();
  m_user.trace.stop();
  if (m_threads.kernel.joinable())
    m_threads.kernel.join();
  if (m_threads.user.joinable())
    m_threads.user.join();
}

void ProcessMonitor::enableKernelProviders() {
  auto cb = [](const EVENT_RECORD &rec, const krabs::trace_context &ctx) {
    ProcessMonitor::onKernelEvent(rec, ctx);
  };

  m_kernel.proc.add_on_event_callback(cb);
  m_kernel.thrd.add_on_event_callback(cb);
  m_kernel.img.add_on_event_callback(cb);
  m_kernel.reg.add_on_event_callback(cb);
  m_kernel.file.add_on_event_callback(cb);
  m_kernel.net.add_on_event_callback(cb);
  m_kernel.fileInit.add_on_event_callback(cb);
  m_kernel.disk.add_on_event_callback(cb);
  m_kernel.diskFile.add_on_event_callback(cb);
  m_kernel.ctx.add_on_event_callback(cb);

  m_kernel.trace.enable(m_kernel.proc);
  m_kernel.trace.enable(m_kernel.thrd);
  m_kernel.trace.enable(m_kernel.img);
  m_kernel.trace.enable(m_kernel.reg);
  m_kernel.trace.enable(m_kernel.file);
  m_kernel.trace.enable(m_kernel.net);
  m_kernel.trace.enable(m_kernel.fileInit);
  m_kernel.trace.enable(m_kernel.disk);
  m_kernel.trace.enable(m_kernel.diskFile);
  m_kernel.trace.enable(m_kernel.ctx);
}

void ProcessMonitor::enableUserProviders() {
  auto cb = [](const EVENT_RECORD &rec, const krabs::trace_context &ctx) {
    ProcessMonitor::onUserEvent(rec, ctx);
  };

  m_user.apiCalls.add_on_event_callback(cb);
  m_user.dns.add_on_event_callback(cb);
  m_user.winhttp.add_on_event_callback(cb);
  m_user.wmi.add_on_event_callback(cb);
  m_user.powershell.add_on_event_callback(cb);
  m_user.dotnet.add_on_event_callback(cb);

  m_user.trace.enable(m_user.apiCalls);
  m_user.trace.enable(m_user.dns);
  m_user.trace.enable(m_user.winhttp);
  m_user.trace.enable(m_user.wmi);
  m_user.trace.enable(m_user.powershell);
  m_user.trace.enable(m_user.dotnet);
}

void ProcessMonitor::runKernel() {
  enableKernelProviders();
  m_kernel.trace.start();
}
void ProcessMonitor::runUser() {
  enableUserProviders();
  m_user.trace.start();
}

void ProcessMonitor::LogEvent(const EVENT_RECORD &record,
                              const krabs::trace_context &ctx) {
  krabs::schema schema(record, ctx.schema_locator);
  krabs::parser parser(schema);

  const std::wstring provider = schema.provider_name();
  const auto eventId = schema.event_id();
  const auto opcode = schema.event_opcode();
  const auto level = static_cast<unsigned>(record.EventHeader.EventDescriptor.Level);
  const DWORD pid = record.EventHeader.ProcessId;

  Logger::Info(std::format(L"[{}] PID={} EventId={} Opcode={} Level={}",
                           provider.empty() ? std::to_wstring(record.EventHeader.ProviderId.Data1) : provider,
                           pid, static_cast<unsigned>(eventId),
                           static_cast<unsigned>(opcode), level));

  auto logProp = [&](const wchar_t *prop) {
    if (std::wstring s; parser.try_parse<std::wstring>(prop, s)) {
      Logger::Info(std::format(L"\t{} = {}", prop, s));
      return;
    }
    if (uint64_t u64 = 0; parser.try_parse<uint64_t>(prop, u64)) {
      Logger::Info(std::format(L"\t{} = {}", prop, std::to_wstring(u64)));
      return;
    }
    if (uint32_t u32 = 0; parser.try_parse<uint32_t>(prop, u32)) {
      Logger::Info(std::format(L"\t{} = {}", prop, std::to_wstring(u32)));
      return;
    }
    if (uint16_t u16 = 0; parser.try_parse<uint16_t>(prop, u16)) {
      Logger::Info(std::format(L"\t{} = {}", prop, std::to_wstring(u16)));
      return;
    }
  };

  // Common aliases
  logProp(L"FileName");
  logProp(L"ImageName");
  logProp(L"ImageFileName");
  logProp(L"CommandLine");
  logProp(L"ParentProcessId");
  logProp(L"ParentID");
  logProp(L"DestinationIp");
  logProp(L"DestinationPort");
}
