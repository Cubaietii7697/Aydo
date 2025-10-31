#include "pch.h"
#include "ProcessMonitor.hpp"

#include <evntrace.h>
#include <tdh.h>
#include <algorithm>
#include <cstring>
#include <evntcons.h>
#include <format>
#include <iostream>
#include <sstream>
#include <string>
#include <tlhelp32.h>
#include <vector>

std::set<DWORD> g_targetPids;
TRACEHANDLE g_hTrace = 0;
TRACEHANDLE g_hSession = 0;

// Find PIDs by process name
std::set<DWORD> ProcessMonitor::FindPidByName(const std::wstring &exeName) {
  std::set<DWORD> pids;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) {
    return pids;
  }

  PROCESSENTRY32W pe;
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
  // One callback for all kernel providers
  auto cb = [](const EVENT_RECORD &record, const krabs::trace_context &ctx) {
    // Bind schema + parser to this event
    krabs::schema schema(record, ctx.schema_locator);
    krabs::parser parser(schema);

    const DWORD headerPid = record.EventHeader.ProcessId;
    const std::wstring provName = schema.provider_name();
    const auto op = static_cast<UCHAR>(schema.event_opcode());

    // Identify Process Start/Stop from the *kernel process provider* by opcode
    // EVENT_TRACE_TYPE_START (1), EVENT_TRACE_TYPE_END (2),
    // EVENT_TRACE_TYPE_DC_START (12), EVENT_TRACE_TYPE_DC_END (13)
    const bool isProcessProvider =
        (_wcsicmp(provName.c_str(), L"Microsoft-Windows-Kernel-Process") == 0);
    const bool isStart = isProcessProvider && (op == EVENT_TRACE_TYPE_START || op == EVENT_TRACE_TYPE_DC_START);
    const bool isStop = isProcessProvider && (op == EVENT_TRACE_TYPE_END || op == EVENT_TRACE_TYPE_DC_END);

    static std::mutex pid_mtx;

    if (isStart) {
      uint32_t newPid = 0, ppid = 0;

      // PIDs may appear under different property names depending on schema
      if (!(parser.try_parse<uint32_t>(L"ProcessId", newPid) ||
            parser.try_parse<uint32_t>(L"ProcessID", newPid))) {
        newPid = headerPid; // fallback
      }

      (void)(parser.try_parse<uint32_t>(L"ParentProcessId", ppid) ||
             parser.try_parse<uint32_t>(L"ParentID", ppid));

      std::scoped_lock lock(pid_mtx);
      if (ppid != 0 && g_targetPids.contains(ppid)) {
        g_targetPids.insert(newPid);
        Logger::Info(std::format(L"[Spawn] parent={} -> child={} (tracked)",
                                 std::to_wstring(ppid), std::to_wstring(newPid)));
      }
    } else if (isStop) {
      std::scoped_lock lock(pid_mtx);
      if (g_targetPids.contains(headerPid)) {
        g_targetPids.erase(headerPid);
        Logger::Debug(std::format(L"[Exit] PID {} removed from tracking", std::to_wstring(headerPid)));
      }
      return;
    }

    // Only log events for tracked PIDs
    {
      std::scoped_lock lock(pid_mtx);
      if (!g_targetPids.contains(headerPid))
        return;
    }
    ProcessMonitor::LogEvent(record, ctx);
  };

  // Wire the callback to all typed kernel providers
  proc_.add_on_event_callback(cb);
  thrd_.add_on_event_callback(cb);
  img_.add_on_event_callback(cb);
  reg_.add_on_event_callback(cb);
  file_.add_on_event_callback(cb);
  net_.add_on_event_callback(cb);

  // Enable them on this trace
  trace_.enable(proc_);
  trace_.enable(thrd_);
  trace_.enable(img_);
  trace_.enable(reg_);
  trace_.enable(file_);
  trace_.enable(net_);

  // Run the trace on a background thread
  t_ = std::jthread([this] { trace_.start(); });
}

void ProcessMonitor::stop() {
  trace_.stop();
  if (t_.joinable())
    t_.join();
}

void ProcessMonitor::LogEvent(const EVENT_RECORD &record, const krabs::trace_context &ctx) {
  krabs::schema schema(record, ctx.schema_locator);
  krabs::parser parser(schema);

  const std::wstring provider = schema.provider_name();
  const auto eventId = schema.event_id();
  const auto opcode = schema.event_opcode();
  const auto level = (int)record.EventHeader.EventDescriptor.Level;
  const DWORD pid = record.EventHeader.ProcessId;

  Logger::Info(std::format(L"[{}] PID={} EventId={} Opcode={} Level={}",
                           provider.empty() ? std::to_wstring(record.EventHeader.ProviderId.Data1) : provider,
                           pid,
                           static_cast<unsigned>(eventId),
                           static_cast<unsigned>(opcode),
                           static_cast<unsigned>(level)));

  // Helper: log a property if it exists (supports string and integers)
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
    uint16_t u16 = 0;
    if (parser.try_parse<uint16_t>(prop, u16)) {
      Logger::Info(std::format(L"\t{} = {}", prop, std::to_wstring(u16)));
      return;
    }
  };

  // Common fields across providers (try several aliases)
  logProp(L"FileName");
  logProp(L"ImageName");
  logProp(L"ImageFileName");
  logProp(L"CommandLine");
  logProp(L"ParentProcessId");
  logProp(L"ParentID");
  logProp(L"DestinationIp");
  logProp(L"DestinationPort");
}
