#pragma once

// Keep the Windows stack tight and in the right order.
// Winsock must precede windows.h to avoid redefinition conflicts.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00 // Windows 10
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

// ETW/WMI headers must come *after* windows.h
#include <evntrace.h>
#include <tdh.h>
#include <evntcons.h>

// Other Windows headers
#include <TlHelp32.h>

// Third-party / project
#include <krabs.hpp>
#include <set>
#include <string>

#include "Logger.hpp"

extern std::set<DWORD> g_targetPids;
extern TRACEHANDLE g_hTrace;
extern TRACEHANDLE g_hSession;

class ProcessMonitor {
public:
  ProcessMonitor() = default;

  std::set<DWORD> FindPidByName(const std::wstring &exeName);

  static void LogEvent(const EVENT_RECORD &record, const krabs::trace_context &ctx);

  void start();
  void stop();

private:
  krabs::kernel_trace trace_{L"AydoKernelTrace"};
  krabs::kernel::process_provider proc_;
  krabs::kernel::thread_provider thrd_;
  krabs::kernel::image_load_provider img_;
  krabs::kernel::registry_provider reg_;
  krabs::kernel::file_io_provider file_;
  krabs::kernel::network_tcpip_provider net_;

  std::jthread t_;
};
