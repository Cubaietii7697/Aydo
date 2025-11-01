#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <evntrace.h>
#include <tdh.h>
#include <TlHelp32.h>
#include <evntcons.h>

#include <set>
#include <string>

#include <krabs.hpp>
#include "Logger.hpp"

#include "Caches.hpp"
#include "KernelBlock.hpp"
#include "Threads.hpp"
#include "UserBlock.hpp"

extern std::set<DWORD> g_targetPids;
extern TRACEHANDLE g_hTrace;
extern TRACEHANDLE g_hSession;

class ProcessMonitor {
public:
  explicit ProcessMonitor(const std::wstring &exeName) noexcept;
  explicit ProcessMonitor(const std::set<DWORD> &initialPids) noexcept;

  std::set<DWORD> FindPidByName(const std::wstring &exeName) const;
  static void LogEvent(const EVENT_RECORD &record, const krabs::trace_context &ctx);

  void start();
  void stop();

private:
  KernelBlock m_kernel;
  UserBlock m_user;
  Caches m_caches;
  Threads m_threads;

private:
  void enableKernelProviders();
  void enableUserProviders();
  void runKernel();
  void runUser();

  static void onKernelEvent(const EVENT_RECORD &record, const krabs::trace_context &ctx);
  static void onUserEvent(const EVENT_RECORD &record, const krabs::trace_context &ctx);
  static bool pid_allowed(DWORD pid);
};
