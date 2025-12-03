#pragma once

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include "pch.h"

#include <TlHelp32.h>
#include <evntcons.h>

#include <set>
#include <string>

#include <krabs.hpp>

#include "Caches.hpp"
#include "EventWriter.hpp"
#include "KernelBlock.hpp"
#include "Threads.hpp"
#include "UserBlock.hpp"

extern std::set<DWORD> g_targetPids;
extern TRACEHANDLE g_hTrace;
extern TRACEHANDLE g_hSession;

class ProcessMonitor {
public:
  explicit ProcessMonitor(const std::wstring &exeName, const std::wstring &sessionNameKernel, const std::wstring &sessionNameUser, const std::wstring &outPath) noexcept;
  explicit ProcessMonitor(const std::set<DWORD> &initialPids, const std::wstring &sessionNameKernel, const std::wstring &sessionNameUser, std::wstring outPath) noexcept;

  std::set<DWORD> FindPidByName(const std::wstring &exeName) const;
  void LogEvent(const EVENT_RECORD &record, const krabs::trace_context &ctx);

  void start();
  void stop();

private:
  UserBlock m_user;
  KernelBlock m_kernel;
  Threads m_threads;
  Caches m_caches;

  std::unique_ptr<EventWriter> m_writer = nullptr;

private:
  void enableKernelProviders();
  void enableUserProviders();
  void onThreadEvent(const EVENT_RECORD &record, const krabs::trace_context &traceContext);
  void onKernelEvent(const EVENT_RECORD &record, const krabs::trace_context &ctx);
  void onUserEvent(const EVENT_RECORD &record, const krabs::trace_context &ctx);
  bool pidAllowed(DWORD pid) const;
};
