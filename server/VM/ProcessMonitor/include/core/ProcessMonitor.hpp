#pragma once

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include "pch.h"

#include <TlHelp32.h>
#include <evntcons.h>

#include <memory>
#include <set>
#include <string>
#include <optional>

#include <krabs.hpp>

#include <mutex>
#include "Caches.hpp"
#include "EventWriter.hpp"
#include "KernelBlock.hpp"
#include "ThreadAnalysisEngine.hpp"
#include "Threads.hpp"
#include "Deadline.hpp"
#include "UserBlock.hpp"

class ProcessMonitor {
public:
  explicit ProcessMonitor(const std::wstring &exeName, const std::wstring &sessionNameKernel, const std::wstring &sessionNameUser, const std::wstring &outPath) noexcept;
  explicit ProcessMonitor(const std::set<DWORD> &initialPids, const std::wstring &sessionNameKernel, const std::wstring &sessionNameUser, std::wstring outPath) noexcept;

  std::set<DWORD> findPidsByName(const std::wstring &exeName) const;
  void logEvent(const EVENT_RECORD &record, const krabs::trace_context &ctx);
  bool waitForTarget(const Deadline &deadline, std::chrono::milliseconds pollInterval);
  bool stopWithDeadline(const Deadline &deadline);

  void start();
  void stop();

private:
  ThreadAnalysisEngine m_threadAnalysis;
  UserBlock m_user;
  KernelBlock m_kernel;
  Threads m_threads;
  Caches m_caches;
  std::mutex m_analysisMtx;
  std::unique_ptr<EventWriter> m_writer = nullptr;
  std::set<DWORD> m_targetPids;
  std::optional<std::wstring> m_targetExeName;

private:
  void _analyzeRecord(const EVENT_RECORD &record,
                      const krabs::trace_context &ctx);
  void _enableKernelProviders();
  void _enableUserProviders();
  void _onKernelEvent(const EVENT_RECORD &record, const krabs::trace_context &ctx);
  void _onUserEvent(const EVENT_RECORD &record, const krabs::trace_context &ctx);
  bool _pidAllowed(const EVENT_RECORD &record, const krabs::trace_context &ctx) const;
};
