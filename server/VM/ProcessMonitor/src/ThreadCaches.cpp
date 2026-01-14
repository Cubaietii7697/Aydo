#include "ThreadCaches.hpp"
#include "ThreadHelpers.hpp"

#include <algorithm>
#include <chrono>
#include <utility>

void ThreadCaches::update(const NormalizedEvent &e) {
  // 1) per-thread updates
  if (e.tid != 0) {
    auto &st = byTid[e.tid];
    if (ThreadHelpers::isSuspend(e))
      st.lastSuspend = e.ts;
    if (ThreadHelpers::isResume(e))
      st.lastResume = e.ts;
    if (ThreadHelpers::isContextChange(e))
      st.lastContextChange = e.ts;
  }

  // 2) cross-proc updates (only when you have both pids)
  const auto src = ThreadHelpers::getU32(e, "SourcePid");
  const auto tgt = ThreadHelpers::getU32(e, "TargetPid");
  if (src && tgt) {
    auto &w = crossProcWindows[{static_cast<DWORD>(*src), static_cast<DWORD>(*tgt)}];
    if (ThreadHelpers::isProcessAccess(e))
      w.lastProcessAccess = e.ts;
    if (ThreadHelpers::isRemoteThread(e))
      w.lastRemoteThread = e.ts;
    if (ThreadHelpers::isApcQueue(e))
      w.lastApcQueue = e.ts;
  }
}

void ThreadCaches::cleanup(std::chrono::time_point<std::chrono::system_clock> now) {
  std::erase_if(byTid, [&](const auto &kv) {
    const auto &s = kv.second;
    const auto last = std::max({s.lastSuspend, s.lastResume, s.lastContextChange});
    return (now - last) > TID_TTL;
  });

  std::erase_if(crossProcWindows, [&](const auto &kv) {
    const auto &w = kv.second;
    const auto last = std::max({w.lastProcessAccess, w.lastRemoteThread, w.lastApcQueue});
    return (now - last) > XPROC_TTL;
  });
}
