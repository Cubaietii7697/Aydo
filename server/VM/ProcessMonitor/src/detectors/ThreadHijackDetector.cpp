#include "ThreadHijackDetector.hpp"

#include <chrono>

#include "ThreadHelpers.hpp"

std::vector<Finding> ThreadHijackDetector::evaluate(const NormalizedEvent &ne, ThreadCaches &caches) {
  const uint64_t tidKey = static_cast<uint64_t>(ne.tid);
  auto it = caches.byTid.find(tidKey);
  if (it == caches.byTid.end())
    return {};

  const ThreadState &st = it->second;
  const auto now = ne.ts.time_since_epoch().count() == 0 ? std::chrono::system_clock::now() : ne.ts;

  if (ThreadHelpers::isContextChange(ne)) {
    if (st.lastSuspend.time_since_epoch().count() != 0 &&
        (now - st.lastSuspend) < std::chrono::seconds(10)) {
      return {buildFinding(ne, st.ownerPid, ne.tid, 5, 45, "context_change")};
    }
  }

  if (ThreadHelpers::isResume(ne)) {
    if (st.lastSuspend.time_since_epoch().count() != 0 &&
        st.lastContextChange.time_since_epoch().count() != 0 &&
        st.lastSuspend <= st.lastContextChange &&
        st.lastContextChange <= now &&
        (now - st.lastSuspend) < std::chrono::seconds(10)) {
      return {buildFinding(ne, st.ownerPid, ne.tid, 7, 65, "resume_after_context_change")};
    }
  }

  return {};
}

Finding ThreadHijackDetector::buildFinding(const NormalizedEvent &ne,
                                          DWORD ownerPid,
                                          DWORD tid,
                                          int severity,
                                          int confidence,
                                          const char *phase) const {
  nlohmann::json ev;
  ev["provider"] = ne.provider;
  ev["eventId"] = ne.eventId;
  if (auto s = ThreadHelpers::getStr(ne, "event")) ev["event"] = *s;
  if (auto s = ThreadHelpers::getStr(ne, "task_name")) ev["task_name"] = *s;
  ev["ownerPid"] = ownerPid;
  ev["tid"] = tid;
  ev["phase"] = phase;

  Finding f;
  f.type = "ThreadHijackHeuristic";
  f.severity = severity;
  f.confidence = confidence;
  f.ts = ne.ts;
  f.source_pid = ne.pid;        // process performing the action (best-effort)
  f.target_pid = ownerPid;      // thread owner process
  f.tid = tid;
  f.evidence_json = ev.dump();
  return f;
}
