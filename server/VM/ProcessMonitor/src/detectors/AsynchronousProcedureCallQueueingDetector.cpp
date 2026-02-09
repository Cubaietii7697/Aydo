#include "AsynchronousProcedureCallQueueingDetector.hpp"

#include <algorithm>

#include "ThreadHelpers.hpp"

std::vector<Finding> AsynchronousProcedureCallQueueingDetector::evaluate(const NormalizedEvent &ne, ThreadCaches &caches) {
  if (!isMatch(ne)) {
    return {};
  }

  const auto now = ThreadHelpers::eventTsOrNow(ne);
  const DWORD srcPid = static_cast<DWORD>(ThreadHelpers::actorPidOrFallback(ne));

  DWORD tgtPid = 0;
  DWORD tgtTid = 0;
  if (!tryGetTarget(ne, tgtPid, tgtTid)) {
    return {};
  }

  if (srcPid == 0 || tgtPid == 0 || srcPid == tgtPid) {
    return {};
  }

  if (!caches.hasRecentProcessAccess(srcPid, tgtPid, now, CORRELATION_WINDOW)) {
    return {};
  }

  if (isDuplicate(srcPid, tgtPid, tgtTid, now)) {
    return {};
  }

  return {buildFinding(ne, srcPid, tgtPid, tgtTid, 8, 75)};
}

bool AsynchronousProcedureCallQueueingDetector::isDuplicate(
    DWORD srcPid,
    DWORD tgtPid,
    DWORD tgtTid,
    std::chrono::time_point<std::chrono::system_clock> now) {
  const auto key = std::make_tuple(srcPid, tgtPid, tgtTid);
  const auto it = m_recentFindings.find(key);
  if (it != m_recentFindings.end() && (now - it->second) <= DEDUP_WINDOW) {
    return true;
  }

  m_recentFindings[key] = now;
  std::erase_if(m_recentFindings, [&](const auto &kv) {
    return (now - kv.second) > std::chrono::minutes(1);
  });
  return false;
}

bool AsynchronousProcedureCallQueueingDetector::isMatch(const NormalizedEvent &ne) const {
  return ThreadHelpers::isApcQueue(ne);
}

bool AsynchronousProcedureCallQueueingDetector::tryGetTarget(const NormalizedEvent &ne, DWORD &targetPid, DWORD &targetTid) const {
  if (auto p = ThreadHelpers::getTargetPid(ne)) {
    targetPid = static_cast<DWORD>(*p);
  } else {
    return false;
  }

  if (auto t = ThreadHelpers::getTargetTid(ne)) {
    targetTid = static_cast<DWORD>(*t);
  } else {
    targetTid = 0;
  }
  return (targetPid != 0);
}

Finding AsynchronousProcedureCallQueueingDetector::buildFinding(const NormalizedEvent &ne,
                                                                DWORD srcPid,
                                                                DWORD tgtPid,
                                                                DWORD tgtTid,
                                                                int severity,
                                                                int confidence) const {
  nlohmann::json ev;
  ev["provider"] = ne.provider;
  ev["eventId"] = ne.eventId;
  if (auto s = ThreadHelpers::getStr(ne, "event"))
    ev["event"] = *s;
  if (auto s = ThreadHelpers::getStr(ne, "task_name"))
    ev["task_name"] = *s;
  ev["srcPid"] = srcPid;
  ev["tgtPid"] = tgtPid;
  ev["tgtTid"] = tgtTid;

  Finding f;
  f.type = "AsynchronousProcedureCallQueueing";
  f.severity = severity;
  f.confidence = confidence;
  f.ts = ne.ts;
  f.source_pid = srcPid;
  f.target_pid = tgtPid;
  f.tid = tgtTid;
  f.evidence_json = ev.dump();
  return f;
}
