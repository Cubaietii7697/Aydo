#include "AsynchronousProcedureCallQueueingDetector.hpp"

#include "ThreadHelpers.hpp"

std::vector<Finding> AsynchronousProcedureCallQueueingDetector::evaluate(const NormalizedEvent &ne, ThreadCaches &) {
  if (!isMatch(ne)) {
    return {};
  }

  DWORD tgtPid = 0, tgtTid = 0;
  if (!tryGetTarget(ne, tgtPid, tgtTid)) {
    return {};
  }

  return {buildFinding(ne, ne.pid, tgtPid, tgtTid, SEVERITY, CONFIDENCE)};
}

bool AsynchronousProcedureCallQueueingDetector::isMatch(const NormalizedEvent &ne) const {
  return ThreadHelpers::isApcQueue(ne);
}

bool AsynchronousProcedureCallQueueingDetector::tryGetTarget(const NormalizedEvent &ne, DWORD &targetPid, DWORD &targetTid) const {
  if (auto p = ThreadHelpers::getU32(ne, "TargetProcessId")) {
    targetPid = static_cast<DWORD>(*p);
  } else if (auto p = ThreadHelpers::getU32(ne, "TargetPid")) {
    targetPid = static_cast<DWORD>(*p);
  } else {
    return false;
  }

  if (auto t = ThreadHelpers::getU32(ne, "TargetThreadId")) {
    targetTid = static_cast<DWORD>(*t);
  } else if (auto t = ThreadHelpers::getU32(ne, "TargetTid")) {
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
