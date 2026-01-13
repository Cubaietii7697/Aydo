#pragma once
#include <string>
#include <vector>

#include "IThreadDetector.hpp"

class ThreadHijackDetector : public IThreadDetector {
public:
  std::vector<Finding> evaluate(const NormalizedEvent &ne, ThreadCaches &caches) override;
  Finding buildFinding(const NormalizedEvent &ne, DWORD ownerPid, DWORD tid, int SEVERITY, int confidence, const char *phase) const;
  std::string name() const override { return "ThreadHijackDetector"; }

private:
  bool isSuspendEvent(const NormalizedEvent &ne) const;
  bool isResumeEvent(const NormalizedEvent &ne) const;
  bool isContextChangeEvent(const NormalizedEvent &ne) const;

  DWORD getAffectedTid(const NormalizedEvent &ne) const;
  bool isHijackSequenceDetected(uint64_t tidKey, const ThreadCaches &caches) const;
};
