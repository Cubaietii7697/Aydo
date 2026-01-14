#pragma once
#include <string>
#include <vector>

#include "IThreadDetector.hpp"

class ThreadStartAddressAnomalyDetector : public IThreadDetector {
public:
  std::vector<Finding> evaluate(const NormalizedEvent &ne, ThreadCaches &caches) override;
  std::string name() const override { return "ThreadStartAddressAnomalyDetector"; }

private:
  bool isThreadStartEvent(const NormalizedEvent &ne) const;

  bool tryGetTarget(const NormalizedEvent &ne, DWORD &targetPid, DWORD &targetTid) const;
  bool tryGetStartAddress(const NormalizedEvent &ne, uint64_t &startAddr) const;

  // Requires module/memory info in caches.
  bool isStartAddressAnomalous(DWORD pid, uint64_t startAddr, const ThreadCaches &caches) const;

  Finding buildFinding(const NormalizedEvent &ne, DWORD srcPid, DWORD tgtPid, DWORD tid,
                       uint64_t startAddr, int severity, int confidence) const;
};
