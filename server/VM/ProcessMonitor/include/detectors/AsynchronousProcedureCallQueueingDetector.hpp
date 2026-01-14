#pragma once
#include <string>
#include <vector>

#include "IThreadDetector.hpp"

class AsynchronousProcedureCallQueueingDetector : public IThreadDetector {
public:
  std::vector<Finding> evaluate(const NormalizedEvent &ne, ThreadCaches &caches) override;
  bool isMatch(const NormalizedEvent &ne) const;
  std::string name() const override { return "AsynchronousProcedureCallQueueingDetector"; }

private:
  bool tryGetTarget(const NormalizedEvent &ne, DWORD &targetPid, DWORD &targetTid) const;
  Finding buildFinding(const NormalizedEvent &ne, DWORD srcPid, DWORD tgtPid, DWORD tgtTid,
                       int severity, int confidence) const;
};
