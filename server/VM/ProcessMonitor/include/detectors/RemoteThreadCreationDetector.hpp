#pragma once
#include <string>
#include <vector>

#include "IThreadDetector.hpp"

class RemoteThreadCreationDetector : public IThreadDetector {
public:
  std::vector<Finding> evaluate(const NormalizedEvent &ne, ThreadCaches &caches) override;
  std::string name() const override { return "RemoteThreadCreationDetector"; }
  bool isMatch(const NormalizedEvent &ne) const;

private:
  bool tryGetTarget(const NormalizedEvent &ne, DWORD &targetPid, DWORD &targetTid) const;
  Finding buildFinding(const NormalizedEvent &ne, DWORD srcPid, DWORD tgtPid, DWORD tgtTid,
                       int severity, int confidence) const;
};
