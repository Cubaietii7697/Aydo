#pragma once
#include <string>
#include <vector>

#include "IThreadDetector.hpp"

class ThreadHijackDetector : public IThreadDetector {
public:
  std::vector<Finding> evaluate(const NormalizedEvent &ne, ThreadCaches &caches) override;
  Finding buildFinding(const NormalizedEvent &ne, DWORD ownerPid, DWORD tid, int severity, int confidence, const char *phase) const;
  std::string name() const override { return "ThreadHijackDetector"; }
};
