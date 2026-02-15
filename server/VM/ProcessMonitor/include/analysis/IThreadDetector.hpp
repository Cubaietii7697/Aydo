#pragma once

#include <chrono>
#include <string>
#include <vector>

#include "Finding.hpp"
#include "NormalizedEvent.hpp"
#include "ThreadCaches.hpp"

class IThreadDetector {
public:
  static constexpr int s_defaultSeverity = 7;
  static constexpr int s_defaultConfidence = 60;
  static constexpr auto s_dedupRetentionWindow = std::chrono::minutes(1);

  virtual ~IThreadDetector() = default;

  virtual std::vector<Finding> evaluate(const NormalizedEvent &ne, ThreadCaches &caches) = 0;
  virtual std::string name() const = 0;
};
