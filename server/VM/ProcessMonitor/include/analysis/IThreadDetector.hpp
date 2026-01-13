#pragma once
#include <string>
#include <vector>
#include "Finding.hpp"
#include "NormalizedEvent.hpp"
#include "ThreadCaches.hpp"

class IThreadDetector {
public:
  const int SEVERITY = 7;
  const int CONFIDENCE = 60;

public:
  virtual ~IThreadDetector() = default; 


  virtual std::vector<Finding> evaluate(const NormalizedEvent & ne, ThreadCaches &caches) = 0;
  
  virtual std::string name() const = 0;
};