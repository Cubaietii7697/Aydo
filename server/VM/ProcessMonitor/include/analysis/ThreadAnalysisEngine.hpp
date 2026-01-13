#pragma once
#include "EventWriter.hpp"
#include "IThreadDetector.hpp"
#include "ThreadCaches.hpp"


class ThreadAnalysisEngine {
public:
  ThreadAnalysisEngine(ThreadCaches *c, EventWriter *w) : caches(c) , writer(w) {};
  void onEvent(const NormalizedEvent& normEvent);

private:
  std::vector<IThreadDetector *> detectors;
  ThreadCaches *caches;
  EventWriter *writer;
};