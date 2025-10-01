#pragma once

#include "../IScanningEngine.hpp"
#include "ACUtils.hpp"

class ACScanningEngine : public IScanningEngine {
private:
  std::vector<ACUtils::PatternInfo> m_parsedPatterns;
  std::vector<std::vector<uint8_t>> m_allSegments;
  size_t m_chunkSize;

public:
  explicit ACScanningEngine(const std::vector<std::string> &hexPatterns, const size_t& chunkSize);
  virtual ~ACScanningEngine() = default;

  SearchResult scanFile(const std::string &filePath) override;
  SearchResult scanMemory(const std::vector<uint8_t> &data) override;
};