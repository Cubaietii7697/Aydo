#pragma once

#include <string>
#include <vector>

#include "../IScanningEngine.hpp"
#include "AhoCorasick.hpp"

class SCAScanningEngine : public IScanningEngine {
private:
  AhoCorasick m_ahoCorasick;

public:
  explicit SCAScanningEngine(const std::vector<std::string> &hexPatterns);
  virtual ~SCAScanningEngine() = default;

  SearchResult scanFile(const std::string &filePath) override;
  SearchResult scanMemory(const std::vector<uint8_t> &data) override;
};
