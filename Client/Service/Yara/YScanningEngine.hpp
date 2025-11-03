#pragma once

#include "../IScanningEngine.hpp"

class YScanningEngine : public IScanningEngine {
public:
  explicit YScanningEngine(const std::vector<std::string> &patterns);
  virtual ~YScanningEngine() = default;

  SearchResult scanFile(const std::string &filePath) override;
  SearchResult scanMemory(const std::vector<uint8_t> &data) override;
};
