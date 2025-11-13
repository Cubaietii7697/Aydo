#pragma once

#include <optional>
#include <string>
#include <vector>

using SearchResult = std::optional<std::string>;

class IScanningEngine {
public:
  virtual SearchResult scanFile(const std::string &filePath) = 0;
  virtual SearchResult scanMemory(const std::vector<uint8_t> &data) = 0;

  IScanningEngine() = default;
  bool operator==(const IScanningEngine &other) const = default;
};
