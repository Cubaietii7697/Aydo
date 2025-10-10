#pragma once

#include <regex>
#include <string>
#include <vector>

#include "../IScanningEngine.hpp"

class RScanningEngine : public IScanningEngine {
private:
  std::vector<std::regex> m_patterns;
  std::regex m_masterRegex;

public:
  explicit RScanningEngine(const std::vector<std::string> &patterns);
  virtual ~RScanningEngine() = default;

  SearchResult scanFile(const std::string &filePath) override;
  SearchResult scanMemory(const std::vector<uint8_t> &data) override;

private:
  static std::string _hexPatternToRegexStr(const std::string &hexPattern);
  static std::string _orJoinRegexParts(const std::vector<std::string> &parts);
  static std::regex _hexPatternToRegex(const std::string &hexPattern);
};