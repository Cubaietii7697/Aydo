#pragma once

#include <memory>

#include "../IScanningEngine.hpp"

extern "C" {
#include "yara_x.h"
}

class YScanningEngine : public IScanningEngine {
private:
  std::vector<std::shared_ptr<YRX_RULES>> _rulesSets;

public:
  explicit YScanningEngine(const std::vector<std::string> &compiledRulesFiles);
  virtual ~YScanningEngine() = default;

  SearchResult scanFile(const std::string &filePath) override;
  SearchResult scanMemory(const std::vector<uint8_t> &data) override;

private:
  static std::shared_ptr<YRX_RULES> _loadCompiledRulesFromFile(const std::string &filePath);
  static void _onMatchingRuleCallback(const struct YRX_RULE *rule, void *user_data);
};
