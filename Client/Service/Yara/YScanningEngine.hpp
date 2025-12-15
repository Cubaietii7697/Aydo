#pragma once

#include <memory>

#include "../IScanningEngine.hpp"
#include "YaraScoringSystem.hpp"

extern "C" {
#include "yara_x.h"
}

// Extended result that includes scoring information
struct YaraScanResult {
  std::vector<std::string> matchedRules;
  ScoringResult scoring;

  bool hasMatches() const { return !matchedRules.empty(); }
};

class YScanningEngine : public IScanningEngine {
private:
  std::vector<std::shared_ptr<YRX_RULES>> m_rulesSets;
  YaraScoringSystem m_scoringSystem;

public:
  explicit YScanningEngine(const std::vector<std::string> &compiledRulesFiles);
  YScanningEngine(const std::vector<std::string> &compiledRulesFiles, int killThreshold);
  virtual ~YScanningEngine() = default;

  // IScanningEngine interface (returns comma-separated rule names)
  SearchResult scanFile(const std::string &filePath) override;
  SearchResult scanMemory(const std::vector<uint8_t> &data) override;

  // Extended methods with scoring
  YaraScanResult scanFileWithScoring(const std::string &filePath);
  YaraScanResult scanMemoryWithScoring(const std::vector<uint8_t> &data);

  // Access to scoring system for configuration
  YaraScoringSystem &getScoringSystem() { return m_scoringSystem; }
  const YaraScoringSystem &getScoringSystem() const { return m_scoringSystem; }

private:
  static std::shared_ptr<YRX_RULES> _loadCompiledRulesFromFile(const std::string &filePath);
  static void _onMatchingRuleCallback(const struct YRX_RULE *rule, void *user_data);

  std::vector<std::string> _scanFileInternal(const std::string &filePath);
  std::vector<std::string> _scanMemoryInternal(const std::vector<uint8_t> &data);
};
