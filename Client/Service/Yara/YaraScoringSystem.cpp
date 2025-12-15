#include "YaraScoringSystem.hpp"
#include "YaraRuleConstants.hpp"

#include <algorithm>

YaraScoringSystem::YaraScoringSystem() : m_killThreshold(DEFAULT_KILL_THRESHOLD) {
  _initializeDefaultScores();
}

YaraScoringSystem::YaraScoringSystem(int killThreshold) : m_killThreshold(killThreshold) {
  _initializeDefaultScores();
}

void YaraScoringSystem::_initializeDefaultScores() {
  m_ruleScores = YaraRuleConstants::DEFAULT_RULE_SCORES;
}

YaraScoringSystem::RuleConfig YaraScoringSystem::_getRuleConfig(const std::string &ruleName) const {
  // Convert to lowercase for case-insensitive matching
  std::string lowerName = ruleName;
  std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(),
                 [](unsigned char c) { return std::tolower(c); });

  // Check for prefix matches (longer prefixes first for specificity)
  RuleConfig bestMatch = {25, ThreatLevel::Low}; // Default for unknown rules
  size_t longestMatch = 0;

  for (const auto &[prefix, config] : m_ruleScores) {
    if (lowerName.find(prefix) == 0 || lowerName.find("_" + prefix) != std::string::npos) {
      if (prefix.length() > longestMatch) {
        longestMatch = prefix.length();
        bestMatch = config;
      }
    }
  }

  return bestMatch;
}

void YaraScoringSystem::setRuleScore(const std::string &ruleNamePrefix, int score, ThreatLevel level) {
  std::string lowerPrefix = ruleNamePrefix;
  std::transform(lowerPrefix.begin(), lowerPrefix.end(), lowerPrefix.begin(),
                 [](unsigned char c) { return std::tolower(c); });
  m_ruleScores[lowerPrefix] = {score, level};
}

ScoringResult YaraScoringSystem::analyze(const std::vector<std::string> &matchedRules) const {
  ScoringResult result{};
  result.totalScore = 0;
  result.highestLevel = ThreatLevel::None;
  result.shouldKill = false;
  result.matchedRules = matchedRules;

  if (matchedRules.empty()) {
    return result;
  }

  for (const auto &rule : matchedRules) {
    RuleConfig config = _getRuleConfig(rule);
    result.totalScore += config.score;

    if (config.level > result.highestLevel) {
      result.highestLevel = config.level;
    }
  }

  // Determine if process should be killed based on:
  // 1. Total score exceeds threshold, OR
  // 2. Any Critical level match
  result.shouldKill = (result.totalScore >= m_killThreshold) ||
                      (result.highestLevel == ThreatLevel::Critical);

  return result;
}
