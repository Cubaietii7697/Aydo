#pragma once

#include <string>
#include <unordered_map>
#include <vector>

enum class ThreatLevel {
  None = 0,        // No threat
  Info = 1,        // Informational (capabilities, behaviors)
  Low = 2,         // Low risk indicators
  Medium = 3,      // Suspicious patterns
  High = 4,        // Known malware signatures
  Critical = 5     // Confirmed malware
};

struct ScoringResult {
  int totalScore;
  ThreatLevel highestLevel;
  bool shouldKill;
  std::vector<std::string> matchedRules;
};

class YaraScoringSystem {
public:
  // Default threshold for killing a process
  // TODO: User config
  static constexpr int DEFAULT_KILL_THRESHOLD = 70;

  YaraScoringSystem();
  explicit YaraScoringSystem(int killThreshold);

  ScoringResult analyze(const std::vector<std::string> &matchedRules) const;

  void setRuleScore(const std::string &ruleNamePrefix, int score, ThreatLevel level);

  int getKillThreshold() const { return m_killThreshold; }
  void setKillThreshold(int threshold) { m_killThreshold = threshold; }

private:
  int m_killThreshold;

  struct RuleConfig {
    int score;
    ThreatLevel level;
  };
  std::unordered_map<std::string, RuleConfig> m_ruleScores;

  void _initializeDefaultScores();

  RuleConfig _getRuleConfig(const std::string &ruleName) const;
};
