#include "YScanningEngine.hpp"

#include <fstream>
#include <ios>

extern "C" {
#include "yara_x.h"
}

#include "../Constants.hpp"
#include "../Errors.hpp"

YScanningEngine::YScanningEngine(const std::vector<std::string> &compiledRulesFiles) {
  for (const auto &file : compiledRulesFiles) {
    m_rulesSets.push_back(_loadCompiledRulesFromFile(file));
  }
}

std::shared_ptr<YRX_RULES> YScanningEngine::_loadCompiledRulesFromFile(const std::string &filePath) {
  std::ifstream file(filePath, std::ios::binary | std::ios::ate);

  if (!file.is_open()) {
    throw Errors::FailedToLoadCompiledRulesException("Failed to open file: " + filePath);
  }

  std::streamsize size = file.tellg();
  file.seekg(0, std::ios::beg);

  std::vector<uint8_t> buffer(size);
  if (!file.read(reinterpret_cast<char *>(buffer.data()), size)) {
    throw Errors::FailedToLoadCompiledRulesException("Failed to read file: " + filePath);
  }

  YRX_RULES *rules_raw = nullptr;
  enum YRX_RESULT r = yrx_rules_deserialize(buffer.data(), buffer.size(), &rules_raw);
  if (r != YRX_SUCCESS || rules_raw == nullptr) {
    const char *err = yrx_last_error();
    std::string emsg = err ? err : "yrx_rules_deserialize failed";

    throw Errors::FailedToLoadCompiledRulesException("Failed to deserialize rules: " + emsg);
  }

  // shared pointer that'll call yrx_rules_destroy when last reference is gone
  return {rules_raw, yrx_rules_destroy};
}

struct MatchCollector {
  std::vector<std::string> matches;
  std::atomic_bool found{false};
};

void YScanningEngine::_onMatchingRuleCallback(const struct YRX_RULE *rule, void *user_data) {
  if (!rule || !user_data)
    return;
  auto *collector = reinterpret_cast<MatchCollector *>(user_data);

  const uint8_t *ident = nullptr;
  size_t len = 0;
  if (yrx_rule_identifier(rule, &ident, &len) == YRX_SUCCESS && ident && len > 0) {
    collector->matches.emplace_back(reinterpret_cast<const char *>(ident), len);
  } else {
    collector->matches.emplace_back("unknown_rule");
  }

  collector->found.store(true, std::memory_order_relaxed);
}

SearchResult YScanningEngine::scanMemory(const std::vector<uint8_t> &data) {
  if (m_rulesSets.empty()) {
    throw Errors::NoPatternsProvidedException();
  }

  MatchCollector collector;

  for (const auto &rules_ptr : m_rulesSets) {
    if (!rules_ptr)
      continue;

    YRX_SCANNER *scanner = nullptr;
    if (yrx_scanner_create(rules_ptr.get(), &scanner) != YRX_SUCCESS || !scanner) {
      throw Errors::FailedToLoadCompiledRulesException("yrx_scanner_create failed");
    }

    // register callback
    if (yrx_scanner_on_matching_rule(scanner, _onMatchingRuleCallback, &collector) != YRX_SUCCESS) {
      yrx_scanner_destroy(scanner);
      throw Errors::FailedToLoadCompiledRulesException("yrx_scanner_on_matching_rule failed");
    }

    // scan the data
    enum YRX_RESULT r = yrx_scanner_scan(scanner, data.data(), data.size());
    yrx_scanner_destroy(scanner);

    if (r != YRX_SUCCESS) {
      const char *err = yrx_last_error();
      std::string emsg = err ? err : "yrx_scanner_scan failed";
      throw Errors::FailedToLoadCompiledRulesException("Scan failed: " + emsg);
    }

    // unlike the other scanners, theres no option here to stop on first match, so we need to return all matches
    // separated by commas
    if (collector.found.load(std::memory_order_relaxed)) {
      std::string result;
      for (size_t i = 0; i < collector.matches.size(); ++i) {
        result += collector.matches[i];
        if (i < collector.matches.size() - 1) {
          result += ", ";
        }
      }

      return result;
    }
  }

  return std::nullopt;
}

SearchResult YScanningEngine::scanFile(const std::string &filePath) {
  std::ifstream ifs(filePath, std::ios::binary | std::ios::ate);
  if (!ifs) {
    throw Errors::FailedToLoadCompiledRulesException("Failed to open file for scanning: " + filePath);
  }

  std::streamsize size = ifs.tellg();
  if (size <= 0) {
    throw Errors::FailedToLoadCompiledRulesException("Invalid file size: " + filePath);
  }

  ifs.seekg(0, std::ios::beg);

  MatchCollector collector;

  for (const auto &rules_ptr : m_rulesSets) {
    if (!rules_ptr)
      continue;

    YRX_SCANNER *scanner = nullptr;
    if (yrx_scanner_create(rules_ptr.get(), &scanner) != YRX_SUCCESS || !scanner) {
      throw Errors::FailedToLoadCompiledRulesException("yrx_scanner_create failed");
    }

    // register callback
    if (yrx_scanner_on_matching_rule(scanner, _onMatchingRuleCallback, &collector) != YRX_SUCCESS) {
      yrx_scanner_destroy(scanner);

      throw Errors::FailedToLoadCompiledRulesException("yrx_scanner_on_matching_rule failed");
    }

    // read and scan file chunk by chunk
    ifs.clear();
    ifs.seekg(0, std::ios::beg);
    std::vector<uint8_t> chunk(Constants::YARA_CHUNK_SIZE);

    while (ifs && !collector.found.load(std::memory_order_relaxed)) {
      ifs.read(reinterpret_cast<char *>(chunk.data()), Constants::YARA_CHUNK_SIZE);
      std::streamsize bytes_read = ifs.gcount();

      if (bytes_read > 0) {
        enum YRX_RESULT r = yrx_scanner_scan(scanner, chunk.data(), static_cast<size_t>(bytes_read));
        if (r != YRX_SUCCESS) {
          const char *err = yrx_last_error();
          std::string emsg = err ? err : "yrx_scanner_scan failed";
          yrx_scanner_destroy(scanner);

          throw Errors::FailedToLoadCompiledRulesException("Scan failed: " + emsg);
        }
      }
    }

    yrx_scanner_destroy(scanner);

    if (collector.found.load(std::memory_order_relaxed)) {
      std::string result;

      for (size_t i = 0; i < collector.matches.size(); ++i) {
        result += collector.matches[i];
        if (i < collector.matches.size() - 1) {
          result += ", ";
        }
      }

      return result;
    }
  }

  return std::nullopt;
}