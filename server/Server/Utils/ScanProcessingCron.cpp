#include "ScanProcessingCron.hpp"

#include <drogon/HttpAppFramework.h>
#include <drogon/orm/DbClient.h>
#include <trantor/utils/Logger.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <json/json.h>
#include <optional>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "../Constants.hpp"

#include "Generic.hpp"

namespace Utils::ScanProcessingCron {
std::filesystem::path resolveFakeResultFilePath() {
  const auto customConfig = drogon::app().getCustomConfig();
  const auto key = std::string(Constants::DYNAMIC_SCAN_FAKE_RESULT_FILE_KEY);

  if (customConfig.isMember(key) && customConfig[key].isString()) {
    return std::filesystem::path(customConfig[key].asString());
  }

  return std::filesystem::path(Constants::DEFAULT_DYNAMIC_SCAN_FAKE_RESULT_FILE);
}

bool readFakeDynamicScanVerdict() {
  const std::filesystem::path fakeResultFilePath = resolveFakeResultFilePath();
  std::ifstream verdictFile(fakeResultFilePath);
  if (!verdictFile) {
    LOG_WARN << "Fake dynamic scan verdict file not found at "
             << fakeResultFilePath.string() << "; defaulting to false";
    return false;
  }

  std::string verdict;
  std::getline(verdictFile, verdict);
  verdict = Utils::Generic::trim(verdict);
  std::transform(verdict.begin(), verdict.end(), verdict.begin(),
                 [](unsigned char c) {
                   return static_cast<char>(std::tolower(c));
                 });

  return verdict == "true";
}

int resolveFakeDelaySeconds(bool shouldReturnTrue, int runtimeSeconds) {
  constexpr int MIN_TRUE_DELAY_SECONDS = 5;
  constexpr int MIN_RUNTIME_SECONDS = 1;
  const int safeRuntimeSeconds =
      (std::max)(runtimeSeconds, MIN_RUNTIME_SECONDS);

  if (!shouldReturnTrue) {
    return safeRuntimeSeconds;
  }

  const int minDelay =
      (std::min)(MIN_TRUE_DELAY_SECONDS, safeRuntimeSeconds);
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<int> dist(minDelay, safeRuntimeSeconds);
  return dist(gen);
}

DynamicScanOutcome runDynamicScan(const Models::Scan &scan) {
  const bool verdictIsTrue = readFakeDynamicScanVerdict();
  const int delaySeconds =
      resolveFakeDelaySeconds(verdictIsTrue, scan.getRuntime());

  LOG_INFO << "[DynamicScan] Fake scan for fileHash=" << scan.getFileHash()
           << " verdict=" << (verdictIsTrue ? "true" : "false")
           << " delaySeconds=" << delaySeconds;
  std::this_thread::sleep_for(std::chrono::seconds(delaySeconds));

  if (verdictIsTrue) {
    constexpr int MALICIOUS_SCORE = 100;
    return {Models::ScanStatus::Completed, Models::VirusType::Unknown,
            MALICIOUS_SCORE};
  }

  return {Models::ScanStatus::Completed, Models::VirusType::Clean, 0};
}

double resolveProcessingIntervalSeconds(const Json::Value &customConfig) {
  if (customConfig.isMember(Constants::PROCESSING_CRON_INTERVAL_KEY.data())) {
    const auto &value =
        customConfig[Constants::PROCESSING_CRON_INTERVAL_KEY.data()];
    if (value.isNumeric()) {
      const double parsed = value.asDouble();
      if (parsed > 0.0) {
        return parsed;
      }
    }
  }

  return Constants::DEFAULT_SCAN_CHECK_INTERVAL_S;
}

void processDueScans(const drogon::orm::DbClientPtr &dbClient) {
  try {
    const auto dueScans = Models::Scan::getDueInProgressScans(dbClient);

    for (const auto &scan : dueScans) {
      LOG_INFO << "Processing scan (fileHash=" << scan.getFileHash()
               << ", runtime=" << scan.getRuntime() << "s)";

      const auto outcome = runDynamicScan(scan);
      Models::Scan::updateResult(dbClient, scan.getFileHash(),
                                 outcome.status, outcome.virusType,
                                 outcome.score);
    }
  } catch (const std::exception &e) {
    LOG_ERROR << "Processing cron failed: " << e.what();
  } catch (...) {
    LOG_ERROR << "Processing cron failed: unknown error";
  }
}

void startProcessingCron() {
  auto dbClient = drogon::app().getDbClient();
  const auto customConfig = drogon::app().getCustomConfig();
  const double intervalSeconds = resolveProcessingIntervalSeconds(customConfig);

  drogon::app().getLoop()->runEvery(intervalSeconds, [dbClient]() {
    processDueScans(dbClient);
  });
}

} // namespace Utils::ScanProcessingCron
