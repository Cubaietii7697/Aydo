
#pragma once

#include <json/json.h>

#include "../Models/Scan.hpp"

namespace Utils::ScanProcessingCron {

struct DynamicScanOutcome {
  Models::ScanStatus status;
  Models::VirusType virusType;
  int score;
};

DynamicScanOutcome runDynamicScan(const Models::Scan &scan);
double resolveProcessingIntervalSeconds(const Json::Value &customConfig);
void startProcessingCron();

} // namespace Utils::ScanProcessingCron
