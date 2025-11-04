#pragma once

#include <string>
#include <vector>

namespace Constants {
constexpr unsigned int SLEEP_BETWEEN_NO_NOTIFICATIONS_MS = 1000 / 8;
const std::vector<std::string> YARA_RULES_FILES = {
    "aaa.yrc",
};
constexpr unsigned int IDLE_SLEEP_TIME_MS = 1000;
constexpr size_t YARA_CHUNK_SIZE = 64 * 1024;
}; // namespace Constants