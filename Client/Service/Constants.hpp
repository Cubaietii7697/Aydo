#pragma once

#include <string>
#include <vector>

namespace Constants {
constexpr unsigned int SLEEP_BETWEEN_NO_NOTIFICATIONS_MS = 1000 / 8;
const std::vector<std::string> YARA_RULES_FILES = {
    "aaa.yrc",
};
constexpr double ENTROPY_THRESHOLD = 0.8;
constexpr unsigned int ALPHABET_SIZE = 256;
constexpr unsigned int IDLE_SLEEP_TIME_MS = 1000;
constexpr size_t YARA_CHUNK_SIZE = 64 * 1024;
constexpr size_t SHA256_BUFFER_SIZE = 64 * 1024;
constexpr std::wstring_view AYDO_DRIVER_DEVICE_PATH = LR"(\\.\AydoDriver)";
constexpr std::string_view HASHES_DB_PATH = "file_hashes.db";
constexpr std::string_view SERVER_URL = "http://127.0.0.1";
constexpr int DYNAMIC_SCAN_POLL_INTERVAL = 5;
}; // namespace Constants
