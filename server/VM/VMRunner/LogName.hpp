#pragma once
#include <chrono>
#include <format>
#include <iomanip>
#include <process.h> // _getpid
#include <sstream>
#include <string>
#include <string_view>

namespace LogName {
std::string sanitizeForFilename(std::string_view s);

std::string makeLogFileName(std::string_view sandboxId,
                            std::string_view base = "pm_log",
                            std::string_view ext = "log");
}; // namespace LogName
