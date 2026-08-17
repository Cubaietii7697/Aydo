#pragma once

#include <string>

namespace Utils::Generic {
[[nodiscard]] long long getCurrentTimestamp();
[[nodiscard]] std::string quoteIfNeeded(const std::string &value);
[[nodiscard]] std::string trim(const std::string &input);
} // namespace Utils::Generic
