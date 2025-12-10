#include "Generic.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <format>


namespace Utils::Generic {

long long getCurrentTimestamp() {
  const auto now = std::chrono::system_clock::now();
  const auto duration = now.time_since_epoch();

  return std::chrono::duration_cast<std::chrono::seconds>(duration).count();
}

std::string quoteIfNeeded(const std::string &value) {
  if (value.empty()) {
    return "\"\"";
  }

  if (value.front() == '"' && value.back() == '"') {
    return value;
  }

  return std::format(R"("{}")", value);
}

std::string trim(const std::string &input) {
  const auto begin =
      std::find_if_not(input.begin(), input.end(), [](unsigned char ch) {
        return std::isspace(ch) != 0;
      });
  const auto rbegin =
      std::find_if_not(input.rbegin(), input.rend(), [](unsigned char ch) {
        return std::isspace(ch) != 0;
      });
  if (begin >= rbegin.base()) {
    return {};
  }
  return std::string(begin, rbegin.base());
}

} // namespace Utils::Generic
