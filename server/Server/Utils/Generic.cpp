#include "Generic.hpp"

#include <chrono>

namespace Utils::Generic {

long long getCurrentTimestamp() {
  const auto now = std::chrono::system_clock::now();
  const auto duration = now.time_since_epoch();

  return std::chrono::duration_cast<std::chrono::seconds>(duration).count();
}

} // namespace Utils::Generic
