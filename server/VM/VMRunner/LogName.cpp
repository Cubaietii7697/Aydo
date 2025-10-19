#include "LogName.hpp"

std::string LogName::sanitizeForFilename(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (char c : s) {
    switch (c) {
    case '<':
    case '>':
    case ':':
    case '"':
    case '/':
    case '\\':
    case '|':
    case '?':
    case '*':
      out.push_back('_');
      break;
    default:
      out.push_back(c);
      break;
    }
  }
  if (out.empty())
    out = "unknown";
  return out;
}

std::string LogName::makeLogFileName(std::string_view sandboxId, std::string_view base, std::string_view ext) {
  const auto now = floor<std::chrono::seconds>(std::chrono::system_clock::now());

#if defined(_MSC_VER) && _MSC_VER >= 1930
  // VS2022 supports chrono formatting with std::format
  const std::string ts = std::format("{:%Y%m%d_%H%M%S}", now);
#else
  // Fallback using std::put_time if your STL is older
  std::time_t tt = system_clock::to_time_t(now);
  std::tm tm{};
  localtime_s(&tm, &tt);
  std::ostringstream oss;
  oss << std::put_time(&tm, "%Y%m%d_%H%M%S");
  const std::string ts = oss.str();
#endif

  const auto pid = static_cast<unsigned>(_getpid());
  const std::string safeId = sanitizeForFilename(sandboxId);

  return std::format("{}_{}_{}_{}.{}",
                     base, safeId, ts, pid, ext);
}
