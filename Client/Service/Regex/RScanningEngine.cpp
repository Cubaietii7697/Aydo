#include "RScanningEngine.hpp"

#include <cctype>
#include <fstream>
#include <iostream>
#include <limits>
#include <regex>
#include <sstream>
#include <string>

#include "../Errors.hpp"

RScanningEngine::RScanningEngine(const std::vector<std::string> &patterns) {
  const unsigned int HEX_STRING_MAX_LEN = 10;

  // Convert each hex pattern to a regex string
  std::vector<std::string> regexParts;
  regexParts.reserve(patterns.size());
  for (const auto &pattern : patterns) {
    try {
      regexParts.push_back(_hexPatternToRegexStr(pattern));
    } catch (const Errors::InvalidHexPatternException &e) {
      std::cerr << "Failed to parse hex pattern: " << pattern.substr(0, HEX_STRING_MAX_LEN) << "... (" << e.what() << ")" << std::endl;
    }
  }

  // Join all regex parts with OR operator
  const std::string masterPattern = _orJoinRegexParts(regexParts);
  m_masterRegex = std::regex(masterPattern, std::regex_constants::ECMAScript | std::regex_constants::icase);
}

SearchResult RScanningEngine::scanFile(const std::string &filePath) {
  try {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
      throw Errors::FailedToOpenFileException();
    }

    // Get file size
    file.seekg(0, std::ios::end);
    const std::streamoff endPos = file.tellg();
    if (endPos <= 0 || endPos == static_cast<std::streamoff>(-1)) {
      return std::nullopt;
    }
    file.seekg(0, std::ios::beg);

    // Read file into buffer
    std::string buffer;
    buffer.resize(static_cast<size_t>(endPos));
    const auto maxStream = std::numeric_limits<std::streamsize>::max();
    const std::streamsize toRead = endPos > maxStream ? maxStream : static_cast<std::streamsize>(endPos);
    file.read(buffer.data(), toRead);
    file.close();

    // Search for regex
    const char *begin = buffer.data();
    const char *end = begin + buffer.size();
    std::cmatch match;
    const bool any = std::regex_search(begin, end, match, m_masterRegex, std::regex_constants::match_default);
    if (!any) {
      return std::nullopt;
    }

    std::regex_search(begin, end, match, m_masterRegex);
    return std::string(match[0].first, match[0].second);
  } catch (const std::exception &e) {
    throw Errors::FailedToSearchFileException(e.what());
  }
}

SearchResult RScanningEngine::scanMemory(const std::vector<uint8_t> &data) {
  if (data.empty()) {
    return std::nullopt;
  }

  const char *begin = reinterpret_cast<const char *>(data.data());
  const char *end = begin + data.size();

  std::cmatch match;
  const bool any = std::regex_search(begin, end, match, m_masterRegex, std::regex_constants::match_default);
  if (!any) {
    return std::nullopt;
  }

  std::regex_search(begin, end, match, m_masterRegex);
  return std::string(match[0].first, match[0].second);
}

// Builds a regex for a hex pattern in the following format:
// AA BB CC -> will match a hex pattern of AA BB CC
// AA ?? CC -> will match a hex pattern of AA <any byte> CC
// AA * CC -> will match a hex pattern of AA <any bytes (including zero bytes)> CC
std::string RScanningEngine::_hexPatternToRegexStr(const std::string &hexPattern) {
  auto isHex = [](char c) { return std::isxdigit(static_cast<unsigned char>(c)) != 0; };

  std::ostringstream out;

  const std::string &s = hexPattern;
  std::size_t i = 0;
  while (i < s.size()) {
    auto ch = static_cast<unsigned char>(s[i]);

    // Skip any whitespace
    if (std::isspace(ch)) {
      i++;
      continue;
    }

    // Variable-length wildcard '*'
    if (s[i] == '*') {
      out << ".*";
      i++;
      continue;
    }

    // Single-byte wildcard '??'
    if (s[i] == '?' && (i + 1) < s.size() && s[i + 1] == '?') {
      out << ".";
      i += 2;
      continue;
    }

    // Exact byte: two hex digits
    if ((i + 1) < s.size() && isHex(s[i]) && isHex(s[i + 1])) {
      out << "\\x" << s[i] << s[i + 1];
      i += 2;
      continue;
    }

    // Invalid token
    throw Errors::InvalidHexPatternException();
    break;
  }

  return out.str();
}

std::regex RScanningEngine::_hexPatternToRegex(const std::string &hexPattern) {
  return std::regex(
      _hexPatternToRegexStr(hexPattern),
      std::regex_constants::ECMAScript | std::regex_constants::icase);
}

std::string RScanningEngine::_orJoinRegexParts(const std::vector<std::string> &parts) {
  std::ostringstream master;

  for (size_t i = 0; i < parts.size(); ++i) {
    if (i > 0) {
        master << '|';
    }
    master << "(?:" << parts[i] << ")";
  }

  return master.str();
}