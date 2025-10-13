#include "ACScanningEngine.hpp"

#include <iostream>
#include <ostream>

#include "../Errors.hpp"

ACScanningEngine::ACScanningEngine(const std::vector<std::string> &hexPatterns, const size_t &chunkSize)
    : m_chunkSize(chunkSize) {
  if (hexPatterns.empty()) {
    throw Errors::NoPatternsProvidedException();
  }

  // Parse patterns and collect segments
  auto [parsedPatterns, allSegments] = ACUtils::parsePatternsAndCollectSegments(hexPatterns);

  if (parsedPatterns.empty()) {
    throw Errors::NoValidPatternsFoundException();
  }

  m_parsedPatterns = parsedPatterns;
  m_allSegments = allSegments;
}

SearchResult ACScanningEngine::scanFile(const std::string &filePath) {
  try {
    // Find segment positions in file
    ACUtils::SegmentPositions segmentPositions;
    try {
      segmentPositions = ACUtils::findSegmentPositionsInFile(filePath, m_allSegments, m_chunkSize);
    } catch (const std::exception &e) {
      std::cerr << "ERROR: Couldn't search file: " << e.what() << std::endl;

      throw Errors::FailedToSearchFileException(e.what());
    }

    auto [success, result] = ACUtils::searchPatternsCommon(m_parsedPatterns, m_allSegments, segmentPositions);

    return success ? std::optional<std::string>(result) : std::nullopt;
  } catch (const std::exception &e) {
    return std::nullopt;
  }
}

SearchResult ACScanningEngine::scanMemory(const std::vector<uint8_t> &data) {
  try {
    // Find segment positions in memory
    ACUtils::SegmentPositions segmentPositions;
    try {
      segmentPositions = ACUtils::findSegmentPositionsInMemory(data, m_allSegments);
    } catch (const std::exception &e) {
      std::cerr << "ERROR: Couldn't search memory: " << e.what() << std::endl;

      throw Errors::FailedToSearchMemoryException(e.what());
    }

    auto [success, result] = ACUtils::searchPatternsCommon(m_parsedPatterns, m_allSegments, segmentPositions);

    return success ? std::optional<std::string>(result) : std::nullopt;
  } catch (const std::exception &e) {
    return std::nullopt;
  }
}
