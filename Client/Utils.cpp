#include "Errors.hpp"
#include "Utils.hpp"

#include <fstream>

std::vector<uint8_t> Utils::readFile(const std::string &path) {
  std::ifstream file(path, std::ios::binary);

  if (!file) {
    throw Errors::FailedToOpenFileException();
  }

  return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}
