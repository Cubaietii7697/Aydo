#include "Utils.hpp"

#include <fstream>

std::vector<uint8_t> Utils::readFile(const std::string &path) {
  std::ifstream file(path, std::ios::binary);

  if (!file) {
    throw std::runtime_error("Failed to open file");
  }

  return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}
