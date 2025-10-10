#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace Utils {
std::vector<uint8_t> readFile(const std::string &path);
}