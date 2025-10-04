#include <windows.h>

#include <cstdlib>
#include <format>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "Constants.hpp"

namespace Utills {
void printBanner(bool isClosing = false);
void executeAndWait(const std::string &command);

bool waitForTools(const std::string &vmRunPath,
                  const std::string &sandboxPath,
                  int maxRetries = 60,
                  int sleepMs = 5000);
} // namespace Utills
