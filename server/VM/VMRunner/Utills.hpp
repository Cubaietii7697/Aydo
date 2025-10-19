#pragma once
#include <chrono>
#include <string>
#include <string_view>

namespace Utills {

void printBanner(bool isClosing = false);

int executeAndWaitRC(const std::string &cmd,
                     std::string *out = nullptr,
                     std::string *err = nullptr,
                     std::chrono::milliseconds timeout = std::chrono::milliseconds::max());

bool waitForTools(const std::string &vmRunPath,
                  const std::string &sandboxPath,
                  int maxRetries = 60,
                  int sleepMs = 5000);

std::string ensureQuoted(const std::string &s);

std::string psQuote(const std::string &s);

std::string winQuote(std::string_view s);

int runPSInGuest(const std::string &vmRunPath,
                 const std::string &sandboxVmx,
                 std::string_view psCommand);

bool guestPathExists(const std::string &vmRunPath,
                     const std::string &sandboxVmx,
                     std::string_view guestPath);

constexpr int BUFFER_SIZE = 256;

} // namespace Utills
