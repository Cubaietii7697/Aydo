#pragma once

#include <botan/argon2.h>
#include <string>

namespace Utils::Password {

std::string hash(const std::string &password);
[[nodiscard]] bool verify(const std::string &password, const std::string &passwordHash);

} // namespace Utils::Password
