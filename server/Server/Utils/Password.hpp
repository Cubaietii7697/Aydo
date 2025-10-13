#pragma once

#include <botan/argon2.h>
#include <string>

namespace Utils::Password {

std::string hash(const std::string &password);
bool verify(const std::string &password, const std::string &passwordHash);

// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
static constexpr size_t PARALLELISM = 1;
static constexpr size_t MEMORY_KB = 1024 * 46;
static constexpr size_t ITERATIONS = 1;

} // namespace Utils::Password
