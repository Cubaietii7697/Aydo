#pragma once

#include <string_view>

namespace Constants {
constexpr std::string_view CONFIG_FILE = "config.json";

// Authentication - JWT Token TTLs
constexpr long long ACCESS_TOKEN_TTL_SECONDS = 15 * 60;              // 15 minutes
constexpr long long REFRESH_TOKEN_TTL_SECONDS = 30LL * 24 * 60 * 60; // 30 days

// Password Hashing - Argon2id Parameters
// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
constexpr size_t ARGON2_PARALLELISM = 1;
constexpr size_t ARGON2_MEMORY_KB = 1024 * 46;
constexpr size_t ARGON2_ITERATIONS = 1;
} // namespace Constants
