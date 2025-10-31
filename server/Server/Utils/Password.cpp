#include <botan/argon2fmt.h>
#include <botan/auto_rng.h>

#include "Password.hpp"
#include "../Constants.hpp"


std::string Utils::Password::hash(const std::string &password) {
  Botan::AutoSeeded_RNG rng;

  return Botan::argon2_generate_pwhash(password.c_str(), password.size(), rng, Constants::ARGON2_PARALLELISM, Constants::ARGON2_MEMORY_KB, Constants::ARGON2_ITERATIONS);
}

bool Utils::Password::verify(const std::string &password, const std::string &passwordHash) {
  return Botan::argon2_check_pwhash(password.c_str(), password.size(), passwordHash);
}
