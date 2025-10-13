#define NOMINMAX

#include "Crypto.hpp"

#include <algorithm>
#include <botan/base64.h>
#include <botan/mac.h>
#include <trantor/utils/Logger.h>

namespace Utils::Crypto {

// A base64 URL is basically a base64 url without padding and with + and / replaced by - and _
std::string base64UrlEncode(const std::string &data) {
  std::string encoded = Botan::base64_encode(
      reinterpret_cast<const uint8_t *>(data.data()), data.size());

  // Convert to base64url format
  for (char &c : encoded) {
    if (c == '+')
      c = '-';
    else if (c == '/')
      c = '_';
  }

  // Remove padding
  encoded.erase(
      std::find_if(encoded.rbegin(), encoded.rend(),
                   [](char c) { return c != '='; })
          .base(),
      encoded.end());

  return encoded;
}

std::string base64UrlDecode(const std::string &data) {
  std::string base64 = data;

  // Convert from base64url to base64
  for (char &c : base64) {
    if (c == '-')
      c = '+';
    else if (c == '_')
      c = '/';
  }

  // Add padding (if the base64 string is not a multiple of 4)
  while (base64.size() % 4 != 0) {
    base64 += '=';
  }

  try {
    auto decoded = Botan::base64_decode(base64);
    return {decoded.begin(), decoded.end()};
  } catch (...) {
    return "";
  }
}

std::string hmacSha256(const std::string &data, const std::string &key) {
  auto mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
  if (!mac) {
    LOG_ERROR << "Failed to create HMAC-SHA256";

    return "";
  }

  mac->set_key(reinterpret_cast<const uint8_t *>(key.data()), key.size());
  mac->update(reinterpret_cast<const uint8_t *>(data.data()), data.size());
  auto result = mac->final();

  return {result.begin(), result.end()};
}

} // namespace Utils::Crypto
