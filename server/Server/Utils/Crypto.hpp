#pragma once

#include <string>


namespace Utils::Crypto {

[[nodiscard]] std::string base64UrlEncode(const std::string &data);

[[nodiscard]] std::string base64UrlDecode(const std::string &data);

[[nodiscard]] std::string hmacSha256(const std::string &data, const std::string &key);

} // namespace Utils::Crypto

