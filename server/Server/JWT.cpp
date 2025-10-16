#include "JWT.hpp"

#include <drogon/HttpAppFramework.h>
#include <nlohmann/json.hpp>
#include <sstream>
#include <trantor/utils/Logger.h>
#include <vector>

#include "Constants.hpp"
#include "Utils/Crypto.hpp"

JWT &JWT::instance() {
  static JWT inst;

  return inst;
}

JWT::JWT() {
  try {
    auto jwtSecret = drogon::app().getCustomConfig().get(reinterpret_cast<const char *>(Constants::JWT_SECRET_JSON_KEY.data()), "");
    m_secret = jwtSecret.asString();
    if (m_secret.empty()) {
      LOG_ERROR << "JWT secret is empty; set 'jwtSecret' in config";
    }
  } catch (const std::exception &e) {
    LOG_ERROR << "Failed to load JWT secret from config: " << e.what();
  }
}

std::string JWT::generate(const Claims &claims) {
  using json = nlohmann::json;

  // Header
  json header = {{"alg", "HS256"}, {"typ", "JWT"}};
  std::string headerStr = Utils::Crypto::base64UrlEncode(header.dump());

  // Payload
  json payload = json::object();
  for (const auto &[key, value] : claims) {
    payload[key] = value;
  }
  std::string payloadStr = Utils::Crypto::base64UrlEncode(payload.dump());

  // Signature
  std::string message = headerStr + SEPARATOR + payloadStr;
  std::string signature = Utils::Crypto::base64UrlEncode(
      Utils::Crypto::hmacSha256(message, instance().m_secret));

  return message + SEPARATOR + signature;
}

std::optional<JWT::Claims> JWT::verify(const std::string &token) {
  using json = nlohmann::json;

  // Split token into parts
  std::vector<std::string> parts;
  std::istringstream stream(token);
  std::string part;
  while (std::getline(stream, part, '.')) {
    parts.push_back(part);
  }

  if (parts.size() != 3) {
    LOG_WARN << "Invalid JWT format: expected 3 parts";

    return std::nullopt;
  }

  const std::string &headerB64 = parts[0];
  const std::string &payloadB64 = parts[1];
  const std::string &signatureB64 = parts[2];

  // Verify signature
  std::string message = headerB64 + SEPARATOR + payloadB64;
  std::string expectedSignature = Utils::Crypto::base64UrlEncode(
      Utils::Crypto::hmacSha256(message, instance().m_secret));

  if (expectedSignature != signatureB64) {
    LOG_WARN << "JWT signature verification failed";

    return std::nullopt;
  }

  // Decode and parse payload
  std::string payloadStr = Utils::Crypto::base64UrlDecode(payloadB64);
  if (payloadStr.empty()) {
    LOG_WARN << "Failed to decode JWT payload";

    return std::nullopt;
  }

  try {
    json payload = json::parse(payloadStr);
    Claims claims;
    for (auto it = payload.begin(); it != payload.end(); ++it) {
      if (it.value().is_string()) {
        claims[it.key()] = it.value().get<std::string>();
      } else {
        // Convert non-string values to string
        claims[it.key()] = it.value().dump();
      }
    }
    return claims;
  } catch (const std::exception &e) {
    LOG_WARN << "Failed to parse JWT payload: " << e.what();

    return std::nullopt;
  }
}
