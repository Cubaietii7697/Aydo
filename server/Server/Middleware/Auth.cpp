#include "Auth.hpp"

#include <ctime>
#include <trantor/utils/Logger.h>

#include "../JWT.hpp"
#include "../Utils/Responses.hpp"

void Middleware::AuthFilter::doFilter(const drogon::HttpRequestPtr &req,
                                      drogon::FilterCallback &&fcb,
                                      drogon::FilterChainCallback &&fccb) {
  LOG_DEBUG << "Got an auth filter request";

  // Extract the Authorization header
  auto authHeader = req->getHeader("Authorization");

  if (authHeader.empty()) {
    return fcb(jsonError("Missing Authorization header",
                         drogon::HttpStatusCode::k401Unauthorized));
  }

  // Check if it's a Bearer token
  const std::string bearerPrefix = "Bearer ";
  if (authHeader.size() <= bearerPrefix.size() ||
      authHeader.substr(0, bearerPrefix.size()) != bearerPrefix) {
    return fcb(jsonError("Invalid Authorization header format",
                         drogon::HttpStatusCode::k401Unauthorized));
  }

  // Extract the token
  std::string token = authHeader.substr(bearerPrefix.size());

  // Verify the token
  auto claims = JWT::verify(token);
  if (!claims) {
    return fcb(jsonError("Invalid or expired token",
                         drogon::HttpStatusCode::k401Unauthorized));
  }

  // Check if it's an access token
  auto typeIt = claims->find("type");
  if (typeIt == claims->end() || typeIt->second != "access") {
    return fcb(jsonError("Invalid token type",
                         drogon::HttpStatusCode::k401Unauthorized));
  }

  // Check expiration
  auto expIt = claims->find("exp");
  if (expIt != claims->end()) {
    try {
      long long exp = std::stoll(expIt->second);
      auto now = static_cast<long long>(std::time(nullptr));
      if (exp < now) {
        return fcb(jsonError("Token expired",
                             drogon::HttpStatusCode::k401Unauthorized));
      }
    } catch (...) {
      return fcb(jsonError("Invalid token",
                           drogon::HttpStatusCode::k401Unauthorized));
    }
  }

  // Get user ID from token
  auto subIt = claims->find("sub");
  if (subIt == claims->end()) {
    return fcb(jsonError("Invalid token",
                         drogon::HttpStatusCode::k401Unauthorized));
  }

  // Store user ID in request attributes for use in handlers
  req->attributes()->insert("userId", subIt->second);

  fccb();
}
