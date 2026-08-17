#pragma once

#include <drogon/HttpController.h>

namespace API {
using namespace drogon;

class Auth : public HttpController<Auth> {
public:
  METHOD_LIST_BEGIN

  METHOD_ADD(Auth::_registerUser, "/register", Post);
  METHOD_ADD(Auth::_loginUser, "/login", Post);
  METHOD_ADD(Auth::_refreshToken, "/refresh-token", Post);
  METHOD_ADD(Auth::_getMe, "/me", Get, "Middleware::AuthFilter");

  METHOD_LIST_END

private:
  static void _registerUser(const HttpRequestPtr &req,
                            std::function<void(const HttpResponsePtr &)> &&callback);

  static void _loginUser(const HttpRequestPtr &req,
                         std::function<void(const HttpResponsePtr &)> &&callback);

  static void _refreshToken(const HttpRequestPtr &req,
                            std::function<void(const HttpResponsePtr &)> &&callback);

  static void _getMe(const HttpRequestPtr &req,
                     std::function<void(const HttpResponsePtr &)> &&callback);

  static std::pair<std::string, std::string> generateTokenPair(const std::string &userId);
};
} // namespace API