#pragma once

#include <drogon/HttpResponse.h>
#include <json/json.h>

inline drogon::HttpResponsePtr jsonError(const std::string &message,
                                         drogon::HttpStatusCode code = drogon::k400BadRequest) {
  Json::Value body;
  body["message"] = message;

  auto res = drogon::HttpResponse::newHttpJsonResponse(body);
  res->setStatusCode(code);

  LOG_DEBUG << "Sending error response: " << message << " (code: " << code << ")";

  return res;
}

inline drogon::HttpResponsePtr jsonOk(const Json::Value &body,
                                      drogon::HttpStatusCode code = drogon::k200OK) {
  auto res = drogon::HttpResponse::newHttpJsonResponse(body);
  res->setStatusCode(code);

  return res;
}
