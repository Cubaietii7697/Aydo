#pragma once

#include <drogon/HttpFilter.h>

namespace Middleware {

class AuthFilter : public drogon::HttpFilter<Middleware::AuthFilter> {
public:
  void doFilter(const drogon::HttpRequestPtr &req,
                drogon::FilterCallback &&fcb,
                drogon::FilterChainCallback &&fccb) override;
};

} // namespace Middleware
