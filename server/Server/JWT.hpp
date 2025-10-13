#pragma once

#include <string>
#include <map>
#include <optional>

class JWT {
public:
  using Claims = std::map<std::string, std::string>;

  static JWT &instance();

  [[nodiscard]] static std::string generate(const Claims &claims);

  [[nodiscard]] static std::optional<Claims> verify(const std::string &token);

private:
  JWT();
  ~JWT() = default;

  std::string m_secret;

  static constexpr char SEPARATOR = '.';
};
