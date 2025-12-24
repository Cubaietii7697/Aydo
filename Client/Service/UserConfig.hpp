#pragma once

#include <string>

// Default config values
class UserConfig {
public:
  int killThreshold = 150;
  std::string serverUrl = "http://127.0.0.1";
  std::string accessToken;
  std::string refreshToken;
  int runtime = 60;

  static UserConfig &getInstance();
  bool load(const std::string &configPath = "config.json");
  bool save(const std::string &configPath = "config.json") const;

private:
  UserConfig() = default;
};
