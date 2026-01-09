#pragma once

#include <string>

// Default config values
class UserConfig {
public:
  int killThreshold = 150;
  double entropyThreshold = 6.0;
  std::string serverUrl = "http://192.168.56.1";
  std::string accessToken;
  std::string refreshToken;
  int runtime = 60;

  static UserConfig &getInstance();
  bool load(const std::string &configPath = "config.json");
  bool save(const std::string &configPath = "config.json") const;

private:
  UserConfig() = default;
};
