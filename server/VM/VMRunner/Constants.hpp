#pragma once
#include <cstdlib>
#include <string>
#include <string_view>

constexpr std::string_view BANNER = R"(
    ___             __    
   /   | __  ______/ /___ 
  / /| |/ / / / __  / __ \
 / ___ / /_/ / /_/ / /_/ /
/_/  |_\__, /\__,_/\____/ 
      /____/              
)";

std::string getEnvOrDefault(const char *name, std::string_view def);

extern const std::string VM_RUN_PATH;
extern const std::string ANALYSIS_VM_PATH;
extern const std::string SANDBOXES_DIRECTORY_PATH;
extern const std::string HOST_FOLDER_PATH;
extern const std::string SHARE_FILE_NAME;
extern const std::string GUEST_USER;
extern const std::string GUEST_PASS;
extern const std::string PM_FILE_PATH;
extern const std::string PM_FILE_PATH_GUEST;
extern const std::string SUSPICIOUS_FILE_PATH;

constexpr unsigned int ANIMATION_SLEEP_TIME_MS = 50;
