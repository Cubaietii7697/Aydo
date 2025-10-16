#pragma once
#include <string_view>

constexpr std::string_view BANNER = R"(
    ___             __    
   /   | __  ______/ /___ 
  / /| |/ / / / __  / __ \
 / ___ / /_/ / /_/ / /_/ /
/_/  |_\__, /\__,_/\____/ 
      /____/              
)";

/*
 * In Real Server should be in config.json
 * In real server path should be in global zone
 */
constexpr std::string_view VM_RUN_PATH = R"("C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe")";
constexpr std::string_view ANALYSIS_VM_PATH = R"("D:\veeeertoooaaalll\SANDBOX1\SANDBOX1.vmx")";
constexpr std::string_view SANDBOXES_DIRECTORY_PATH = R"(D:\veeeertoooaaalll\copy.me.here.plz)";

constexpr unsigned int ANIMATION_SLEEP_TIME_MS = 50;
