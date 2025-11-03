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
 * Path in Host
 */
constexpr std::string_view VM_RUN_PATH = R"("C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe")";
constexpr std::string_view ANALYSIS_VM_PATH = R"("D:\veeeertoooaaalll\SANDBOX1\SANDBOX1.vmx")";
constexpr std::string_view SANDBOXES_DIRECTORY_PATH = R"(D:\veeeertoooaaalll\)";
constexpr std::string_view PM_FILE_PATH = R"(C:\Dev\Magshii\Project\aydo\Server\VM\ProcessMonitor\bin\x64\Release\ProcessMonitor.exe)";
constexpr std::string_view HOST_FOLDER_PATH = R"(D:\Shared)";

/*
 * Path in VM
 */
constexpr std::string_view PM_FILE_PATH_INSIDE_VM = R"(C:\Temp\Ghost.exe)";
constexpr std::string_view FILE_PATH_INSIDE = R"(C:\Temp)";

/*
 * Path in BOTH
 */
constexpr std::string_view SHARED_FOLDER_NAME = "shared";
constexpr std::string_view LOG_FILE_NAME = "logs.log";

/* !!!
 *  Must be the username and password of VM
 */
constexpr std::string_view GUEST_USER = R"(KAN12)";
constexpr std::string_view GUEST_PASS = "1234";
/*-------------------------------------------------------------------------------------------*/
constexpr unsigned int ANIMATION_SLEEP_TIME_MS = 50;
constexpr unsigned int ANIMATION_SLEEP_TIME_S = 5;
constexpr unsigned int BOOTUP_SLEEP_TIME_S = 20;
constexpr unsigned int DEFUALT_TIME_CHECK = 60;
