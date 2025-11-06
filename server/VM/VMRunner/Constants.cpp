#include "Constants.hpp"

#include <cstdlib>

std::string getEnvOrDefault(const char *name, std::string_view def) {
  if (const char *v = std::getenv(name)) {
    return std::string(v);
  }
  return std::string(def);
}

const std::string VM_RUN_PATH =
    getEnvOrDefault("VM_RUN_PATH", R"(C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe)");

const std::string ANALYSIS_VM_PATH =
    getEnvOrDefault("ANALYSIS_VM_PATH", R"(D:\veeeertoooaaalll\SANDBOX1\SANDBOX1.vmx)");

const std::string SANDBOXES_DIRECTORY_PATH =
    getEnvOrDefault("SANDBOXES_DIRECTORY_PATH", R"(D:\veeeertoooaaalll\copy.me.here.plz)");

const std::string HOST_FOLDER_PATH =
    getEnvOrDefault("HOST_FOLDER_PATH", R"(C:\Shared)");

const std::string SHARE_FILE_NAME =
    getEnvOrDefault("SHARE_FILE_NAME", "logs.log");

const std::string GUEST_USER =
    getEnvOrDefault("GUEST_USER", "vmuser");

const std::string GUEST_PASS =
    getEnvOrDefault("GUEST_PASS", "vmpassword");

const std::string PM_FILE_PATH =
    getEnvOrDefault("PM_FILE_PATH", R"(C:\Projects\ProcessMonitor\x64\Debug\readFromVm.exe)");

const std::string PM_FILE_PATH_GUEST =
    getEnvOrDefault("PM_FILE_PATH_GUEST", R"(C:\Users\vmuser\Desktop\Ghost.exe)");

const std::string SUSPICIOUS_FILE_PATH =
    getEnvOrDefault("SUSPICIOUS_FILE_PATH", R"(C:\Users\vmuser\Desktop\filetoplot.exe)");
