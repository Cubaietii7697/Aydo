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
    getEnvOrDefault("ANALYSIS_VM_PATH", R"(D:\SandboxAnalysis\SANDBOX1.vmx)");

const std::string SANDBOXES_DIRECTORY_PATH =
    getEnvOrDefault("SANDBOXES_DIRECTORY_PATH", R"(D:\SandboxAnalysis\)");

const std::string PM_FILE_PATH_GUEST =
    getEnvOrDefault("PM_FILE_PATH_GUEST",
                    R"(C:\Users\vmuser\Desktop\ProcessMonitor.exe)");

const std::string DLL_INJECTOR_FILE_PATH_GUEST =
    getEnvOrDefault("DLL_INJECTOR_FILE_PATH_GUEST",
                    R"(C:\Users\vmuser\Desktop\InjectedDLL.dll)");

const std::string PROCCES_RUNNER_FILE_PATH_GUEST =
    getEnvOrDefault("PROCCES_RUNNER_FILE_PATH_GUEST",
                    R"(C:\Users\vmuser\Desktop\ProcessRunner.exe)");

const std::string HOST_FOLDER_PATH =
    getEnvOrDefault("HOST_FOLDER_PATH", R"(D:\Shared)");

const std::string SHARE_FILE_NAME =
    getEnvOrDefault("SHARE_FILE_NAME", "log.sqlite");

const std::string GUEST_SHARED_DIR =
    getEnvOrDefault("GUEST_SHARED_DIR",
                    R"(\\vmware-host\Shared Folders\Shared)");

const std::string GUEST_USER =
    getEnvOrDefault("GUEST_USER", "vmuser");

const std::string GUEST_PASS =
    getEnvOrDefault("GUEST_PASS", "vmpassword");

const std::string PM_FILE_PATH =
    getEnvOrDefault("PM_FILE_PATH",
                    R"(D:\SandboxBin\ProcessMonitor.exe)");

const std::string DLL_INJECTOR_FILE_PATH =
    getEnvOrDefault("DLL_INJECTOR_FILE_PATH",
                    R"(D:\SandboxBin\ProcessRunnerDLL.dll)");

const std::string PROCCES_RUNNER_FILE_PATH =
    getEnvOrDefault("PROCCES_RUNNER_FILE_PATH",
                    R"(D:\SandboxBin\ProcessRunner.exe)");

const std::string SUSPICIOUS_FILE_NAME_GUEST =
    getEnvOrDefault("SUSPICIOUS_FILE_NAME_GUEST",
                    "filetoplot.exe");

const std::string SUSPICIOUS_WORKDIR_GUEST =
    getEnvOrDefault("SUSPICIOUS_WORKDIR_GUEST",
                    R"(C:\Users\vmuser\Desktop\checks)");
