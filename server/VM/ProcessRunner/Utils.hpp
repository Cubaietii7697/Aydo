#pragma once

#include <windows.h>

#include <string>
#include <vector>

namespace Utils {
bool doesFileExist(const std::string &path);
std::string vectorStringToString(const std::vector<std::string> &vector, const std::string &separator);
bool injectDll(HANDLE hProcess, const std::string &dllPath);
bool createSuspendedProcess(const std::string &cmdLine,
                            const std::string &workingDirectory,
                            STARTUPINFOA &startupInfo,
                            PROCESS_INFORMATION &processInfo);
}; // namespace Utils
