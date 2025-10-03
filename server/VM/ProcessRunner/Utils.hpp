#pragma once

#include <string>
#include <windows.h>

namespace Utils {
  bool doesFileExist(const std::string &path);
  std::string createCmdLine(const std::string &program, const std::string &arguments);
  bool injectDll(HANDLE hProcess, const std::string &dllPath);
};
