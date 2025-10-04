#include "Utils.hpp"

#include <filesystem>
#include <vector>

bool Utils::doesFileExist(const std::string &path) {
  return std::filesystem::exists(path);
}

std::string Utils::vectorStringToString(const std::vector<std::string> &vector, const std::string &separator) {
  std::string result;

  for (const auto &str : vector) {
    result += str + separator;
  }

  return result;
}

bool Utils::injectDll(HANDLE hProcess, const std::string &dllPath) {
  SIZE_T dllPathLength = dllPath.length() + 1; // Include null char

  // Allocate memory in the remote process (for the DLL)
  LPVOID remoteMemory = VirtualAllocEx(
      hProcess,
      nullptr,
      dllPathLength,
      MEM_COMMIT,
      PAGE_READWRITE);
  if (!remoteMemory) {
    return false;
  }

  // Write the DLL path to the remote process
  if (!WriteProcessMemory(hProcess,
                          remoteMemory,
                          dllPath.c_str(),
                          dllPathLength,
                          nullptr)) {
    VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
    return false;
  }

  // Create a remote thread to load the DLL
  HANDLE hThread = CreateRemoteThread(
      hProcess,
      nullptr,
      0,
      (LPTHREAD_START_ROUTINE)LoadLibraryA,
      remoteMemory,
      0,
      nullptr);
  if (!hThread) {
    VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
    return false;
  }

  // Wait for the thread to finish
  WaitForSingleObject(hThread, INFINITE);

  VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
  CloseHandle(hThread);

  return true;
}

bool Utils::createSuspendedProcess(const std::string &cmdLine,
                                   const std::string &workingDirectory,
                                   STARTUPINFOA &startupInfo,
                                   PROCESS_INFORMATION &processInfo) {
  std::vector<char> mutableCmdLine(cmdLine.begin(), cmdLine.end());
  mutableCmdLine.push_back('\0');

  bool success = CreateProcessA(
                     nullptr,
                     mutableCmdLine.data(),
                     nullptr,
                     nullptr,
                     FALSE,
                     CREATE_SUSPENDED,
                     nullptr,
                     workingDirectory.c_str(),
                     &startupInfo,
                     &processInfo) != 0;

  return success;
}
