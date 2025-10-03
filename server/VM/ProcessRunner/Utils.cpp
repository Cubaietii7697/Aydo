#include "Utils.hpp"

#include <filesystem>

bool Utils::doesFileExist(const std::string &path) {
  return std::filesystem::exists(path);
}

std::string Utils::createCmdLine(const std::string &program, const std::string &arguments) {
  return program + " " + arguments;
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
