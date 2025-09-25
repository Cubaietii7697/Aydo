#include <iostream>
#include <print>

#include "Utils.hpp"

int main(int argc, char *argv[]) {
  if (argc != 2) {
    std::cerr << "[usage] KernalDriver.exe <file-to-kill>" << std::endl;
    return 1;
  }
  const std::filesystem::path &file = argv[1];
  if (std::set<DWORD> pids = Utils::findProcess(file); !Utils::KillAllProcess(pids)) {
    Utils::PrintError(L"didn't kill all because:");
    return 1;
  }
  std::print("Successfully killed");
  return 0;
}
