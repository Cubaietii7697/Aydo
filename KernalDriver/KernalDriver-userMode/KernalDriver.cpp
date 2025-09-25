#include <iostream>

#include "Utils.hpp"

int main(int argc, char *argv[]) {
  if (argc != 3) {
    std::cerr << "[usage] KernalDriver.exe <file-to-kill> <0=user 1=kernel>" << std::endl;
    return 1;
  }
  const std::filesystem::path &exePath = argv[1];
  const int mode = std::stoi(argv[2]);
  std::set<DWORD> pids = Utils::findProcess(exePath);

  if (pids.empty()) {
    std::cerr << "No running process matches: " << exePath.filename().string() << "\n";
    return 2;
  }

  if (mode == 0) {
    if (!Utils::KillAllProcess(pids)) {
      Utils::PrintError(L"[user] KillAllProcess failed");
      return 3;
    }
  } else if (mode == 1) {
    if (!Utils::UseKernelMode(pids)) {
      Utils::PrintError(L"[user] KillAllProcess failed");
      return 3;
    }
  } else {
    std::cerr << "Invalid mode: " << mode << " (expected 0 or 1)\n";
    return 6;
  }

  std::cout << "Successfully sent terminate requests (" << (mode ? "kernel" : "user") << " mode)\n";
  return 0;
}
