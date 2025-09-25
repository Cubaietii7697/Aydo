#include <iostream>

#include "Utils.hpp"

int main(int argc, char *argv[]) {
  constexpr int FILE = 1;
  constexpr int MODE = 2;

  if (argc != 3) {
    std::cerr << "[usage] KernalDriver.exe <file-to-kill> <0=user 1=kernel>" << std::endl;
    return EXIT_FAILURE;
  }
  const std::filesystem::path &exePath = argv[FILE];
  const int mode = std::stoi(argv[MODE]);
  std::set<DWORD> pids = Utils::findProcess(exePath);

  if (pids.empty()) {
    std::cerr << "No running process matches: " << exePath.filename().string() << std::endl;
    return EXIT_FAILURE;
  }

  if (mode == 0) {
    if (!Utils::KillAllProcess(pids)) {
      Utils::PrintError(L"[user] KillAllProcess failed");
      return EXIT_FAILURE;
    }
  } else if (mode == 1) {
    if (!Utils::UseKernelMode(pids)) {
      Utils::PrintError(L"[user] KillAllProcess failed");
      return EXIT_FAILURE;
    }
  } else {
    std::cerr << "Invalid mode: " << mode << " (expected 0 or 1)" << std::endl;
    return EXIT_FAILURE;
  }

  std::cout << "Successfully sent terminate requests (" << (mode ? "kernel" : "user") << " mode)" << std::endl;
  return EXIT_SUCCESS;
}
