#include "Utills.hpp"

namespace Utills {

void printBanner(bool isClosing) {
  std::string bannerStr(BANNER);
  std::vector<std::string> lines;
  std::stringstream ss(bannerStr);
  std::string line;

  while (std::getline(ss, line)) {
    lines.push_back(line);
  }

  if (isClosing) {
    for (size_t i = lines.size() - 1; i < lines.size(); i--) {
      system("cls");

      for (size_t j = 0; j <= i; j++) {
        std::cout << lines[j] << std::endl;
      }

      Sleep(ANIMATION_SLEEP_TIME_MS);
    }
    system("cls");
  } else {
    for (size_t i = 0; i < lines.size(); i++) {
      system("cls");

      for (size_t j = 0; j <= i; j++) {
        std::cout << lines[j] << std::endl;
      }

      Sleep(ANIMATION_SLEEP_TIME_MS);
    }
  }
}

void executeAndWait(const std::string &command) {
  STARTUPINFOA si = {sizeof(STARTUPINFOA)};
  PROCESS_INFORMATION pi;

  std::string cmdCopy = command;

  if (CreateProcessA(
          nullptr,     // Application name
          &cmdCopy[0], // Command line
          nullptr,     // Process handle not inheritable
          nullptr,     // Thread handle not inheritable
          FALSE,       // Set handle inheritance to FALSE
          0,           // No creation flags
          nullptr,     // Use parent's environment block
          nullptr,     // Use parent's starting directory
          &si,         // Pointer to STARTUPINFO structure
          &pi)) {      // Pointer to PROCESS_INFORMATION structure
    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
  } else {
    std::cerr << "Failed to execute command: " << command << std::endl;
    std::cerr << "Error: " << GetLastError() << std::endl;
  }
}

bool waitForTools(const std::string &vmRunPath,
                  const std::string &sandboxPath,
                  int maxRetries,
                  int sleepMs) {
  for (int i = 0; i < maxRetries; i++) {
    STARTUPINFOA si = {sizeof(STARTUPINFOA)};
    PROCESS_INFORMATION pi;
    SECURITY_ATTRIBUTES sa{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};

    HANDLE hRead;
    HANDLE hWrite;
    CreatePipe(&hRead, &hWrite, &sa, 0);
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    if (std::string cmd = std::format(R"("{}" checkToolsState "{}")",
                                      vmRunPath,
                                      sandboxPath);
        CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, TRUE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
      CloseHandle(hWrite);
      char buffer[256];
      DWORD bytesRead;
      std::string output;

      while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr)) {
        buffer[bytesRead] = '\0';
        output += buffer;
      }
      WaitForSingleObject(pi.hProcess, INFINITE);
      CloseHandle(pi.hProcess);
      CloseHandle(pi.hThread);
      CloseHandle(hRead);

      if (output.find("running") != std::string::npos) {
        return true;
      }
    }
    Sleep(sleepMs);
  }
  return false;
}
} // namespace Utills
