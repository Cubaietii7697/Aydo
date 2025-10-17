#include "Utills.hpp"

#include <algorithm>
#include <ranges>

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
  auto dequote = [](std::string s) {
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"')
      s = s.substr(1, s.size() - 2);
    return s;
  };
  auto ensureQuoted = [](const std::string &s) -> std::string {
    if (!s.empty() && s.front() == '"' && s.back() == '"')
      return s;
    return std::string("\"") + s + "\"";
  };
  auto squashDoubleSlashes = [](std::string s) {
    for (size_t i = 1; i < s.size(); ++i) {
      if (s[i] == '\\' && s[i - 1] == '\\')
        s.erase(i--, 1);
    }
    return s;
  };

  // Build one full, mutable command line. Pass ApplicationName = nullptr.
  const std::string vmrun = dequote(vmRunPath);
  std::string vmx = squashDoubleSlashes(dequote(sandboxPath));
  std::string full = std::string("\"") + vmrun + "\" -T ws checkToolsState " + ensureQuoted(vmx);

  for (int i = 0; i < maxRetries; ++i) {
    SECURITY_ATTRIBUTES sa{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    HANDLE hRead = nullptr, hWrite = nullptr;
    CreatePipe(&hRead, &hWrite, &sa, 0);
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;

    PROCESS_INFORMATION pi{};
    // CreateProcess requires a writable buffer for the command line
    std::vector<char> cmd(full.begin(), full.end());
    cmd.push_back('\0');

    BOOL ok = CreateProcessA(
        /*lpApplicationName*/ nullptr,
        /*lpCommandLine    */ cmd.data(),
        nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr,
        &si, &pi);

    CloseHandle(hWrite);

    std::string output;
    if (ok) {
      char buf[BUFFER_SIZE]{};
      DWORD n = 0;
      while (ReadFile(hRead, buf, sizeof(buf) - 1, &n, nullptr) && n) {
        buf[n] = '\0';
        output += buf;
      }
      WaitForSingleObject(pi.hProcess, INFINITE);
      CloseHandle(pi.hProcess);
      CloseHandle(pi.hThread);
    }
    CloseHandle(hRead);

    // Debug so this never gaslights you again
    std::string lower = output;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    std::cout << "[vmrun cmd] " << full << "\n";
    std::cout << "[vmrun output] " << lower << "\n";

    if (lower.find("not running") == std::string::npos &&
        lower.find("running") != std::string::npos) {
      return true;
    }
    Sleep(sleepMs);
  }
  return false;
}

} // namespace Utills
