#define NOMINMAX
#include "Utills.hpp"

#include <Windows.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <format>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "Constants.hpp"

namespace Utills {

void printBanner(bool isClosing) {
  std::string bannerStr(BANNER);
  std::vector<std::string> lines;
  std::stringstream ss(bannerStr);
  std::string line;

  while (std::getline(ss, line))
    lines.push_back(line);

  if (isClosing) {
    for (size_t i = lines.size(); i-- > 0;) {
      system("cls");
      for (size_t j = 0; j <= i; ++j)
        std::cout << lines[j] << '\n';
      Sleep(ANIMATION_SLEEP_TIME_MS);
    }
    system("cls");
  } else {
    for (size_t i = 0; i < lines.size(); ++i) {
      system("cls");
      for (size_t j = 0; j <= i; ++j)
        std::cout << lines[j] << '\n';
      Sleep(ANIMATION_SLEEP_TIME_MS);
    }
  }
  std::cout << std::endl;
}

static std::wstring utf8ToWide(const std::string &s) {
  if (s.empty()) {
    return std::wstring();
  }
  const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
  std::wstring w(n - 1, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);

  return w;
}

static void readPipeToString(HANDLE hPipe, std::string &out) {
  constexpr DWORD CHUNK_SIZE = 16 * 1024;
  std::vector<char> buf(CHUNK_SIZE);
  DWORD read = 0;
  for (;;) {
    if (!ReadFile(hPipe, buf.data(), CHUNK_SIZE, &read, nullptr) || read == 0)
      break;
    out.append(buf.data(), buf.data() + read);
  }
}

int executeAndWaitRC(const std::string &cmdUtf8,
                     std::string *out,
                     std::string *err,
                     std::chrono::milliseconds timeout) {
  SECURITY_ATTRIBUTES sa{};
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;

  HANDLE outRead = nullptr;
  HANDLE outWrite = nullptr;
  HANDLE errRead = nullptr;
  HANDLE errWrite = nullptr;

  if (!CreatePipe(&outRead, &outWrite, &sa, 0)) {
    return -1;
  }
  if (!SetHandleInformation(outRead, HANDLE_FLAG_INHERIT, 0)) {
    return -1;
  }
  if (!CreatePipe(&errRead, &errWrite, &sa, 0)) {
    return -1;
  }
  if (!SetHandleInformation(errRead, HANDLE_FLAG_INHERIT, 0)) {
    return -1;
  }

  STARTUPINFOW si{};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdOutput = outWrite;
  si.hStdError = errWrite;
  si.hStdInput = nullptr;

  PROCESS_INFORMATION pi{};

  std::wstring cmdW = utf8ToWide(cmdUtf8);
  std::vector<wchar_t> cmdBuf(cmdW.begin(), cmdW.end());
  cmdBuf.push_back(L'\0');

  BOOL ok = CreateProcessW(
      nullptr, cmdBuf.data(),
      nullptr, nullptr,
      TRUE, CREATE_NO_WINDOW,
      nullptr, nullptr,
      &si, &pi);

  CloseHandle(outWrite);
  outWrite = nullptr;
  CloseHandle(errWrite);
  errWrite = nullptr;

  if (!ok) {
    const DWORD le = GetLastError();
    std::cerr << "CreateProcessW failed for cmd: " << cmdUtf8
              << " (GetLastError=" << le << ")\n";
    CloseHandle(outRead);
    CloseHandle(errRead);
    return -1;
  }

  std::string outBuf;
  std::string errBuf;
  std::jthread tOut(readPipeToString, outRead, std::ref(outBuf));
  std::jthread tErr(readPipeToString, errRead, std::ref(errBuf));

  DWORD waitMs = (timeout == std::chrono::milliseconds::max())
                     ? INFINITE
                     : static_cast<DWORD>(timeout.count());
  DWORD wr = WaitForSingleObject(pi.hProcess, waitMs);

  int rc = -1;
  if (wr == WAIT_TIMEOUT) {
    constexpr DWORD EXITCODE_TIMEOUT_GNU = 124;
    TerminateProcess(pi.hProcess, EXITCODE_TIMEOUT_GNU);
    WaitForSingleObject(pi.hProcess, INFINITE);
    rc = EXITCODE_TIMEOUT_GNU;
  } else {
    DWORD code = 0;
    if (GetExitCodeProcess(pi.hProcess, &code))
      rc = static_cast<int>(code);
  }

  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  CloseHandle(outRead);
  CloseHandle(errRead);

  tOut.join();
  tErr.join();

  if (!outBuf.empty())
    std::cout << outBuf;
  if (!errBuf.empty())
    std::cerr << errBuf;

  if (out)
    *out = std::move(outBuf);
  if (err)
    *err = std::move(errBuf);
  return rc;
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
  auto ensureQuotedLocal = [](const std::string &s) {
    if (!s.empty() && s.front() == '"' && s.back() == '"') {
      return s;
    }
    return std::string("\"") + s + "\"";
  };
  auto squashDoubleSlashes = [](std::string s) {
    for (size_t i = 1; i < s.size(); ++i) {
      if (s[i] == '\\' && s[i - 1] == '\\')
        s.erase(i--, 1);
    }

    return s;
  };

  const std::string vmrun = dequote(vmRunPath);
  std::string vmx = squashDoubleSlashes(dequote(sandboxPath));
  std::string full = std::string("\"") + vmrun + "\" -T ws checkToolsState " + ensureQuotedLocal(vmx);

  for (int i = 0; i < maxRetries; ++i) {
    SECURITY_ATTRIBUTES sa{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    HANDLE hRead = nullptr;
    HANDLE hWrite = nullptr;
    CreatePipe(&hRead, &hWrite, &sa, 0);
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;

    PROCESS_INFORMATION pi{};
    std::vector<char> cmd(full.begin(), full.end());
    cmd.push_back('\0');

    BOOL ok = CreateProcessA(nullptr, cmd.data(),
                             nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                             nullptr, nullptr, &si, &pi);

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

    std::string lower = output;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (lower.find("not running") == std::string::npos &&
        lower.find("running") != std::string::npos) {
      return true;
    }

    Sleep(sleepMs);
  }
  return false;
}

int runPSInGuest(const std::string &vmRunPath,
                 const std::string &sandboxVmx,
                 std::string_view psCommand) {
  const std::string psPath = R"(C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe)";
  const std::string cmd = std::format(
      R"({} -T ws -gu {} -gp {} runProgramInGuest {} {} -NoLogo -NoProfile -NonInteractive -Command {})",
      vmRunPath, std::string(GUEST_USER), std::string(GUEST_PASS),
      sandboxVmx, ensureQuoted(psPath), psQuote(std::string(psCommand)));
  return executeAndWaitRC(cmd);
}

bool guestPathExists(const std::string &vmRunPath,
                     const std::string &sandboxVmx,
                     std::string_view guestPath) {
  const std::string cmd = std::format(
      R"(if (Test-Path {}) {{ exit 0 }} else {{ exit 1 }})",
      psQuote(std::string(guestPath)));
  return runPSInGuest(vmRunPath, sandboxVmx, cmd) == 0;
}

std::string ensureQuoted(const std::string &s) {
  if (!s.empty() && s.front() == '"' && s.back() == '"') {
    return s;
  }
  return std::format(R"("{}")", s);
}

std::string psQuote(const std::string &s) {
  std::string out;
  out.reserve(s.size() + 2);
  out.push_back('\'');
  for (char c : s) {
    if (c == '\'')
      out += "''";
    else
      out.push_back(c);
  }
  out.push_back('\'');
  return out;
}

std::string winQuote(std::string_view s) {
  if (const bool need = s.empty() || s.find_first_of(" \t\n\v\"") != std::string_view::npos; !need)
    return std::string(s);

  std::string out;
  out.push_back('"');
  size_t bs = 0;

  for (char c : s) {
    if (c == '\\') {
      ++bs;
      continue;
    }
    if (c == '"') {
      out.append(bs * 2 + 1, '\\'); // escape quote
      out.push_back('"');
      bs = 0;
      continue;
    }
    if (bs) {
      out.append(bs, '\\');
      bs = 0;
    }
    out.push_back(c);
  }
  if (bs)
    out.append(bs * 2, '\\');
  out.push_back('"');
  return out;
}

} // namespace Utills
