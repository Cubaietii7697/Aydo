#include <windows.h>

#include <cstdlib>
#include <iostream>
#include <mutex>
#include <psapi.h>
#include <string_view>
#include <thread>
#include <vector>

#include "AhoCorasick/ACScanningEngine.hpp"
#include "Regex/RScanningEngine.hpp"
#include "Service/Service.hpp"
#include "SignaturesDatabase.hpp"
#include "Utils.hpp"

constexpr std::string_view BANNER = R"(
   ___ ___ _  _ ___ _   _ ___ 
  / __| __| \| |_ _| | | / __|
 | (_ | _|| .` || || |_| \__ \
  \___|___|_|\_|___|\___/|___/
                              
)";

// Rainbow colors for console output
const std::vector<WORD> rainbowColors = {
    FOREGROUND_RED | FOREGROUND_INTENSITY,
    FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
    FOREGROUND_GREEN | FOREGROUND_INTENSITY,
    FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
    FOREGROUND_BLUE | FOREGROUND_INTENSITY,
    FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY};

void setConsoleColor(WORD color) {
  SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

void printRainbowText(const std::string &text) {
  HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  GetConsoleScreenBufferInfo(hConsole, &csbi);

  WORD defaultColor = csbi.wAttributes;

  for (size_t i = 0; i < text.length(); ++i) {
    setConsoleColor(rainbowColors[i % rainbowColors.size()]);
    std::cout << text[i];
  }

  setConsoleColor(defaultColor);
}

void printRainbowBanner() {
  HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  GetConsoleScreenBufferInfo(hConsole, &csbi);

  WORD defaultColor = csbi.wAttributes;
  std::string bannerStr(BANNER);

  for (size_t i = 0; i < bannerStr.length(); ++i) {
    if (bannerStr[i] != '\n' && bannerStr[i] != ' ') {
      setConsoleColor(rainbowColors[i % rainbowColors.size()]);
    } else {
      setConsoleColor(defaultColor);
    }
    std::cout << bannerStr[i];
  }

  setConsoleColor(defaultColor);
}

static std::vector<std::string> getPatterns(const SignaturesDatabase &sd) {
  return sd.getSignatures(SignatureType::Simple);
}

static std::atomic<bool> _stop{false};

static BOOL WINAPI CtrlHandler(DWORD t) {
  if (t == CTRL_C_EVENT || t == CTRL_BREAK_EVENT || t == CTRL_CLOSE_EVENT) {
    _stop.store(true, std::memory_order_relaxed);
    return TRUE;
  }
  return FALSE;
}

// ---------------- scan result adapter ----------------
// Works whether SearchResult is bool, vector<...>, or optional<...>.
template <typename T>
static bool is_hit(const T &r) { return !!r; } // bool
template <typename T>
static bool is_hit(const std::vector<T> &r) { return !r.empty(); } // vector
template <typename T>
static bool is_hit(const std::optional<T> &r) { return r && is_hit(*r); } // optional<...>

// ---------------- run-forever watcher ----------------
static void run_forever(Service &s, RScanningEngine &RSE) {
  DWORD backoff_ms = 250;
  const DWORD backoff_max = 10'000;

  while (!_stop.load(std::memory_order_relaxed)) {
    // watch() should block until a process starts or stop flag is set.
    // If it returns early due to an error, we’ll sleep and retry.
    s.watch(L"", _stop, [&RSE, &s](const ProcessStartEvent &e) {
      const std::wstring wpath = Utils::resolve_process_path(e.pid, e.image);
      const std::string path = Utils::wstring_to_utf8(wpath);

      const auto res = RSE.scanFile(path);
      if (is_hit(res)) {
        s.killByPid(e.pid);
      }
    });

    if (_stop.load(std::memory_order_relaxed))
      break;

    // Error/disconnect: backoff and retry
    Sleep(backoff_ms);
    backoff_ms = std::min<DWORD>(backoff_ms * 2, backoff_max);
  }
}

int main() {
  std::string DB_PATH = "";
  printRainbowText("Itay&Dori\n");
  printRainbowBanner();
  std::cout << std::endl;

  Service s;
  if (!s.init())
    return EXIT_FAILURE;
  SignaturesDatabase sd{DB_PATH};

  RScanningEngine RSE{getPatterns(sd)};
  SetConsoleCtrlHandler(CtrlHandler, TRUE);

  // Single, long-lived watcher thread
  std::thread watcher([&s, &RSE] { run_forever(s, RSE); });

  // Main thread idles until Ctrl+C
  while (!_stop.load(std::memory_order_relaxed)) {
    Sleep(200);
  }

  if (watcher.joinable())
    watcher.join();
  s.shutdown();
  return EXIT_SUCCESS;
}
