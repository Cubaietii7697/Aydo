#include <windows.h>

#include <cstdlib>
#include <iostream>
#include <mutex>
#include <psapi.h>
#include <string_view>
#include <thread>
#include <vector>

#include "AhoCorasick/ACScanningEngine.hpp"
#include "AhoCorasick/AhoCorasick.hpp"
#include "AhoCorasick/SCAScanningEngine.hpp"
#include "HashesDatabase.hpp"
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

static std::atomic<bool> _stop{false};

static BOOL WINAPI CtrlHandler(DWORD t) {
  if (t == CTRL_C_EVENT || t == CTRL_BREAK_EVENT || t == CTRL_CLOSE_EVENT) {
    _stop.store(true, std::memory_order_relaxed);
    return TRUE;
  }
  return FALSE;
}

static bool isThreat(const std::string &path,
                     RScanningEngine &RSE,
                     SCAScanningEngine &SCA,
                     HashesDatabase const &hs) {
  const auto resRSE = RSE.scanFile(path);
  const auto resSCA = SCA.scanFile(path);
  const auto hexHash = Utils::computeSHA256(path);
  const auto resHASH = hs.getHashName(hexHash);

  return (resRSE && !resRSE->empty()) ||
         (resSCA && !resSCA->empty()) ||
         (resHASH && !resHASH->empty());
}

// ---------------- run-forever watcher ----------------
static void processStartWatcher(Service &s,
                                RScanningEngine &RSE,
                                SCAScanningEngine &SCA,
                                HashesDatabase const &hs) {
  DWORD backoff_ms = 250;
  const DWORD backoff_max = 10'000;
  DWORD currentPid = GetCurrentProcessId();

  while (!_stop.load(std::memory_order_relaxed)) {
    s.watch(L"", _stop, [&currentPid, &RSE, &SCA, &hs, &s](const ProcessStartEvent &e) {
      if (e.pid == currentPid)
        return;

      const std::wstring wpath = Utils::resolve_process_path(e.pid, e.image);
      const std::string path = Utils::wstring_to_utf8(wpath);

      if (path.empty())
        return;

      try {
        if (isThreat(path, RSE, SCA, hs)) {
          std::cout << "[ALERT] Killing PID=" << e.pid
                    << " (" << path << ")\n";
          s.killByPid(e.pid);
        }
      } catch (const std::exception &ex) {
        std::cerr << "[ERROR] Scan failed for " << path << ": "
                  << ex.what() << "\n";
      }
    });

    if (_stop.load(std::memory_order_relaxed)) {
      break;
    }

    Sleep(backoff_ms);
    backoff_ms = std::min<DWORD>(backoff_ms * 2, backoff_max);
  }
}

int main() {
  std::string DB_PATH_SIG = "";
  std::string DB_PATH_HASHES = "";
  printRainbowText("Itay&Dori\n");
  printRainbowBanner();
  std::cout << std::endl;

  Service s;
  if (!s.init())
    return EXIT_FAILURE;
  SignaturesDatabase sd{DB_PATH_SIG};
  HashesDatabase hs{DB_PATH_HASHES};
  RScanningEngine RSE{sd.getSignatures(SignatureType::Complex)};
  SCAScanningEngine SCA{sd.getSignatures(SignatureType::Simple)};
  SetConsoleCtrlHandler(CtrlHandler, TRUE);

  // Single, long-lived watcher thread
  std::thread watcher([&s, &RSE, &SCA, &hs] { processStartWatcher(s, RSE, SCA, hs); });

  // Main thread idles until Ctrl+C
  while (!_stop.load(std::memory_order_relaxed)) {
    Sleep(200);
  }

  if (watcher.joinable()) {
    watcher.join();
  }

  s.shutdown();
  return EXIT_SUCCESS;
}
