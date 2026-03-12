#include "AhoCorasick/ACScanningEngine.hpp"
#include "AhoCorasick/AhoCorasick.hpp"
#include "AhoCorasick/SCAScanningEngine.hpp"
#include "ServerCommunications/ServerCommunications.hpp"
#include "UserConfig.hpp"
#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <cstdlib>
#include <iostream>
#include <string_view>
#include <vector>

#include "Constants.hpp"
#include "Databases/HashesDatabase.hpp"
#include "KernelCommunications/KernelCommunications.hpp"
#include "ProcessMonitor.hpp"
#include "Yara/YScanningEngine.hpp"

#pragma comment(lib, "ws2_32.lib")

static std::atomic<bool> g_stopMonitoring{false};
static ProcessMonitor *g_monitor = nullptr;

static bool reportSelfTest(bool condition, std::string_view name) {
  if (condition) {
    std::cout << "[PASS] " << name << std::endl;
    return true;
  }

  std::cerr << "[FAIL] " << name << std::endl;
  return false;
}

static int runSelfTests() {
  bool allPassed = true;

  try {
    {
      ACScanningEngine engine({"AA??BB"}, 8);
      const std::vector<uint8_t> data{0xAA, 0x10, 0xBB};
      const auto result = engine.scanMemory(data);
      allPassed &= reportSelfTest(
          result && *result == "AA??BB",
          "ACScanningEngine matches a constrained pattern at byte 0");
    }

    {
      ACScanningEngine engine({"AA??BB*CC"}, 16);
      const std::vector<uint8_t> data{0xAA, 0x11, 0xBB, 0x55, 0x66, 0xCC};
      const auto result = engine.scanMemory(data);
      allPassed &= reportSelfTest(
          result && *result == "AA??BB*CC",
          "ACScanningEngine matches multi-segment wildcard patterns");
    }

    {
      const std::vector<std::vector<uint8_t>> patterns{
          {0xAA, 0xBB},
          {0xBB}};
      const std::vector<uint8_t> data{0xAA, 0xBB};
      const auto matches = AhoCorasick(patterns).search(data);

      bool foundLongMatch = false;
      bool foundSuffixMatch = false;
      for (const auto &match : matches) {
        if (match.patternIndex == 0 && match.startPos == 0 && match.endPos == 1) {
          foundLongMatch = true;
        }
        if (match.patternIndex == 1 && match.startPos == 1 && match.endPos == 1) {
          foundSuffixMatch = true;
        }
      }

      allPassed &= reportSelfTest(
          matches.size() == 2 && foundLongMatch && foundSuffixMatch,
          "AhoCorasick returns every output at the same end position");
    }

    {
      SCAScanningEngine engine({"AA"});
      const std::vector<uint8_t> data{0xAA, 0x00, 0xBB};
      const auto result = engine.scanMemory(data);
      const bool matchesExpectedBytes =
          result && result->size() == 1 &&
          static_cast<unsigned char>((*result)[0]) == 0xAA;
      allPassed &= reportSelfTest(
          matchesExpectedBytes,
          "SCAScanningEngine returns the matched bytes");
    }
  } catch (const std::exception &ex) {
    std::cerr << "[FAIL] Unhandled self-test exception: " << ex.what()
              << std::endl;
    return EXIT_FAILURE;
  }

  return allPassed ? EXIT_SUCCESS : EXIT_FAILURE;
}

static BOOL WINAPI CtrlHandler(DWORD t) {
  if (t == CTRL_C_EVENT || t == CTRL_BREAK_EVENT || t == CTRL_CLOSE_EVENT) {
    g_stopMonitoring.store(true, std::memory_order_relaxed);
    if (g_monitor) {
      g_monitor->stop();
    }

    return TRUE;
  }

  return FALSE;
}

static void handleUserAuth() {
  auto &config = UserConfig::getInstance();
  auto &server = ServerCommunications::getInstance();

  if (!config.accessToken.empty()) {
    return;
  }

  std::cout << "Authentication required." << std::endl;
  std::cout << "1. Login" << std::endl;
  std::cout << "2. Register" << std::endl;
  std::cout << "Choice: ";

  std::string choice;
  std::getline(std::cin, choice);

  std::string email, password, nickname;

  if (choice == "1") {
    std::cout << "Email: ";
    std::getline(std::cin, email);
    std::cout << "Password: ";
    std::getline(std::cin, password);

    if (server.login(email, password)) {
      std::cout << "Login successful!" << std::endl;
    } else {
      std::cerr << "Login failed. Please restart the service to try again." << std::endl;
      exit(EXIT_FAILURE);
    }
  } else if (choice == "2") {
    std::cout << "Email: ";
    std::getline(std::cin, email);
    std::cout << "Nickname: ";
    std::getline(std::cin, nickname);
    std::cout << "Password: ";
    std::getline(std::cin, password);

    if (server.registerUser(email, nickname, password)) {
      std::cout << "Registration successful!" << std::endl;
    } else {
      std::cerr << "Registration failed. Please restart the service to try again." << std::endl;
      exit(EXIT_FAILURE);
    }
  } else {
    std::cerr << "Invalid choice." << std::endl;
    exit(EXIT_FAILURE);
  }
}

int main(int argc, char *argv[]) {
  if (argc == 2 && std::string_view(argv[1]) == "--self-test") {
    return runSelfTests();
  }

  std::cout << "==================================" << std::endl;
  std::cout << "     Aydo Process Monitor" << std::endl;
  std::cout << "==================================" << std::endl
            << std::endl;

  // Load configuration
  auto &config = UserConfig::getInstance();
  if (!config.load()) {
    std::cout << "Creating default config.json..." << std::endl;
    config.save();
  }

  // Connect to server
  std::cout << "Connecting to server..." << config.serverUrl << std::endl;
  ServerCommunications::initialize(config.serverUrl, config.accessToken, config.refreshToken);

  // Handle authentication if tokens are missing
  if (config.refreshToken == "") {
    handleUserAuth();
  }

  // Set up Ctrl+C handler
  if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
    std::cerr << "Warning: Could not set Ctrl+C handler" << std::endl;
  }

  auto driver = KernelCommunications::getInstance();

  std::wstring devicePath{Constants::AYDO_DRIVER_DEVICE_PATH.begin(), Constants::AYDO_DRIVER_DEVICE_PATH.end()};
  if (!driver->connect(devicePath)) {
    std::cerr << "Failed to open driver device. Error: " << GetLastError() << std::endl;
    std::cerr << "Make sure the driver is loaded!" << std::endl;
    std::cout << "\nPress Enter to exit...";
    std::cin.get();

    return EXIT_FAILURE;
  }

  std::cout << "Successfully connected to driver!" << std::endl;
  std::cout << std::endl;

  std::cout << "Initializing scanning engines..." << std::endl;

  try {
    YScanningEngine yara(Constants::YARA_RULES_FILES, config.killThreshold);
    std::cout << "  -> Initialized YARA scanning engine (Kill Threshold: " << config.killThreshold << ")" << std::endl;

    // Initialize hashes database
    std::string hashesDbPath{Constants::HASHES_DB_PATH.begin(), Constants::HASHES_DB_PATH.end()};
    HashesDatabase hashDb(hashesDbPath);
    std::cout << "  -> Loaded hashes database" << std::endl;

    std::cout << "All scanning engines initialized successfully!" << std::endl
              << std::endl;

    ProcessMonitor monitor(driver, yara, hashDb);
    g_monitor = &monitor;

    std::cout << "Starting background monitoring thread..." << std::endl;
    monitor.start();

    std::cout << "Monitoring active. Press Ctrl+C to stop." << std::endl
              << std::endl;

    // Wait for stop signal
    while (!g_stopMonitoring.load(std::memory_order_relaxed)) {
      Sleep(Constants::IDLE_SLEEP_TIME_MS);
    }

    monitor.stop();
    g_monitor = nullptr;

    std::cout << "Shutting down..." << std::endl;

  } catch (const std::exception &ex) {
    std::cerr << "\nFATAL ERROR: Failed to initialize scanning engines: " << ex.what() << std::endl;
    std::cerr << "Make sure the data directory exists with compiled_rules.yara and file_hashes.db" << std::endl;
    std::cout << "\nPress Enter to exit...";
    std::cin.get();

    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
