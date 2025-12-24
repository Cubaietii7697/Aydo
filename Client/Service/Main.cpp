#include "ServerCommunications/ServerCommunications.hpp"
#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <cstdlib>
#include <iostream>

#include "Constants.hpp"
#include "Databases/HashesDatabase.hpp"
#include "KernelCommunications/KernelCommunications.hpp"
#include "ProcessMonitor.hpp"
#include "Yara/YScanningEngine.hpp"

static std::atomic<bool> g_stopMonitoring{false};
static ProcessMonitor *g_monitor = nullptr;

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

int main() {
  std::cout << "==================================" << std::endl;
  std::cout << "     Aydo Process Monitor" << std::endl;
  std::cout << "==================================" << std::endl
            << std::endl;

  // Connect to server
  // TODO: Load auth token from config
  std::cout << "Connecting to server..." << std::endl;
  std::string serverUrl{Constants::SERVER_URL};
  ServerCommunications::initialize(serverUrl);

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
    YScanningEngine yara(Constants::YARA_RULES_FILES);
    std::cout << "  -> Initialized YARA scanning engine" << std::endl;

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
