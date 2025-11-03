#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <cstdlib>
#include <iostream>

#include "Databases/HashesDatabase.hpp"
#include "Databases/SignaturesDatabase.hpp"
#include "KernelCommunications/KernelCommunications.hpp"
#include "ProcessMonitor.hpp"
#include "Regex/RScanningEngine.hpp"

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

  // Set up Ctrl+C handler
  if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
    std::cerr << "Warning: Could not set Ctrl+C handler" << std::endl;
  }

  auto driver = KernelCommunications::getInstance();

  if (!driver->connect(L"\\\\.\\AydoDriver")) {
    std::cerr << "Failed to open driver device. Error: " << GetLastError() << std::endl;
    std::cerr << "Make sure the driver is loaded!" << std::endl;
    std::cout << "\nPress Enter to exit...";
    std::cin.get();
    return EXIT_FAILURE;
  }

  std::cout << "Successfully connected to driver!" << std::endl;
  std::cout << std::endl;

  // Initialize scanning engines and databases
  std::cout << "Initializing scanning engines..." << std::endl;

  try {
    // Load signatures database
    SignaturesDatabase sigDb("file_signatures.json");
    sigDb.load();
    std::cout << "  -> Loaded signatures database" << std::endl;

    // Get signatures for engines
    auto complexSignatures = sigDb.getSignatures(SignatureType::Complex);
    auto simpleSignatures = sigDb.getSignatures(SignatureType::Simple);
    std::cout << "  -> Complex signatures: " << complexSignatures.size() << std::endl;
    std::cout << "  -> Simple signatures: " << simpleSignatures.size() << std::endl;

    // Initialize Regex scanning engine
    RScanningEngine RSE(complexSignatures);
    std::cout << "  -> Initialized Regex scanning engine" << std::endl;

    // Initialize SCAS (Aho-Corasick) scanning engine
    SCAScanningEngine SCA(simpleSignatures);
    std::cout << "  -> Initialized SCAS scanning engine" << std::endl;

    // Initialize hashes database
    HashesDatabase hashDb("file_hashes.db");
    std::cout << "  -> Loaded hashes database" << std::endl;

    std::cout << "All scanning engines initialized successfully!" << std::endl
              << std::endl;

    // Create and start process monitor
    ProcessMonitor monitor(driver, RSE, SCA, hashDb);
    g_monitor = &monitor;

    std::cout << "Starting background monitoring thread..." << std::endl;
    monitor.start();

    std::cout << "Monitoring active. Press Ctrl+C to stop." << std::endl
              << std::endl;

    // Wait for stop signal
    while (!g_stopMonitoring.load(std::memory_order_relaxed)) {
      Sleep(1000);
    }

    // Stop monitoring
    monitor.stop();
    g_monitor = nullptr;

    std::cout << "Shutting down..." << std::endl;

  } catch (const std::exception &ex) {
    std::cerr << "\nFATAL ERROR: Failed to initialize scanning engines: " << ex.what() << std::endl;
    std::cerr << "Make sure the data directory exists with signatures.json and hashes.json" << std::endl;
    std::cout << "\nPress Enter to exit...";
    std::cin.get();
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
