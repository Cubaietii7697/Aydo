#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <cstdlib>
#include <iostream>
#include <psapi.h>
#include <thread>
#include <unordered_map>

#include "AhoCorasick/SCAScanningEngine.hpp"
#include "Databases/HashesDatabase.hpp"
#include "Databases/SignaturesDatabase.hpp"
#include "KernelCommunications/KernelCommunications.hpp"
#include "Regex/RScanningEngine.hpp"
#include "Types.hpp"
#include "Utils.hpp"

static bool isThreat(const std::string &path,
                     RScanningEngine &RSE,
                     SCAScanningEngine &SCA,
                     HashesDatabase const &hs,
                     std::unordered_map<std::string, bool> &scannedHashes) {
  // check if signed windows file
  if (Utils::isWindowsSigned(path)) {
    return false;
  }

  // check hashes
  const auto hexHash = Utils::computeSHA256(path);
  
  // Check if already scanned
  auto it = scannedHashes.find(hexHash);
  if (it != scannedHashes.end()) {
    std::cout << "  -> [CACHED] File already scanned (" 
              << (it->second ? "THREAT" : "clean") << ")" << std::endl;
    return it->second;
  }
  
  const auto resHASH = hs.getHashName(hexHash);

  if (resHASH && !resHASH->empty()) {
    scannedHashes[hexHash] = true;
    return true;
  }

  std::cout << "  -> [HASH] Not found" << std::endl;

  // check signatures #1
  const auto resRSE = RSE.scanFile(path);

  if (resRSE && !resRSE->empty()) {
    scannedHashes[hexHash] = true;
    return true;
  }

  std::cout << "  -> [RSE] Not found" << std::endl;

  // check signatures #2
  const auto resSCA = SCA.scanFile(path);

  if (resSCA && !resSCA->empty()) {
    scannedHashes[hexHash] = true;
    return true;
  }

  std::cout << "  -> [SCA] Not found" << std::endl;

  // Add to scanned hashes (file is clean)
  scannedHashes[hexHash] = false;
  
  return false;
}

// Continuous monitoring function that watches for process creation and scans them
static std::atomic<bool> g_stopMonitoring{false};

static void continuousMonitor(const std::shared_ptr<KernelCommunications> &driver,
                              RScanningEngine &RSE,
                              SCAScanningEngine &SCA,
                              HashesDatabase const &hs,
                              std::unordered_map<std::string, bool> &scannedHashes) {
  DWORD currentPid = GetCurrentProcessId();

  while (!g_stopMonitoring.load(std::memory_order_relaxed)) {
    auto notificationOpt = driver->getProcessNotification();

    if (notificationOpt.has_value()) {
      const auto &notification = notificationOpt.value();

      // Only process creation events
      if (!notification.IsCreated) {
        continue;
      }

      // Skip our own process
      if (notification.ProcessId == currentPid) {
        continue;
      }

      // Get the process path
      const std::wstring wpath = Utils::resolve_process_path(notification.ProcessId, notification.ImageFileName);
      const std::string path = Utils::wstring_to_utf8(wpath);

      if (path.empty()) {
        continue;
      }

      // Convert image name for display
      char imageFileNameA[MAX_PATH];
      WideCharToMultiByte(CP_UTF8, 0, notification.ImageFileName, -1,
                          imageFileNameA, sizeof(imageFileNameA), nullptr, nullptr);

      std::cout << "[NEW PROCESS] PID: " << notification.ProcessId
                << " | Image: " << imageFileNameA << std::endl;
      std::cout << "  -> Scanning: " << path << std::endl;

      try {
        if (isThreat(path, RSE, SCA, hs, scannedHashes)) {
          std::cout << "  -> [ALERT] MALICIOUS DETECTED! Killing PID=" << notification.ProcessId
                    << " (" << path << ")" << std::endl
                    << std::endl;

          if (driver->killProcess(notification.ProcessId)) {
            std::cout << "  -> [SUCCESS] Process terminated!" << std::endl
                      << std::endl;
          } else {
            std::cout << "  -> [FAILED] Could not terminate process (Error: " << GetLastError() << ")" << std::endl
                      << std::endl;
          }
        } else {
          std::cout << "  -> [CLEAN] Process is safe." << std::endl
                    << std::endl;
        }
      } catch (const std::exception &ex) {
        std::cerr << "  -> [ERROR] Scan failed: " << ex.what() << std::endl
                  << std::endl;
      }
    } else {
      Sleep(100); // Sleep 100ms between checks if no notifications
    }
  }
}

static BOOL WINAPI CtrlHandler(DWORD t) {
  if (t == CTRL_C_EVENT || t == CTRL_BREAK_EVENT || t == CTRL_CLOSE_EVENT) {
    g_stopMonitoring.store(true, std::memory_order_relaxed);
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

    // Initialize scanned hashes cache (hash -> isThreat)
    std::unordered_map<std::string, bool> scannedHashes;

    // Reset stop flag and start monitoring thread
    g_stopMonitoring.store(false, std::memory_order_relaxed);

    std::cout << "Starting background monitoring thread..." << std::endl;
    std::thread monitorThread(continuousMonitor, std::cref(driver), std::ref(RSE), std::ref(SCA), std::cref(hashDb), std::ref(scannedHashes));

    std::cout << "Monitoring active. Press Ctrl+C to stop." << std::endl
              << std::endl;

    // Wait for stop signal
    while (!g_stopMonitoring.load(std::memory_order_relaxed)) {
      Sleep(1000);
    }

    // Wait for the monitoring thread to finish
    if (monitorThread.joinable()) {
      monitorThread.join();
    }

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
