#include "ProcessMonitor.hpp"

#include <iostream>
#include <utility>
#include <windows.h>

#include "Constants.hpp"
#include "Utils.hpp"

ProcessMonitor::ProcessMonitor(std::shared_ptr<KernelCommunications> driver,
                               YScanningEngine &yara,
                               const HashesDatabase &hashDb)
    : m_driver(std::move(driver)), m_yara(yara), m_hashDb(hashDb) {}

ProcessMonitor::~ProcessMonitor() {
  stop();
}

void ProcessMonitor::start() {
  if (m_monitorThread.joinable()) {
    std::cerr << "Warning: Monitoring thread is already running" << std::endl;
    return;
  }

  m_stopMonitoring.store(false, std::memory_order_relaxed);
  m_monitorThread = std::thread(&ProcessMonitor::monitorLoop, this);
  std::cout << "Process monitoring started" << std::endl;
}

void ProcessMonitor::stop() {
  if (!m_monitorThread.joinable()) {
    return;
  }

  m_stopMonitoring.store(true, std::memory_order_relaxed);

  if (m_monitorThread.joinable()) {
    m_monitorThread.join();
  }

  std::cout << "Process monitoring stopped" << std::endl;
}

bool ProcessMonitor::isMonitoring() const {
  return !m_stopMonitoring.load(std::memory_order_relaxed) && m_monitorThread.joinable();
}

bool ProcessMonitor::isThreat(const std::string &path) {
  // Check if signed Windows file
  if (Utils::isWindowsSigned(path)) {
    return false;
  }

  // Compute hash
  const auto hexHash = Utils::computeSHA256(path);

  // Check if already scanned
  auto it = m_scannedHashes.find(hexHash);
  if (it != m_scannedHashes.end()) {
    std::cout << "  -> [CACHED] File already scanned ("
              << (it->second ? "THREAT" : "clean") << ")" << std::endl;
    return it->second;
  }

  // Check hashes database
  const auto resHASH = m_hashDb.getHashName(hexHash);

  if (resHASH && !resHASH->empty()) {
    std::cout << "  -> [HASH] MATCH: " << *resHASH << std::endl;
    m_scannedHashes[hexHash] = true;

    return true;
  }

  std::cout << "  -> [HASH] Not found" << std::endl;

  // Check YARA signatures with scoring
  const auto yaraResult = m_yara.scanFileWithScoring(path);

  if (yaraResult.hasMatches()) {
    std::string rulesStr;
    for (size_t i = 0; i < yaraResult.matchedRules.size(); ++i) {
      rulesStr += yaraResult.matchedRules[i];
      if (i < yaraResult.matchedRules.size() - 1) {
        rulesStr += ", ";
      }
    }

    std::cout << "  -> [YARA] MATCH: " << rulesStr << std::endl;
    std::cout << "  -> [YARA] Score: " << yaraResult.scoring.totalScore
              << " (threshold: " << m_yara.getScoringSystem().getKillThreshold() << ")" << std::endl;

    if (yaraResult.scoring.shouldKill) {
      std::cout << "  -> [YARA] Threat level exceeds threshold!" << std::endl;
      m_scannedHashes[hexHash] = true;
      return true;
    }

    std::cout << "  -> [YARA] Score below threshold, not a critical threat" << std::endl;
  } else {
    std::cout << "  -> [YARA] Not found" << std::endl;
  }

  // Add to scanned hashes (file is clean)
  m_scannedHashes[hexHash] = false;

  return false;
}

void ProcessMonitor::monitorLoop() {
  DWORD currentPid = GetCurrentProcessId();

  while (!m_stopMonitoring.load(std::memory_order_relaxed)) {
    auto notificationOpt = m_driver->getProcessNotification();

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
        if (isThreat(path)) {
          std::cout << "  -> [ALERT] MALICIOUS DETECTED! Killing PID=" << notification.ProcessId
                    << " (" << path << ")" << std::endl
                    << std::endl;

          if (m_driver->killProcess(notification.ProcessId)) {
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
      Sleep(Constants::SLEEP_BETWEEN_NO_NOTIFICATIONS_MS); // Sleep between checks if no notifications
    }
  }
}
