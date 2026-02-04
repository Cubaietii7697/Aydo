#include "ProcessMonitor.hpp"
#include <windows.h>
#include <array>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <utility>
#include <vector>
#include "UserConfig.hpp"

#include "Constants.hpp"
#include "ServerCommunications/ServerCommunications.hpp"
#include "Utils.hpp"

ProcessMonitor::ProcessMonitor(std::shared_ptr<KernelCommunications> driver,
                               YScanningEngine &yara,
                               const HashesDatabase &hashDb)
    : m_driver(std::move(driver))
    , m_yara(yara)
    , m_hashDb(hashDb) {}

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

bool ProcessMonitor::scanFile(const std::string &path) {
  if (path.empty()) {
    std::cerr << "[SCAN ERROR] Missing path" << std::endl;
    return false;
  }

  if (!std::filesystem::exists(path)) {
    std::cerr << "[SCAN ERROR] File not found: " << path << std::endl;
    return false;
  }

  if (std::filesystem::is_directory(path)) {
    std::cerr << "[SCAN ERROR] Directory scans are not supported: " << path << std::endl;
    return false;
  }

  std::cout << "[SCAN] Requested: " << path << std::endl;

  try {
    const bool threat = isThreat(path);
    if (threat) {
      std::cout << "[SCAN RESULT] THREAT: " << path << std::endl;
    } else {
      std::cout << "[SCAN RESULT] CLEAN: " << path << std::endl;
    }
    return threat;
  } catch (const std::exception &ex) {
    std::cerr << "[SCAN ERROR] " << ex.what() << std::endl;
    return false;
  }
}

bool ProcessMonitor::isThreat(const std::string &path) {
  // Layer 1: Check if signed Windows file
  if (Utils::isWindowsSigned(path)) {
    std::cout << "  -> [SIGNED] Digitally signed by trusted publisher" << std::endl;
    return false;
  }

  // Compute hash
  const auto hexHash = Utils::computeSHA256(path);

  // Check if already scanned
  {
    std::lock_guard<std::mutex> lock(m_cacheMutex);
    if (auto it = m_scannedHashes.find(hexHash); it != m_scannedHashes.end()) {
      std::cout << "  -> [CACHED] File already scanned ("
                << (it->second ? "THREAT" : "clean") << ")" << std::endl;
      return it->second;
    }
  }

  // check the Entropy
  const auto bytes = Utils::readFile(path);

  std::array<int, Constants::ALPHABET_SIZE> freq{};
  for (uint8_t b : bytes) {
    ++freq[b];
  }

  const std::vector<int> countedBytes(freq.begin(), freq.end());
  const double entropy = Utils::calculateEntropy(
      countedBytes,
      static_cast<std::streamsize>(bytes.size()));

  // Check hashes database
  if (const auto resHASH = m_hashDb.getHashName(hexHash); resHASH && !resHASH->empty()) {
    std::cout << "  -> [HASH] MATCH: " << *resHASH << std::endl;
    {
      std::lock_guard<std::mutex> lock(m_cacheMutex);
      m_scannedHashes[hexHash] = true;
    }

    return true;
  }

  std::cout << "  -> [HASH] Not found" << std::endl;

  // Check YARA signatures with scoring
  if (const auto yaraResult = m_yara.scanFileWithScoring(path); yaraResult.hasMatches()) {
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
    std::cout << "  -> [YARA] Matched rules: " << yaraResult.matchedRules.size() << std::endl;

    // If only low-value info rules matched, don't kill even if score is high
    if (yaraResult.scoring.highestLevel <= ThreatLevel::Info && yaraResult.matchedRules.size() < 20) {
      std::cout << "  -> [YARA] Only info-level rules matched, insufficient for threat classification" << std::endl;
      {
        std::lock_guard<std::mutex> lock(m_cacheMutex);
        m_scannedHashes[hexHash] = false;
      }
      return false;
    }

    if (yaraResult.scoring.shouldKill) {
      std::cout << "  -> [YARA] Threat level exceeds threshold!" << std::endl;
      {
        std::lock_guard<std::mutex> lock(m_cacheMutex);
        m_scannedHashes[hexHash] = true;
      }
      return true;
    }

    std::cout << "  -> [YARA] Score below threshold, not a critical threat" << std::endl;
  } else {
    std::cout << "  -> [YARA] Not found" << std::endl;
  }

  auto &config = UserConfig::getInstance();

  if (entropy > config.entropyThreshold) {
    std::cout << "  -> [ENTROPY] High entropy detected (" << entropy << "). Requesting cloud analysis..." << std::endl;

    try {
      auto &server = ServerCommunications::getInstance();
      nlohmann::json response;
      bool fileUploaded = false;

      while (true) {
        if (server.requestFileScan(hexHash, config.runtime, response)) {
          std::string status = response.value("status", "Unknown");

          if (status == "Completed") {
            std::string virusType = response.value("virusType", "Unknown");
            int score = response.value("score", 0);

            if (virusType != "Clean" || score > 0) {
              std::cout << "  -> [SERVER] Threat detected: " << virusType << " (Score: " << score << ")" << std::endl;
              {
                std::lock_guard<std::mutex> lock(m_cacheMutex);
                m_scannedHashes[hexHash] = true;
              }
              return true;
            }

            std::cout << "  -> [SERVER] File confirmed clean by server analysis." << std::endl;
            {
              std::lock_guard<std::mutex> lock(m_cacheMutex);
              m_scannedHashes[hexHash] = false;
            }
            return false;
          }

          if (status == "Pending" && !fileUploaded) {
            std::cout << "  -> [SERVER] File unknown to server. Uploading..." << std::endl;
            if (server.uploadFile(hexHash, path)) {
              std::cout << "  -> [SERVER] Upload successful. Sandbox analysis started." << std::endl;
              fileUploaded = true;
            } else {
              std::cerr << "  -> [SERVER] Failed to upload file." << std::endl;
              break;
            }
          } else if (status == "InProgress" || status == "Pending") {
          } else if (status == "Failed") {
            std::cerr << "  -> [SERVER] Analysis failed on the server side." << std::endl;
            break;
          }
        } else {
          std::cerr << "  -> [SERVER] Failed to communicate with server." << std::endl;
          break;
        }

        Sleep(Constants::DYNAMIC_SCAN_POLL_INTERVAL * 1000);
      }
    } catch (const std::exception &e) {
      std::cerr << "  -> [SERVER] Communication error: " << e.what() << std::endl;
    }
  }

  // Add to scanned hashes (file is clean)
  {
    std::lock_guard<std::mutex> lock(m_cacheMutex);
    m_scannedHashes[hexHash] = false;
  }

  return false;
}

void ProcessMonitor::handleProcessStarted(uint32_t pid, const std::string &path) {
  try {
    if (isThreat(path)) {
      std::cout << "  -> [ALERT] MALICIOUS DETECTED! Killing PID=" << pid
                << " (" << path << ")" << std::endl
                << std::endl;

      if (m_driver->killProcess(pid)) {
        std::cout << "  -> [SUCCESS] Process terminated!" << std::endl
                  << std::endl;
      } else {
        std::cout << "  -> [FAILED] Could not terminate process (Error: " << GetLastError() << ")" << std::endl
                  << std::endl;
      }
    } else {
      std::cout << "  -> [CLEAN] Process is safe: " << path << std::endl
                << std::endl;
    }
  } catch (const std::exception &ex) {
    std::cerr << "  -> [ERROR] Scan failed for PID=" << pid << ": " << ex.what() << std::endl;
  }
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

      // Start scan in a new thread
      std::thread(&ProcessMonitor::handleProcessStarted, this, notification.ProcessId, path).detach();
    } else {
      Sleep(Constants::SLEEP_BETWEEN_NO_NOTIFICATIONS_MS); // Sleep between checks if no notifications
    }
  }
}
