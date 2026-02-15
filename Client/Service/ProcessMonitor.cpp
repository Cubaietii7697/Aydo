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

void ProcessMonitor::setLogger(LoggerCallback logger) {
  std::lock_guard<std::mutex> lock(m_loggerMutex);
  m_logger = std::move(logger);
}

void ProcessMonitor::log(const std::string &message) {
  // Always print to stdout/stderr for local debugging service
  std::cout << message << std::endl;

  // Also send to pipe if connected
  std::lock_guard<std::mutex> lock(m_loggerMutex);
  if (m_logger) {
    m_logger(message + "\n");
  }
}

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

void ProcessMonitor::printStatus() {
  log("Process monitoring started");
  if (m_driver) {
    log("Successfully connected to driver");
  }
  // Assuming HashDB is loaded if we're here
  log("Loaded hashes database");
  log("Initialized YARA scanning engine");
  log("[ENTROPY] Monitoring active");

  // Check Cloud
  auto &config = UserConfig::getInstance();
  if (!config.serverUrl.empty()) {
    log("Connecting to server... " + config.serverUrl);
  }
}

std::string ProcessMonitor::getCapabilitiesJson() {
  nlohmann::json caps;
  caps["driver"] = (m_driver != nullptr);
  caps["hashdb"] = true;  // Initialized in main
  caps["yara"] = true;    // Initialized in main
  caps["entropy"] = true; // Built-in

  auto &config = UserConfig::getInstance();
  caps["cloud"] = !config.serverUrl.empty();

  return caps.dump();
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
    log("[SCAN ERROR] File not found: " + path);
    return false;
  }

  if (std::filesystem::is_directory(path)) {
    return scanDirectory(path);
  }

  log("[SCAN] Requested: " + std::filesystem::path(path).filename().string());

  try {
    const bool threat = isThreat(path);
    if (threat) {
      log("[SCAN RESULT] THREAT: " + path);
      auto &config = UserConfig::getInstance();
      if (config.infectedFileAction == 1) { // Quarantine
        if (Utils::quarantineFile(path)) {
          log("[QUARANTINE] Isolated: " + path);
        } else {
          log("[ERROR] Failed to quarantine: " + path);
        }
      } else if (config.infectedFileAction == 2) { // Delete
        if (Utils::deleteFile(path)) {
          log("[DELETE] Removed: " + path);
        } else {
          log("[ERROR] Failed to delete: " + path);
        }
      }
    } else {
      log("[SCAN RESULT] CLEAN: " + path);
    }
    return threat;
  } catch (const std::exception &ex) {
    log("[SCAN ERROR] " + std::string(ex.what()));
    return false;
  }
}

bool ProcessMonitor::scanDirectory(const std::string &path) {
  log("[SCAN] Starting directory scan: " + path);

  std::vector<std::filesystem::path> files;
  try {
    for (const auto &entry : std::filesystem::recursive_directory_iterator(path)) {
      if (entry.is_regular_file()) {
        files.push_back(entry.path());
      }
    }
  } catch (const std::exception &e) {
    log("[SCAN ERROR] Failed to iterate directory: " + std::string(e.what()));
    return false;
  }

  if (files.empty()) {
    log("[SCAN RESULT] CLEAN: " + path + " (Empty)");
    return false;
  }

  size_t total = files.size();
  size_t threats = 0;
  size_t scanned = 0;

  for (const auto &file : files) {
    std::string filePath = file.string();
    scanned++;

    // Shorten path for display to prevent overflow in GUI
    std::string displayPath;
    try {
      displayPath = std::filesystem::relative(file, path).string();
    } catch (...) {
      displayPath = file.filename().string();
    }

    int progress = static_cast<int>((scanned * 100) / total);
    // Format specifically for ClientEngine.ts to pick up
    log("[SCAN] " + std::to_string(progress) + "% - Scanning: " + displayPath);

    try {
      if (isThreat(filePath)) {
        threats++;
        log("[ALERT] THREAT DETECTED in " + filePath);
        auto &config = UserConfig::getInstance();
        if (config.infectedFileAction == 1) { // Quarantine
          if (Utils::quarantineFile(filePath)) {
            log("[QUARANTINE] Isolated: " + filePath);
          } else {
            log("[ERROR] Failed to quarantine: " + filePath);
          }
        } else if (config.infectedFileAction == 2) { // Delete
          if (Utils::deleteFile(filePath)) {
            log("[DELETE] Removed: " + filePath);
          } else {
            log("[ERROR] Failed to delete: " + filePath);
          }
        }
      }
    } catch (...) {
      // Continue even if one file fails
    }
  }

  std::string result = "[SCAN RESULT] Directory scan complete. Scanned: " + std::to_string(scanned) +
                       ", Threats found: " + std::to_string(threats);

  if (threats > 0) {
    log("[SCAN RESULT] THREAT: " + path);
  } else {
    log("[SCAN RESULT] CLEAN: " + path);
  }

  return threats > 0;
}

bool ProcessMonitor::isThreat(const std::string &path) {
  // Layer 1: Check if signed Windows file
  if (Utils::isWindowsSigned(path)) {
    log("  -> [SIGNED] Digitally signed by trusted publisher");
    return false;
  }

  // Compute hash
  const auto hexHash = Utils::computeSHA256(path);

  // Check if already scanned
  {
    std::lock_guard<std::mutex> lock(m_cacheMutex);
    if (auto it = m_scannedHashes.find(hexHash); it != m_scannedHashes.end()) {
      log("  -> [CACHED] File already scanned (" + std::string(it->second ? "THREAT" : "clean") + ")");
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
    log("  -> [HASH] MATCH: " + *resHASH);
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

    log("  -> [YARA] MATCH: " + rulesStr);
    log("  -> [YARA] Score: " + std::to_string(yaraResult.scoring.totalScore) +
        " (threshold: " + std::to_string(m_yara.getScoringSystem().getKillThreshold()) + ")");
    log("  -> [YARA] Matched rules: " + std::to_string(yaraResult.matchedRules.size()));

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
    log("  -> [ENTROPY] High entropy detected (" + std::to_string(entropy) + "). Requesting cloud analysis...");

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
      log("  -> [ALERT] MALICIOUS DETECTED! Killing PID=" + std::to_string(pid) + " (" + path + ")");

      if (m_driver->killProcess(pid)) {
        log("  -> [SUCCESS] Process terminated!");
      } else {
        log("  -> [FAILED] Could not terminate process (Error: " + std::to_string(GetLastError()) + ")");
      }

      auto &config = UserConfig::getInstance();
      if (config.infectedFileAction == 1) { // Quarantine
        if (Utils::quarantineFile(path)) {
          log("[QUARANTINE] Isolated: " + path);
        } else {
          log("[ERROR] Failed to quarantine: " + path);
        }
      } else if (config.infectedFileAction == 2) { // Delete
        if (Utils::deleteFile(path)) {
          log("[DELETE] Removed: " + path);
        } else {
          log("[ERROR] Failed to delete: " + path);
        }
      }
    } else {
      log("  -> [CLEAN] Process is safe: " + path);
    }
  } catch (const std::exception &ex) {
    log("  -> [ERROR] Scan failed for PID=" + std::to_string(pid) + ": " + ex.what());
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

      std::string msg = "[NEW PROCESS] PID: " + std::to_string(notification.ProcessId) + " | Image: " + imageFileNameA;
      log(msg);
      log("  -> Scanning: " + path);

      // Start scan in a new thread
      std::thread(&ProcessMonitor::handleProcessStarted, this, notification.ProcessId, path).detach();
    } else {
      Sleep(Constants::SLEEP_BETWEEN_NO_NOTIFICATIONS_MS); // Sleep between checks if no notifications
    }
  }
}
