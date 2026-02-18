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

void ProcessMonitor::setEventHandler(EventCallback handler) {
  std::lock_guard<std::mutex> lock(m_loggerMutex);
  m_eventHandler = std::move(handler);
}

void ProcessMonitor::notifyEvent(Protocol::EventType type, std::string severity, std::string message, nlohmann::json data) {
  if (severity == "high") {
    std::cerr << "[" << Protocol::eventTypeToString(type) << "] " << message << std::endl;
  } else {
    std::cout << "[" << Protocol::eventTypeToString(type) << "] " << message << std::endl;
  }

  std::lock_guard<std::mutex> lock(m_loggerMutex);
  if (m_eventHandler) {
    m_eventHandler(Protocol::Event(type, std::move(severity), std::move(message), std::move(data)));
  }
}

void ProcessMonitor::log(const std::string &message) {
  notifyEvent(Protocol::EventType::Info, "low", message);
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

nlohmann::json ProcessMonitor::getCapabilities() {
  nlohmann::json caps;
  caps["driver"] = (m_driver != nullptr);
  caps["hashdb"] = true;  // Initialized in main
  caps["yara"] = true;    // Initialized in main
  caps["entropy"] = true; // Built-in

  auto &config = UserConfig::getInstance();
  caps["cloud"] = !config.serverUrl.empty();

  return caps;
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

  notifyEvent(Protocol::EventType::ScanProgress, "low", "Requested: " + std::filesystem::path(path).filename().string(), {{"target", path}});

  try {
    const bool threat = isThreat(path);
    if (threat) {
      notifyEvent(Protocol::EventType::ThreatDetected, "high", "THREAT: " + path, {{"target", path}});
      auto &config = UserConfig::getInstance();
      if (config.infectedFileAction == 1) { // Quarantine
        if (Utils::quarantineFile(path)) {
          notifyEvent(Protocol::EventType::Quarantine, "medium", "Isolated: " + path, {{"target", path}});
        } else {
          notifyEvent(Protocol::EventType::Info, "medium", "Failed to quarantine: " + path, {{"target", path}});
        }
      } else if (config.infectedFileAction == 2) { // Delete
        if (Utils::deleteFile(path)) {
          notifyEvent(Protocol::EventType::Delete, "medium", "Removed: " + path, {{"target", path}});
        } else {
          notifyEvent(Protocol::EventType::Info, "medium", "Failed to delete: " + path, {{"target", path}});
        }
      }
    } else {
      notifyEvent(Protocol::EventType::ScanComplete, "low", "CLEAN: " + path, {{"target", path}, {"threats", 0}});
    }
    return threat;
  } catch (const std::exception &ex) {
    notifyEvent(Protocol::EventType::Info, "medium", "SCAN ERROR: " + std::string(ex.what()), {{"target", path}});
    return false;
  }
}

bool ProcessMonitor::scanDirectory(const std::string &path) {
  notifyEvent(Protocol::EventType::ScanProgress, "low", "Starting directory scan: " + path, {{"target", path}, {"progress", 0}});

  std::vector<std::filesystem::path> files;
  try {
    for (const auto &entry : std::filesystem::recursive_directory_iterator(path)) {
      if (entry.is_regular_file()) {
        files.push_back(entry.path());
      }
    }
  } catch (const std::exception &e) {
    notifyEvent(Protocol::EventType::Info, "medium", "Failed to iterate directory: " + std::string(e.what()), {{"target", path}});
    return false;
  }

  if (files.empty()) {
    notifyEvent(Protocol::EventType::ScanComplete, "low", "CLEAN: " + path + " (Empty)", {{"target", path}, {"threats", 0}});
    return false;
  }

  size_t total = files.size();
  size_t threats = 0;
  size_t scanned = 0;

  for (const auto &file : files) {
    std::string filePath = file.string();
    scanned++;

    // Shorten path for display
    std::string displayPath;
    try {
      displayPath = std::filesystem::relative(file, path).string();
    } catch (...) {
      displayPath = file.filename().string();
    }

    int progress = static_cast<int>((scanned * 100) / total);
    notifyEvent(Protocol::EventType::ScanProgress, "low", "Scanning: " + displayPath, {{"target", path}, {"progress", progress}});

    try {
      if (isThreat(filePath)) {
        threats++;
        notifyEvent(Protocol::EventType::ThreatDetected, "high", "THREAT DETECTED: " + filePath, {{"target", filePath}});
        auto &config = UserConfig::getInstance();
        if (config.infectedFileAction == 1) { // Quarantine
          if (Utils::quarantineFile(filePath)) {
            notifyEvent(Protocol::EventType::Quarantine, "medium", "Isolated: " + filePath, {{"target", filePath}});
          } else {
            notifyEvent(Protocol::EventType::Info, "medium", "Failed to quarantine: " + filePath, {{"target", filePath}});
          }
        } else if (config.infectedFileAction == 2) { // Delete
          if (Utils::deleteFile(filePath)) {
            notifyEvent(Protocol::EventType::Delete, "medium", "Removed: " + filePath, {{"target", filePath}});
          } else {
            notifyEvent(Protocol::EventType::Info, "medium", "Failed to delete: " + filePath, {{"target", filePath}});
          }
        }
      }
    } catch (...) {
      // Continue even if one file fails
    }
  }

  if (threats > 0) {
    notifyEvent(Protocol::EventType::ScanComplete, "high", "Directory scan complete. Threats found: " + std::to_string(threats), {{"target", path}, {"threats", threats}});
  } else {
    notifyEvent(Protocol::EventType::ScanComplete, "low", "Directory scan complete. Clean.", {{"target", path}, {"threats", 0}});
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

    if (yaraResult.scoring.highestLevel <= ThreatLevel::Info && yaraResult.matchedRules.size() < Constants::YARA_INFO_MATCH_THRESHOLD) {
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
