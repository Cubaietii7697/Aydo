#include "ProcessMonitor.hpp"

#include <windows.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <utility>
#include <vector>

#include "Constants.hpp"
#include "Utils.hpp"

// Whitelist of trusted Windows system processes
const std::unordered_set<std::string> ProcessMonitor::WINDOWS_SYSTEM_WHITELIST = {
    // Core Windows system processes
    "system",
    "csrss.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "winlogon.exe",
    "explorer.exe",
    "dwm.exe",
    "taskmgr.exe",

    // Search and indexing
    "searchprotocolhost.exe",
    "searchfilterhost.exe",
    "searchindexer.exe",

    // Windows Update and maintenance
    "wuauclt.exe",
    "trustedinstaller.exe",
    "tiworker.exe",
    "musnotification.exe",
    "wuapihost.exe",

    // Windows Defender and security
    "msmpeng.exe",
    "nissrv.exe",
    "securityhealthservice.exe",
    "securityhealthsystray.exe",
    "msedge.exe",
    "smartscreen.exe",

    // System utilities
    "conhost.exe",
    "cmd.exe",
    "powershell.exe",
    "powershell_ise.exe",
    "notepad.exe",
    "rundll32.exe",
    "regsvcs.exe",
    "regasm.exe",
    "msiexec.exe",
    "werfault.exe",

    // Network and connectivity
    "dllhost.exe",
    "runtimebroker.exe",
    "sihost.exe",
    "ctfmon.exe",

    // Windows services
    "spoolsv.exe",
    "lsm.exe",
    "wininit.exe",
    "smss.exe",
    "winrshost.exe",

    // Additional common system processes
    "audiodg.exe",
    "fontdrvhost.exe",
    "nvvsvc.exe",
    "igfxem.exe",
    "backgroundtaskhost.exe",
    "applicationframehost.exe",
    "shellexperiencehost.exe",
    "startmenuexperiencehost.exe",
    "textinputhost.exe",
    "lockapp.exe",
    "systemsettings.exe",
    "taskhostw.exe",
    "userinit.exe",
    "logonui.exe",
};

// Trusted Windows system directories (case-insensitive)
const std::unordered_set<std::string> ProcessMonitor::TRUSTED_DIRECTORIES = {
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
    "c:\\windows\\winsxs",
    "c:\\windows\\systemapps",
    "c:\\program files\\windows defender",
    "c:\\program files (x86)\\windows defender",
    "c:\\program files\\windows defender advanced threat protection",
    "c:\\program files\\windowsapps",
};

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

bool ProcessMonitor::isWhitelisted(const std::string &path) {
  // Extract filename from path
  size_t lastSlash = path.find_last_of("\\/");
  std::string filename = (lastSlash != std::string::npos) ? path.substr(lastSlash + 1) : path;

  // Convert to lowercase for case-insensitive comparison
  std::transform(filename.begin(), filename.end(), filename.begin(),
                 [](unsigned char c) { return std::tolower(c); });

  return WINDOWS_SYSTEM_WHITELIST.find(filename) != WINDOWS_SYSTEM_WHITELIST.end();
}

bool ProcessMonitor::isInTrustedDirectory(const std::string &path) {
  // Convert path to lowercase for case-insensitive comparison
  std::string lowerPath = path;
  std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(),
                 [](unsigned char c) { return std::tolower(c); });

  // Check if path starts with any trusted directory
  for (const auto &trustedDir : TRUSTED_DIRECTORIES) {
    if (lowerPath.find(trustedDir) == 0) {
      return true;
    }
  }

  return false;
}

bool ProcessMonitor::isThreat(const std::string &path) {
  // Layer 1: Check if whitelisted Windows system process
  if (isWhitelisted(path)) {
    std::cout << "  -> [WHITELISTED] Trusted Windows system process" << std::endl;
    return false;
  }

  // Layer 2: Check if in trusted Windows directory
  if (isInTrustedDirectory(path)) {
    std::cout << "  -> [TRUSTED DIR] Process in trusted Windows directory" << std::endl;
    return false;
  }

  // Layer 3: Check if signed Windows file
  if (Utils::isWindowsSigned(path)) {
    std::cout << "  -> [SIGNED] Digitally signed by trusted publisher" << std::endl;
    return false;
  }

  // Compute hash
  const auto hexHash = Utils::computeSHA256(path);

  // Check if already scanned
  if (auto it = m_scannedHashes.find(hexHash); it != m_scannedHashes.end()) {
    std::cout << "  -> [CACHED] File already scanned ("
              << (it->second ? "THREAT" : "clean") << ")" << std::endl;
    return it->second;
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

  if (entropy > Constants::ENTROPY_THRESHOLD) {
    // TODO : send file to server.
    bool res = Utils::sentRequestForDynamicScan(path);
    return res;
  }

  // Check hashes database
  if (const auto resHASH = m_hashDb.getHashName(hexHash); resHASH && !resHASH->empty()) {
    std::cout << "  -> [HASH] MATCH: " << *resHASH << std::endl;
    m_scannedHashes[hexHash] = true;

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

    // Additional safeguard: Require minimum number of high-value rules
    // If only low-value info rules matched, don't kill even if score is high
    if (yaraResult.scoring.highestLevel <= ThreatLevel::Info && yaraResult.matchedRules.size() < 20) {
      std::cout << "  -> [YARA] Only info-level rules matched, insufficient for threat classification" << std::endl;
      m_scannedHashes[hexHash] = false;
      return false;
    }

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
