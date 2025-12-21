#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include "Databases/HashesDatabase.hpp"
#include "KernelCommunications/KernelCommunications.hpp"
#include "Yara/YScanningEngine.hpp"

class ProcessMonitor {
private:
  std::shared_ptr<KernelCommunications> m_driver;
  YScanningEngine &m_yara;
  const HashesDatabase &m_hashDb;

  std::atomic<bool> m_stopMonitoring{false};
  std::unordered_map<std::string, bool> m_scannedHashes;
  std::thread m_monitorThread;

  // Whitelist of trusted Windows system processes (case-insensitive)
  static const std::unordered_set<std::string> WINDOWS_SYSTEM_WHITELIST;

  // Trusted Windows system directories
  static const std::unordered_set<std::string> TRUSTED_DIRECTORIES;

public:
  ProcessMonitor(std::shared_ptr<KernelCommunications> driver,
                 YScanningEngine &yara,
                 const HashesDatabase &hashDb);
  ~ProcessMonitor();

  ProcessMonitor(const ProcessMonitor &) = delete;
  ProcessMonitor &operator=(const ProcessMonitor &) = delete;

  void start();
  void stop();

  bool isMonitoring() const;

private:
  void monitorLoop();

  bool isThreat(const std::string &path);

  static bool isWhitelisted(const std::string &path);

  static bool isInTrustedDirectory(const std::string &path);
};
