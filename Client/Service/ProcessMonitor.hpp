#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>

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
  std::mutex m_cacheMutex;
  std::thread m_monitorThread;

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

  void handleProcessStarted(uint32_t pid, const std::string &path);
  bool isThreat(const std::string &path);
};
