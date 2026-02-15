#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>

#include <functional>
#include "Databases/HashesDatabase.hpp"
#include "KernelCommunications/KernelCommunications.hpp"
#include "Yara/YScanningEngine.hpp"

using LoggerCallback = std::function<void(const std::string &)>;

class ProcessMonitor {
private:
  std::shared_ptr<KernelCommunications> m_driver;
  YScanningEngine &m_yara;
  const HashesDatabase &m_hashDb;

  std::atomic<bool> m_stopMonitoring{false};
  std::unordered_map<std::string, bool> m_scannedHashes;
  std::mutex m_cacheMutex;
  std::thread m_monitorThread;
  LoggerCallback m_logger;
  std::mutex m_loggerMutex;

public:
  ProcessMonitor(std::shared_ptr<KernelCommunications> driver,
                 YScanningEngine &yara,
                 const HashesDatabase &hashDb);
  ~ProcessMonitor();

  ProcessMonitor(const ProcessMonitor &) = delete;
  ProcessMonitor &operator=(const ProcessMonitor &) = delete;

  void setLogger(LoggerCallback logger);
  void log(const std::string &message);

  void start();
  void stop();
  void printStatus();
  std::string getCapabilitiesJson();

  bool isMonitoring() const;
  bool scanFile(const std::string &path);

private:
  void monitorLoop();

  bool scanDirectory(const std::string &path);
  void handleProcessStarted(uint32_t pid, const std::string &path);
  bool isThreat(const std::string &path);
};
