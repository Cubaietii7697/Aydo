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

#include "Protocol.hpp"

using EventCallback = std::function<void(const Protocol::Event &)>;

class ProcessMonitor {
private:
  std::shared_ptr<KernelCommunications> m_driver;
  YScanningEngine &m_yara;
  const HashesDatabase &m_hashDb;

  std::atomic<bool> m_stopMonitoring{false};
  std::unordered_map<std::string, bool> m_scannedHashes;
  std::mutex m_cacheMutex;
  std::thread m_monitorThread;
  EventCallback m_eventHandler;
  std::mutex m_loggerMutex;

public:
  ProcessMonitor(std::shared_ptr<KernelCommunications> driver,
                 YScanningEngine &yara,
                 const HashesDatabase &hashDb);
  ~ProcessMonitor();

  ProcessMonitor(const ProcessMonitor &) = delete;
  ProcessMonitor &operator=(const ProcessMonitor &) = delete;

  void setEventHandler(EventCallback handler);
  void notifyEvent(Protocol::EventType type, std::string severity, std::string message, nlohmann::json data = nlohmann::json::object());
  void log(const std::string &message);

  void start();
  void stop();
  void printStatus();
  nlohmann::json getCapabilities();

  bool isMonitoring() const;
  bool scanFile(const std::string &path);

  bool isThreat(const std::string &path);
  void setBlockingActive(bool active);

  bool isThreat(const std::string &path);
  void setBlockingActive(bool active);

private:
  std::atomic<bool> m_blockingActive{false};
  void monitorLoop();

  bool scanDirectory(const std::string &path);
  void handleProcessStarted(uint32_t pid, const std::string &path);
};
