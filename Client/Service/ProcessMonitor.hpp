#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>

#include "AhoCorasick/SCAScanningEngine.hpp"
#include "Databases/HashesDatabase.hpp"
#include "KernelCommunications/KernelCommunications.hpp"
#include "Regex/RScanningEngine.hpp"

class ProcessMonitor {
private:
  std::shared_ptr<KernelCommunications> m_driver;
  RScanningEngine &m_rse;
  SCAScanningEngine &m_sca;
  const HashesDatabase &m_hashDb;

  std::atomic<bool> m_stopMonitoring{false};
  std::unordered_map<std::string, bool> m_scannedHashes;
  std::thread m_monitorThread;

public:
  ProcessMonitor(std::shared_ptr<KernelCommunications> driver,
                 RScanningEngine &rse,
                 SCAScanningEngine &sca,
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
};
