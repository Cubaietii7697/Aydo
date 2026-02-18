#include "ServerCommunications/ServerCommunications.hpp"
#include "UserConfig.hpp"
#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

#include "Constants.hpp"
#include "Databases/HashesDatabase.hpp"
#include "KernelCommunications/KernelCommunications.hpp"
#include "ProcessMonitor.hpp"
#include "Protocol.hpp"
#include "Yara/YScanningEngine.hpp"

#pragma comment(lib, "ws2_32.lib")

static std::atomic<bool> g_stopMonitoring{false};
static ProcessMonitor *g_monitor = nullptr;

static void pipeServerLoop(ProcessMonitor *monitor) {
  std::string pipeName{Constants::AYDO_GUI_PIPE_NAME};
  std::cout << "Starting Named Pipe Server at " << pipeName << std::endl;

  while (!g_stopMonitoring.load(std::memory_order_relaxed)) {
    HANDLE hPipe = CreateNamedPipeA(
        pipeName.c_str(),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        512,
        512,
        0,
        NULL);

    if (hPipe == INVALID_HANDLE_VALUE) {
      std::cerr << "CreateNamedPipe failed, GLE=" << GetLastError() << std::endl;
      Sleep(Constants::PIPE_TIMEOUT_MS);
      continue;
    }

    if (ConnectNamedPipe(hPipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
      std::cout << "Client connected to pipe." << std::endl;

      auto sendEvent = [hPipe](const Protocol::Event &ev) {
        std::string serialized = Protocol::serialize(nlohmann::json(ev));
        DWORD written;
        WriteFile(hPipe, serialized.c_str(), static_cast<DWORD>(serialized.size()), &written, NULL);
      };

      monitor->setEventHandler([sendEvent](const Protocol::Event &ev) {
        sendEvent(ev);
      });

      monitor->printStatus();
      Protocol::Event capsEv(Protocol::EventType::CapabilitiesUpdate, "low", "Engine capabilities update", monitor->getCapabilities());
      sendEvent(capsEv);

      char buffer[Constants::PIPE_BUFFER_SIZE];
      DWORD bytesRead;

      while (!g_stopMonitoring.load(std::memory_order_relaxed)) {
        if (!ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
          break;
        }

        buffer[bytesRead] = '\0';
        std::string line(buffer);

        size_t pos = 0;
        while ((pos = line.find('\n')) != std::string::npos) {
          std::string rawCmd = line.substr(0, pos);
          line.erase(0, pos + 1);

          try {
            auto j = nlohmann::json::parse(rawCmd);
            std::string type = j.value("command", "");

            if (type == "ping") {
              sendEvent(Protocol::Event(Protocol::EventType::Heartbeat, "low", "PONG"));
            } else if (type == "status") {
              monitor->printStatus();
              sendEvent(Protocol::Event(Protocol::EventType::CapabilitiesUpdate, "low", "Capabilities refreshed", monitor->getCapabilities()));
            } else if (type == "scan") {
              std::string path = j.value("path", "");
              if (path.empty()) {
                sendEvent(Protocol::Event(Protocol::EventType::Info, "medium", "Scan command missing path"));
              } else {
                monitor->scanFile(path);
              }
            } else {
              sendEvent(Protocol::Event(Protocol::EventType::Info, "medium", "Unknown command: " + type));
            }
          } catch (const std::exception &e) {
            if (rawCmd == "ping") {
              sendEvent(Protocol::Event(Protocol::EventType::Heartbeat, "low", "PONG"));
            } else {
              sendEvent(Protocol::Event(Protocol::EventType::Info, "medium", "JSON Parse Error: " + std::string(e.what())));
            }
          }
        }
      }
      monitor->setEventHandler(nullptr);
    }

    CloseHandle(hPipe);
    std::cout << "Client disconnected." << std::endl;
  }
}

static BOOL WINAPI CtrlHandler(DWORD t) {
  if (t == CTRL_C_EVENT || t == CTRL_BREAK_EVENT || t == CTRL_CLOSE_EVENT) {
    g_stopMonitoring.store(true, std::memory_order_relaxed);
    if (g_monitor) {
      g_monitor->stop();
    }

    return TRUE;
  }

  return FALSE;
}

int main() {
  auto &config = UserConfig::getInstance();
  if (!config.load()) {
    config.save();
  }

  ServerCommunications::initialize(config.serverUrl, config.accessToken, config.refreshToken);

  if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
    std::cerr << "Error: Could not set console control handler" << std::endl;
  }

  auto driver = KernelCommunications::getInstance();
  std::wstring devicePath{Constants::AYDO_DRIVER_DEVICE_PATH.begin(), Constants::AYDO_DRIVER_DEVICE_PATH.end()};

  if (!driver->connect(devicePath)) {
    std::cerr << "Fail: Driver device unavailable." << std::endl;
    return EXIT_FAILURE;
  }

  try {
    YScanningEngine yara(Constants::YARA_RULES_FILES, config.killThreshold);

    std::string hashesDbPath{Constants::HASHES_DB_PATH.begin(), Constants::HASHES_DB_PATH.end()};
    HashesDatabase hashDb(hashesDbPath);

    ProcessMonitor monitor(driver, yara, hashDb);
    g_monitor = &monitor;

    monitor.start();

    std::thread commandThread(pipeServerLoop, &monitor);
    commandThread.detach();

    while (!g_stopMonitoring.load(std::memory_order_relaxed)) {
      Sleep(Constants::IDLE_SLEEP_TIME_MS);
    }

    monitor.stop();
    g_monitor = nullptr;

  } catch (const std::exception &ex) {
    std::cerr << "Fatal Error: " << ex.what() << std::endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
