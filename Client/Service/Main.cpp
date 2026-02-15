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
#include "Yara/YScanningEngine.hpp"

#pragma comment(lib, "ws2_32.lib")

static std::atomic<bool> g_stopMonitoring{false};
static ProcessMonitor *g_monitor = nullptr;

static std::string trim(const std::string &value) {
  const auto start = value.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) {
    return "";
  }
  const auto end = value.find_last_not_of(" \t\r\n");
  return value.substr(start, end - start + 1);
}

static std::string stripQuotes(const std::string &value) {
  if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
    return value.substr(1, value.size() - 2);
  }
  return value;
}

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
      Sleep(1000);
      continue;
    }

    if (ConnectNamedPipe(hPipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
      std::cout << "Client connected to pipe." << std::endl;

      // Redirect monitor output to this pipe
      monitor->setLogger([hPipe](const std::string &msg) {
        DWORD written;
        // Important: clientEngine expects line-based, log() adds newline already if needed.
        // ProcessMonitor::log appends \n.
        WriteFile(hPipe, msg.c_str(), msg.size(), &written, NULL);
      });

      // Send full status dump on connection so GUI updates capabilities
      monitor->printStatus();
      std::string caps = "[CAPABILITIES] " + monitor->getCapabilitiesJson() + "\n";
      DWORD written;
      WriteFile(hPipe, caps.c_str(), caps.size(), &written, NULL);

      char buffer[1024];
      DWORD bytesRead;

      while (!g_stopMonitoring.load(std::memory_order_relaxed)) {
        if (!ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
          break;
        }

        buffer[bytesRead] = '\0';
        std::string line(buffer);

        // Process multiple commands if they come in one packet
        size_t pos = 0;
        while ((pos = line.find('\n')) != std::string::npos) {
          std::string cmd = line.substr(0, pos);
          line.erase(0, pos + 1);

          std::string trimmed = trim(cmd);
          if (trimmed.empty()) {
            continue;
          }

          if (trimmed == "ping") {
            std::string response = "[PING] OK\n";
            DWORD written;
            WriteFile(hPipe, response.c_str(), response.size(), &written, NULL);
          } else if (trimmed == "status") {
            monitor->printStatus();
            std::string capsResponse = "[CAPABILITIES] " + monitor->getCapabilitiesJson() + "\n";
            WriteFile(hPipe, capsResponse.c_str(), capsResponse.size(), &written, NULL);
          } else if (trimmed.rfind("scan", 0) == 0) {
            auto path = trim(trimmed.substr(4));
            path = stripQuotes(path);
            if (path.empty()) {
              std::string err = "[SCAN ERROR] Missing path\n";
              DWORD written;
              WriteFile(hPipe, err.c_str(), err.size(), &written, NULL);
            } else {
              monitor->scanFile(path);
            }
          }
        }
      }
      monitor->setLogger(nullptr);
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

static void handleUserAuth() {
  auto &config = UserConfig::getInstance();
  auto &server = ServerCommunications::getInstance();

  if (!config.accessToken.empty()) {
    return;
  }

  std::cout << "Authentication required." << std::endl;
  std::cout << "1. Login" << std::endl;
  std::cout << "2. Register" << std::endl;
  std::cout << "Choice: ";

  std::string choice;
  std::getline(std::cin, choice);

  std::string email, password, nickname;

  if (choice == "1") {
    std::cout << "Email: ";
    std::getline(std::cin, email);
    std::cout << "Password: ";
    std::getline(std::cin, password);

    if (server.login(email, password)) {
      std::cout << "Login successful!" << std::endl;
    } else {
      std::cerr << "Login failed. Please restart the service to try again." << std::endl;
      exit(EXIT_FAILURE);
    }
  } else if (choice == "2") {
    std::cout << "Email: ";
    std::getline(std::cin, email);
    std::cout << "Nickname: ";
    std::getline(std::cin, nickname);
    std::cout << "Password: ";
    std::getline(std::cin, password);

    if (server.registerUser(email, nickname, password)) {
      std::cout << "Registration successful!" << std::endl;
    } else {
      std::cerr << "Registration failed. Please restart the service to try again." << std::endl;
      exit(EXIT_FAILURE);
    }
  } else {
    std::cerr << "Invalid choice." << std::endl;
    exit(EXIT_FAILURE);
  }
}

int main() {
  std::cout << "==================================" << std::endl;
  std::cout << "     Aydo Process Monitor" << std::endl;
  std::cout << "==================================" << std::endl
            << std::endl;

  // Load configuration
  auto &config = UserConfig::getInstance();
  if (!config.load()) {
    std::cout << "Creating default config.json..." << std::endl;
    config.save();
  }

  // Connect to server
  std::cout << "Connecting to server..." << config.serverUrl << std::endl;
  ServerCommunications::initialize(config.serverUrl, config.accessToken, config.refreshToken);

  // Handle authentication if tokens are missing
  if (config.refreshToken == "") {
    std::cout << "Warning: Refresh token missing. Authentication required via GUI." << std::endl;
  }

  // Set up Ctrl+C handler
  if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
    std::cerr << "Warning: Could not set Ctrl+C handler" << std::endl;
  }

  auto driver = KernelCommunications::getInstance();

  std::wstring devicePath{Constants::AYDO_DRIVER_DEVICE_PATH.begin(), Constants::AYDO_DRIVER_DEVICE_PATH.end()};
  if (!driver->connect(devicePath)) {
    std::cerr << "Failed to open driver device. Error: " << GetLastError() << std::endl;
    std::cerr << "Make sure the driver is loaded!" << std::endl;

    return EXIT_FAILURE;
  }

  std::cout << "Successfully connected to driver!" << std::endl;
  std::cout << std::endl;

  std::cout << "Initializing scanning engines..." << std::endl;

  try {
    YScanningEngine yara(Constants::YARA_RULES_FILES, config.killThreshold);
    std::cout << "  -> Initialized YARA scanning engine (Kill Threshold: " << config.killThreshold << ")" << std::endl;

    // Initialize hashes database
    std::string hashesDbPath{Constants::HASHES_DB_PATH.begin(), Constants::HASHES_DB_PATH.end()};
    HashesDatabase hashDb(hashesDbPath);
    std::cout << "  -> Loaded hashes database" << std::endl;

    std::cout << "All scanning engines initialized successfully!" << std::endl
              << std::endl;

    ProcessMonitor monitor(driver, yara, hashDb);
    g_monitor = &monitor;

    std::cout << "Starting background monitoring thread..." << std::endl;
    monitor.start();

    std::thread commandThread(pipeServerLoop, &monitor);
    commandThread.detach();

    std::cout << "Monitoring active. Press Ctrl+C to stop." << std::endl
              << std::endl;

    // Wait for stop signal
    while (!g_stopMonitoring.load(std::memory_order_relaxed)) {
      Sleep(Constants::IDLE_SLEEP_TIME_MS);
    }

    monitor.stop();
    g_monitor = nullptr;

    std::cout << "Shutting down..." << std::endl;

  } catch (const std::exception &ex) {
    std::cerr << "\nFATAL ERROR: Failed to initialize scanning engines: " << ex.what() << std::endl;
    std::cerr << "Make sure the data directory exists with compiled_rules.yara and file_hashes.db" << std::endl;

    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
