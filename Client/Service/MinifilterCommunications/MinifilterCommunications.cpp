#include "MinifilterCommunications.hpp"
#include <iostream>
#include <string>
#include "../ProcessMonitor.hpp"
#include "../Utils.hpp"

MinifilterCommunications::MinifilterCommunications()
    : m_hPort(INVALID_HANDLE_VALUE)
    , m_stopListener(false)
    , m_monitor(nullptr) {
}

MinifilterCommunications::~MinifilterCommunications() {
  stopListener();
  disconnect();
}

bool MinifilterCommunications::connect(const std::wstring &portName) {
  if (isConnected()) {
    return true;
  }

  std::wcout << L"Connecting to minifilter port: " << portName << std::endl;

  HRESULT hr = FilterConnectCommunicationPort(
      portName.c_str(),
      0,       // Options
      nullptr, // Context
      0,       // Context size
      nullptr, // Security attributes
      &m_hPort);

  if (SUCCEEDED(hr)) {
    std::cout << "Successfully connected to minifilter!" << std::endl;
    return true;
  } else {
    std::cerr << "Failed to connect to minifilter. HRESULT: 0x"
              << std::hex << hr << std::dec << std::endl;
    return false;
  }
}

void MinifilterCommunications::disconnect() {
  stopListener();

  if (isConnected()) {
    CloseHandle(m_hPort);
    m_hPort = INVALID_HANDLE_VALUE;
    if (m_monitor) {
      m_monitor->setBlockingActive(false);
    }
    std::cout << "Disconnected from minifilter" << std::endl;
  }
}

bool MinifilterCommunications::isConnected() const {
  return m_hPort != INVALID_HANDLE_VALUE;
}

void MinifilterCommunications::setProcessMonitor(ProcessMonitor *monitor) {
  m_monitor = monitor;
}

void MinifilterCommunications::updateConfig(unsigned long long maxScanSize) {
  if (!isConnected()) {
    return;
  }

  Config config;
  config.MaxScanSize = maxScanSize;

  DWORD bytesReturned = 0;
  HRESULT hr = FilterSendMessage(
      m_hPort,
      &config,
      sizeof(config),
      nullptr,
      0,
      &bytesReturned);

  if (SUCCEEDED(hr)) {
    std::cout << "Successfully updated minifilter configuration (MaxScanSize: "
              << maxScanSize / (1024 * 1024) << "MB)" << std::endl;
  } else {
    std::cerr << "Failed to update minifilter configuration. HRESULT: 0x"
              << std::hex << hr << std::dec << std::endl;
  }
}

void MinifilterCommunications::startListener() {
  if (m_listenerThread.joinable()) {
    std::cerr << "Warning: Listener thread already running" << std::endl;
    return;
  }

  if (!m_monitor) {
    std::cerr << "Error: ProcessMonitor not set!" << std::endl;
    return;
  }

  m_stopListener.store(false, std::memory_order_relaxed);
  m_listenerThread = std::thread(&MinifilterCommunications::listenerLoop, this);
  std::cout << "Minifilter listener started" << std::endl;
}

void MinifilterCommunications::stopListener() {
  if (!m_listenerThread.joinable()) {
    return;
  }

  m_stopListener.store(true, std::memory_order_relaxed);

  if (m_listenerThread.joinable()) {
    m_listenerThread.join();
  }

  std::cout << "Minifilter listener stopped" << std::endl;
}

void MinifilterCommunications::listenerLoop() {
  std::cout << "Minifilter listener loop started" << std::endl;

  while (!m_stopListener.load(std::memory_order_relaxed)) {
    if (!isConnected()) {
      std::cerr << "Minifilter port disconnected!" << std::endl;
      break;
    }

    // Prepare message buffer
    struct {
      FILTER_MESSAGE_HEADER header;
      ScanRequest request;
    } message{};

    // Prepare reply buffer
    struct {
      FILTER_REPLY_HEADER header;
      ScanResponse response;
    } reply{};

    ZeroMemory(&message, sizeof(message));
    ZeroMemory(&reply, sizeof(reply));

    // Get message from kernel (blocking)
    HRESULT hr = FilterGetMessage(
        m_hPort,
        &message.header,
        sizeof(message),
        nullptr);

    if (!SUCCEEDED(hr)) {
      if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)) {
        std::cerr << "Minifilter port handle is invalid" << std::endl;
        break;
      }

      // Check if we're shutting down
      if (m_stopListener.load(std::memory_order_relaxed)) {
        break;
      }

      std::cerr << "FilterGetMessage failed. HRESULT: 0x"
                << std::hex << hr << std::dec << std::endl;
      Sleep(100); // wait a bit
      continue;
    }

    // Process the scan request
    std::string filePath = Utils::wstring_to_utf8(message.request.FileName);
    std::string reasonStr;

    switch (message.request.Reason) {
    case ScanReasonExecute:
      reasonStr = "EXECUTE";
      break;
    case ScanReasonWriteComplete:
      reasonStr = "DOWNLOAD/UPDATE (Write Complete)";
      break;
    case ScanReasonRename:
      reasonStr = "MOVE/RENAME";
      break;
    case ScanReasonProcessCreation:
      reasonStr = "PROCESS START";
      break;
    default:
      reasonStr = "UNKNOWN (" + std::to_string(message.request.Reason) + ")";
      break;
    }

    std::cout << "[MINIFILTER SCAN] [" << reasonStr << "] PID: " << (ULONG)(ULONG_PTR)message.request.ProcessId
              << " | File: " << filePath << std::endl;

    bool isThreat = false;
    if (m_monitor) {
      try {
        isThreat = m_monitor->isThreat(filePath);
      } catch (const std::exception &ex) {
        std::cerr << "  -> [ERROR] Scan exception: " << ex.what() << std::endl;
        isThreat = false;
      }
    }

    // Prepare response
    reply.header.Status = 0;
    reply.header.MessageId = message.header.MessageId;
    reply.response.RequestId = message.request.RequestId;
    reply.response.Status = 0;
    reply.response.Verdict = isThreat ? 1 : 0; // 1=Malicious, 0=Clean
    reply.response.ThreatLevel = isThreat ? 100 : 0;

    if (isThreat) {
      wcscpy_s(reply.response.ThreatName, L"Detected by Aydo");
      std::cout << "  -> [BLOCKED] Malicious file detected!" << std::endl;
    } else {
      wcscpy_s(reply.response.ThreatName, L"Clean");
      std::cout << "  -> [ALLOWED] File is clean" << std::endl;
    }

    // Send reply back to kernel
    hr = FilterReplyMessage(m_hPort, &reply.header, sizeof(reply));
    if (!SUCCEEDED(hr)) {
      std::cerr << "FilterReplyMessage failed. HRESULT: 0x"
                << std::hex << hr << std::dec << std::endl;
    }

    std::cout << std::endl;
  }

  if (m_monitor) {
    m_monitor->setBlockingActive(false);
  }
  std::cout << "Minifilter listener loop exited" << std::endl;
}
