#pragma once

#include <windows.h>
#include <atomic>
#include <fltuser.h>
#include <functional>
#include <memory>
#include <string>
#include <thread>

#pragma comment(lib, "fltlib.lib")

// Forward declarations
class ProcessMonitor;

// Scan Reasons
enum ScanReason {
  ScanReasonExecute = 0,
  ScanReasonWriteComplete,
  ScanReasonRename,
  ScanReasonProcessCreation
};

typedef struct Config {
  ULONG64 MaxScanSize;
} Config, *PConfig;

// Match kernel structures (must be identical)
#pragma pack(push, 1)

typedef struct ScanRequest {
  ULONG RequestId;
  HANDLE ProcessId;
  ACCESS_MASK DesiredAccess;
  USHORT FileNameLength;
  WCHAR FileName[512];
  UCHAR FileHash[32];
  BOOLEAN IsExecute;
  ULONG Reason; // ScanReason
} ScanRequest, *PScanRequest;

typedef struct ScanResponse {
  ULONG RequestId;
  NTSTATUS Status;
  ULONG Verdict; // 0=Clean, 1=Malicious, 2=Unknown
  ULONG ThreatLevel;
  WCHAR ThreatName[64];
} ScanResponse, *PScanResponse;

#pragma pack(pop)

class MinifilterCommunications {
private:
  HANDLE m_hPort;
  std::thread m_listenerThread;
  std::atomic<bool> m_stopListener;
  ProcessMonitor *m_monitor; // Pointer to the process monitor for scanning

  void listenerLoop();

public:
  MinifilterCommunications();
  ~MinifilterCommunications();

  // Delete copy constructor and assignment
  MinifilterCommunications(const MinifilterCommunications &) = delete;
  MinifilterCommunications &operator=(const MinifilterCommunications &) = delete;

  bool connect(const std::wstring &portName);
  void disconnect();
  bool isConnected() const;

  void setProcessMonitor(ProcessMonitor *monitor);
  void updateConfig(unsigned long long maxScanSize);
  void startListener();
  void stopListener();
};
