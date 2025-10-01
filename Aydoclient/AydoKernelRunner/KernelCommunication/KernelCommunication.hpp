#pragma once

#include <Windows.h>

#include <string>
#include <variant>

struct KillProcessData {
  DWORD pid;
};

// Expand later with more request types if needed
enum class RequestType {
  KillProcess
};

struct KillProcessResult {
  DWORD terminatedPid{};
  DWORD driverStatus{};
  DWORD errorCode{};
};

enum class ResponseStatus {
  success,
  failure,
  invalidHandleVal,
  invalidRequestType
};

class KernelCommunication {
public:
  // Singleton accessor
  static KernelCommunication &instance();

  // Open handle to device
  bool initKernel(const std::wstring &deviceName = LR"(\\.\AydoKernelDriver)");

  // Graceful cleanup
  void shutdown();

  // Send a request to kernel
  std::pair<ResponseStatus, KillProcessResult> sendRequest(RequestType type, const std::variant<KillProcessData> &data) const;

private:
  // Singleton enforcement
  KernelCommunication();
  ~KernelCommunication();
  KernelCommunication(const KernelCommunication &) = delete;
  KernelCommunication &operator=(const KernelCommunication &) = delete;

private:
  HANDLE m_hDev;
};
