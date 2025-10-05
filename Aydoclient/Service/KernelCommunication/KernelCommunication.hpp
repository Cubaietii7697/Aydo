#pragma once

#include <Windows.h>

#include <memory>
#include <string>
#include <variant>

#include "../../AydoKernelDriver/include/Public.hpp"

// Expand later with more request types if needed
enum class RequestType {
  KillProcess
};

struct ResultData {
  DWORD errorCode{};
  virtual ~ResultData() = default;
};

struct KillProcessResult : ResultData {
  DWORD terminatedPid{};
  DWORD driverStatus{};
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
  std::pair<ResponseStatus, std::unique_ptr<ResultData>>
  sendRequest(const RequestType type,
              const std::variant<KillProcessData> &data) const;

private:
  // Singleton enforcement
  KernelCommunication();
  ~KernelCommunication();
  KernelCommunication(const KernelCommunication &) = delete;
  KernelCommunication &operator=(const KernelCommunication &) = delete;

private:
  HANDLE m_hDev;
};
