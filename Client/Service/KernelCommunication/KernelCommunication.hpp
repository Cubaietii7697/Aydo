#pragma once

#include <Windows.h>

#include <memory>
#include <string>
#include <variant>

#include "../../KernelDriver/include/Public.hpp"

enum class RequestType {
  KillProcess,
  WaitForProcessStart
};

struct ResultData {
  DWORD errorCode{};
  virtual ~ResultData() = default;
};

struct KillProcessResult : ResultData {
  DWORD terminatedPid{};
  DWORD driverStatus{};
};

struct ProcessNotifyResult : ResultData {
  PROCESS_NOTIFY_INFO info{};
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
  static std::shared_ptr<KernelCommunication> instance() {
    struct make_shared_enabler : public KernelCommunication {}; // gives access
    static std::shared_ptr<KernelCommunication> inst =
        std::make_shared<make_shared_enabler>();
    return inst;
  }

  // Open handle to device
  bool initKernel(const std::wstring &deviceName = LR"(\\.\AydoKernelDriver)");

  // Graceful cleanup
  void shutdown();

  // Send a request to kernel
  std::pair<ResponseStatus, std::unique_ptr<ResultData>>
  sendRequest(const RequestType type,
              const std::variant<KillProcessData, std::wstring> &data) const;

private:
  // Singleton enforcement
  KernelCommunication();
  ~KernelCommunication();
  KernelCommunication(const KernelCommunication &) = delete;
  KernelCommunication &operator=(const KernelCommunication &) = delete;

private:
  HANDLE m_hDev;
};
