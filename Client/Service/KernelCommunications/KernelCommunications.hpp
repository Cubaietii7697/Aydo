#pragma once

#include <windows.h>

#include <memory>
#include <optional>
#include <string>

#include "../Types.hpp"

class KernelCommunications {
private:
  HANDLE m_hDevice;

  // Base function to send IOCTL requests to the kernel
  bool sendIoctl(DWORD ioctlCode,
                 void *inputBuffer,
                 DWORD inputSize,
                 void *outputBuffer,
                 DWORD outputSize,
                 DWORD *bytesReturned = nullptr);

public:
  KernelCommunications();
  KernelCommunications(const KernelCommunications &) = delete;
  KernelCommunications &operator=(const KernelCommunications &) = delete;
  ~KernelCommunications();

  static std::shared_ptr<KernelCommunications> getInstance() {
    static std::shared_ptr<KernelCommunications> instance = std::make_shared<KernelCommunications>();

    return instance;
  }

  bool connect(const std::wstring &devicePath);
  void disconnect();
  [[nodiscard]] bool isConnected() const;

  // Wrapper functions for specific IOCTL operations
  bool killProcess(ULONG processId);
  std::optional<IOCTL_GET_PROCESS_NOTIFICATION_OUTPUT> getProcessNotification();
};