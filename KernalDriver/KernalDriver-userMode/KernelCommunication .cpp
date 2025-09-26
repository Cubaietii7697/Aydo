#include <iostream>

#include "../ioctlDefs.h"
#include "KernelCommunication.hpp"

// Singleton accessor
KernelCommunication &KernelCommunication::instance() {
  static KernelCommunication inst;
  return inst;
}

KernelCommunication::KernelCommunication()
    : hDev_(INVALID_HANDLE_VALUE) {}

KernelCommunication::~KernelCommunication() {
  shutdown();
}

bool KernelCommunication::initKernel(const std::wstring &deviceName) {
  if (hDev_ != INVALID_HANDLE_VALUE) {
    return true;
  }
  hDev_ = CreateFileW(deviceName.c_str(),
                      GENERIC_READ | GENERIC_WRITE,
                      FILE_SHARE_READ | FILE_SHARE_WRITE,
                      nullptr,
                      OPEN_EXISTING,
                      FILE_ATTRIBUTE_NORMAL,
                      nullptr);
  return hDev_ != INVALID_HANDLE_VALUE;
}

void KernelCommunication::shutdown() {
  if (hDev_ != INVALID_HANDLE_VALUE) {
    CloseHandle(hDev_);
    hDev_ = INVALID_HANDLE_VALUE;
  }
}

bool KernelCommunication::sendRequest(RequestType type, const std::variant<KillProcessData> &data) const {
  if (hDev_ == INVALID_HANDLE_VALUE) {
    return false;
  }

  DWORD bytes = 0;
  bool ok = false;

  switch (type) {
  case RequestType::KillProcess: {
    const auto &payload = std::get<KillProcessData>(data);
    ok = DeviceIoControl(hDev_,
                         IOCTL_KILL_PROCESS,
                         (LPVOID)&payload.pid, sizeof(DWORD),
                         nullptr, 0,
                         &bytes,
                         nullptr);
    break;
  }
  default:
    return false;
  }

  return ok;
}
