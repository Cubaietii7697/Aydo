#include "KernelCommunication.hpp"

#include <iostream>

#include "../../IOCTLDefs.h"

// Singleton
KernelCommunication &KernelCommunication::instance() {
  static KernelCommunication inst;
  return inst;
}

KernelCommunication::KernelCommunication()
    : m_hDev(INVALID_HANDLE_VALUE) {}

KernelCommunication::~KernelCommunication() {
  shutdown();
}

bool KernelCommunication::initKernel(const std::wstring &deviceName) {
  if (m_hDev != INVALID_HANDLE_VALUE) {
    return true;
  }
  m_hDev = CreateFileW(deviceName.c_str(),
                       GENERIC_READ | GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                       nullptr,
                       OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL,
                       nullptr);
  return m_hDev != INVALID_HANDLE_VALUE;
}

void KernelCommunication::shutdown() {
  if (m_hDev != INVALID_HANDLE_VALUE) {
    CloseHandle(m_hDev);
    m_hDev = INVALID_HANDLE_VALUE;
  }
}

RespondType KernelCommunication::sendRequest(RequestType type, const std::variant<KillProcessData> &data) const {
  DWORD bytes = 0;
  if (m_hDev == INVALID_HANDLE_VALUE) {
    return RespondType::invalidHandleVal;
  }

  switch (type) {
  case RequestType::KillProcess: {
    const auto &payload = std::get<KillProcessData>(data);
    BOOL success = DeviceIoControl(m_hDev,
                                   IOCTL_KILL_PROCESS,
                                   (LPVOID)&payload.pid, sizeof(DWORD),
                                   nullptr, 0,
                                   &bytes,
                                   nullptr);

    if (success) {
      return RespondType::work;
    } else {
      return RespondType::crash;
    }
  }
  default:
    return RespondType::invalidRequestType;
  }
}
