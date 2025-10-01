#include "KernelCommunication.hpp"

#include <iostream>

#include "../../IOCTLDefs.hpp"

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
std::pair<ResponseStatus, KillProcessResult>
KernelCommunication::sendRequest(RequestType type,
                                 const std::variant<KillProcessData> &data) const {
  KillProcessResult result{};
  DWORD bytesReturned = 0;
  ResponseStatus status = ResponseStatus::invalidHandleVal;

  if (m_hDev == INVALID_HANDLE_VALUE) {
    result.errorCode = ERROR_INVALID_HANDLE;
    return {status, result};
  }

  switch (type) {
  case RequestType::KillProcess: {
    const auto &payload = std::get<KillProcessData>(data);

    if (BOOL success = DeviceIoControl(
            m_hDev,
            IOCTL_KILL_PROCESS,
            (LPVOID)&payload.pid, sizeof(DWORD),
            &result, sizeof(result),
            &bytesReturned,
            nullptr);
        success) {
      status = ResponseStatus::success;
      result.errorCode = ERROR_SUCCESS;

    } else {
      status = ResponseStatus::failure;
      result.errorCode = GetLastError();
    }
    break;
  }

  default:
    status = ResponseStatus::invalidRequestType;
    result.errorCode = ERROR_INVALID_FUNCTION;
    break;
  }

  return {status, result};
}
