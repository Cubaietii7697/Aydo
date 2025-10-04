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

std::pair<ResponseStatus, std::unique_ptr<ResultData>>
KernelCommunication::sendRequest(const RequestType &type,
                                 const std::variant<KillProcessData> &data) const {
  std::unique_ptr<ResultData> result;
  DWORD bytesReturned = 0;
  ResponseStatus status = ResponseStatus::invalidHandleVal;

  if (m_hDev == INVALID_HANDLE_VALUE) {
    auto base = std::make_unique<ResultData>();
    base->errorCode = ERROR_INVALID_HANDLE;
    return {ResponseStatus::invalidHandleVal, std::move(base)};
  }

  switch (type) {
  case RequestType::KillProcess: {
    auto killRes = std::make_unique<KillProcessResult>();
    const auto &payload = std::get<KillProcessData>(data);

    if (DeviceIoControl(m_hDev,
                        IOCTL_KILL_PROCESS,
                        (LPVOID)&payload.pid, sizeof(DWORD),
                        killRes.get(), sizeof(KillProcessResult),
                        &bytesReturned,
                        nullptr)) {
      status = ResponseStatus::success;
      killRes->errorCode = ERROR_SUCCESS;
    } else {
      status = ResponseStatus::failure;
      killRes->errorCode = GetLastError();
    }

    result = std::move(killRes);
    break;
  }

  default: {
    auto base = std::make_unique<ResultData>();
    status = ResponseStatus::invalidRequestType;
    base->errorCode = ERROR_INVALID_FUNCTION;
    result = std::move(base);
    break;
  }
  }

  return {status, std::move(result)};
}
