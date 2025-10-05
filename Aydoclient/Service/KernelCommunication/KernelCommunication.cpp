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
KernelCommunication::sendRequest(const RequestType type,
                                 const std::variant<KillProcessData> &data) const {
  if (m_hDev == INVALID_HANDLE_VALUE) {
    auto r = std::make_unique<ResultData>();
    r->errorCode = ERROR_INVALID_HANDLE;
    return {ResponseStatus::invalidHandleVal, std::move(r)};
  }

  switch (type) {
  case RequestType::KillProcess: {
    auto r = std::make_unique<KillProcessResult>();
    const KillProcessData &payload = std::get<KillProcessData>(data);

    DWORD bytes = 0;
    BOOL ok = ::DeviceIoControl(
        m_hDev,
        IOCTL_KILL_PROCESS,
        (LPVOID)&payload, sizeof(payload),
        nullptr, 0,
        &bytes,
        nullptr);

    r->errorCode = ok ? ERROR_SUCCESS : ::GetLastError();
    return {ok ? ResponseStatus::success : ResponseStatus::failure, std::move(r)};
  }
  default: {
    auto r = std::make_unique<ResultData>();
    r->errorCode = ERROR_INVALID_FUNCTION;
    return {ResponseStatus::invalidRequestType, std::move(r)};
  }
  }
}
