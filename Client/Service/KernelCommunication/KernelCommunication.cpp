#include "KernelCommunication.hpp"

#include <iostream>

#include "../../IOCTLDefs.hpp"
#include "../../KernelDriver/include/Public.hpp"

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
                                 const std::variant<KillProcessData, std::wstring> &data) const {
  if (m_hDev == INVALID_HANDLE_VALUE) {
    auto r = std::make_unique<ResultData>();
    r->errorCode = ERROR_INVALID_HANDLE;
    return {ResponseStatus::invalidHandleVal, std::move(r)};
  }

  switch (type) {
  case RequestType::KillProcess: {
    const auto &in = std::get<KillProcessData>(data);

    KillProcessOut out{};
    DWORD bytes = 0;
    BOOL ok = ::DeviceIoControl(
        m_hDev,
        IOCTL_KILL_PROCESS,
        (LPVOID)&in, sizeof(in),
        &out, sizeof(out),
        &bytes, nullptr);

    auto res = std::make_unique<KillProcessResult>();

    if (!ok) {
      res->errorCode = ::GetLastError();
      if (bytes == sizeof(KillProcessOut)) {
        res->driverStatus = static_cast<DWORD>(out.ntStatus);
        res->terminatedPid = out.terminatedPid;
      } else {
        res->driverStatus = 0;
        res->terminatedPid = 0;
      }

      return {ResponseStatus::failure, std::move(res)};
    }

    res->errorCode = ERROR_SUCCESS;
    res->driverStatus = static_cast<DWORD>(out.ntStatus);
    res->terminatedPid = out.terminatedPid;

    return {ResponseStatus::success, std::move(res)};
  }

  case RequestType::WaitForProcessStart: {
    const auto &exeName = std::get<std::wstring>(data);

    WAIT_FOR_PROCESS_START_IN input{};
    wcsncpy_s(input.TargetImageName, exeName.c_str(), _TRUNCATE);

    auto result = std::make_unique<ProcessNotifyResult>();
    DWORD bytesReturned = 0;

    if (BOOL ok = ::DeviceIoControl(
            m_hDev,
            IOCTL_WAIT_FOR_PROCESS_START,
            &input, sizeof(input),
            result.get(), sizeof(result->info),
            &bytesReturned,
            nullptr);
        !ok) {
      DWORD err = GetLastError();
      auto errResult = std::make_unique<ResultData>();
      errResult->errorCode = err;

      return {ResponseStatus::failure, std::move(errResult)};
    }

    return {ResponseStatus::success, std::move(result)};
  }

  default: {
    auto r = std::make_unique<ResultData>();
    r->errorCode = ERROR_INVALID_FUNCTION;

    return {ResponseStatus::invalidRequestType, std::move(r)};
  }
  }
}
