#include "KernelCommunications.hpp"

#include "../../IOCTLs.hpp"

KernelCommunications::KernelCommunications()
    : m_hDevice(INVALID_HANDLE_VALUE) {
}

KernelCommunications::~KernelCommunications() {
  disconnect();
}

bool KernelCommunications::connect(const std::wstring &devicePath) {
  // Already connected
  if (m_hDevice != INVALID_HANDLE_VALUE) {
    return true;
  }

  m_hDevice = CreateFileW(
      devicePath.c_str(),
      GENERIC_READ | GENERIC_WRITE,
      0,
      nullptr,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL,
      nullptr);

  return m_hDevice != INVALID_HANDLE_VALUE;
}

void KernelCommunications::disconnect() {
  if (m_hDevice != INVALID_HANDLE_VALUE) {
    CloseHandle(m_hDevice);
    m_hDevice = INVALID_HANDLE_VALUE;
  }
}

bool KernelCommunications::isConnected() const {
  return m_hDevice != INVALID_HANDLE_VALUE;
}

bool KernelCommunications::sendIoctl(DWORD ioctlCode,
                                     void *inputBuffer,
                                     DWORD inputSize,
                                     void *outputBuffer,
                                     DWORD outputSize,
                                     DWORD *bytesReturned) {
  if (!isConnected()) {
    return false;
  }

  DWORD bytesRet = 0;
  BOOL result = DeviceIoControl(
      m_hDevice,
      ioctlCode,
      inputBuffer,
      inputSize,
      outputBuffer,
      outputSize,
      &bytesRet,
      nullptr);

  if (bytesReturned != nullptr) {
    *bytesReturned = bytesRet;
  }

  return result != FALSE;
}

bool KernelCommunications::killProcess(ULONG processId) {
  IOCTL_KILL_PROCESS_INPUT input;
  input.ProcessId = processId;

  return sendIoctl(IOCTL_KILL_PROCESS, &input, sizeof(input), nullptr, 0);
}

std::optional<IOCTL_GET_PROCESS_NOTIFICATION_OUTPUT> KernelCommunications::getProcessNotification() {
  IOCTL_GET_PROCESS_NOTIFICATION_OUTPUT output;
  DWORD bytesReturned = 0;

  if (sendIoctl(IOCTL_GET_PROCESS_NOTIFICATION, nullptr, 0, &output, sizeof(output), &bytesReturned)) {
    if (bytesReturned == sizeof(output)) {
      return output;
    }
  }

  return std::nullopt;
}