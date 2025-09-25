#include "Driver.h"
#include "ioctl_defs.h"

VOID KernalDriver1EvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode) {
  UNREFERENCED_PARAMETER(Queue);
  UNREFERENCED_PARAMETER(OutputBufferLength);

  NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
  size_t bytesReturned = 0;

  if (IoControlCode == IOCTL_KILL_PROCESS) {
    if (InputBufferLength < sizeof(ULONG)) {
      status = STATUS_BUFFER_TOO_SMALL;
    } else {
      PULONG pPid = NULL;
      status = WdfRequestRetrieveInputBuffer(Request,
                                             sizeof(ULONG),
                                             (PVOID *)&pPid,
                                             NULL);
      if (NT_SUCCESS(status)) {
        status = KernelKillProcess((HANDLE)(ULONG_PTR)(*pPid));
      }
    }
  }

  WdfRequestCompleteWithInformation(Request, status, bytesReturned);
}
