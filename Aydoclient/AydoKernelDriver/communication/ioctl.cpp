#include "ioctl.hpp"

#include "../logging/logger.hpp"
#include "../pch.hpp"
#include "../requests/request_handler.hpp"

NTSTATUS Comm_InitDefaultQueue(WDFDEVICE dev) {
  WDF_IO_QUEUE_CONFIG qc;
  WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&qc, WdfIoQueueDispatchSequential);
  qc.EvtIoDeviceControl = Comm_EvtIoDeviceControl;
  qc.EvtIoStop = Comm_EvtIoStop;
  return WdfIoQueueCreate(dev, &qc, WDF_NO_OBJECT_ATTRIBUTES, nullptr);
}

VOID Comm_EvtIoDeviceControl(WDFQUEUE, WDFREQUEST req,
                             size_t outLen, size_t inLen, ULONG code) {
  UNREFERENCED_PARAMETER(outLen);
  NTSTATUS st = STATUS_INVALID_DEVICE_REQUEST;
  size_t written = 0;

  switch (code) {
  case IOCTL_KILL_PROCESS: {
    if (inLen < sizeof(ULONG)) {
      st = STATUS_BUFFER_TOO_SMALL;
      break;
    }
    PULONG pPid = nullptr;
    st = WdfRequestRetrieveInputBuffer(req, sizeof(ULONG), (PVOID *)&pPid, NULL);
    if (!NT_SUCCESS(st))
      break;
    st = Requests_HandleKill(*pPid);
    if (NT_SUCCESS(st))
      written = sizeof(ULONG);
    break;
  }
  default:
    break;
  }
  WdfRequestCompleteWithInformation(req, st, written);
}

VOID Comm_EvtIoStop(WDFQUEUE, WDFREQUEST req, ULONG flags) {
  UNREFERENCED_PARAMETER(flags);
  WdfRequestCancelSentRequest(req);
  WdfRequestComplete(req, STATUS_CANCELLED);
}
