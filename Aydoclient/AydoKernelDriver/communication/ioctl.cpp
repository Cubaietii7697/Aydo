#include "ioctl.hpp"

#include "../include/Public.hpp"
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
    if (inLen < sizeof(KillProcessData) || outLen < sizeof(KillProcessOut)) {
      st = STATUS_BUFFER_TOO_SMALL;
      break;
    }

    PKillProcessData in = nullptr;
    st = WdfRequestRetrieveInputBuffer(req, sizeof(KillProcessData),
                                       reinterpret_cast<PVOID *>(&in), nullptr);
    if (!NT_SUCCESS(st))
      break;

    KillProcessOut *out = nullptr;
    st = WdfRequestRetrieveOutputBuffer(req, sizeof(KillProcessOut),
                                        reinterpret_cast<PVOID *>(&out), nullptr);
    if (!NT_SUCCESS(st))
      break;

    NTSTATUS killSt = Requests_HandleKill(in->Pid);

    out->requestedPid = in->Pid;
    out->terminatedPid = NT_SUCCESS(killSt) ? in->Pid : 0;
    out->ntStatus = static_cast<long>(killSt);

    st = killSt;
    written = sizeof(KillProcessOut);
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
