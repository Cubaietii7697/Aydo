#include "ioctl.hpp"

#include "../include/Public.hpp"
#include "../logging/logger.hpp"
#include "../pch.hpp"
#include "../requests/request_handler.hpp"

NTSTATUS Comm_InitDefaultQueue(WDFDEVICE dev) {
  NTSTATUS status;

  //
  // 1. Create the default sequential queue for normal IOCTLs
  //
  WDF_IO_QUEUE_CONFIG qc;
  WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&qc, WdfIoQueueDispatchSequential);
  qc.EvtIoDeviceControl = Comm_EvtIoDeviceControl;
  qc.EvtIoStop = Comm_EvtIoStop;

  status = WdfIoQueueCreate(dev, &qc, WDF_NO_OBJECT_ATTRIBUTES, nullptr);
  if (!NT_SUCCESS(status)) {
    AYDO_ERROR("Failed to create default queue (0x%X)", status);
    return status;
  }

  //
  // 2. Create the manual-dispatch queue for process-start notifications
  //
  WDF_IO_QUEUE_CONFIG notifyCfg;
  WDF_IO_QUEUE_CONFIG_INIT(&notifyCfg, WdfIoQueueDispatchManual);

  status = WdfIoQueueCreate(dev,
                            &notifyCfg,
                            WDF_NO_OBJECT_ATTRIBUTES,
                            &g_NotifyQueue);
  if (NT_SUCCESS(status)) {
    AYDO_INFO("Notification queue created successfully.");
  } else {
    AYDO_ERROR("Failed to create notification queue (0x%X)", status);
  }

  return status;
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
  case IOCTL_REGISTER_PROCESS_NOTIFY: {
    NTSTATUS status = Requests_RegisterProcessNotify();
    WdfRequestComplete(req, status);
    return;
  }
  case IOCTL_UNREGISTER_PROCESS_NOTIFY: {
    NTSTATUS status = Requests_UnregisterProcessNotify();
    WdfRequestComplete(req, status);
    return;
  }
  case IOCTL_WAIT_FOR_PROCESS_START: {
    if (inLen < sizeof(WAIT_FOR_PROCESS_START_IN)) {
      WdfRequestComplete(req, STATUS_BUFFER_TOO_SMALL);
      return;
    }

    // Save target image name in request context or global list
    PWAIT_FOR_PROCESS_START_IN inBuf = nullptr;
    NTSTATUS stIn = WdfRequestRetrieveInputBuffer(req,
                                                  sizeof(WAIT_FOR_PROCESS_START_IN),
                                                  reinterpret_cast<PVOID *>(&inBuf), nullptr);
    if (!NT_SUCCESS(stIn)) {
      WdfRequestComplete(req, stIn);
      return;
    }

    // You can store this per-request in a custom request context
    // For simplicity, we forward it directly to the manual queue
    WdfRequestForwardToIoQueue(req, g_NotifyQueue);
    return;
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
