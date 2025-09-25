#include "Queue.h"

#include <ntddk.h>
#include <wdf.h>

#include "Driver.h"     // KernelKillProcess prototype (implemented in driver.c)
#include "ioctl_defs.h" // IOCTL_KILL_PROCESS

/*
 * Initialize the default I/O queue and bind our callbacks.
 * Attaches QUEUE_CONTEXT so QueueGetContext(queue) is valid.
 */
NTSTATUS
AydoKernelDriverQueueInitialize(_In_ WDFDEVICE Device) {
  WDF_IO_QUEUE_CONFIG queueConfig;
  WDFQUEUE queue;
  WDF_OBJECT_ATTRIBUTES queueAttributes;
  NTSTATUS status;

  WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
  queueConfig.EvtIoDeviceControl = AydoKernelDriverEvtIoDeviceControl;
  queueConfig.EvtIoStop = AydoKernelDriverEvtIoStop;

  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&queueAttributes, QUEUE_CONTEXT);

  status = WdfIoQueueCreate(Device,
                            &queueConfig,
                            &queueAttributes,
                            &queue);
  if (!NT_SUCCESS(status)) {
    KdPrint(("AydoKernelDriver: WdfIoQueueCreate failed 0x%X\n", status));
    return status;
  }
  {
    PQUEUE_CONTEXT qctx = QueueGetContext(queue);
    qctx->PrivateDeviceData = 0;
  }

  return STATUS_SUCCESS;
}

VOID AydoKernelDriverEvtIoStop(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ ULONG ActionFlags) {
  UNREFERENCED_PARAMETER(Queue);

  // If you previously sent it down the stack, ask lower driver to cancel.
  WdfRequestCancelSentRequest(Request);

  // Whether this is a purge or a suspend, we drop the request.
  WdfRequestComplete(Request, STATUS_CANCELLED);
}

VOID AydoKernelDriverEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode) {
  UNREFERENCED_PARAMETER(Queue);
  UNREFERENCED_PARAMETER(OutputBufferLength);

  NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
  size_t bytesReturned = 0;

  switch (IoControlCode) {
  case IOCTL_KILL_PROCESS: {
    if (InputBufferLength < sizeof(ULONG)) {
      status = STATUS_BUFFER_TOO_SMALL;
      break;
    }

    PULONG pPid = NULL;
    status = WdfRequestRetrieveInputBuffer(Request,
                                           sizeof(ULONG),
                                           (PVOID *)&pPid,
                                           NULL);
    if (!NT_SUCCESS(status)) {
      break;
    }

    ULONG pid = *pPid;

    status = KernelKillProcess((HANDLE)(ULONG_PTR)pid);
    if (NT_SUCCESS(status)) {
      bytesReturned = sizeof(ULONG);
    }
    break;
  }

  default:
    status = STATUS_INVALID_DEVICE_REQUEST;
    break;
  }

  WdfRequestCompleteWithInformation(Request, status, bytesReturned);
}
