#pragma once
#include "../pch.hpp"
#include "public.hpp"

EXTERN_C_START

// Per-device context
typedef struct _DEVICE_CONTEXT {
  ULONG _; // placeholder for future state
} DEVICE_CONTEXT, *PDEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, DeviceGetContext)

// Creates the WDFDEVICE and configures interfaces/queues
NTSTATUS
AydoKernelDriverCreateDevice(
    _Inout_ PWDFDEVICE_INIT DeviceInit);

// Initializes default I/O queue
NTSTATUS
AydoKernelDriverQueueInitialize(_In_ WDFDEVICE Device);

EXTERN_C_END
