#pragma once

#include <ntddk.h>
#include <wdf.h>

#include "public.h" // GUID_DEVINTERFACE_KernalDriver1 (interface GUID)

EXTERN_C_START

// Per-device context (similar to a WDM device extension)
typedef struct _DEVICE_CONTEXT {
  ULONG PrivateDeviceData; // placeholder for future state
} DEVICE_CONTEXT, *PDEVICE_CONTEXT;

// Generates inline DeviceGetContext(WDFDEVICE)
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, DeviceGetContext)

// Creates the WDFDEVICE and configures interfaces/queues (implemented in Device.c)
NTSTATUS
KernalDriver1CreateDevice(
    _Inout_ PWDFDEVICE_INIT DeviceInit);

// Initializes default I/O queue (implemented in Queue.c)
NTSTATUS
KernalDriver1QueueInitialize(_In_ WDFDEVICE Device);

EXTERN_C_END
