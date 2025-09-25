#pragma once

#include <ntddk.h>
#include <wdf.h>

EXTERN_C_START

// KMDF driver entry points
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD KernelDriver1EvtDeviceAdd;
DRIVER_UNLOAD DriverUnload;

// Kernel termination primitive (called from Queue.c)
NTSTATUS KernelKillProcess(_In_ HANDLE TargetPid);

EXTERN_C_END
