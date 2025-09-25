/*++

Module Name:

    driver.h

Abstract:

    This file contains the driver definitions.

Environment:

    Kernel-mode Driver Framework

--*/

#include <initguid.h>
#include <ntddk.h>
#include <wdf.h>

#include "device.h"
#include "queue.h"
#include "trace.h"

EXTERN_C_START

//
// WDFDRIVER Events
//

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD KernalDriver1EvtDeviceAdd;
EVT_WDF_OBJECT_CONTEXT_CLEANUP KernalDriver1EvtDriverContextCleanup;
NTSTATUS KernelKillProcess(_In_ HANDLE TargetPid);

EXTERN_C_END
