#include "Driver.h"

#include <ntddk.h>
#include <ntifs.h> // PsLookupProcessByProcessId, ObOpenObjectByPointer
#include <wdf.h>

#include "Device.h"

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif

extern POBJECT_TYPE *PsProcessType; // provided by the kernel

static const ULONG kSystemPids[] = {0u, 4u};

// KMDF bootstrap
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
  NTSTATUS status;
  WDF_DRIVER_CONFIG config;

  WDF_DRIVER_CONFIG_INIT(&config, AydoKernelDriverEvtDeviceAdd);

  status = WdfDriverCreate(DriverObject,
                           RegistryPath,
                           WDF_NO_OBJECT_ATTRIBUTES,
                           &config,
                           WDF_NO_HANDLE);
  if (!NT_SUCCESS(status)) {
    KdPrint(("AydoKernelDriver: WdfDriverCreate failed 0x%X\n", status));
    return status;
  }

  DriverObject->DriverUnload = DriverUnload;
  KdPrint(("AydoKernelDriver: DriverEntry OK (no notify)\n"));
  return STATUS_SUCCESS;
}

NTSTATUS
AydoKernelDriverEvtDeviceAdd(_In_ WDFDRIVER Driver, _Inout_ PWDFDEVICE_INIT DeviceInit) {
  UNREFERENCED_PARAMETER(Driver);
  return AydoKernelDriverCreateDevice(DeviceInit);
}

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);
  KdPrint(("AydoKernelDriver: DriverUnload\n"));
}

// Kernel-side terminate primitive
NTSTATUS
KernelKillProcess(_In_ HANDLE TargetPid) {
  // safety for obvious system PIDs
  if (TargetPid == kSystemPids[0] || TargetPid == kSystemPids[1]) {
    return STATUS_ACCESS_DENIED;
  }

  PEPROCESS proc = NULL;
  NTSTATUS status = PsLookupProcessByProcessId(TargetPid, &proc);
  if (!NT_SUCCESS(status)) {
    KdPrint(("AydoKernelDriver: PsLookupProcessByProcessId(%u) -> 0x%X\n",
             (ULONG)(ULONG_PTR)TargetPid, status));
    return status;
  }

  HANDLE hProc = NULL;
  status = ObOpenObjectByPointer(proc,
                                 OBJ_KERNEL_HANDLE,
                                 NULL,
                                 PROCESS_TERMINATE,
                                 *PsProcessType,
                                 KernelMode,
                                 &hProc);
  if (!NT_SUCCESS(status)) {
    KdPrint(("AydoKernelDriver: ObOpenObjectByPointer -> 0x%X\n", status));
    ObDereferenceObject(proc);
    return status;
  }

  status = ZwTerminateProcess(hProc, STATUS_SUCCESS);
  if (!NT_SUCCESS(status)) {
    KdPrint(("AydoKernelDriver: ZwTerminateProcess -> 0x%X\n", status));
  }

  ZwClose(hProc);
  ObDereferenceObject(proc);
  return status;
}
