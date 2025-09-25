#include "Driver.h"

#include <ntddk.h>
#include <ntifs.h> // PsLookupProcessByProcessId, ObOpenObjectByPointer
#include <wdf.h>

#include "Device.h"

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif

extern POBJECT_TYPE *PsProcessType; // provided by the kernel

// KMDF bootstrap
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
  NTSTATUS status;
  WDF_DRIVER_CONFIG config;

  WDF_DRIVER_CONFIG_INIT(&config, KernelDriver1EvtDeviceAdd);

  status = WdfDriverCreate(DriverObject,
                           RegistryPath,
                           WDF_NO_OBJECT_ATTRIBUTES,
                           &config,
                           WDF_NO_HANDLE);
  if (!NT_SUCCESS(status)) {
    KdPrint(("KernelDriver1: WdfDriverCreate failed 0x%X\n", status));
    return status;
  }

  DriverObject->DriverUnload = DriverUnload;
  KdPrint(("KernelDriver1: DriverEntry OK (no notify)\n"));
  return STATUS_SUCCESS;
}

NTSTATUS
KernelDriver1EvtDeviceAdd(_In_ WDFDRIVER Driver, _Inout_ PWDFDEVICE_INIT DeviceInit) {
  UNREFERENCED_PARAMETER(Driver);
  return KernelDriver1CreateDevice(DeviceInit); // implemented in Device.c
}

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);
  KdPrint(("KernelDriver1: DriverUnload\n"));
}

// Kernel-side terminate primitive (used by IOCTL handler in Queue.c)
NTSTATUS
KernelKillProcess(_In_ HANDLE TargetPid) {
  // trivial safety for obvious system PIDs
  if (TargetPid == (HANDLE)0 || TargetPid == (HANDLE)4) {
    return STATUS_ACCESS_DENIED;
  }

  PEPROCESS proc = NULL;
  NTSTATUS status = PsLookupProcessByProcessId(TargetPid, &proc);
  if (!NT_SUCCESS(status)) {
    KdPrint(("KernelDriver1: PsLookupProcessByProcessId(%u) -> 0x%X\n",
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
    KdPrint(("KernelDriver1: ObOpenObjectByPointer -> 0x%X\n", status));
    ObDereferenceObject(proc);
    return status;
  }

  status = ZwTerminateProcess(hProc, STATUS_SUCCESS);
  if (!NT_SUCCESS(status)) {
    KdPrint(("KernelDriver1: ZwTerminateProcess -> 0x%X\n", status));
  }

  ZwClose(hProc);
  ObDereferenceObject(proc);
  return status;
}
