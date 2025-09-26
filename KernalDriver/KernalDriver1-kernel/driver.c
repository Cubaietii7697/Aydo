
#include "Driver.h"

#include <ntddk.h>

#include <wdf.h>

#include "AydoLogger.h"
#include "Device.h"

#define INITGUID
#include "Public.h"

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif

// ---- Forward declarations we actually need (avoid <ntifs.h>) ----
NTSYSAPI NTSTATUS NTAPI PsLookupProcessByProcessId(
    HANDLE ProcessId,
    PEPROCESS *Process);

NTSYSAPI NTSTATUS NTAPI ObOpenObjectByPointer(
    PVOID Object,
    ULONG HandleAttributes,
    PACCESS_STATE PassedAccessState,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    PHANDLE Handle);

extern POBJECT_TYPE *PsProcessType;

typedef BOOLEAN(NTAPI *PFN_PsIsProcessCritical)(
    PEPROCESS Process, PBOOLEAN Critical);

typedef struct _PS_PROTECTION {
  UCHAR Type : 3;
  UCHAR Audit : 1;
  UCHAR Signer : 4;
} PS_PROTECTION, *PPS_PROTECTION;

typedef PS_PROTECTION(NTAPI *PFN_PsGetProcessProtection)(
    PEPROCESS Process);

static PFN_PsIsProcessCritical g_PsIsProcessCritical = NULL;
static PFN_PsGetProcessProtection g_PsGetProcessProtection = NULL;

// Known never-kill PIDs
static const ULONG PIDS_TO_NOT_KILL[] = {
    0u, // Idle
    4u  // System
};

static VOID ResolveOptionalKernelExports(VOID) {
  UNICODE_STRING name;

  RtlInitUnicodeString(&name, L"PsIsProcessCritical");
  g_PsIsProcessCritical = (PFN_PsIsProcessCritical)MmGetSystemRoutineAddress(&name);

  RtlInitUnicodeString(&name, L"PsGetProcessProtection");
  g_PsGetProcessProtection = (PFN_PsGetProcessProtection)MmGetSystemRoutineAddress(&name);

  AYDO_INFO("Resolved PsIsProcessCritical=%p, PsGetProcessProtection=%p",
            g_PsIsProcessCritical, g_PsGetProcessProtection);
}

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
    AYDO_ERROR("WdfDriverCreate failed 0x%X", status);
    return status;
  }

  ResolveOptionalKernelExports();

  DriverObject->DriverUnload = DriverUnload;
  AYDO_INFO("DriverEntry OK");
  return STATUS_SUCCESS;
}

NTSTATUS
AydoKernelDriverEvtDeviceAdd(_In_ WDFDRIVER Driver, _Inout_ PWDFDEVICE_INIT DeviceInit) {
  UNREFERENCED_PARAMETER(Driver);
  return AydoKernelDriverCreateDevice(DeviceInit);
}

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);
  AYDO_INFO("DriverUnload");
}

NTSTATUS
KernelKillProcess(_In_ HANDLE TargetPid) {
  // Reject obvious system PIDs
  for (SIZE_T i = 0; i < RTL_NUMBER_OF(PIDS_TO_NOT_KILL); ++i) {
    if ((ULONG_PTR)TargetPid == PIDS_TO_NOT_KILL[i]) {
      AYDO_WARNING("Refusing to terminate PID %u (protected list)",
                   (ULONG)(ULONG_PTR)TargetPid);
      return STATUS_ACCESS_DENIED;
    }
  }

  PEPROCESS proc = NULL;
  NTSTATUS status = PsLookupProcessByProcessId(TargetPid, &proc);
  if (!NT_SUCCESS(status)) {
    AYDO_ERROR("PsLookupProcessByProcessId(%u) -> 0x%X",
               (ULONG)(ULONG_PTR)TargetPid, status);
    return status;
  }

  // Extra guard: critical process
  if (g_PsIsProcessCritical) {
    BOOLEAN isCritical = FALSE;
    if (g_PsIsProcessCritical(proc, &isCritical) && isCritical) {
      AYDO_WARNING("PID %u is marked CRITICAL, refusing",
                   (ULONG)(ULONG_PTR)TargetPid);
      ObDereferenceObject(proc);
      return STATUS_ACCESS_DENIED;
    }
  }

  // Extra guard: protected process / PPL
  if (g_PsGetProcessProtection) {
    PS_PROTECTION prot = g_PsGetProcessProtection(proc);
    // Nonzero Type/Signer generally indicates protection
    if (prot.Type != 0 || prot.Signer != 0) {
      AYDO_WARNING("PID %u has protection flags (type=%u signer=%u), refusing",
                   (ULONG)(ULONG_PTR)TargetPid, prot.Type, prot.Signer);
      ObDereferenceObject(proc);
      return STATUS_ACCESS_DENIED;
    }
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
    AYDO_ERROR("ObOpenObjectByPointer -> 0x%X", status);
    ObDereferenceObject(proc);
    return status;
  }

  status = ZwTerminateProcess(hProc, STATUS_SUCCESS);
  if (!NT_SUCCESS(status)) {
    AYDO_ERROR("ZwTerminateProcess -> 0x%X", status);
  } else {
    AYDO_INFO("Terminated PID %u", (ULONG)(ULONG_PTR)TargetPid);
  }

  ZwClose(hProc);
  ObDereferenceObject(proc);
  return status;
}
