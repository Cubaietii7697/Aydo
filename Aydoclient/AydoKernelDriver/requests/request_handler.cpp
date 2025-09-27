#include "request_handler.hpp"

#include "../logging/logger.hpp"
#include "../pch.hpp"

extern "C" {
NTSYSAPI NTSTATUS NTAPI PsLookupProcessByProcessId(HANDLE, PEPROCESS *);
NTSYSAPI NTSTATUS NTAPI ObOpenObjectByPointer(PVOID, ULONG, PACCESS_STATE,
                                              ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, PHANDLE);
extern POBJECT_TYPE *PsProcessType;

typedef BOOLEAN(NTAPI *PFN_PsIsProcessCritical)(PEPROCESS, PBOOLEAN);
typedef struct _PS_PROTECTION {
  UCHAR Type : 3;
  UCHAR Audit : 1;
  UCHAR Signer : 4;
} PS_PROTECTION, *PPS_PROTECTION;
typedef PS_PROTECTION(NTAPI *PFN_PsGetProcessProtection)(PEPROCESS);
}

static PFN_PsIsProcessCritical g_PsIsProcessCritical = nullptr;
static PFN_PsGetProcessProtection g_PsGetProcessProtection = nullptr;
static const ULONG PIDS_TO_NOT_KILL[] = {0u, 4u};

NTSTATUS Requests_HandleKill(ULONG pid) {
  HANDLE hPid = (HANDLE)(ULONG_PTR)pid;
  for (SIZE_T i = 0; i < RTL_NUMBER_OF(PIDS_TO_NOT_KILL); ++i) {
    if ((ULONG_PTR)hPid == PIDS_TO_NOT_KILL[i]) {
      AYDO_WARNING("Refusing to terminate PID %u", pid);
      return STATUS_ACCESS_DENIED;
    }
  }

  PEPROCESS proc = nullptr;
  NTSTATUS st = PsLookupProcessByProcessId(hPid, &proc);
  if (!NT_SUCCESS(st)) {
    AYDO_ERROR("PsLookupProcessByProcessId(%u) -> 0x%X", pid, st);
    return st;
  }

  if (g_PsIsProcessCritical) {
    BOOLEAN isCritical = FALSE;
    if (g_PsIsProcessCritical(proc, &isCritical) && isCritical) {
      AYDO_WARNING("PID %u is CRITICAL, refusing", pid);
      ObDereferenceObject(proc);
      return STATUS_ACCESS_DENIED;
    }
  }

  if (g_PsGetProcessProtection) {
    PS_PROTECTION prot = g_PsGetProcessProtection(proc);
    if (prot.Type != 0 || prot.Signer != 0) {
      AYDO_WARNING("PID %u has protection flags (type=%u signer=%u), refusing",
                   pid, prot.Type, prot.Signer);
      ObDereferenceObject(proc);
      return STATUS_ACCESS_DENIED;
    }
  }

  HANDLE hProc = NULL;
  st = ObOpenObjectByPointer(proc, OBJ_KERNEL_HANDLE, NULL,
                             PROCESS_TERMINATE, *PsProcessType,
                             KernelMode, &hProc);
  if (!NT_SUCCESS(st)) {
    ObDereferenceObject(proc);
    return st;
  }

  st = ZwTerminateProcess(hProc, STATUS_SUCCESS);
  if (NT_SUCCESS(st))
    AYDO_INFO("Terminated PID %u", pid);
  else
    AYDO_ERROR("ZwTerminateProcess -> 0x%X", st);

  ZwClose(hProc);
  ObDereferenceObject(proc);
  return st;
}
