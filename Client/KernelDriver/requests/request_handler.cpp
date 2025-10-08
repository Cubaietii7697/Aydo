#include "request_handler.hpp"

#include "../include/Public.hpp"
#include "../logging/logger.hpp"
#include "../pch.hpp"
#include "../utils/utils.hpp"

extern "C" {
NTSYSAPI NTSTATUS NTAPI PsLookupProcessByProcessId(HANDLE, PEPROCESS *);
NTSYSAPI NTSTATUS NTAPI ObOpenObjectByPointer(PVOID, ULONG, PACCESS_STATE,
                                              ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, PHANDLE);
extern POBJECT_TYPE *PsProcessType;
}

// PID 0 = Idle Process(none exist process),PID 4 = System Process
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

static BOOLEAN g_ProcessNotifyRegistered = FALSE;

NTSTATUS Requests_RegisterProcessNotify() {
  if (g_ProcessNotifyRegistered)
    return STATUS_SUCCESS;

  NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(OnProcessNotifyEx, FALSE);
  if (NT_SUCCESS(status)) {
    g_ProcessNotifyRegistered = TRUE;
    AYDO_DEBUG(DPFLTR_IHVDRIVER_ID + DPFLTR_INFO_LEVEL + "Process notify callback registered.");
  } else {
    AYDO_ERROR(DPFLTR_IHVDRIVER_ID + DPFLTR_ERROR_LEVEL + "Failed to register process notify callback (0x%X)", status);
  }

  return status;
}

NTSTATUS Requests_UnregisterProcessNotify() {
  if (!g_ProcessNotifyRegistered)
    return STATUS_SUCCESS;

  NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(OnProcessNotifyEx, TRUE);
  if (NT_SUCCESS(status)) {
    g_ProcessNotifyRegistered = FALSE;
    AYDO_DEBUG(DPFLTR_IHVDRIVER_ID + DPFLTR_INFO_LEVEL + "Process notify callback unregistered.");
  } else {
    AYDO_ERROR(DPFLTR_IHVDRIVER_ID + DPFLTR_ERROR_LEVEL + "Failed to unregister process notify callback (0x%X)", status);
  }

  return status;
}

WDFQUEUE g_NotifyQueue = nullptr;

VOID OnProcessNotifyEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
  UNREFERENCED_PARAMETER(Process);

  if (CreateInfo == NULL || g_NotifyQueue == nullptr)
    return;

  WDFREQUEST req;
  NTSTATUS st = WdfIoQueueRetrieveNextRequest(g_NotifyQueue, &req);
  if (!NT_SUCCESS(st))
    return;

  // Retrieve input buffer (target exe name)
  PWAIT_FOR_PROCESS_START_IN inBuf;
  size_t inSize;
  st = WdfRequestRetrieveInputBuffer(req, sizeof(WAIT_FOR_PROCESS_START_IN),
                                     reinterpret_cast<PVOID *>(&inBuf), &inSize);
  if (!NT_SUCCESS(st)) {
    WdfRequestComplete(req, st);
    return;
  }

  // Compare target exe name (case-insensitive)
  UNICODE_STRING targetName;
  UNICODE_STRING currentName;
  RtlInitUnicodeString(&targetName, inBuf->TargetImageName);
  currentName = *CreateInfo->ImageFileName;

  if (RtlEqualUnicodeString(&targetName, &currentName, TRUE)) {
    // Match! Fill output buffer
    size_t bufSize;
    PPROCESS_NOTIFY_INFO info;
    WdfRequestRetrieveOutputBuffer(req, sizeof(PROCESS_NOTIFY_INFO),
                                   reinterpret_cast<PVOID *>(&info), &bufSize);
    info->ProcessId = HandleToULong(ProcessId);
    RtlStringCchCopyNW(info->ImageFileName, ARRAYSIZE(info->ImageFileName),
                       CreateInfo->ImageFileName->Buffer,
                       CreateInfo->ImageFileName->Length / sizeof(WCHAR));
    WdfRequestCompleteWithInformation(req, STATUS_SUCCESS, sizeof(PROCESS_NOTIFY_INFO));
  } else {
    // Not the target process; put it back into the queue
    WdfRequestForwardToIoQueue(req, g_NotifyQueue);
  }
}
