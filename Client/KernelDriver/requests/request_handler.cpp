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

static void ExtractBasename(_In_ const UNICODE_STRING &full, _Out_ UNICODE_STRING &base) {
  USHORT i = full.Length / sizeof(WCHAR);
  while (i > 0 && full.Buffer[i - 1] != L'\\' && full.Buffer[i - 1] != L'/')
    --i;
  base.Buffer = full.Buffer + i;
  base.Length = full.Length - (i * sizeof(WCHAR));
  base.MaximumLength = base.Length;
}

WDFQUEUE g_NotifyQueue = nullptr;

VOID EvtRequestCancelWait(_In_ WDFREQUEST Request) {

  WDFREQUEST prev = nullptr;

  for (;;) {
    WDFREQUEST found = nullptr;
    NTSTATUS st = WdfIoQueueFindRequest(
        g_NotifyQueue,
        prev,    // start-after (NULL)
        nullptr, // IoTarget
        nullptr, // RequestParameters
        &found);

    if (!NT_SUCCESS(st)) {
      if (prev)
        WdfObjectDereference(prev);
      WdfRequestComplete(Request, STATUS_CANCELLED);
      return;
    }

    if (found == Request) {
      if (prev)
        WdfObjectDereference(prev);

      WDFREQUEST dummy = nullptr;
      NTSTATUS rt = WdfIoQueueRetrieveFoundRequest(g_NotifyQueue, found, &dummy);
      UNREFERENCED_PARAMETER(rt);
      WdfRequestComplete(Request, STATUS_CANCELLED);
      return;
    }

    if (prev)
      WdfObjectDereference(prev);
    prev = found;
  }
}

VOID OnProcessNotifyEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
  UNREFERENCED_PARAMETER(Process);
  if (CreateInfo == NULL || g_NotifyQueue == nullptr || CreateInfo->ImageFileName == nullptr)
    return;

  UNICODE_STRING base{};
  ExtractBasename(*CreateInfo->ImageFileName, base);

  WDFREQUEST matched = nullptr;
  WDFREQUEST park[32];
  ULONG parkCount = 0;

  for (;;) {
    WDFREQUEST req = nullptr;
    NTSTATUS st = WdfIoQueueRetrieveNextRequest(g_NotifyQueue, &req);
    if (!NT_SUCCESS(st))
      break;

    PWAIT_FOR_PROCESS_START_IN inBuf = nullptr;
    st = WdfRequestRetrieveInputBuffer(req, sizeof(WAIT_FOR_PROCESS_START_IN),
                                       reinterpret_cast<PVOID *>(&inBuf), nullptr);
    if (!NT_SUCCESS(st)) {
      WdfRequestComplete(req, st);
      continue;
    }

    UNICODE_STRING target{};
    RtlInitUnicodeString(&target, inBuf->TargetImageName);
    const BOOLEAN wildcard = (target.Length == 0) || (target.Length == sizeof(WCHAR) && target.Buffer && target.Buffer[0] == L'*');

    if (wildcard || RtlEqualUnicodeString(&target, &base, TRUE)) {
      matched = req;
      break;
    }

    if (parkCount < RTL_NUMBER_OF(park)) {
      park[parkCount++] = req;
    } else {
      (void)WdfRequestForwardToIoQueue(req, g_NotifyQueue);
    }
  }

  for (ULONG i = 0; i < parkCount; ++i) {
    (void)WdfRequestForwardToIoQueue(park[i], g_NotifyQueue);
  }

  if (!matched)
    return;

  (void)WdfRequestUnmarkCancelable(matched);

  PPROCESS_NOTIFY_INFO out = nullptr;
  NTSTATUS st = WdfRequestRetrieveOutputBuffer(matched, sizeof(PROCESS_NOTIFY_INFO),
                                               reinterpret_cast<PVOID *>(&out), nullptr);
  if (!NT_SUCCESS(st) || out == nullptr) {
    WdfRequestComplete(matched, NT_SUCCESS(st) ? STATUS_INVALID_PARAMETER : st);
    return;
  }

  out->ProcessId = HandleToULong(ProcessId);

  size_t copyChars = min(static_cast<size_t>(AYDO_MAX_PATH - 1), static_cast<size_t>(base.Length / sizeof(WCHAR)));
  if (copyChars) {
    RtlStringCchCopyNW(out->ImageFileName, AYDO_MAX_PATH, base.Buffer, copyChars);
    out->ImageFileName[copyChars] = L'\0';
  } else {
    out->ImageFileName[0] = L'\0';
  }

  WdfRequestCompleteWithInformation(matched, STATUS_SUCCESS, sizeof(PROCESS_NOTIFY_INFO));
}
