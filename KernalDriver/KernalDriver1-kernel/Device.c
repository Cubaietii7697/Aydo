//
// Driver.c
// kernel driver: register process-create notify and optionally terminate matching procs.
// WARNING: TEST IN VM ONLY. READ COMMENTS.
//

#include <ntddk.h>
#include <ntifs.h> // for PsLookupProcessByProcessId, ObOpenObjectByPointer, etc.
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
VOID CreateProcessNotifyEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);

static NTSTATUS KernelKillProcess(_In_ HANDLE TargetPid);

// Blacklist: lower-case wide strings to match against ImageFileName->Buffer.
// Change as needed (e.g., L"notepad.exe", L"calc.exe"). Keep it short for testing.
static const UNICODE_STRING g_blacklist[] = {
    RTL_CONSTANT_STRING(L"notepad.exe"),
    RTL_CONSTANT_STRING(L"calc.exe")};
static const size_t g_blacklist_count = sizeof(g_blacklist) / sizeof(g_blacklist[0]);

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(RegistryPath);

  NTSTATUS status = STATUS_SUCCESS;

  DriverObject->DriverUnload = DriverUnload;

  // Register create-process notify (Remove = FALSE)
  status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, FALSE);
  if (!NT_SUCCESS(status)) {
    KdPrint(("DriverEntry: PsSetCreateProcessNotifyRoutineEx failed 0x%X\n", status));
    return status;
  }

  KdPrint(("DriverEntry: registered create-process notify. Driver loaded.\n"));
  return STATUS_SUCCESS;
}

VOID DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);

  // Remove the notify routine. This call will wait for in-flight callbacks to complete.
  NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, TRUE);
  if (!NT_SUCCESS(status)) {
    KdPrint(("DriverUnload: PsSetCreateProcessNotifyRoutineEx(REMOVE) failed 0x%X\n", status));
    // Still continue with unload — but this is suspicious.
  } else {
    KdPrint(("DriverUnload: removed create-process notify.\n"));
  }

  KdPrint(("DriverUnload: unloading driver.\n"));
}

//
// CreateProcessNotifyEx: called at process create and exit. CreateInfo != NULL on create.
// Runs at PASSIVE_LEVEL inside a critical region (APCs disabled).
//
VOID CreateProcessNotifyEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo) {
  UNREFERENCED_PARAMETER(Process);

  // Only interested in creation events
  if (CreateInfo == NULL) {
    return;
  }

  // CreateInfo->ImageFileName may be NULL in some cases
  if (CreateInfo->ImageFileName == NULL || CreateInfo->ImageFileName->Buffer == NULL) {
    return;
  }

  // We'll compare just the filename: the ImageFileName might be full path (L"C:\\Windows\\System32\\notepad.exe")
  // Find the last backslash in the string and take the tail.
  PWCHAR full = CreateInfo->ImageFileName->Buffer;
  SIZE_T len = CreateInfo->ImageFileName->Length / sizeof(WCHAR);

  // Find last slash
  PWCHAR nameStart = full;
  for (SIZE_T i = 0; i < len; ++i) {
    if (full[i] == L'\\' || full[i] == L'/')
      nameStart = full + i + 1;
  }

  // Build a temporary UNICODE_STRING pointing to filename tail
  UNICODE_STRING tail;
  tail.Buffer = nameStart;
  tail.Length = (USHORT)((full + len - nameStart) * sizeof(WCHAR));
  tail.MaximumLength = tail.Length;

  // Convert tail to lower-case in-place? We'll do case-insensitive comparison by RtlCompareUnicodeString with TRUE.
  for (size_t i = 0; i < g_blacklist_count; ++i) {
    // RtlCompareUnicodeString: case-insensitive when TRUE
    if (RtlCompareUnicodeString(&tail, (PUNICODE_STRING)&g_blacklist[i], TRUE) == 0) {
      // blacklist match — attempt to kill process
      HANDLE pidHandle = ProcessId;
      KdPrint(("CreateProcessNotifyEx: matched blacklist '%wZ' pid=%u -> trying to kill\n", &tail, (ULONG)(ULONG_PTR)pidHandle));

      NTSTATUS kst = KernelKillProcess(pidHandle);
      if (!NT_SUCCESS(kst)) {
        KdPrint(("KernelKillProcess failed 0x%X for pid %u\n", kst, (ULONG)(ULONG_PTR)pidHandle));
      } else {
        KdPrint(("KernelKillProcess succeeded for pid %u\n", (ULONG)(ULONG_PTR)pidHandle));
      }
      break; // one match enough
    }
  }
}

//
// KernelKillProcess: get a HANDLE for the PEPROCESS and call ZwTerminateProcess
// Uses PsLookupProcessByProcessId -> ObOpenObjectByPointer -> ZwTerminateProcess -> cleanup
//
NTSTATUS KernelKillProcess(_In_ HANDLE TargetPid) {
  PEPROCESS proc = NULL;
  NTSTATUS status = PsLookupProcessByProcessId(TargetPid, &proc);
  if (!NT_SUCCESS(status)) {
    KdPrint(("KernelKillProcess: PsLookupProcessByProcessId failed 0x%X pid=%u\n", status, (ULONG)(ULONG_PTR)TargetPid));
    return status;
  }

  // If the returned proc is system/process we should refuse as a safety net
  // TODO: smart check for system pid
  if (TargetPid == (HANDLE)0 || TargetPid == (HANDLE)4) {
    ObDereferenceObject(proc);
    return STATUS_ACCESS_DENIED;
  }

  // Get a handle from PEPROCESS
  HANDLE hProc = NULL;
  extern POBJECT_TYPE *PsProcessType; // provided by kernel
  status = ObOpenObjectByPointer(proc,
                                 OBJ_KERNEL_HANDLE,
                                 NULL,
                                 PROCESS_TERMINATE,
                                 *PsProcessType,
                                 KernelMode,
                                 &hProc);
  if (!NT_SUCCESS(status)) {
    KdPrint(("KernelKillProcess: ObOpenObjectByPointer failed 0x%X pid=%u\n", status, (ULONG)(ULONG_PTR)TargetPid));
    ObDereferenceObject(proc);
    return status;
  }

  // Terminate
  status = ZwTerminateProcess(hProc, STATUS_SUCCESS);
  if (!NT_SUCCESS(status)) {
    KdPrint(("KernelKillProcess: ZwTerminateProcess failed 0x%X pid=%u\n", status, (ULONG)(ULONG_PTR)TargetPid));
  }

  ZwClose(hProc);
  ObDereferenceObject(proc);
  return status;
}
