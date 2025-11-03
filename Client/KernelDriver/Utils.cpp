#include "Utils.hpp"

#include "Hooks.hpp"
#include "Logger.hpp"
#include "Types.hpp"

static LIST_ENTRY g_ProcessNotificationQueue;
static KSPIN_LOCK g_QueueLock;
static BOOLEAN g_IsInitialized = FALSE;

// Kills a process by its PID
//  ** Does not perform any checks for whether the process shouldn't be killed **
NTSTATUS Utils::killProcessByPID(ULONG pid) {
  LOG_INFO("Killing process by PID: %lu", pid);

  // Find the process
  PEPROCESS process;
  if (!NT_SUCCESS(PsLookupProcessByProcessId(ULongToHandle(pid), &process))) {
    LOG_ERROR("Failed to find process by PID: %lu", pid);

    return STATUS_INVALID_PARAMETER;
  }

  // Open the process
  HANDLE hProcess;
  if (!NT_SUCCESS(ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, nullptr, PROCESS_TERMINATE, *PsProcessType, KernelMode, &hProcess))) {
    LOG_ERROR("Failed to open process by PID: %lu", pid);
    ObDereferenceObject(process);

    return STATUS_UNSUCCESSFUL;
  }

  // Terminate the process
  NTSTATUS terminateStatus = ZwTerminateProcess(hProcess, STATUS_SUCCESS);
  if (!NT_SUCCESS(terminateStatus)) {
    LOG_ERROR("Failed to terminate process by PID: %lu, status: 0x%X", pid, terminateStatus);
  } else {
    LOG_INFO("Process by PID: %lu terminated successfully", pid);
  }

  // Close the process
  ZwClose(hProcess);
  ObDereferenceObject(process);

  return terminateStatus;
}

// Checks if a process is killable by its PID (it's not in the protected list and is not critical)
bool Utils::isProcessKillable(ULONG pid) {
  LOG_INFO("Checking if process by PID: %lu is killable", pid);

  // Check if the process is in the protected list (includes critical system processes)
  for (size_t i = 0; i < sizeof(PROTECTED_PROCESSES) / sizeof(PROTECTED_PROCESSES[0]); i++) {
    if (PROTECTED_PROCESSES[i] == pid) {
      LOG_WARNING("Process by PID: %lu is in the protected list and cannot be killed", pid);

      return false;
    }
  }

  // Find the process
  PEPROCESS process;
  if (!NT_SUCCESS(PsLookupProcessByProcessId(ULongToHandle(pid), &process))) {
    LOG_ERROR("Failed to find process by PID: %lu", pid);

    return false;
  }

  // Open the process
  HANDLE hProcess;
  if (!NT_SUCCESS(ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, nullptr, PROCESS_QUERY_INFORMATION, *PsProcessType, KernelMode, &hProcess))) {
    LOG_ERROR("Failed to open process by PID: %lu for query", pid);
    ObDereferenceObject(process);

    return false;
  }

  // Check if the process is critical
  ULONG isCritical = 0;
  ULONG returnLength = 0;
  NTSTATUS status = ZwQueryInformationProcess(hProcess, ProcessBreakOnTermination, &isCritical, sizeof(isCritical), &returnLength);

  ZwClose(hProcess);
  ObDereferenceObject(process);

  if (!NT_SUCCESS(status)) {
    LOG_WARNING("Failed to query critical status for process by PID: %lu, status: 0x%X", pid, status);

    return true; // If we can't query, assume it's killable
  }

  return isCritical == 0;
}

NTSTATUS Utils::initializeProcessNotifications() {
  if (g_IsInitialized) {
    return STATUS_SUCCESS;
  }

  InitializeListHead(&g_ProcessNotificationQueue);
  KeInitializeSpinLock(&g_QueueLock);

  // Register the process notification callback
  NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(Hooks::onProcessStart, FALSE);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR("Failed to register process notify routine, status: 0x%X", status);

    return status;
  }

  g_IsInitialized = TRUE;
  LOG_INFO("Process notifications initialized successfully");

  return STATUS_SUCCESS;
}

VOID Utils::cleanupProcessNotifications() {
  if (!g_IsInitialized) {
    return;
  }

  // Unregister the callback
  NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(Hooks::onProcessStart, TRUE);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR("Failed to unregister process notify routine, status: 0x%X", status);
  }

  // Clean up the queue
  KIRQL oldIrql;
  KeAcquireSpinLock(&g_QueueLock, &oldIrql);

  while (!IsListEmpty(&g_ProcessNotificationQueue)) {
    PLIST_ENTRY entry = RemoveHeadList(&g_ProcessNotificationQueue);
    PPROCESS_NOTIFICATION notification = CONTAINING_RECORD(entry, PROCESS_NOTIFICATION, ListEntry);
    ExFreePoolWithTag(notification, 'nPrP');
  }

  KeReleaseSpinLock(&g_QueueLock, oldIrql);

  g_IsInitialized = FALSE;
  LOG_INFO("Process notifications cleaned up successfully");
}

PVOID Utils::dequeueProcessNotification() {
  if (!g_IsInitialized) {
    return nullptr;
  }

  KIRQL oldIrql;
  PPROCESS_NOTIFICATION notification = nullptr;

  KeAcquireSpinLock(&g_QueueLock, &oldIrql);

  if (!IsListEmpty(&g_ProcessNotificationQueue)) {
    PLIST_ENTRY entry = RemoveHeadList(&g_ProcessNotificationQueue);
    notification = CONTAINING_RECORD(entry, PROCESS_NOTIFICATION, ListEntry);
  }

  KeReleaseSpinLock(&g_QueueLock, oldIrql);

  return notification;
}

VOID Utils::enqueueProcessNotification(PVOID notificationPtr) {
  if (!g_IsInitialized || notificationPtr == nullptr) {
    return;
  }

  PPROCESS_NOTIFICATION notification = (PPROCESS_NOTIFICATION)notificationPtr;

  KIRQL oldIrql;
  KeAcquireSpinLock(&g_QueueLock, &oldIrql);
  InsertTailList(&g_ProcessNotificationQueue, &notification->ListEntry);
  KeReleaseSpinLock(&g_QueueLock, oldIrql);
}
