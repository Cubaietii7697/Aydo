#include "FileProtection.hpp"
#include "../IOCTLs.hpp"
#include "Constants.hpp"
#include "Logger.hpp"
#include "Utils.hpp"

namespace FileProtection {

// Global filter data
FILTER_DATA g_filterData = {0};

//
// FLT_REGISTRATION Structure
//
const FLT_OPERATION_REGISTRATION Callbacks[] = {
    {IRP_MJ_CREATE,
     FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO | FLTFL_OPERATION_REGISTRATION_SKIP_CACHED_IO,
     preCreateCallback,
     postCreateCallback},
    {IRP_MJ_WRITE,
     FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO | FLTFL_OPERATION_REGISTRATION_SKIP_CACHED_IO,
     preWriteCallback,
     nullptr},
    {IRP_MJ_CLEANUP,
     0,
     preCleanupCallback,
     nullptr},
    {IRP_MJ_SET_INFORMATION,
     FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
     preSetInformationCallback,
     nullptr},
    {IRP_MJ_OPERATION_END}};

const FLT_CONTEXT_REGISTRATION ContextNotifications[] = {
    {FLT_FILE_CONTEXT,
     0,
     contextCleanup,
     sizeof(FileContext),
     Constants::AYDO_POOL_TAG_CONTEXT,
     nullptr,
     nullptr,
     nullptr},
    {FLT_CONTEXT_END}};

const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION), //  Size
    FLT_REGISTRATION_VERSION, //  Version
    0,                        //  Flags
    ContextNotifications,     //  Context
    Callbacks,                //  Operation callbacks
    unload,                   //  MiniFilterUnload
    instanceSetup,            //  InstanceSetup
    instanceQueryTeardown,    //  InstanceQueryTeardown
    nullptr,                  //  InstanceTeardownStart
    nullptr,                  //  InstanceTeardownComplete
    nullptr,                  //  GenerateFileName
    nullptr,                  //  NormalizeNameComponent
    nullptr,                  //  NormalizeContextCleanup
    nullptr,                  //  TransactionNotification
    nullptr                   //  NormalizeNameComponentEx
};

NTSTATUS initialize(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath) {
  UNREFERENCED_PARAMETER(registryPath);
  NTSTATUS status;
  OBJECT_ATTRIBUTES oa;
  UNICODE_STRING portName;
  PSECURITY_DESCRIPTOR sd = nullptr;

  LOG_INFO("Initializing FileProtection (AV + Self-Protection)");

  // Initialize global data
  RtlZeroMemory(&g_filterData, sizeof(g_filterData));
  KeInitializeSpinLock(&g_filterData.Lock);
  KeInitializeSpinLock(&g_filterData.ContextListLock);
  InitializeListHead(&g_filterData.ContextList);
  KeInitializeEvent(&g_filterData.ShutdownEvent, NotificationEvent, FALSE);

  g_filterData.MaxScanSize = 50 * 1024 * 1024; // Default 50MB
  InterlockedExchange(&g_filterData.DriverState, DriverStateStarting);

  // Register filter
  status = FltRegisterFilter(driverObject, &FilterRegistration, &g_filterData.FilterHandle);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR("Failed to register filter: 0x%x", status);
    return status;
  }

  // Create security descriptor for port
  status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR("Failed to build security descriptor: 0x%x", status);
    goto Cleanup;
  }

  // Create communication port
  RtlInitUnicodeString(&portName, Constants::AYDO_PORT_NAME);
  InitializeObjectAttributes(&oa, &portName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, sd);

  status = FltCreateCommunicationPort(
      g_filterData.FilterHandle,
      &g_filterData.ServerPort,
      &oa,
      nullptr,                        // ServerPortCookie
      portConnect,                    // ConnectNotifyCallback
      portDisconnect,                 // DisconnectNotifyCallback
      portMessage,                    // MessageNotifyCallback
      Constants::AYDO_MAX_QUEUE_DEPTH // MaxConnections
  );

  FltFreeSecurityDescriptor(sd);

  if (!NT_SUCCESS(status)) {
    LOG_ERROR("Failed to create communication port: 0x%x", status);
    goto Cleanup;
  }

  // Connect to core driver (for self-protection PID)
  status = connectToCoreDriver();
  if (!NT_SUCCESS(status)) {
    LOG_WARNING("Failed to connect to core driver: 0x%x", status);
  }

  // Start filtering
  status = FltStartFiltering(g_filterData.FilterHandle);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR("Failed to start filtering: 0x%x", status);
    goto Cleanup;
  }

  // Register process notifications
  status = registerProcessCallbacks();
  if (!NT_SUCCESS(status)) {
    LOG_WARNING("Failed to register process notifications: 0x%x", status);
    // Not fatal, but process protection won't work
  }

  InterlockedExchange(&g_filterData.DriverState, DriverStateRunning);
  LOG_INFO("FileProtection initialized successfully");
  return STATUS_SUCCESS;

Cleanup:
  cleanup();
  return status;
}

NTSTATUS unload(FLT_FILTER_UNLOAD_FLAGS flags) {
  UNREFERENCED_PARAMETER(flags);

  LOG_INFO("Unloading FileProtection");
  InterlockedExchange(&g_filterData.DriverState, DriverStateStopping);

  cleanup();

  InterlockedExchange(&g_filterData.DriverState, DriverStateStopped);
  return STATUS_SUCCESS;
}

void cleanup() {
  // Close communication port
  if (g_filterData.ServerPort != nullptr) {
    FltCloseCommunicationPort(g_filterData.ServerPort);
    g_filterData.ServerPort = nullptr;
  }

  // Unregister process notifications
  unregisterProcessCallbacks();

  // Signal shutdown and wait (simplified)
  KeSetEvent(&g_filterData.ShutdownEvent, 0, FALSE);

  if (g_filterData.CoreDriverHandle != nullptr) {
    ZwClose(g_filterData.CoreDriverHandle);
    g_filterData.CoreDriverHandle = nullptr;
  }

  if (g_filterData.FilterHandle != nullptr) {
    FltUnregisterFilter(g_filterData.FilterHandle);
    g_filterData.FilterHandle = nullptr;
  }

  LOG_INFO("Cleanup complete");
}

FLT_PREOP_CALLBACK_STATUS preCreateCallback(
    PFLT_CALLBACK_DATA data,
    PCFLT_RELATED_OBJECTS fltObjects,
    PVOID *completionContext) {

  NTSTATUS status = STATUS_SUCCESS;
  FLT_PREOP_CALLBACK_STATUS returnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
  PFLT_FILE_NAME_INFORMATION nameInfo = nullptr;
  PFileContext context = nullptr;
  HANDLE processId = nullptr;
  BOOLEAN executable = FALSE;
  BOOLEAN isExecute = FALSE;

  *completionContext = nullptr;

  // Check if driver is running
  if (g_filterData.DriverState != DriverStateRunning) {
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

  // Skip paging I/O and system process
  if (FlagOn(data->Iopb->IrpFlags, IRP_PAGING_IO)) {
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

  processId = (HANDLE)(ULONG_PTR)FltGetRequestorProcessId(data);
  if (processId == (HANDLE)4) { // System process
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

  // Get file name information
  status = FltGetFileNameInformation(
      data,
      FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
      &nameInfo);

  if (!NT_SUCCESS(status)) {
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

  status = FltParseFileNameInformation(nameInfo);
  if (!NT_SUCCESS(status)) {
    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

  // --- SELF-PROTECTION LOGIC ---
  if (isProtectedPath(&nameInfo->Name)) {
    ACCESS_MASK desiredAccess = data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    ULONG disposition = (data->Iopb->Parameters.Create.Options >> 24) & 0xFF;

    BOOLEAN isDangerous = FALSE;
    if (desiredAccess & DELETE) {
      isDangerous = TRUE;
    }
    if (desiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA)) {
      isDangerous = TRUE;
    }
    if (disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF || disposition == FILE_SUPERSEDE) {
      isDangerous = TRUE;
    }

    if (isDangerous && !isProtectedProcess()) {
      LOG_INFO("FileProtection: Blocked unauthorized access to %wZ from PID %lu",
               &nameInfo->Name, (ULONG)(ULONG_PTR)PsGetCurrentProcessId());

      FltReleaseFileNameInformation(nameInfo);
      data->IoStatus.Status = STATUS_ACCESS_DENIED;
      data->IoStatus.Information = 0;
      return FLT_PREOP_COMPLETE;
    }
  }

  // --- AV SCAN LOGIC ---

  // Check if executable
  executable = isExecutable(&nameInfo->Extension);

  // Get or create file context
  status = FltGetFileContext(fltObjects->Instance, fltObjects->FileObject, (PFLT_CONTEXT *)&context);

  if (status == STATUS_NOT_FOUND) {
    context = createFileContext();
    if (!context) {
      returnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
      goto Cleanup;
    }

    // Initialize context BEFORE setting it to prevent race condition
    ExAcquirePushLockExclusive(&context->ContextLock);
    context->Magic = Constants::AYDO_CONTEXT_MAGIC;
    context->FileId = (ULONG64)fltObjects->FileObject->FsContext;
    context->IsExecutable = executable;

    USHORT bytesToCopy = (USHORT)min((ULONG)nameInfo->Name.Length, (ULONG)sizeof(context->FileName) - (ULONG)sizeof(WCHAR));
    RtlCopyMemory(context->FileName, nameInfo->Name.Buffer, bytesToCopy);
    context->FileNameLength = bytesToCopy / (USHORT)sizeof(WCHAR);
    context->FileName[context->FileNameLength] = L'\0';
    ExReleasePushLockExclusive(&context->ContextLock);

    status = FltSetFileContext(fltObjects->Instance, fltObjects->FileObject,
                               FLT_SET_CONTEXT_KEEP_IF_EXISTS, context, NULL);

    if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
      // Another thread already set a context, use that one instead
      FltReleaseContext(context);
      status = FltGetFileContext(fltObjects->Instance, fltObjects->FileObject, (PFLT_CONTEXT *)&context);
      if (!NT_SUCCESS(status)) {
        goto Cleanup;
      }
    } else if (!NT_SUCCESS(status)) {
      // Failed to set context, release our reference
      FltReleaseContext(context);
      context = nullptr;
      goto Cleanup;
    } else {
      // Successfully set the context, add to tracking list
      KIRQL irql;
      KeAcquireSpinLock(&g_filterData.ContextListLock, &irql);
      InsertTailList(&g_filterData.ContextList, &context->ListEntry);
      g_filterData.ContextCount++;
      KeReleaseSpinLock(&g_filterData.ContextListLock, irql);
    }
  } else if (!NT_SUCCESS(status)) {
    goto Cleanup;
  }

  // Check cache
  ExAcquirePushLockShared(&context->ContextLock);
  if (context->CacheExpiry.QuadPart != 0) {
    LARGE_INTEGER now;
    KeQuerySystemTime(&now);
    if (now.QuadPart < context->CacheExpiry.QuadPart) {
      ExReleasePushLockShared(&context->ContextLock);
      InterlockedIncrement64((volatile LONG64 *)&g_filterData.CacheHits);
      returnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
      goto Cleanup;
    }
  }
  ExReleasePushLockShared(&context->ContextLock);

  // Determine if scan needed
  isExecute = BooleanFlagOn(data->Iopb->Parameters.Create.SecurityContext->DesiredAccess, FILE_EXECUTE);

  if (isExecute) {
    // Check file size limit
    FILE_STANDARD_INFORMATION stdInfo;
    status = FltQueryInformationFile(fltObjects->Instance, fltObjects->FileObject, &stdInfo, sizeof(stdInfo), FileStandardInformation, nullptr);
    if (NT_SUCCESS(status) && stdInfo.EndOfFile.QuadPart > (LONGLONG)g_filterData.MaxScanSize) {
      LOG_INFO("Skipping scan for %ws: file too large (%lld bytes)", context->FileName, stdInfo.EndOfFile.QuadPart);
      returnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
      goto Cleanup;
    }

    InterlockedIncrement64((volatile LONG64 *)&g_filterData.TotalFilesScanned);

    ScanRequest request;
    RtlZeroMemory(&request, sizeof(request));
    request.ProcessId = processId;
    request.DesiredAccess = data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    request.IsExecute = TRUE;
    request.Reason = ScanReasonExecute;

    RtlCopyMemory(request.FileName, context->FileName,
                  min((ULONG)context->FileNameLength * (ULONG)sizeof(WCHAR), (ULONG)sizeof(request.FileName)));
    request.FileNameLength = context->FileNameLength;

    ScanResponse response;
    RtlZeroMemory(&response, sizeof(response));
    NTSTATUS scanStatus = sendSyncScanRequest(&request, sizeof(request), &response, sizeof(response));

    if (NT_SUCCESS(scanStatus) && response.Verdict == 1) { // Malicious
      LOG_WARNING("Blocked malicious file: %ws", context->FileName);
      data->IoStatus.Status = STATUS_VIRUS_INFECTED;
      data->IoStatus.Information = 0;
      InterlockedIncrement64((volatile LONG64 *)&g_filterData.ThreatsBlocked);
      returnStatus = FLT_PREOP_COMPLETE;
    } else {
      // Allow the file if scan succeeded with clean verdict OR if scan failed (e.g., no client connected)
      returnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
  } else {
    returnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

Cleanup:
  if (nameInfo) {
    FltReleaseFileNameInformation(nameInfo);
  }
  if (context) {
    // FltReleaseContext is sufficient - don't call dereferenceContext to avoid double-free
    FltReleaseContext(context);
  }
  return returnStatus;
}

FLT_POSTOP_CALLBACK_STATUS postCreateCallback(
    PFLT_CALLBACK_DATA data,
    PCFLT_RELATED_OBJECTS fltObjects,
    PVOID completionContext,
    FLT_POST_OPERATION_FLAGS flags) {
  UNREFERENCED_PARAMETER(data);
  UNREFERENCED_PARAMETER(fltObjects);
  UNREFERENCED_PARAMETER(completionContext);
  UNREFERENCED_PARAMETER(flags);
  return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS preSetInformationCallback(
    PFLT_CALLBACK_DATA data,
    PCFLT_RELATED_OBJECTS fltObjects,
    PVOID *completionContext) {

  UNREFERENCED_PARAMETER(fltObjects);
  UNREFERENCED_PARAMETER(completionContext);

  NTSTATUS status;
  PFLT_FILE_NAME_INFORMATION nameInfo = nullptr;
  FILE_INFORMATION_CLASS infoClass = data->Iopb->Parameters.SetFileInformation.FileInformationClass;

  if (infoClass != FileDispositionInformation &&
      infoClass != FileDispositionInformationEx &&
      infoClass != FileRenameInformation &&
      infoClass != FileRenameInformationEx &&
      infoClass != FileLinkInformation) {
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

  status = FltGetFileNameInformation(data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
  if (!NT_SUCCESS(status)) {
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

  status = FltParseFileNameInformation(nameInfo);
  if (!NT_SUCCESS(status)) {
    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

  if (isProtectedPath(&nameInfo->Name)) {
    if (!isProtectedProcess()) {
      LOG_INFO("FileProtection: Blocked SetFileInformation (class %d) on %wZ from PID %lu",
               infoClass, &nameInfo->Name, (ULONG)(ULONG_PTR)PsGetCurrentProcessId());

      FltReleaseFileNameInformation(nameInfo);
      data->IoStatus.Status = STATUS_ACCESS_DENIED;
      data->IoStatus.Information = 0;
      return FLT_PREOP_COMPLETE;
    }
  }

  // AV Scan on Rename/Move
  if (infoClass == FileRenameInformation || infoClass == FileRenameInformationEx) {
    PFileContext context = nullptr;
    status = FltGetFileContext(fltObjects->Instance, fltObjects->FileObject, (PFLT_CONTEXT *)&context);
    if (NT_SUCCESS(status)) {
      // Check file size limit
      FILE_STANDARD_INFORMATION stdInfo;
      status = FltQueryInformationFile(fltObjects->Instance, fltObjects->FileObject, &stdInfo, sizeof(stdInfo), FileStandardInformation, nullptr);
      if (NT_SUCCESS(status) && stdInfo.EndOfFile.QuadPart > (LONGLONG)g_filterData.MaxScanSize) {
        LOG_INFO("Skipping rename scan for %ws: file too large", context->FileName);
        FltReleaseContext(context);
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
      }

      ScanRequest request;
      RtlZeroMemory(&request, sizeof(request));
      request.ProcessId = (HANDLE)(ULONG_PTR)FltGetRequestorProcessId(data);
      request.Reason = ScanReasonRename;
      request.IsExecute = context->IsExecutable;

      RtlCopyMemory(request.FileName, context->FileName,
                    min((ULONG)context->FileNameLength * (ULONG)sizeof(WCHAR), (ULONG)sizeof(request.FileName)));
      request.FileNameLength = context->FileNameLength;

      ScanResponse response;
      RtlZeroMemory(&response, sizeof(response));
      NTSTATUS scanStatus = sendSyncScanRequest(&request, sizeof(request), &response, sizeof(response));

      if (NT_SUCCESS(scanStatus) && response.Verdict == 1) {
        LOG_WARNING("Blocked move/rename of malicious file: %ws", context->FileName);
        FltReleaseContext(context);
        FltReleaseFileNameInformation(nameInfo);
        data->IoStatus.Status = STATUS_VIRUS_INFECTED;
        data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
      }
      FltReleaseContext(context);
    }
  }

  FltReleaseFileNameInformation(nameInfo);
  return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS preWriteCallback(
    PFLT_CALLBACK_DATA data,
    PCFLT_RELATED_OBJECTS fltObjects,
    PVOID *completionContext) {

  UNREFERENCED_PARAMETER(completionContext);

  NTSTATUS status;
  PFLT_FILE_NAME_INFORMATION nameInfo = nullptr;
  PFileContext context = nullptr;

  status = FltGetFileContext(fltObjects->Instance, fltObjects->FileObject, (PFLT_CONTEXT *)&context);
  if (NT_SUCCESS(status)) {
    ExAcquirePushLockExclusive(&context->ContextLock);
    context->IsModified = TRUE;
    ExReleasePushLockExclusive(&context->ContextLock);
    // FltReleaseContext is sufficient - don't call dereferenceContext
    FltReleaseContext(context);
  }

  status = FltGetFileNameInformation(data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
  if (!NT_SUCCESS(status)) {
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

  status = FltParseFileNameInformation(nameInfo);
  if (!NT_SUCCESS(status)) {
    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

  if (isProtectedPath(&nameInfo->Name)) {
    if (!isProtectedProcess()) {
      LOG_INFO("FileProtection: Blocked write to %wZ from PID %lu",
               &nameInfo->Name, (ULONG)(ULONG_PTR)PsGetCurrentProcessId());

      FltReleaseFileNameInformation(nameInfo);
      data->IoStatus.Status = STATUS_ACCESS_DENIED;
      data->IoStatus.Information = 0;
      return FLT_PREOP_COMPLETE;
    }
  }

  FltReleaseFileNameInformation(nameInfo);
  return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS preCleanupCallback(
    PFLT_CALLBACK_DATA data,
    PCFLT_RELATED_OBJECTS fltObjects,
    PVOID *completionContext) {
  UNREFERENCED_PARAMETER(data);
  UNREFERENCED_PARAMETER(completionContext);

  PFileContext context = nullptr;
  NTSTATUS status = FltGetFileContext(fltObjects->Instance, fltObjects->FileObject, (PFLT_CONTEXT *)&context);
  if (NT_SUCCESS(status)) {
    BOOLEAN shouldScan = FALSE;

    ExAcquirePushLockExclusive(&context->ContextLock);
    if (context->IsModified) {
      shouldScan = TRUE;
      context->IsModified = FALSE; // Reset for next time if handle reused (though cleanup usually means last)
    }
    ExReleasePushLockExclusive(&context->ContextLock);

    if (shouldScan) {
      // Check file size limit
      FILE_STANDARD_INFORMATION stdInfo;
      status = FltQueryInformationFile(fltObjects->Instance, fltObjects->FileObject, &stdInfo, sizeof(stdInfo), FileStandardInformation, nullptr);
      if (NT_SUCCESS(status) && stdInfo.EndOfFile.QuadPart > (LONGLONG)g_filterData.MaxScanSize) {
        LOG_INFO("Skipping post-write scan for %ws: file too large", context->FileName);
        FltReleaseContext(context);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
      }

      ScanRequest request;
      RtlZeroMemory(&request, sizeof(request));
      request.ProcessId = (HANDLE)(ULONG_PTR)FltGetRequestorProcessId(data);
      request.Reason = ScanReasonWriteComplete;
      request.IsExecute = context->IsExecutable;

      // Get latest name in case it was renamed
      PFLT_FILE_NAME_INFORMATION nameInfo = nullptr;
      status = FltGetFileNameInformation(data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
      if (NT_SUCCESS(status)) {
        FltParseFileNameInformation(nameInfo);
        RtlCopyMemory(request.FileName, nameInfo->Name.Buffer,
                      min((ULONG)nameInfo->Name.Length, (ULONG)sizeof(request.FileName) - (ULONG)sizeof(WCHAR)));
        request.FileNameLength = (USHORT)(min((ULONG)nameInfo->Name.Length, (ULONG)sizeof(request.FileName) - (ULONG)sizeof(WCHAR)) / sizeof(WCHAR));
        FltReleaseFileNameInformation(nameInfo);
      } else {
        // Fallback to context name
        RtlCopyMemory(request.FileName, context->FileName,
                      min((ULONG)context->FileNameLength * (ULONG)sizeof(WCHAR), (ULONG)sizeof(request.FileName)));
        request.FileNameLength = context->FileNameLength;
      }

      ScanResponse response;
      RtlZeroMemory(&response, sizeof(response));
      // Note: We don't necessarily block cleanup if scan fails or is malicious,
      // as the data is already written. But we can log it.
      sendSyncScanRequest(&request, sizeof(request), &response, sizeof(response));

      if (response.Verdict == 1) {
        LOG_WARNING("Detected malicious file after write: %ws", context->FileName);
        // Possible action: Quarantine or Delete (handled by service)
      }
    }

    // FltReleaseContext is sufficient - don't call dereferenceContext
    FltReleaseContext(context);
  }
  return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

void contextCleanup(PFLT_CONTEXT context, FLT_CONTEXT_TYPE contextType) {
  if (contextType != FLT_FILE_CONTEXT) {
    return;
  }

  auto fileContext = (PFileContext)context;
  KIRQL irql;
  KeAcquireSpinLock(&g_filterData.ContextListLock, &irql);
  if (!IsListEmpty(&fileContext->ListEntry)) {
    RemoveEntryList(&fileContext->ListEntry);
    InitializeListHead(&fileContext->ListEntry);
    // Decrement count while holding the lock for consistency
    g_filterData.ContextCount--;
  }
  KeReleaseSpinLock(&g_filterData.ContextListLock, irql);
}

NTSTATUS instanceSetup(
    PCFLT_RELATED_OBJECTS fltObjects,
    FLT_INSTANCE_SETUP_FLAGS flags,
    DEVICE_TYPE volumeDeviceType,
    FLT_FILESYSTEM_TYPE volumeFilesystemType) {
  UNREFERENCED_PARAMETER(fltObjects);
  UNREFERENCED_PARAMETER(flags);
  if (volumeFilesystemType != FLT_FSTYPE_NTFS) {
    return STATUS_FLT_DO_NOT_ATTACH;
  }
  if (volumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM) {
    return STATUS_FLT_DO_NOT_ATTACH;
  }
  return STATUS_SUCCESS;
}

NTSTATUS instanceQueryTeardown(
    PCFLT_RELATED_OBJECTS fltObjects,
    FLT_INSTANCE_QUERY_TEARDOWN_FLAGS flags) {
  UNREFERENCED_PARAMETER(fltObjects);
  UNREFERENCED_PARAMETER(flags);
  return STATUS_SUCCESS;
}

NTSTATUS portConnect(
    PFLT_PORT clientPort,
    PVOID serverPortCookie,
    PVOID connectionContext,
    ULONG sizeOfContext,
    PVOID *connectionCookie) {
  UNREFERENCED_PARAMETER(serverPortCookie);
  UNREFERENCED_PARAMETER(connectionContext);
  UNREFERENCED_PARAMETER(sizeOfContext);
  UNREFERENCED_PARAMETER(connectionCookie);

  LOG_INFO("Client connected to Aydo port");

  // Update protected PID from the connecting process
  HANDLE currentPID = PsGetCurrentProcessId();
  KIRQL oldIrql;
  KeAcquireSpinLock(&g_filterData.Lock, &oldIrql);
  g_filterData.ProtectedPID = currentPID;
  KeReleaseSpinLock(&g_filterData.Lock, oldIrql);

  LOG_INFO("Protected PID updated via Aydo port connection: %lu",
           (ULONG)(ULONG_PTR)currentPID);

  InterlockedExchangePointer((volatile PVOID *)&g_filterData.ClientPort, clientPort);
  return STATUS_SUCCESS;
}

void portDisconnect(PVOID connectionCookie) {
  UNREFERENCED_PARAMETER(connectionCookie);
  LOG_INFO("Client disconnected from Aydo port");

  KIRQL oldIrql;
  KeAcquireSpinLock(&g_filterData.Lock, &oldIrql);
  g_filterData.ProtectedPID = nullptr;
  KeReleaseSpinLock(&g_filterData.Lock, oldIrql);

  InterlockedExchangePointer((volatile PVOID *)&g_filterData.ClientPort, NULL);
}

NTSTATUS portMessage(
    PVOID portCookie,
    PVOID inputBuffer,
    ULONG inputBufferLength,
    PVOID outputBuffer,
    ULONG outputBufferLength,
    PULONG returnOutputBufferLength) {
  UNREFERENCED_PARAMETER(portCookie);
  UNREFERENCED_PARAMETER(outputBuffer);
  UNREFERENCED_PARAMETER(outputBufferLength);

  if (inputBuffer != nullptr && inputBufferLength >= sizeof(Config)) {
    PConfig config = (PConfig)inputBuffer;
    g_filterData.MaxScanSize = config->MaxScanSize;
    LOG_INFO("Driver configuration updated. MaxScanSize: %llu bytes", g_filterData.MaxScanSize);
  }

  *returnOutputBufferLength = 0;
  return STATUS_SUCCESS;
}

PFileContext createFileContext() {
  auto context = (PFileContext)ExAllocatePoolZero(NonPagedPoolNx, sizeof(FileContext), Constants::AYDO_POOL_TAG_CONTEXT);
  if (context) {
    context->Magic = Constants::AYDO_CONTEXT_MAGIC;
    context->ReferenceCount = 1;
    ExInitializePushLock(&context->ContextLock);
    InitializeListHead(&context->ListEntry);
  }
  return context;
}

void referenceContext(PFileContext context) {
  if (context && context->Magic == Constants::AYDO_CONTEXT_MAGIC) {
    InterlockedIncrement(&context->ReferenceCount);
  }
}

void dereferenceContext(PFileContext context) {
  if (context && context->Magic == Constants::AYDO_CONTEXT_MAGIC) {
    if (InterlockedDecrement(&context->ReferenceCount) == 0) {
      // Memory is managed by Minifilter if set as context, but this is for our own tracking too
    }
  }
}

NTSTATUS sendSyncScanRequest(
    PScanRequest request,
    ULONG requestSize,
    PScanResponse response,
    ULONG responseSize) {
  auto clientPort = (PFLT_PORT)InterlockedCompareExchangePointer((volatile PVOID *)&g_filterData.ClientPort, NULL, NULL);
  if (!clientPort) {
    return STATUS_PORT_DISCONNECTED;
  }

  LARGE_INTEGER timeout;
  timeout.QuadPart = -10000LL * Constants::AYDO_SCAN_TIMEOUT;
  return FltSendMessage(g_filterData.FilterHandle, &clientPort, request, requestSize, response, &responseSize, &timeout);
}

NTSTATUS registerProcessCallbacks() {
  return PsSetCreateProcessNotifyRoutineEx(onProcessNotify, FALSE);
}

void unregisterProcessCallbacks() {
  PsSetCreateProcessNotifyRoutineEx(onProcessNotify, TRUE);
}

void onProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
  UNREFERENCED_PARAMETER(Process);
  UNREFERENCED_PARAMETER(ProcessId);

  // We only care about process creation
  if (CreateInfo == nullptr) {
    return;
  }

  // Skip our own service if we can identify it
  if (isProtectedProcess()) {
    return;
  }

  LOG_INFO("Process notification: PID %lu is starting image %wZ",
           HandleToULong(ProcessId), CreateInfo->ImageFileName);

  ScanRequest request;
  RtlZeroMemory(&request, sizeof(request));
  request.ProcessId = ProcessId;
  request.IsExecute = TRUE;
  request.Reason = ScanReasonProcessCreation;

  if (CreateInfo->ImageFileName != nullptr) {
    auto bytesToCopy = (USHORT)min((ULONG)CreateInfo->ImageFileName->Length, (ULONG)sizeof(request.FileName) - (ULONG)sizeof(WCHAR));
    RtlCopyMemory(request.FileName, CreateInfo->ImageFileName->Buffer, bytesToCopy);
    request.FileNameLength = bytesToCopy / (USHORT)sizeof(WCHAR);
    request.FileName[request.FileNameLength] = L'\0';

    // Check file size limit
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK iosb;
    HANDLE fileHandle;
    InitializeObjectAttributes(&objAttr, (PUNICODE_STRING)CreateInfo->ImageFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

    NTSTATUS status = ZwOpenFile(&fileHandle, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &objAttr, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT);
    if (NT_SUCCESS(status)) {
      FILE_STANDARD_INFORMATION stdInfo;
      status = ZwQueryInformationFile(fileHandle, &iosb, &stdInfo, sizeof(stdInfo), FileStandardInformation);
      ZwClose(fileHandle);

      if (NT_SUCCESS(status) && stdInfo.EndOfFile.QuadPart > (LONGLONG)g_filterData.MaxScanSize) {
        LOG_INFO("Skipping process scan for %wZ: file too large", CreateInfo->ImageFileName);
        return;
      }
    }
  }

  ScanResponse response;
  RtlZeroMemory(&response, sizeof(response));

  NTSTATUS scanStatus = sendSyncScanRequest(&request, sizeof(request), &response, sizeof(response));

  if (NT_SUCCESS(scanStatus)) {
    if (response.Verdict == 1) { // Malicious
      LOG_WARNING("Blocked malicious process: %wZ (PID %lu)",
                  CreateInfo->ImageFileName, HandleToULong(ProcessId));
      CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
    } else {
      LOG_INFO("Allowed clean process: %wZ (PID %lu)",
               CreateInfo->ImageFileName, HandleToULong(ProcessId));
    }
  } else {
    LOG_INFO("Allowed process (scan skipped/failed): %wZ", CreateInfo->ImageFileName);
  }
}

} // namespace FileProtection
