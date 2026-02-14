#include <fltKernel.h>

#include "Logger.hpp"

#include "Minifilter.hpp"
#include "utils.hpp"

extern "C" NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath) {
  return Minifilter::DriverEntryImpl(DriverObject, RegistryPath);
}

namespace Minifilter {

GLOBAL_STATE gState;

// --- Operation registration array ---
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    {IRP_MJ_CREATE,
     0,
     PreCreateCallback,
     nullptr},

    {IRP_MJ_WRITE,
     0,
     PreWriteCallback,
     nullptr},

    {IRP_MJ_SET_INFORMATION,
     0,
     PreSetInfoCallback,
     nullptr},

    {IRP_MJ_OPERATION_END}};

// Minimal registration
CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION), // Size
    FLT_REGISTRATION_VERSION, // Version
    0,                        // Flags
    nullptr,                  // ContextRegistration
    Callbacks,                // OperationRegistration
    MinimalUnload,            // FilterUnload
    InstanceSetup,            // InstanceSetup
    nullptr,                  // InstanceQueryTeardown
    nullptr,                  // InstanceTeardownStart
    nullptr,                  // InstanceTeardownComplete
    nullptr,                  // GenerateFileName
    nullptr,                  // GenerateDestinationFileName
    nullptr                   // NormalizeNameComponent
};

// ----------------------- Implementation -----------------------
NTSTATUS
DriverEntryImpl(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath) {
  NTSTATUS status;

  UNREFERENCED_PARAMETER(DriverObject);

  RtlZeroMemory(&gState, sizeof(gState));

  // default: zero-length protected path (must be set by registry)
  RtlInitUnicodeString(&gState.ProtectedPath, nullptr);

  // Register filter
  status = FltRegisterFilter(DriverObject, &FilterRegistration, &gState.Filter);
  CHECK_NT_RETURN(status, "FltRegisterFilter failed 0x%08x", status);

  status = LoadProtectedPathFromRegistry(RegistryPath);
  if (!NT_SUCCESS(status)) {
    // If registry read fails, we leave ProtectedPath empty and log. You could set a default here.
    LOG_ERROR("Failed to load registry protected path: 0x%08x", status);
  } else if (gState.ProtectedPath.Length != 0 && gState.ProtectedPath.Buffer != nullptr) {
    status = InitProtectedPathFromDosPath(gState.ProtectedPath.Buffer);
    if (!NT_SUCCESS(status)) {
      LOG_ERROR("InitProtectedPathFromDosPath failed: 0x%08x", status);
      RtlZeroMemory(gState.ProtectedPathBuffer, sizeof(gState.ProtectedPathBuffer));
      RtlInitUnicodeString(&gState.ProtectedPath, nullptr);
      status = STATUS_SUCCESS;
    }
  }

  status = FltStartFiltering(gState.Filter);
  CHECK_NT_RETURN_CLEANUP(status, 
    FltUnregisterFilter(gState.Filter);
    gState.Filter = nullptr;, 
    "FltStartFiltering failed 0x%08x", status);

  LOG_INFO("started");
  return STATUS_SUCCESS;
}

NTSTATUS
MinimalUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags) {
  UNREFERENCED_PARAMETER(Flags);

  LOG_INFO("Unloading");

  if (gState.Filter) {
    FltUnregisterFilter(gState.Filter);
    gState.Filter = nullptr;
  }

  // zero out buffer for hygiene
  if (gState.ProtectedPathBuffer[0] != 0) {
    RtlZeroMemory(gState.ProtectedPathBuffer, sizeof(gState.ProtectedPathBuffer));
    RtlInitUnicodeString(&gState.ProtectedPath, nullptr);
  }

  return STATUS_SUCCESS;
}

NTSTATUS
InstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType) {
  UNREFERENCED_PARAMETER(FltObjects);
  UNREFERENCED_PARAMETER(Flags);
  UNREFERENCED_PARAMETER(VolumeDeviceType);
  UNREFERENCED_PARAMETER(VolumeFilesystemType);

  // attach to all volumes
  return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS
PreCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID *CompletionContext) {
  UNREFERENCED_PARAMETER(FltObjects);
  UNREFERENCED_PARAMETER(CompletionContext);

  PFLT_FILE_NAME_INFORMATION nameInfo = nullptr;
  NTSTATUS status;

  status = FltGetFileNameInformation(Data,
                                     FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT | FLT_FILE_NAME_ALLOW_QUERY_ON_REPARSE,
                                     &nameInfo);
  if (!NT_SUCCESS(status) || nameInfo == nullptr) {
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

  status = FltParseFileNameInformation(nameInfo);
  if (!NT_SUCCESS(status)) {
    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

  FLT_PREOP_CALLBACK_STATUS ret = BlockIfProtected(Data, nameInfo);

  FltReleaseFileNameInformation(nameInfo);
  return ret;
}

FLT_PREOP_CALLBACK_STATUS
PreWriteCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID *CompletionContext) {
  UNREFERENCED_PARAMETER(FltObjects);
  UNREFERENCED_PARAMETER(CompletionContext);

  PFLT_FILE_NAME_INFORMATION nameInfo = nullptr;
  NTSTATUS status;

  status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
  if (!NT_SUCCESS(status) || nameInfo == nullptr) {
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

  status = FltParseFileNameInformation(nameInfo);
  if (!NT_SUCCESS(status)) {
    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

  FLT_PREOP_CALLBACK_STATUS ret = BlockIfProtected(Data, nameInfo);

  FltReleaseFileNameInformation(nameInfo);
  return ret;
}

FLT_PREOP_CALLBACK_STATUS
PreSetInfoCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID *CompletionContext) {
  UNREFERENCED_PARAMETER(FltObjects);
  UNREFERENCED_PARAMETER(CompletionContext);

  FILE_INFORMATION_CLASS infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

  // only care about delete/rename/link classes
  if (infoClass != FileDispositionInformation &&
      infoClass != FileDispositionInformationEx &&
      infoClass != FileRenameInformation &&
      infoClass != FileRenameInformationEx &&
      infoClass != FileRenameInformationExBypassAccessCheck &&
      infoClass != FileLinkInformation) {
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

  PFLT_FILE_NAME_INFORMATION nameInfo = nullptr;
  NTSTATUS status;

  status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
  if (!NT_SUCCESS(status) || nameInfo == nullptr) {
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

  status = FltParseFileNameInformation(nameInfo);
  if (!NT_SUCCESS(status)) {
    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

  FLT_PREOP_CALLBACK_STATUS ret = BlockIfProtected(Data, nameInfo);

  FltReleaseFileNameInformation(nameInfo);
  return ret;
}
} // namespace Minifilter