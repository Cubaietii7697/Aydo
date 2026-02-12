#pragma once

#include <ntifs.h>
#include <fltKernel.h>

#include "Constants.hpp"

namespace Minifilter {

typedef struct GLOBAL_STATE_TAG {
  PFLT_FILTER Filter;
  UNICODE_STRING ProtectedPath; // points at ProtectedPathBuffer
  WCHAR ProtectedPathBuffer[Constants::PROTECTED_PATH_BUFFER_CHARS];
  ULONG OpLogCount;
} GLOBAL_STATE, *PGLOBAL_STATE;

extern GLOBAL_STATE gState;

NTSTATUS
DriverEntryImpl(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath);

NTSTATUS
MinimalUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags);

NTSTATUS
InstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);

FLT_PREOP_CALLBACK_STATUS
PreCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID *CompletionContext);

FLT_PREOP_CALLBACK_STATUS
PreWriteCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID *CompletionContext);

FLT_PREOP_CALLBACK_STATUS
PreSetInfoCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID *CompletionContext);

} // namespace Minifilter
