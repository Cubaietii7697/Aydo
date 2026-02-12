#pragma once

#include <ntifs.h>
#include <fltKernel.h>

namespace Minifilter {

NTSTATUS
InitProtectedPathFromDosPath(
    _In_ PCWSTR DosPath);

BOOLEAN
IsPathProtected(
    _In_ PUNICODE_STRING Name);

NTSTATUS
LoadProtectedPathFromRegistry(
    _In_ PUNICODE_STRING RegistryPath);

FLT_PREOP_CALLBACK_STATUS
BlockIfProtected(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo);

} // namespace Minifilter
