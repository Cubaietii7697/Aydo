#pragma once

#include <ntifs.h>
#include <fltKernel.h>

#include "Logger.hpp"

#define CHECK_NT_RETURN(status, fmt, ...) \
    do { \
        if (!NT_SUCCESS(status)) { \
            LOG_ERROR(fmt, __VA_ARGS__); \
            return status; \
        } \
    } while (0)

#define CHECK_NT_RETURN_CLEANUP(status, cleanup, fmt, ...) \
    do { \
        if (!NT_SUCCESS(status)) { \
            LOG_ERROR(fmt, __VA_ARGS__); \
            cleanup; \
            return status; \
        } \
    } while (0)

#define CHECK_NT_RETURN_FALSE(status, fmt, ...) \
    do { \
        if (!NT_SUCCESS(status)) { \
            LOG_ERROR(fmt, __VA_ARGS__); \
            return false; \
        } \
    } while (0)

#define CHECK_NT_RETURN_FALSE_CLEANUP(status, cleanup, fmt, ...) \
    do { \
        if (!NT_SUCCESS(status)) { \
            LOG_ERROR(fmt, __VA_ARGS__); \
            cleanup; \
            return false; \
        } \
    } while (0)

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
