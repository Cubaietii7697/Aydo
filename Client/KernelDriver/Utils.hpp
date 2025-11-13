#pragma once

#include <ntifs.h>

extern "C" NTSTATUS NTAPI ZwQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_ PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength);

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION 0x0400
#endif

// Basic list of protected processes (shouldn't be killed)
static const ULONG PROTECTED_PROCESSES[] = {
    0, // NtOSKRNL
    4, // System
};

namespace Utils {
NTSTATUS killProcessByPID(ULONG pid);
bool isProcessKillable(ULONG pid);
NTSTATUS initializeProcessNotifications();
VOID cleanupProcessNotifications();
PVOID dequeueProcessNotification();
VOID enqueueProcessNotification(PVOID notification);
} // namespace Utils