#pragma once

#include <windows.h>
#include <winternl.h>

namespace ProcessRunnerHooks {
using Sleep_t = VOID(WINAPI *)(DWORD);
extern Sleep_t oldSleepFunction;
VOID WINAPI newSleepFunction(DWORD dwMilliseconds);

using NtDelayExecution_t = NTSTATUS(NTAPI *)(BOOLEAN, PLARGE_INTEGER);
extern NtDelayExecution_t oldNtDelayExecution;
NTSTATUS NTAPI newNtDelayExecution(BOOLEAN alertable, PLARGE_INTEGER delayInterval);
} // namespace ProcessRunnerHooks
