#include "ProcessRunnerHooks.hpp"

#include <cstdlib>

namespace ProcessRunnerHooks {

Sleep_t oldSleepFunction = nullptr;

VOID WINAPI newSleepFunction(DWORD dwMilliseconds) {
  UNREFERENCED_PARAMETER(dwMilliseconds);
  // Do nothing
}

NtDelayExecution_t oldNtDelayExecution = nullptr;

NTSTATUS NTAPI newNtDelayExecution(BOOLEAN alertable, PLARGE_INTEGER delayInterval) {
  UNREFERENCED_PARAMETER(alertable);
  UNREFERENCED_PARAMETER(delayInterval);

  // Do nothing

  return static_cast<NTSTATUS>(EXIT_SUCCESS);
}

} // namespace ProcessRunnerHooks
