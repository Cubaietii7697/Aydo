#include "Hooks.hpp"

#include "Logger.hpp"
#include "Types.hpp"
#include "Utils.hpp"

namespace Hooks {

VOID onProcessStart(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
  UNREFERENCED_PARAMETER(Process);

  auto notification = (PPROCESS_NOTIFICATION)ExAllocatePool2(
      POOL_FLAG_NON_PAGED,
      sizeof(PROCESS_NOTIFICATION),
      'nPrP' // PrpN tag
  );

  if (notification == nullptr) {
    LOG_ERROR("Failed to allocate memory for process notification");

    return;
  }

  RtlZeroMemory(notification, sizeof(PROCESS_NOTIFICATION));

  // Fill in the notification data
  notification->ProcessId = HandleToULong(ProcessId);
  notification->IsCreated = (CreateInfo != nullptr);

  if (CreateInfo != nullptr) {
    // Process is being created
    notification->ParentProcessId = HandleToULong(CreateInfo->ParentProcessId);

    // Copy the image file name if available
    if (CreateInfo->ImageFileName != nullptr) {
      SIZE_T lengthToCopy = min(CreateInfo->ImageFileName->Length / sizeof(WCHAR), MAX_PATH - 1);
      RtlCopyMemory(
          notification->ImageFileName,
          CreateInfo->ImageFileName->Buffer,
          lengthToCopy * sizeof(WCHAR));
      notification->ImageFileName[lengthToCopy] = L'\0';
    } else {
      notification->ImageFileName[0] = L'\0';
    }

    // Copy the command line if available
    if (CreateInfo->CommandLine != nullptr && CreateInfo->CommandLine->Length > 0) {
      SIZE_T lengthToCopy = min(CreateInfo->CommandLine->Length / sizeof(WCHAR), MAX_COMMANDLINE - 1);
      RtlCopyMemory(
          notification->CommandLine,
          CreateInfo->CommandLine->Buffer,
          lengthToCopy * sizeof(WCHAR));
      notification->CommandLine[lengthToCopy] = L'\0';
    } else {
      notification->CommandLine[0] = L'\0';
    }

    LOG_INFO("Process created - PID: %lu, Parent: %lu, Image: %wZ, CommandLine: %wZ",
             notification->ProcessId,
             notification->ParentProcessId,
             CreateInfo->ImageFileName,
             CreateInfo->CommandLine);
  } else {
    // Process is being terminated
    notification->ParentProcessId = 0;
    notification->ImageFileName[0] = L'\0';
    notification->CommandLine[0] = L'\0';

    LOG_INFO("Process terminated - PID: %lu", notification->ProcessId);
  }

  // Add to queue
  Utils::enqueueProcessNotification(notification);
}

} // namespace Hooks