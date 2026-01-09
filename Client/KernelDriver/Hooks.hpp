#pragma once

#include <ntifs.h>

namespace Hooks {
VOID onProcessStart(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
} // namespace Hooks
