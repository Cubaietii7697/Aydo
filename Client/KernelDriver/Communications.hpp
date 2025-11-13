#pragma once

#include <ntifs.h>

namespace Communications {
extern NTSTATUS handleKillProcessRequest(PIRP Irp);
extern NTSTATUS handleGetProcessNotificationRequest(PIRP Irp, ULONG *BytesReturned);
NTSTATUS handleDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
} // namespace Communications
