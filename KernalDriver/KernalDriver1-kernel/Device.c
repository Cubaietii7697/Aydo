#include "Device.h"

#include <ntddk.h>

#include <wdf.h>

#include "AydoLogger.h"
#include "Public.h"
#include "Queue.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, AydoKernelDriverCreateDevice)
#endif

NTSTATUS
AydoKernelDriverCreateDevice(_Inout_ PWDFDEVICE_INIT DeviceInit) {
  PAGED_CODE();

  NTSTATUS status;
  WDFDEVICE device;
  WDF_OBJECT_ATTRIBUTES deviceAttributes;
  PDEVICE_CONTEXT deviceContext;

  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICE_CONTEXT);

  status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &device);
  if (!NT_SUCCESS(status)) {
    AYDO_ERROR("WdfDeviceCreate failed 0x%X", status);
    return status;
  }

  deviceContext = DeviceGetContext(device);

  // interface GUID for enumeration-based open
  status = WdfDeviceCreateDeviceInterface(device,
                                          &GUID_DEVINTERFACE_AydoKernelDriver,
                                          NULL);
  if (!NT_SUCCESS(status)) {
    AYDO_ERROR("WdfDeviceCreateDeviceInterface failed 0x%X", status);
    return status;
  }

  // Symbolic link for CreateFileW(L"\\\\.\\AydoKernelDriver")
  UNICODE_STRING symLink;
  RtlInitUnicodeString(&symLink, L"\\DosDevices\\AydoKernelDriver");
  status = WdfDeviceCreateSymbolicLink(device, &symLink);
  if (!NT_SUCCESS(status)) {
    AYDO_ERROR("WdfDeviceCreateSymbolicLink failed 0x%X", status);
    return status;
  }

  // Initialize the default I/O queue
  status = AydoKernelDriverQueueInitialize(device);
  if (!NT_SUCCESS(status)) {
    AYDO_ERROR("QueueInitialize failed 0x%X", status);
    return status;
  }

  AYDO_INFO("Device created OK");
  return STATUS_SUCCESS;
}
