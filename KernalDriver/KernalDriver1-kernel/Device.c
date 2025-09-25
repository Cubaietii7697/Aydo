#include "Device.h"

#include <ntddk.h>
#include <wdf.h>

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
    KdPrint(("AydoKernelDriver: WdfDeviceCreate failed 0x%X\n", status));
    return status;
  }

  deviceContext = DeviceGetContext(device);
  deviceContext->PrivateDeviceData = 0;

  // interface GUID for enumeration-based open
  status = WdfDeviceCreateDeviceInterface(device,
                                          &GUID_DEVINTERFACE_AydoKernelDriver,
                                          NULL);
  if (!NT_SUCCESS(status)) {
    KdPrint(("AydoKernelDriver: WdfDeviceCreateDeviceInterface failed 0x%X\n", status));
    return status;
  }

  // Symbolic link for CreateFileW(L"\\\\.\\AydoKernelDriver")
  UNICODE_STRING symLink;
  RtlInitUnicodeString(&symLink, L"\\DosDevices\\AydoKernelDriver");
  status = WdfDeviceCreateSymbolicLink(device, &symLink);
  if (!NT_SUCCESS(status)) {
    KdPrint(("AydoKernelDriver: WdfDeviceCreateSymbolicLink failed 0x%X\n", status));
    return status;
  }

  // Initialize the default I/O queue (IOCTLs handled in Queue.c)
  status = AydoKernelDriverQueueInitialize(device);
  if (!NT_SUCCESS(status)) {
    KdPrint(("AydoKernelDriver: QueueInitialize failed 0x%X\n", status));
    return status;
  }

  KdPrint(("AydoKernelDriver: Device created OK\n"));
  return STATUS_SUCCESS;
}
