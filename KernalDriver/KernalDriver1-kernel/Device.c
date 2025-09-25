#include "Device.h"

#include <ntddk.h>
#include <wdf.h>

#include "Public.h" // GUID_DEVINTERFACE_KernelDriver1
#include "Queue.h"  // KernelDriver1QueueInitialize

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, KernelDriver1CreateDevice)
#endif

NTSTATUS
KernelDriver1CreateDevice(_Inout_ PWDFDEVICE_INIT DeviceInit) {
  PAGED_CODE();

  NTSTATUS status;
  WDFDEVICE device;
  WDF_OBJECT_ATTRIBUTES deviceAttributes;
  PDEVICE_CONTEXT deviceContext;

  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICE_CONTEXT);

  status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &device);
  if (!NT_SUCCESS(status)) {
    KdPrint(("KernelDriver1: WdfDeviceCreate failed 0x%X\n", status));
    return status;
  }

  deviceContext = DeviceGetContext(device);
  deviceContext->PrivateDeviceData = 0;

  // Optional: interface GUID for enumeration-based open
  status = WdfDeviceCreateDeviceInterface(device,
                                          &GUID_DEVINTERFACE_KernelDriver1,
                                          NULL);
  if (!NT_SUCCESS(status)) {
    KdPrint(("KernelDriver1: WdfDeviceCreateDeviceInterface failed 0x%X\n", status));
    return status;
  }

  // Symbolic link for CreateFileW(L"\\\\.\\KernelDriver1")
  UNICODE_STRING symLink;
  RtlInitUnicodeString(&symLink, L"\\DosDevices\\KernelDriver1");
  status = WdfDeviceCreateSymbolicLink(device, &symLink);
  if (!NT_SUCCESS(status)) {
    KdPrint(("KernelDriver1: WdfDeviceCreateSymbolicLink failed 0x%X\n", status));
    return status;
  }

  // Initialize the default I/O queue (IOCTLs handled in Queue.c)
  status = KernelDriver1QueueInitialize(device);
  if (!NT_SUCCESS(status)) {
    KdPrint(("KernelDriver1: QueueInitialize failed 0x%X\n", status));
    return status;
  }

  KdPrint(("KernelDriver1: Device created OK\n"));
  return STATUS_SUCCESS;
}
