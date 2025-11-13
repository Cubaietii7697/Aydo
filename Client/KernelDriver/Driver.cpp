#include <ntdef.h>

#include "Communications.hpp"
#include "Constants.hpp"
#include "Logger.hpp"
#include "Utils.hpp"

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
VOID DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(RegistryPath);

  LOG_INFO("Loading driver...");

  NTSTATUS status;
  PDEVICE_OBJECT DeviceObject = nullptr;
  UNICODE_STRING deviceName, symlinkName;

  RtlInitUnicodeString(&deviceName, Constants::DEVICE_NAME);
  RtlInitUnicodeString(&symlinkName, Constants::SYMLINK_NAME);

  // Create device object
  status = IoCreateDevice(
      DriverObject,
      0,
      &deviceName,
      FILE_DEVICE_UNKNOWN,
      FILE_DEVICE_SECURE_OPEN,
      FALSE,
      &DeviceObject);

  if (!NT_SUCCESS(status)) {
    LOG_ERROR("Failed to create device object, status: 0x%X", status);

    return status;
  }

  // Create symbolic link
  status = IoCreateSymbolicLink(&symlinkName, &deviceName);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR("Failed to create symbolic link, status: 0x%X", status);
    IoDeleteDevice(DeviceObject);

    return status;
  }

  // Set IRP handlers
  DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
  DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Communications::handleDeviceControl;

  // Initialize process notifications
  status = Utils::initializeProcessNotifications();
  if (!NT_SUCCESS(status)) {
    LOG_ERROR("Failed to initialize process notifications, status: 0x%X", status);
    IoDeleteSymbolicLink(&symlinkName);
    IoDeleteDevice(DeviceObject);

    return status;
  }

  // Only allow unloading in debug mode
#if defined(DBG) || true // TODO: remove this
  DriverObject->DriverUnload = DriverUnload;
  LOG_INFO("Driver loaded successfully (debug mode - unloading allowed)");
#else
  DriverObject->DriverUnload = nullptr;
  LOG_INFO("Driver loaded successfully (release mode - unloading disabled)");
#endif

  return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
  UNICODE_STRING symlinkName;

  LOG_INFO("Unloading driver...");

  // Cleanup process notifications
  Utils::cleanupProcessNotifications();

  RtlInitUnicodeString(&symlinkName, Constants::SYMLINK_NAME);

  IoDeleteSymbolicLink(&symlinkName);

  if (DriverObject->DeviceObject) {
    IoDeleteDevice(DriverObject->DeviceObject);
  }

  LOG_INFO("Driver unloaded successfully");
}
NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
  UNREFERENCED_PARAMETER(DeviceObject);

  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  return STATUS_SUCCESS;
}
