#include "../include/Driver.hpp"

#include "../logging/logger.hpp"
#include "../pch.hpp"
#include "../utils/utils.hpp"

extern NTSTATUS EvtDeviceAddShim(WDFDRIVER drv, PWDFDEVICE_INIT init) {
  UNREFERENCED_PARAMETER(drv);
  return Utils_InitDeviceAndQueues(init);
}

extern VOID DriverUnload(PDRIVER_OBJECT drv) {
  UNREFERENCED_PARAMETER(drv);
  AYDO_INFO("DriverUnload\n");
}

// Forward declarations
extern NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg) {
  WDF_DRIVER_CONFIG cfg;
  WDF_DRIVER_CONFIG_INIT(&cfg, EvtDeviceAddShim);

  NTSTATUS st = WdfDriverCreate(drv, reg, WDF_NO_OBJECT_ATTRIBUTES, &cfg, WDF_NO_HANDLE);
  if (!NT_SUCCESS(st)) {
    AYDO_ERROR("WdfDriverCreate failed 0x%x\n", st);
    return st;
  }

  drv->DriverUnload = DriverUnload;
  AYDO_INFO("DriverEntry OK\n");
  return STATUS_SUCCESS;
}
