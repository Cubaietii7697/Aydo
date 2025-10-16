#include "utils.hpp"

#include "../communication/ioctl.hpp"
#include "../include/Device.hpp"
#include "../include/Public.hpp"
#include "../logging/logger.hpp"
#include "../pch.hpp"

PFN_PsIsProcessCritical g_PsIsProcessCritical = nullptr;
PFN_PsGetProcessProtection g_PsGetProcessProtection = nullptr;

NTSTATUS Utils_InitDeviceAndQueues(PWDFDEVICE_INIT init) {
  PAGED_CODE();
  WDFDEVICE dev;
  WDF_OBJECT_ATTRIBUTES attrs;
  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attrs, DEVICE_CONTEXT);

  NTSTATUS st = WdfDeviceCreate(&init, &attrs, &dev);
  if (!NT_SUCCESS(st))
    return st;

  st = WdfDeviceCreateDeviceInterface(dev, &GUID_DEVINTERFACE_AydoKernelDriver, NULL);
  if (!NT_SUCCESS(st))
    return st;

  st = Comm_InitDefaultQueue(dev);
  if (!NT_SUCCESS(st))
    return st;

  AYDO_INFO("Device created OK");

  return STATUS_SUCCESS;
}

VOID ResolveOptionalKernelExports() {
  UNICODE_STRING name;

  RtlInitUnicodeString(&name, L"PsIsProcessCritical");
  g_PsIsProcessCritical =
      reinterpret_cast<PFN_PsIsProcessCritical>(MmGetSystemRoutineAddress(&name));

  RtlInitUnicodeString(&name, L"PsGetProcessProtection");
  g_PsGetProcessProtection =
      reinterpret_cast<PFN_PsGetProcessProtection>(MmGetSystemRoutineAddress(&name));

  AYDO_INFO("Resolved PsIsProcessCritical=%p, PsGetProcessProtection=%p",
            g_PsIsProcessCritical, g_PsGetProcessProtection);
}
