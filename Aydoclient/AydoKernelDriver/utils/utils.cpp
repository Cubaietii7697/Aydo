#include "utils.hpp"

#include "../communication/ioctl.hpp"
#include "../include/Device.hpp"
#include "../include/Public.hpp"
#include "../logging/logger.hpp"
#include "../pch.hpp"

extern "C" {
typedef BOOLEAN(NTAPI *PFN_PsIsProcessCritical)(PEPROCESS, PBOOLEAN);
typedef struct _PS_PROTECTION {
  UCHAR Type : 3;
  UCHAR Audit : 1;
  UCHAR Signer : 4;
} PS_PROTECTION, *PPS_PROTECTION;
typedef PS_PROTECTION(NTAPI *PFN_PsGetProcessProtection)(PEPROCESS);

static PFN_PsIsProcessCritical g_PsIsProcessCritical = nullptr;
static PFN_PsGetProcessProtection g_PsGetProcessProtection = nullptr;
}

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
  g_PsIsProcessCritical = (PFN_PsIsProcessCritical)MmGetSystemRoutineAddress(&name);

  RtlInitUnicodeString(&name, L"PsGetProcessProtection");
  g_PsGetProcessProtection = (PFN_PsGetProcessProtection)MmGetSystemRoutineAddress(&name);

  AYDO_INFO("Resolved PsIsProcessCritical=%p, PsGetProcessProtection=%p",
            g_PsIsProcessCritical, g_PsGetProcessProtection);
}
