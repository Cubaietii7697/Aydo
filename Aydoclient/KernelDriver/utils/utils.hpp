#pragma once
#include "../pch.hpp"

extern "C" {
typedef BOOLEAN(NTAPI *PFN_PsIsProcessCritical)(PEPROCESS, PBOOLEAN);
typedef struct _PS_PROTECTION {
  UCHAR Type : 3;
  UCHAR Audit : 1;
  UCHAR Signer : 4;
} PS_PROTECTION, *PPS_PROTECTION;
typedef PS_PROTECTION(NTAPI *PFN_PsGetProcessProtection)(PEPROCESS);
}

extern PFN_PsIsProcessCritical g_PsIsProcessCritical;
extern PFN_PsGetProcessProtection g_PsGetProcessProtection;

EXTERN_C_START
NTSTATUS Utils_InitDeviceAndQueues(PWDFDEVICE_INIT init);
VOID ResolveOptionalKernelExports();
EXTERN_C_END
