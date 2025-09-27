#pragma once
#include "../pch.hpp"

EXTERN_C_START
NTSTATUS Utils_InitDeviceAndQueues(PWDFDEVICE_INIT init);
VOID ResolveOptionalKernelExports();
EXTERN_C_END
