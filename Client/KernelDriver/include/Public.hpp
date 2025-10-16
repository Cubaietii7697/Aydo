#pragma once
#define AYDO_MAX_PATH 260

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <Windows.h>
#endif

#include <initguid.h>

struct KillProcessData {
  unsigned long Pid;
};
using PKillProcessData = KillProcessData *;

struct KillProcessOut {
  unsigned long requestedPid;
  unsigned long terminatedPid;
  long ntStatus;
};

typedef struct _PROCESS_NOTIFY_INFO {
  ULONG ProcessId;
  WCHAR ImageFileName[AYDO_MAX_PATH];
} PROCESS_NOTIFY_INFO, *PPROCESS_NOTIFY_INFO;

typedef struct _WAIT_FOR_PROCESS_START_IN {
  WCHAR TargetImageName[AYDO_MAX_PATH];
} WAIT_FOR_PROCESS_START_IN, *PWAIT_FOR_PROCESS_START_IN;

DEFINE_GUID(GUID_DEVINTERFACE_AydoKernelDriver,
            0x3b2f8294, 0x9173, 0x4043, 0xae, 0x6f, 0xff, 0x6d, 0x72, 0xe0, 0x2e, 0xcd);
// {3b2f8294-9173-4043-ae6f-ff6d72e02ecd}
