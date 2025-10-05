#pragma once
#include <initguid.h>

struct KillProcessData {
  unsigned long Pid;
};
using PKillProcessData = KillProcessData *;

DEFINE_GUID(GUID_DEVINTERFACE_AydoKernelDriver,
            0x3b2f8294, 0x9173, 0x4043, 0xae, 0x6f, 0xff, 0x6d, 0x72, 0xe0, 0x2e, 0xcd);
// {3b2f8294-9173-4043-ae6f-ff6d72e02ecd}
