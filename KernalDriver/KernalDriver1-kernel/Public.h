/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that apps can find the device and talk to it.
//

DEFINE_GUID(GUID_DEVINTERFACE_KernelDriver1,
            0x3b2f8294, 0x9173, 0x4043, 0xae, 0x6f, 0xff, 0x6d, 0x72, 0xe0, 0x2e, 0xcd);
// {3b2f8294-9173-4043-ae6f-ff6d72e02ecd}
