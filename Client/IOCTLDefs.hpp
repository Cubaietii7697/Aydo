// !!! THESE MUST BE IN SYNC WITH THE DRIVER'S IOTCLS !!! //

#pragma once
#include <winioctl.h>

// Private device type avoids collisions with FILE_DEVICE_UNKNOWN
#ifndef FILE_DEVICE_AYDO
#define FILE_DEVICE_AYDO 0xCAFE
#endif

// Destructive op require write access;
#define IOCTL_KILL_PROCESS \
  CTL_CODE(FILE_DEVICE_AYDO, 0x800, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_WAIT_FOR_PROCESS_START \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
