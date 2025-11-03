#pragma once

#include <windows.h>

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

#ifndef MAX_COMMANDLINE
#define MAX_COMMANDLINE 512
#endif

typedef struct {
  ULONG ProcessId;
} IOCTL_KILL_PROCESS_INPUT;

typedef struct {
  ULONG ProcessId;
  ULONG ParentProcessId;
  WCHAR ImageFileName[MAX_PATH];
  WCHAR CommandLine[MAX_COMMANDLINE];
  BOOLEAN IsCreated; // TRUE = created, FALSE = terminated
} IOCTL_GET_PROCESS_NOTIFICATION_OUTPUT;
