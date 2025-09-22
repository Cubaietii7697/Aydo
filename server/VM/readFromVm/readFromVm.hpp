#pragma once

#include <windows.h>
#include <TlHelp32.h>
#include <evntcons.h>
#include <evntrace.h>
#include <set>
#include <string>
#include <tdh.h>

extern "C" const GUID KERNEL_LOGGER_GUID;

static const GUID GUID_KERNEL_FILE = {0xEDD08927, 0x9CC4, 0x4E65, {0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89}};
static const GUID GUID_KERNEL_REGISTRY = {0x70EB4F03, 0xC1DE, 0x4F73, {0xA0, 0x51, 0x33, 0xD1, 0x3D, 0x54, 0x13, 0xBD}};
static const GUID GUID_KERNEL_NETWORK =
    {0x7dd42a49, 0x5329, 0x4832, {0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88}};

extern std::set<DWORD> g_targetPids;
extern TRACEHANDLE g_hTrace;
extern TRACEHANDLE g_hSession;

class readFromVm {
public:
  static void WINAPI StaticEventRecordCallback(PEVENT_RECORD pEvent);
  static bool StartKernelSession(const std::wstring &sessionName, ULONG &outStatus);
  static void StopKernelSession(const std::wstring &sessionName);
  static bool OpenAndProcessRealTime(const std::wstring &sessionName);
  static std::set<DWORD> FindPidByName(const std::wstring &exeName);

private:
  static std::wstring GetStringFromInfo(PTRACE_EVENT_INFO pInfo, ULONG offset);
  static std::wstring FormatProperty(PTRACE_EVENT_INFO pInfo, PEVENT_RECORD pEvent, USHORT propertyIndex);
  static std::wstring FormatBasicProperty(USHORT inType, PBYTE propertyData, USHORT propertyLength);
  static void PrintEventDetailed(PEVENT_RECORD pEvent);
  static std::wstring FormatTimestamp(PEVENT_RECORD pEvent);
  static std::wstring ToLowerW(const std::wstring &s);
  static std::wstring BytesToHex(const BYTE *data, ULONG size, ULONG maxBytes = 32);
};