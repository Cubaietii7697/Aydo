#pragma once

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <TlHelp32.h>
#include <tdh.h>
#include <string>
#include <thread>
#include <atomic>
#include <set>


extern "C" const GUID KERNEL_LOGGER_GUID;

extern std::set<DWORD> g_targetPids;
extern TRACEHANDLE g_hTrace;
extern TRACEHANDLE g_hSession;

class readFromVm {
public:
	std::set<DWORD> FindPidByName(const std::wstring& exeName);
	static void WINAPI StaticEventRecordCallback(PEVENT_RECORD pEvent);
	bool StartKernelSession(const std::wstring& sessionName, ULONG& outStatus);
	void StopKernelSession(const std::wstring& sessionName);
	bool OpenAndProcessRealTime(const std::wstring& sessionName);
private:
	static std::wstring GetStringFromInfo(PTRACE_EVENT_INFO pInfo, ULONG offset);
	static std::wstring FormatProperty(PTRACE_EVENT_INFO pInfo, PEVENT_RECORD pEvent, USHORT propertyIndex);
	static void PrintEventDetailed(PEVENT_RECORD pEvent);
};