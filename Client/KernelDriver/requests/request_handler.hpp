#pragma once
#include "../pch.hpp"

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif

extern WDFQUEUE g_NotifyQueue;
EVT_WDF_REQUEST_CANCEL EvtRequestCancelWait;

EXTERN_C_START
NTSTATUS Requests_HandleKill(ULONG pid);
NTSTATUS Requests_RegisterProcessNotify();
NTSTATUS Requests_UnregisterProcessNotify();
VOID OnProcessNotifyEx(PEPROCESS Process,
                       HANDLE ProcessId,
                       PPS_CREATE_NOTIFY_INFO CreateInfo);

EXTERN_C_END
