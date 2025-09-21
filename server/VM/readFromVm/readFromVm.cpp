#include "readFromVm.hpp"
#include <fstream>
#include <iostream>
#include <memory>
#include <set>
#include <sstream>
#include <vector>

std::set<DWORD> g_targetPids;
TRACEHANDLE g_hTrace = 0;
TRACEHANDLE g_hSession = 0;

std::set<DWORD> readFromVm::FindPidByName(const std::wstring &exeName) {
  std::set<DWORD> pids;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE)
    return pids;

  PROCESSENTRY32W pe;
  pe.dwSize = sizeof(pe);

  if (Process32FirstW(snap, &pe)) {
    do {
      if (_wcsicmp(pe.szExeFile, exeName.c_str()) == 0) {
        pids.insert(pe.th32ProcessID);
      }
    } while (Process32NextW(snap, &pe));
  }

  CloseHandle(snap);
  return pids;
}

void WINAPI readFromVm::StaticEventRecordCallback(PEVENT_RECORD pEvent) {
  if (!pEvent)
    return;

  static int totalEvents = 0;
  static int targetEvents = 0;
  static DWORD startTime = GetTickCount();
  const int SEC = 1000;
  const int FIRST_15SEC = 15 * SEC;
  const int EVENTS = 50;
  totalEvents++;
  DWORD pid = pEvent->EventHeader.ProcessId;
  DWORD tid = pEvent->EventHeader.ThreadId;
  DWORD currentTime = GetTickCount();
  bool debugMode = (currentTime - startTime) < FIRST_15SEC; // First 15 seconds

  // Show statistics every EVENTS events
  if (totalEvents % EVENTS == 0) {
    std::wcout << L"[STATS] Total events: " << totalEvents
               << L" Target events: " << targetEvents << L" Time: "
               << (currentTime - startTime) / SEC << L"s\n";
  }

  // Debug mode: show first EVENTS events
  if (debugMode && totalEvents <= EVENTS) {
    std::wcout << L"[DEBUG] Event #" << totalEvents << L" PID: " << pid
               << L" (hex: 0x" << std::hex << pid << std::dec << L")"
               << L" TID: " << tid << L" Provider: 0x" << std::hex
               << pEvent->EventHeader.ProviderId.Data1 << std::dec
               << L" EventID: " << pEvent->EventHeader.EventDescriptor.Id
               << L" Opcode: " << pEvent->EventHeader.EventDescriptor.Opcode
               << std::endl;
  }

  // Handle invalid PIDs (kernel/system events)
  if (pid == 0xFFFFFFFF || pid == 0) {
    return;
  }

  if (!g_targetPids.empty() && g_targetPids.count(pid) > 0) {
    targetEvents++;
    std::wcout << L"[TARGET] Event #" << targetEvents << L" from PID " << pid
               << L" EventID: " << pEvent->EventHeader.EventDescriptor.Id
               << L" Opcode: "
               << (int)pEvent->EventHeader.EventDescriptor.Opcode << std::endl;

    PrintEventDetailed(pEvent);
    return;
  }

  // Optionally show some other events in debug mode
  if (debugMode && totalEvents <= 20) {
    std::wcout << L"[OTHER] PID " << pid << L" EventID: "
               << pEvent->EventHeader.EventDescriptor.Id << L" Provider: 0x"
               << std::hex << pEvent->EventHeader.ProviderId.Data1 << std::dec
               << std::endl;
  }
}

bool readFromVm::StartKernelSession(const std::wstring &sessionName,
                                    ULONG &outStatus) {
  const size_t propsSize =
      sizeof(EVENT_TRACE_PROPERTIES) + (MAX_PATH * sizeof(wchar_t)) * 2;
  EVENT_TRACE_PROPERTIES *pProps = (EVENT_TRACE_PROPERTIES *)malloc(propsSize);
  if (!pProps) {
    outStatus = ERROR_OUTOFMEMORY;
    return false;
  }

  ZeroMemory(pProps, propsSize);
  pProps->Wnode.BufferSize = (ULONG)propsSize;
  pProps->Wnode.Flags = WNODE_FLAG_TRACED_GUID;

  // CRITICAL: Set the GUID for NT Kernel Logger
  pProps->Wnode.Guid = KERNEL_LOGGER_GUID;

  pProps->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
  pProps->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

  // Add more flags to get more events for debugging
  pProps->EnableFlags = EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_THREAD |
                        EVENT_TRACE_FLAG_IMAGE_LOAD | EVENT_TRACE_FLAG_DISK_IO |
                        EVENT_TRACE_FLAG_NETWORK_TCPIP;

  std::wcout << L"[DEBUG] EnableFlags set to: 0x" << std::hex
             << pProps->EnableFlags << std::dec << std::endl;

  // Clean old session if exists
  std::wcout << L"[DEBUG] Stopping any existing session..." << std::endl;
  ControlTraceW(0, sessionName.c_str(), pProps, EVENT_TRACE_CONTROL_STOP);
  Sleep(200);

  std::wcout << L"[DEBUG] Starting new trace session..." << std::endl;
  outStatus = StartTraceW(&g_hSession, sessionName.c_str(), pProps);
  std::wcout << L"[DBG] StartTraceW returned: " << outStatus << L"\n";

  if (outStatus != ERROR_SUCCESS) {
    std::wcerr << L"[ERROR] StartTraceW failed: " << outStatus;
    switch (outStatus) {
    case ERROR_ACCESS_DENIED:
      std::wcerr << L" (Access Denied - Run as Administrator)";
      break;
    case ERROR_ALREADY_EXISTS:
      std::wcerr << L" (Session Already Exists)";
      break;
    case ERROR_BAD_LENGTH:
      std::wcerr << L" (Bad Length)";
      break;
    case ERROR_INVALID_PARAMETER:
      std::wcerr << L" (Invalid Parameter)";
      break;
    default:
      break;
    }
    std::wcerr << L"\n";
    free(pProps);
    return false;
  }

  std::wcout << L"[DEBUG] Kernel session started successfully, handle: "
             << g_hSession << std::endl;
  free(pProps);
  return true;
}

void readFromVm::StopKernelSession(const std::wstring &sessionName) {
  std::wcout << L"[DEBUG] Stopping kernel session..." << std::endl;
  ULONG status = ControlTraceW(g_hSession, sessionName.c_str(), nullptr,
                               EVENT_TRACE_CONTROL_STOP);
  std::wcout << L"[DEBUG] StopTrace returned: " << status << std::endl;
}

bool readFromVm::OpenAndProcessRealTime(const std::wstring &sessionName) {
  std::wcout << L"[DEBUG] Opening real-time trace..." << std::endl;

  EVENT_TRACE_LOGFILEW log = {};
  ZeroMemory(&log, sizeof(log));

  log.LoggerName = const_cast<LPWSTR>(sessionName.c_str());
  log.ProcessTraceMode =
      PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
  log.EventRecordCallback =
      (PEVENT_RECORD_CALLBACK)readFromVm::StaticEventRecordCallback;

  std::wcout << L"[DEBUG] Calling OpenTraceW..." << std::endl;
  g_hTrace = OpenTraceW(&log);
  if (g_hTrace == INVALID_PROCESSTRACE_HANDLE) {
    DWORD error = GetLastError();
    std::wcerr << L"[ERROR] OpenTrace failed with error: " << error
               << std::endl;
    return false;
  }
  std::wcout << L"[DBG] OpenTraceW succeeded, handle: " << g_hTrace
             << std::endl;

  std::wcout << L"[DEBUG] Starting ProcessTrace..." << std::endl;
  ULONG status = ProcessTrace(&g_hTrace, 1, nullptr, nullptr);
  std::wcout << L"[DBG] ProcessTrace returned: " << status << std::endl;

  if (status == ERROR_SUCCESS) {
    std::wcout << L"[DEBUG] ProcessTrace completed successfully" << std::endl;
    return true;
  }
  if (status == ERROR_CANCELLED) {
    std::wcout << L"[INFO] Trace stopped by user (ERROR_CANCELLED)"
               << std::endl;
    return true;
  }

  std::wcerr << L"[ERROR] ProcessTrace failed with status " << status
             << std::endl;
  return false;
}

// helpers

std::wstring readFromVm::GetStringFromInfo(PTRACE_EVENT_INFO pInfo,
                                           ULONG offset) {
  if (!pInfo || offset == 0)
    return L"";
  PWSTR p = (PWSTR)((PBYTE)pInfo + offset);
  return std::wstring(p);
}

std::wstring readFromVm::FormatProperty(PTRACE_EVENT_INFO pInfo,
                                        PEVENT_RECORD pEvent,
                                        USHORT propertyIndex) {
  if (!pInfo)
    return L"<no-info>";

  if (propertyIndex >= pInfo->TopLevelPropertyCount)
    return L"<bad-index>";

  // Prepare descriptor for this property
  PROPERTY_DATA_DESCRIPTOR desc;
  desc.PropertyName =
      (ULONGLONG)(ULONG_PTR)pInfo->EventPropertyInfoArray[propertyIndex]
              .NameOffset
          ? (ULONGLONG)((PBYTE)pInfo +
                        pInfo->EventPropertyInfoArray[propertyIndex].NameOffset)
          : 0;
  desc.ArrayIndex = ULONG_MAX; // default: get all items

  ULONG size = 0;
  DWORD status = TdhGetPropertySize(pEvent, 0, nullptr, 1, &desc, &size);
  if (status != ERROR_SUCCESS)
    return L"<size-fail>";

  std::vector<BYTE> buffer(size);
  status = TdhGetProperty(pEvent, 0, nullptr, 1, &desc, (ULONG)buffer.size(),
                          buffer.data());
  if (status != ERROR_SUCCESS)
    return L"<prop-fail>";

  EVENT_PROPERTY_INFO &propInfo = pInfo->EventPropertyInfoArray[propertyIndex];
  USHORT inType = propInfo.nonStructType.InType;

  // Format based on type
  switch (inType) {
  case TDH_INTYPE_UNICODESTRING:
    return std::wstring((PWSTR)buffer.data());
  case TDH_INTYPE_ANSISTRING: {
    std::string tmp((PCHAR)buffer.data());
    return std::wstring(tmp.begin(), tmp.end());
  }
  case TDH_INTYPE_UINT32: {
    DWORD val = *(DWORD *)buffer.data();
    return std::to_wstring(val);
  }
  case TDH_INTYPE_INT32: {
    LONG val = *(LONG *)buffer.data();
    return std::to_wstring(val);
  }
  case TDH_INTYPE_UINT64: {
    ULONGLONG val = *(ULONGLONG *)buffer.data();
    return std::to_wstring(val);
  }
  case TDH_INTYPE_INT64: {
    LONGLONG val = *(LONGLONG *)buffer.data();
    return std::to_wstring(val);
  }
  case TDH_INTYPE_BOOLEAN: {
    BOOL val = *(BOOL *)buffer.data();
    return val ? L"true" : L"false";
  }
  default:
    // given as his
    std::wstringstream ss;
    ss << L"0x";
    for (size_t i = 0; i < buffer.size(); ++i)
      ss << std::hex << (int)buffer[i];
    return ss.str();
  }
}

// BIG helper: print an entire event in a readable way.
// Call this from StaticEventRecordCallback (it is safe-ish to call from
// callback; keep output minimal)
void readFromVm::PrintEventDetailed(PEVENT_RECORD pEvent) {
  if (!pEvent)
    return;

  // Get trace event info
  PTRACE_EVENT_INFO pInfo = nullptr;
  ULONG bufferSize = 0;
  ULONG status = TdhGetEventInformation(pEvent, 0, nullptr, pInfo, &bufferSize);
  if (status == ERROR_INSUFFICIENT_BUFFER) {
    pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
    if (!pInfo)
      return;
    status = TdhGetEventInformation(pEvent, 0, nullptr, pInfo, &bufferSize);
  }
  if (status != ERROR_SUCCESS) {
    // fallback minimal info
    std::wcout << L"[ETW] Provider=" << std::hex
               << pEvent->EventHeader.ProviderId.Data1 << std::dec << L" EID="
               << pEvent->EventHeader.EventDescriptor.Id << L" Op="
               << (int)pEvent->EventHeader.EventDescriptor.Opcode << L" Level="
               << (int)pEvent->EventHeader.EventDescriptor.Level << L" PID="
               << pEvent->EventHeader.ProcessId << std::endl;
    if (pInfo)
      free(pInfo);
    return;
  }

  // Extract human names
  std::wstring providerName =
      GetStringFromInfo(pInfo, pInfo->ProviderNameOffset);
  std::wstring taskName = GetStringFromInfo(pInfo, pInfo->TaskNameOffset);
  std::wstring opcodeName = GetStringFromInfo(pInfo, pInfo->OpcodeNameOffset);
  std::wstring eventName = GetStringFromInfo(pInfo, pInfo->EventNameOffset);
  std::wstring keywords = GetStringFromInfo(pInfo, pInfo->KeywordsNameOffset);

  // Print header
  std::wcout << L"[ETW] Provider: "
             << (providerName.empty()
                     ? std::to_wstring(pEvent->EventHeader.ProviderId.Data1)
                     : providerName)
             << L" Event: "
             << (eventName.empty()
                     ? std::to_wstring(pEvent->EventHeader.EventDescriptor.Id)
                     : eventName)
             << L" Task: " << (taskName.empty() ? L"-" : taskName)
             << L" Opcode: "
             << (opcodeName.empty()
                     ? std::to_wstring(
                           (int)pEvent->EventHeader.EventDescriptor.Opcode)
                     : opcodeName)
             << L" Level: " << (int)pEvent->EventHeader.EventDescriptor.Level
             << L" PID: " << pEvent->EventHeader.ProcessId << std::endl;

  // print properties if any
  if (pInfo->TopLevelPropertyCount > 0) {
    for (USHORT i = 0; i < pInfo->TopLevelPropertyCount; ++i) {
      EVENT_PROPERTY_INFO &prop = pInfo->EventPropertyInfoArray[i];
      std::wstring propName;
      if (prop.NameOffset) {
        propName = (PWSTR)((PBYTE)pInfo + prop.NameOffset);
      } else {
        propName = L"<prop>";
      }

      std::wstring val = FormatProperty(pInfo, pEvent, i);
      std::wcout << L"    " << propName << L" = " << val << std::endl;
    }
  } else {
    std::wcout << L"    (no properties)" << std::endl;
  }

  if (pInfo)
    free(pInfo);
}
