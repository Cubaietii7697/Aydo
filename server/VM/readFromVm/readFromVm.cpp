#include "readFromVm.hpp"
#include <algorithm>
#include <cstring>
#include <evntcons.h>
#include <evntrace.h>
#include <iostream>
#include <sstream>
#include <string>
#include <tdh.h>
#include <tlhelp32.h>
#include <vector>
#include <windows.h>

std::set<DWORD> g_targetPids;
TRACEHANDLE g_hTrace = 0;
TRACEHANDLE g_hSession = 0;

// Find PIDs by process name
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

// Whenever an event is registered, it is transfered to this function,
// which then filters it based on the PIDs we are interested in and
// by the opcodes we are interested in. If the event is not filtered out,
// it is then printed.
void WINAPI readFromVm::StaticEventRecordCallback(PEVENT_RECORD pEvent) {
  // These opcodes aren't needed because they are logging and telemetry events (they happen all the time, and do not show any useful information)
  const std::vector<int> OPCODES_TO_SKIP = {38, 33, 44};

  // Shouldn't happen, just a failsafe to make sure we don't print something that doesn't exist in memory
  if (!pEvent)
    return;

  DWORD pid = pEvent->EventHeader.ProcessId;

  // If the PID is not in the set of PIDs we are interested in, skip it
  if (g_targetPids.find(pid) == g_targetPids.end()) {
    return;
  }

  // Skip noisy opcodes
  int opcode = (int)pEvent->EventHeader.EventDescriptor.Opcode;
  if (std::find(OPCODES_TO_SKIP.begin(), OPCODES_TO_SKIP.end(), opcode) != OPCODES_TO_SKIP.end()) {
    return;
  }

  // Get event metadata
  PTRACE_EVENT_INFO pInfo = nullptr;
  ULONG bufSize = 0;
  ULONG status = TdhGetEventInformation(pEvent, 0, nullptr, pInfo, &bufSize);
  if (status == ERROR_INSUFFICIENT_BUFFER) {
    pInfo = (PTRACE_EVENT_INFO)malloc(bufSize);
    if (!pInfo)
      return;
    status = TdhGetEventInformation(pEvent, 0, nullptr, pInfo, &bufSize);
  }
  if (status != ERROR_SUCCESS) {
    if (pInfo)
      free(pInfo);
    return;
  }

  std::wstring providerName = GetStringFromInfo(pInfo, pInfo->ProviderNameOffset);
  std::wstring eventName = GetStringFromInfo(pInfo, pInfo->EventNameOffset);
  std::wstring timestamp = FormatTimestamp(pEvent);

  // Print a concise header
  std::wcout << L"[" << timestamp << L"] PID: " << pid
             << L" Provider: "
             << (providerName.empty() ? std::to_wstring(pEvent->EventHeader.ProviderId.Data1) : providerName)
             << L" Event: "
             << (eventName.empty() ? std::to_wstring(pEvent->EventHeader.EventDescriptor.Id) : eventName)
             << L" Opcode: " << opcode
             << std::endl;

  // Print only matching properties
  if (pInfo->TopLevelPropertyCount > 0) {
    for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; ++i) {
      EVENT_PROPERTY_INFO &prop = pInfo->EventPropertyInfoArray[i];
      std::wstring propName = prop.NameOffset ? GetStringFromInfo(pInfo, prop.NameOffset) : L"<prop>";

      std::wstring val = FormatProperty(pInfo, pEvent, i);
      if (val.empty())
        val = L"(empty)";
      std::wcout << L"\t" << propName << L" = " << val << std::endl;
    }
  } else {
    std::wcout << L"\t(no properties)" << std::endl;
  }

  if (pInfo)
    free(pInfo);
}

// Starts a kernel logging session
bool readFromVm::StartKernelSession(const std::wstring &sessionName,
                                    ULONG &outStatus) {
  const ULONG FLAGS = EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_THREAD |
                      EVENT_TRACE_FLAG_IMAGE_LOAD | EVENT_TRACE_FLAG_DISK_IO |
                      EVENT_TRACE_FLAG_NETWORK_TCPIP;

  const size_t propsSize =
      sizeof(EVENT_TRACE_PROPERTIES) + (MAX_PATH * sizeof(wchar_t)) * 2;
  auto pProps = (EVENT_TRACE_PROPERTIES *)malloc(propsSize);
  if (!pProps) {
    std::wcerr << L"[ERROR] malloc EVENT_TRACE_PROPERTIES failed\n";
    return false;
  }

  ZeroMemory(pProps, propsSize);
  pProps->Wnode.BufferSize = (ULONG)propsSize;
  pProps->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
  pProps->Wnode.Guid = KERNEL_LOGGER_GUID;

  // CRITICAL: request kernel classes here
  pProps->EnableFlags = FLAGS;

  pProps->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
  pProps->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

  std::wcout << L"[DEBUG] StartTrace session='" << sessionName << L"' EnableFlags=0x"
             << std::hex << pProps->EnableFlags << std::dec << std::endl;

  outStatus = StartTraceW(&g_hSession, sessionName.c_str(), pProps);
  if (outStatus != ERROR_SUCCESS) {
    if (outStatus == ERROR_ALREADY_EXISTS) {
      std::wcerr << L"[WARN] StartTrace: session already exists, attempting stop/retry\n";
      ULONG ctrl = ControlTraceW(0, sessionName.c_str(), nullptr, EVENT_TRACE_CONTROL_STOP);
      std::wcout << L"[DEBUG] ControlTrace stop returned " << ctrl << std::endl;
      Sleep(200);
      outStatus = StartTraceW(&g_hSession, sessionName.c_str(), pProps);
    }
    if (outStatus != ERROR_SUCCESS) {
      std::wcerr << L"[ERROR] StartTrace failed: " << outStatus << std::endl;
      free(pProps);
      return false;
    }
  }

  std::wcout << L"[DEBUG] StartTrace succeeded, session handle " << g_hSession << std::endl;

  // Explicitly enable kernel providers too (best-practice in many setups).
  ULONG rc;
  rc = EnableTraceEx2(g_hSession, &GUID_KERNEL_FILE, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                      TRACE_LEVEL_VERBOSE, 0, 0, 0, nullptr);
  std::wcout << L"[DEBUG] EnableTraceEx2 GUID_KERNEL_FILE -> " << rc << std::endl;

  rc = EnableTraceEx2(g_hSession, &GUID_KERNEL_REGISTRY, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                      TRACE_LEVEL_VERBOSE, 0, 0, 0, nullptr);
  std::wcout << L"[DEBUG] EnableTraceEx2 GUID_KERNEL_REGISTRY -> " << rc << std::endl;

  // Enable kernel-network provider (the correct GUID, not a placeholder)
  rc = EnableTraceEx2(g_hSession, &GUID_KERNEL_NETWORK, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                      TRACE_LEVEL_VERBOSE, 0, 0, 0, nullptr);
  std::wcout << L"[DEBUG] EnableTraceEx2 GUID_KERNEL_NETWORK -> " << rc << std::endl;

  free(pProps);
  return true;
}

// Stops the kernel session
void readFromVm::StopKernelSession(const std::wstring &sessionName) {
  std::wcout << L"[DEBUG] Stopping kernel session..." << std::endl;
  if (g_hTrace != 0 && g_hTrace != INVALID_PROCESSTRACE_HANDLE) {
    CloseTrace(g_hTrace);
    g_hTrace = 0;
  }
  if (g_hSession != 0) {
    ControlTraceW(g_hSession, sessionName.c_str(), nullptr, EVENT_TRACE_CONTROL_STOP);
    g_hSession = 0;
  }
}

// Starts logging events
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
    StopKernelSession(sessionName);
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

// === HELPERS === //

// Formats basic property types (string, int, bool, etc)
// If the type is unknown, returns it as a hex string (up to MAX_HEX_BYTES_FOR_UNKOWN_TYPE bytes)
std::wstring readFromVm::FormatBasicProperty(USHORT inType, PBYTE propertyData, USHORT propertyLength) {
  const unsigned int MAX_HEX_BYTES_FOR_UNKOWN_TYPE = 8;

  if (!propertyData || propertyLength == 0)
    return L"";

  switch (inType) {
  case TDH_INTYPE_INT8:
    return std::to_wstring(*((INT8 *)propertyData));
  case TDH_INTYPE_UINT8:
    return std::to_wstring(*((UINT8 *)propertyData));
  case TDH_INTYPE_INT16:
    return std::to_wstring(*((INT16 *)propertyData));
  case TDH_INTYPE_UINT16:
    return std::to_wstring(*((UINT16 *)propertyData));
  case TDH_INTYPE_INT32:
    return std::to_wstring(*((INT32 *)propertyData));
  case TDH_INTYPE_UINT32:
    return std::to_wstring(*((UINT32 *)propertyData));
  case TDH_INTYPE_INT64:
    return std::to_wstring(*((INT64 *)propertyData));
  case TDH_INTYPE_UINT64:
    return std::to_wstring(*((UINT64 *)propertyData));
  case TDH_INTYPE_FLOAT:
    return std::to_wstring(*((float *)propertyData));
  case TDH_INTYPE_DOUBLE:
    return std::to_wstring(*((double *)propertyData));
  case TDH_INTYPE_UNICODESTRING: {
    if (propertyLength >= sizeof(wchar_t)) {
      return std::wstring((wchar_t *)propertyData, propertyLength / sizeof(wchar_t));
    }
    return L"";
  }
  case TDH_INTYPE_ANSISTRING: {
    if (propertyLength >= sizeof(char)) {
      std::string ansiStr((char *)propertyData, propertyLength);
      return std::wstring(ansiStr.begin(), ansiStr.end());
    }
    return L"";
  }
  case TDH_INTYPE_BOOLEAN: {
    BOOL boolVal = *((BOOL *)propertyData);
    return boolVal ? L"true" : L"false";
  }
  default:
    // For unknown types, return them as hex
    std::wstring hexStr;
    for (USHORT i = 0; i < propertyLength && i < MAX_HEX_BYTES_FOR_UNKOWN_TYPE; ++i) {
      hexStr += std::to_wstring(propertyData[i]);
      if (i < propertyLength - 1)
        hexStr += L" ";
    }
    return hexStr;
  }
}

// Gets a string from a event info memory with an offset
std::wstring readFromVm::GetStringFromInfo(PTRACE_EVENT_INFO pInfo,
                                           ULONG offset) {
  if (!pInfo || offset == 0)
    return L"";
  auto p = (PWSTR)((PBYTE)pInfo + offset);

  return {p};
}

// Formats bytes as a hex string
std::wstring readFromVm::BytesToHex(const BYTE *data, ULONG size, ULONG maxBytes) {
  if (!data || size == 0)
    return L"";

  std::wostringstream oss;
  ULONG toShow = (size > maxBytes) ? maxBytes : size;
  for (ULONG i = 0; i < toShow; ++i) {
    if (i)
      oss << L" ";
    oss << std::hex << std::uppercase << (int)data[i];
  }
  if (size > maxBytes) {
    oss << L" ... (" << std::dec << size << L" bytes)";
  } else {
    oss << std::dec; // Reset it back to decimal
  }

  return oss.str();
}

// Formats a property from an event record
std::wstring readFromVm::FormatProperty(PTRACE_EVENT_INFO pInfo,
                                        PEVENT_RECORD pEvent,
                                        USHORT propertyIndex) {
  if (!pInfo || !pEvent)
    return L"";

  EVENT_PROPERTY_INFO *propInfo = &pInfo->EventPropertyInfoArray[propertyIndex];

  // Build a PROPERTY_DATA_DESCRIPTOR that points to the property's name string inside pInfo.
  PROPERTY_DATA_DESCRIPTOR pdd = {};
  pdd.PropertyName = (ULONGLONG)((PBYTE)pInfo + propInfo->NameOffset);
  pdd.ArrayIndex = ULONG_MAX; // whole property

  // Ask size
  ULONG propSize = 0;
  ULONG status = TdhGetPropertySize(pEvent, 0, nullptr, 1, &pdd, &propSize);
  if (status != ERROR_SUCCESS) {
    // Could not get size — fallback to very small manual attempt or return empty
    // but we'll try some common alternative property names below
    propSize = 0;
  }

  // If we have a non-zero size, retrieve it
  std::vector<BYTE> data;
  if (propSize > 0) {
    data.resize(propSize);
    status = TdhGetProperty(pEvent, 0, nullptr, 1, &pdd, propSize, data.data());
    if (status != ERROR_SUCCESS) {
      data.clear();
    }
  }
  // First attempt: format what we just fetched (if any)
  USHORT inType = propInfo->nonStructType.InType;
  if (!data.empty()) {
    std::wstring formatted = FormatBasicProperty(inType, data.data(), data.size());
    if (!formatted.empty())
      return formatted;
  }

  // If empty and the property looks like a string, try a few common alternative names
  // often used by kernel registry / file events.
  const std::vector<std::wstring> altNames = {
      L"ObjectName", L"KeyName", L"RegNt.KeyName", L"RegNt.ObjectName",
      L"Key", L"FileName", L"FileNameOffset", L"FileNameLength", L"Value"};

  for (const auto &alt : altNames) {
    PROPERTY_DATA_DESCRIPTOR altPdd = {};
    altPdd.PropertyName = (ULONGLONG)alt.c_str();
    altPdd.ArrayIndex = ULONG_MAX;

    ULONG altSize = 0;
    ULONG rc = TdhGetPropertySize(pEvent, 0, nullptr, 1, &altPdd, &altSize);
    if (rc != ERROR_SUCCESS || altSize == 0)
      continue;

    std::vector<BYTE> altData(altSize);
    rc = TdhGetProperty(pEvent, 0, nullptr, 1, &altPdd, altSize, altData.data());
    if (rc == ERROR_SUCCESS && !altData.empty()) {
      // Try to format as Unicode string first, then fall back
      std::wstring out = FormatBasicProperty(TDH_INTYPE_UNICODESTRING, altData.data(), altData.size());
      if (!out.empty())
        return out;
      // Try as ANSI
      out = FormatBasicProperty(TDH_INTYPE_ANSISTRING, altData.data(), altData.size());
      if (!out.empty())
        return out;
      // General fallback
      return BytesToHex(altData.data(), (ULONG)altData.size());
    }
  }

  // Final fallback: empty hex preview of original data (or empty string)
  if (!data.empty())
    return BytesToHex(data.data(), (ULONG)data.size());

  return L"";
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

  // Extract human readable names
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
    for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; ++i) {
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

// Formats a timestamp from an event record
std::wstring readFromVm::FormatTimestamp(PEVENT_RECORD pEvent) {
  const unsigned int MAX_TIME_BUF_SIZE = 100;

  SYSTEMTIME st;
  FileTimeToSystemTime((FILETIME *)&pEvent->EventHeader.TimeStamp, &st);
  wchar_t timebuf[MAX_TIME_BUF_SIZE];
  swprintf_s(timebuf, L"%04u-%02u-%02u %02u:%02u:%02u",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

  return {timebuf};
}

// Converts a wstring to lowercase
std::wstring readFromVm::ToLowerW(const std::wstring &s) {
  std::wstring t = s;
  std::transform(t.begin(), t.end(), t.begin(), ::towlower);

  return t;
}
