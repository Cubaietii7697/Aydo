#include "processMonitor.hpp"

#include <windows.h>

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

std::set<DWORD> g_targetPids;
TRACEHANDLE g_hTrace = 0;
TRACEHANDLE g_hSession = 0;

// Find PIDs by process name
std::set<DWORD> processMonitor::FindPidByName(const std::wstring &exeName) {
  std::set<DWORD> pids;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) {
    return pids;
  }

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
void WINAPI processMonitor::StaticEventRecordCallback(PEVENT_RECORD pEvent) {
  // 33 = PhaseStart events (e.g. Kernel-Power, Resume/Suspend phases) – very frequent, low diagnostic value
  // 38 = Internal phase/telemetry events (provider-defined) – high volume, not tied to actionable operations
  // 44 = Provider-specific state/phase change events – noisy background activity with little forensic use
  const std::vector<int> OPCODES_TO_SKIP = {38, 33, 44};

  // Shouldn't happen, just a failsafe to make sure we don't print something that doesn't exist in memory
  if (!pEvent) {
    return;
  }

  DWORD pid = pEvent->EventHeader.ProcessId;

  // If the PID is not in the set of PIDs we are interested in, skip it
  if (!g_targetPids.contains(pid)) {
    return;
  }

  // Skip noisy opcodes
  auto opcode = (int)pEvent->EventHeader.EventDescriptor.Opcode;
  if (std::find(OPCODES_TO_SKIP.begin(), OPCODES_TO_SKIP.end(), opcode) != OPCODES_TO_SKIP.end()) {
    return;
  }

  // Get event metadata
  PTRACE_EVENT_INFO pInfo = nullptr;
  ULONG bufSize = 0;
  ULONG status = TdhGetEventInformation(pEvent, 0, nullptr, pInfo, &bufSize);
  if (status == ERROR_INSUFFICIENT_BUFFER) {
    pInfo = (PTRACE_EVENT_INFO)malloc(bufSize);
    if (!pInfo) {
      return;
    }

    status = TdhGetEventInformation(pEvent, 0, nullptr, pInfo, &bufSize);
  }
  if (status != ERROR_SUCCESS) {
    if (pInfo) {
      free(pInfo);
    }

    return;
  }

  std::wstring providerName = GetStringFromInfo(pInfo, pInfo->ProviderNameOffset);
  std::wstring eventName = GetStringFromInfo(pInfo, pInfo->EventNameOffset);
  std::wstring timestamp = FormatTimestamp(pEvent);

  // Print a concise header
  Logger::Info(std::format(L"[{}] PID: {} Provider: {} Event: {} Opcode: {}",
                           timestamp,
                           pid,
                           providerName.empty() ? std::to_wstring(pEvent->EventHeader.ProviderId.Data1) : providerName,
                           eventName.empty() ? std::to_wstring(pEvent->EventHeader.EventDescriptor.Id) : eventName,
                           opcode));

  // Print only matching properties
  if (pInfo->TopLevelPropertyCount > 0) {
    for (USHORT i = 0; i < pInfo->TopLevelPropertyCount; ++i) {
      EVENT_PROPERTY_INFO const &prop = pInfo->EventPropertyInfoArray[i];
      std::wstring propName = prop.NameOffset ? GetStringFromInfo(pInfo, prop.NameOffset) : L"<prop>";

      std::wstring val = FormatProperty(pInfo, pEvent, i);
      if (val.empty()) {
        val = L"(empty)";
        Logger::Info(std::format(L"\t{} = {}", propName, val));
      }
    }
  } else {
    Logger::Info(L"\t(no properties)");
  }

  if (pInfo) {
    free(pInfo);
  }
}

// Starts a kernel logging session
bool processMonitor::StartKernelSession(const std::wstring &sessionName,
                                        ULONG &outStatus) {
  const ULONG FLAGS = EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_THREAD |
                      EVENT_TRACE_FLAG_IMAGE_LOAD | EVENT_TRACE_FLAG_DISK_IO |
                      EVENT_TRACE_FLAG_NETWORK_TCPIP;
  const unsigned int WAIT_FOR_SESSION_STOP_MS = 200;

  const size_t propsSize =
      sizeof(EVENT_TRACE_PROPERTIES) + (MAX_PATH * sizeof(wchar_t)) * 2;
  auto pProps = (EVENT_TRACE_PROPERTIES *)malloc(propsSize);
  if (!pProps) {
    outStatus = ERROR_OUTOFMEMORY;
    Logger::Error(L"malloc EVENT_TRACE_PROPERTIES failed\n");

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
  Logger::Debug(std::format(L"StartTrace session='{}' EnableFlags=0x{:X}",
                            sessionName,
                            pProps->EnableFlags));

  outStatus = StartTraceW(&g_hSession, sessionName.c_str(), pProps);
  if (outStatus != ERROR_SUCCESS) {
    if (outStatus == ERROR_ALREADY_EXISTS) {
      Logger::Error(L"[WARN] StartTrace: session already exists, attempting stop/retry");
      ULONG ctrl = ControlTraceW(0, sessionName.c_str(), nullptr, EVENT_TRACE_CONTROL_STOP);
      Logger::Debug(std::format(L"ControlTrace stop returned {}", ctrl));
      Sleep(WAIT_FOR_SESSION_STOP_MS); // Wait for the session to be stopped
      outStatus = StartTraceW(&g_hSession, sessionName.c_str(), pProps);
    }
    if (outStatus != ERROR_SUCCESS) {
      Logger::Error(std::format(L"StartTrace failed: {}", outStatus));
      free(pProps);

      return false;
    }
  }

  Logger::Debug(std::format(L"StartTrace succeeded, session handle {}", outStatus));

  // Explicitly enable kernel providers too (best-practice in many setups).
  ULONG rc;
  rc = EnableTraceEx2(g_hSession, &GUID_KERNEL_FILE, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                      TRACE_LEVEL_VERBOSE, 0, 0, 0, nullptr);
  Logger::Debug(std::format(L"EnableTraceEx2 GUID_KERNEL_FILE -> {}", rc));

  rc = EnableTraceEx2(g_hSession, &GUID_KERNEL_REGISTRY, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                      TRACE_LEVEL_VERBOSE, 0, 0, 0, nullptr);
  Logger::Debug(std::format(L"EnableTraceEx2 GUID_KERNEL_REGISTRY -> {}", rc));

  // Enable kernel-network provider (the correct GUID, not a placeholder)
  rc = EnableTraceEx2(g_hSession, &GUID_KERNEL_NETWORK, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                      TRACE_LEVEL_VERBOSE, 0, 0, 0, nullptr);
  Logger::Debug(std::format(L"EnableTraceEx2 GUID_KERNEL_NETWORK -> {}", rc));

  free(pProps);

  return true;
}

// Stops the kernel session
void processMonitor::StopKernelSession(const std::wstring &sessionName) {
  Logger::Debug(std::format(L"Stopping kernel session '{}'", sessionName));

  if (g_hTrace && g_hTrace != INVALID_PROCESSTRACE_HANDLE) {
    CloseTrace(g_hTrace);
    g_hTrace = 0;
  }
  if (g_hSession) {
    ControlTraceW(g_hSession, sessionName.c_str(), nullptr, EVENT_TRACE_CONTROL_STOP);
    g_hSession = 0;
  }
}

// Starts logging events
bool processMonitor::OpenAndProcessRealTime(const std::wstring &sessionName) {
  Logger::Debug(std::format(L"Opening real-time trace for session '{}'", sessionName));

  EVENT_TRACE_LOGFILEW log = {};
  ZeroMemory(&log, sizeof(log));

  log.LoggerName = const_cast<LPWSTR>(sessionName.c_str());
  log.ProcessTraceMode =
      PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
  log.EventRecordCallback =
      (PEVENT_RECORD_CALLBACK)processMonitor::StaticEventRecordCallback;

  Logger::Debug(L"Calling OpenTraceW...");
  g_hTrace = OpenTraceW(&log);
  if (g_hTrace == INVALID_PROCESSTRACE_HANDLE) {
    DWORD error = GetLastError();
    Logger::Error(std::format(L"OpenTrace failed with error: {}", error));
    StopKernelSession(sessionName);

    return false;
  }
  Logger::Debug(std::format(L"OpenTraceW succeeded, handle: {}", g_hTrace));

  Logger::Debug(L"Starting ProcessTrace...");
  ULONG status = ProcessTrace(&g_hTrace, 1, nullptr, nullptr);
  Logger::Debug(std::format(L"ProcessTrace returned: {}", status));

  if (status == ERROR_SUCCESS) {
    Logger::Debug(L"ProcessTrace completed successfully");

    return true;
  }
  if (status == ERROR_CANCELLED) {
    Logger::Info(L"Trace stopped by user (ERROR_CANCELLED)");

    return true;
  }

  Logger::Error(std::format(L"ProcessTrace failed with status {}", status));

  return false;
}

// === HELPERS === //

// Formats basic property types (string, int, bool, etc)
// If the type is unknown, returns it as a hex string (up to MAX_HEX_BYTES_FOR_UNKOWN_TYPE bytes)
std::wstring processMonitor::FormatBasicProperty(USHORT inType, PBYTE propertyData, USHORT propertyLength) {
  const unsigned int MAX_HEX_BYTES_FOR_UNKOWN_TYPE = 8;

  if (!propertyData || propertyLength == 0) {
    return L"";
  }

  switch (inType) {
  case TDH_INTYPE_INT8:
    return std::to_wstring(*((INT8 *)propertyData));
  case TDH_INTYPE_UINT8:
    return std::to_wstring(*(propertyData));
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
      if (i < propertyLength - 1) {
        hexStr += L" ";
      }
    }

    return hexStr;
  }
}

// Gets a string from a event info memory with an offset
std::wstring processMonitor::GetStringFromInfo(PTRACE_EVENT_INFO pInfo,
                                               ULONG offset) {
  if (!pInfo || offset == 0) {
    return L"";
  }

  auto p = (PWSTR)((PBYTE)pInfo + offset);

  return {p};
}

// Formats bytes as a hex string
std::wstring processMonitor::BytesToHex(const BYTE *data, ULONG size, ULONG maxBytes) {
  if (!data || size == 0) {
    return L"";
  }

  std::wostringstream oss;
  ULONG toShow = (size > maxBytes) ? maxBytes : size;
  for (ULONG i = 0; i < toShow; ++i) {
    if (i) {
      oss << L" ";
    }

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
std::wstring processMonitor::FormatProperty(PTRACE_EVENT_INFO pInfo,
                                            PEVENT_RECORD pEvent,
                                            USHORT propertyIndex) {
  if (!pInfo || !pEvent) {
    return L"";
  }

  EVENT_PROPERTY_INFO const *propInfo = &pInfo->EventPropertyInfoArray[propertyIndex];

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
    std::wstring formatted = FormatBasicProperty(inType, data.data(), USHORT(data.size()));
    if (!formatted.empty()) {
      return formatted;
    }
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
    if (rc != ERROR_SUCCESS || altSize == 0) {
      continue;
    }

    std::vector<BYTE> altData(altSize);
    rc = TdhGetProperty(pEvent, 0, nullptr, 1, &altPdd, altSize, altData.data());
    if (rc == ERROR_SUCCESS && !altData.empty()) {
      // Try to format as Unicode string first, then fall back
      std::wstring out = FormatBasicProperty(TDH_INTYPE_UNICODESTRING, altData.data(), USHORT(altData.size()));
      if (!out.empty()) {
        return out;
      }

      // Try as ANSI
      out = FormatBasicProperty(TDH_INTYPE_ANSISTRING, altData.data(), USHORT(altData.size()));
      if (!out.empty()) {
        return out;
      }

      // General fallback
      return BytesToHex(altData.data(), (ULONG)altData.size());
    }
  }

  // Final fallback: empty hex preview of original data (or empty string)
  if (!data.empty()) {
    return BytesToHex(data.data(), (ULONG)data.size());
  }

  return L"";
}

// BIG helper: print an entire event in a readable way.
// Call this from StaticEventRecordCallback (it is safe-ish to call from
// callback; keep output minimal)
void processMonitor::PrintEventDetailed(PEVENT_RECORD pEvent) {
  if (!pEvent) {
    return;
  }

  // Get trace event info
  PTRACE_EVENT_INFO pInfo = nullptr;
  ULONG bufferSize = 0;
  ULONG status = TdhGetEventInformation(pEvent, 0, nullptr, pInfo, &bufferSize);
  if (status == ERROR_INSUFFICIENT_BUFFER) {
    pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
    if (!pInfo) {
      return;
    }

    status = TdhGetEventInformation(pEvent, 0, nullptr, pInfo, &bufferSize);
  }
  if (status != ERROR_SUCCESS) {
    // fallback minimal info
    Logger::Info(std::format(
        L"[ETW] Provider={:X} EID={} Op={} Level={} PID={}",
        pEvent->EventHeader.ProviderId.Data1,
        pEvent->EventHeader.EventDescriptor.Id,
        (int)pEvent->EventHeader.EventDescriptor.Opcode,
        (int)pEvent->EventHeader.EventDescriptor.Level,
        pEvent->EventHeader.ProcessId));
    if (pInfo) {
      free(pInfo);
    }

    return;
  }

  // Extract human readable names
  std::wstring providerName = GetStringFromInfo(pInfo, pInfo->ProviderNameOffset);
  std::wstring taskName = GetStringFromInfo(pInfo, pInfo->TaskNameOffset);
  std::wstring opcodeName = GetStringFromInfo(pInfo, pInfo->OpcodeNameOffset);
  std::wstring eventName = GetStringFromInfo(pInfo, pInfo->EventNameOffset);
  std::wstring keywords = GetStringFromInfo(pInfo, pInfo->KeywordsNameOffset);

  // Print header
  Logger::Info(std::format(
      L"[ETW] Provider: {} Event: {} Task: {} Opcode: {} Level: {} PID: {}",
      providerName.empty() ? std::to_wstring(pEvent->EventHeader.ProviderId.Data1) : providerName,
      eventName.empty() ? std::to_wstring(pEvent->EventHeader.EventDescriptor.Id) : eventName,
      taskName.empty() ? L"-" : taskName,
      opcodeName.empty() ? std::to_wstring((int)pEvent->EventHeader.EventDescriptor.Opcode) : opcodeName,
      (int)pEvent->EventHeader.EventDescriptor.Level,
      pEvent->EventHeader.ProcessId));

  // print properties if any
  if (pInfo->TopLevelPropertyCount > 0) {
    for (USHORT i = 0; i < pInfo->TopLevelPropertyCount; ++i) {
      EVENT_PROPERTY_INFO const &prop = pInfo->EventPropertyInfoArray[i];
      std::wstring propName = prop.NameOffset
                                  ? (PWSTR)((PBYTE)pInfo + prop.NameOffset)
                                  : L"<prop>";
      std::wstring val = FormatProperty(pInfo, pEvent, i);
      Logger::Info(std::format(L"\t{} = {}", propName, val));
    }
  } else {
    Logger::Info(L"\t(no properties)");
  }

  if (pInfo) {
    free(pInfo);
  }
}

// Formats a timestamp from an event record
std::wstring processMonitor::FormatTimestamp(PEVENT_RECORD pEvent) {
  const unsigned int MAX_TIME_BUF_SIZE = 100;

  SYSTEMTIME st;
  FileTimeToSystemTime((FILETIME *)&pEvent->EventHeader.TimeStamp, &st);
  wchar_t timebuf[MAX_TIME_BUF_SIZE];
  swprintf_s(timebuf, L"%04u-%02u-%02u %02u:%02u:%02u",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

  return {timebuf};
}

// Converts a wstring to lowercase
std::wstring processMonitor::ToLowerW(const std::wstring &s) {
  std::wstring t = s;
  std::transform(t.begin(), t.end(), t.begin(), ::towlower);

  return t;
}
