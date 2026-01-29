#pragma once

#include <ntifs.h>
#include <fltKernel.h>

namespace FileProtection {

// OS Version Info
#define AYDO_FILTER_VERSION_MAJOR 1
#define AYDO_FILTER_VERSION_MINOR 0

// Driver State
enum DriverState {
  DriverStateStopped = 0,
  DriverStateStarting,
  DriverStateRunning,
  DriverStateStopping
};

// Scan Reasons
enum ScanReason {
  ScanReasonExecute = 0,
  ScanReasonWriteComplete,
  ScanReasonRename,
  ScanReasonProcessCreation
};

typedef struct Config {
  ULONG64 MaxScanSize;
} Config, *PConfig;

// File Context Structure
typedef struct FileContext {
  ULONG Magic;
  ULONG64 FileId;
  USHORT FileNameLength;
  WCHAR FileName[512];

  BOOLEAN IsDirectory;
  BOOLEAN IsExecutable;
  BOOLEAN ScanPending;
  BOOLEAN IsModified;
  volatile LONG ReferenceCount;

  ULONG CacheTtl;
  LARGE_INTEGER CacheExpiry;
  UCHAR CachedHash[32];

  EX_PUSH_LOCK ContextLock;
  LIST_ENTRY ListEntry;
} FileContext, *PFileContext;

// Scan Request Header (shared with user-mode)
typedef struct ScanRequest {
  ULONG RequestId;
  HANDLE ProcessId;
  ACCESS_MASK DesiredAccess;
  USHORT FileNameLength;
  WCHAR FileName[512];
  UCHAR FileHash[32];
  BOOLEAN IsExecute;
  ULONG Reason; // ScanReason
} ScanRequest, *PScanRequest;

typedef struct ScanResponse {
  ULONG RequestId;
  NTSTATUS Status;
  ULONG Verdict; // 0=Clean, 1=Malicious, 2=Unknown
  ULONG ThreatLevel;
  WCHAR ThreatName[64];
} ScanResponse, *PScanResponse;

typedef struct FILTER_DATA {
  PFLT_FILTER FilterHandle;
  PFLT_PORT ServerPort; // Server port for communication
  PFLT_PORT ClientPort; // Current connected client port
  HANDLE CoreDriverHandle;
  HANDLE ProtectedPID;
  KSPIN_LOCK Lock;

  // AV Specific
  volatile LONG DriverState;
  volatile ULONG64 TotalFilesScanned;
  volatile ULONG64 CacheHits;
  volatile ULONG64 ThreatsBlocked;

  LIST_ENTRY ContextList;
  KSPIN_LOCK ContextListLock;
  volatile ULONG ContextCount;

  // Configuration
  ULONG64 MaxScanSize;

  KEVENT ShutdownEvent;
} FILTER_DATA, *PFILTER_DATA;

extern FILTER_DATA g_filterData;

// Forward declarations
FLT_PREOP_CALLBACK_STATUS preCreateCallback(
    PFLT_CALLBACK_DATA data,
    PCFLT_RELATED_OBJECTS fltObjects,
    PVOID *completionContext);

FLT_POSTOP_CALLBACK_STATUS postCreateCallback(
    PFLT_CALLBACK_DATA data,
    PCFLT_RELATED_OBJECTS fltObjects,
    PVOID completionContext,
    FLT_POST_OPERATION_FLAGS flags);

FLT_PREOP_CALLBACK_STATUS preSetInformationCallback(
    PFLT_CALLBACK_DATA data,
    PCFLT_RELATED_OBJECTS fltObjects,
    PVOID *completionContext);

FLT_PREOP_CALLBACK_STATUS preWriteCallback(
    PFLT_CALLBACK_DATA data,
    PCFLT_RELATED_OBJECTS fltObjects,
    PVOID *completionContext);

FLT_PREOP_CALLBACK_STATUS preCleanupCallback(
    PFLT_CALLBACK_DATA data,
    PCFLT_RELATED_OBJECTS fltObjects,
    PVOID *completionContext);

void contextCleanup(
    PFLT_CONTEXT context,
    FLT_CONTEXT_TYPE contextType);

NTSTATUS instanceSetup(
    PCFLT_RELATED_OBJECTS fltObjects,
    FLT_INSTANCE_SETUP_FLAGS flags,
    DEVICE_TYPE volumeDeviceType,
    FLT_FILESYSTEM_TYPE volumeFilesystemType);

NTSTATUS instanceQueryTeardown(
    PCFLT_RELATED_OBJECTS fltObjects,
    FLT_INSTANCE_QUERY_TEARDOWN_FLAGS flags);

// Port Callbacks
NTSTATUS portConnect(
    PFLT_PORT clientPort,
    PVOID serverPortCookie,
    PVOID connectionContext,
    ULONG sizeOfContext,
    PVOID *connectionCookie);

void portDisconnect(PVOID connectionCookie);

NTSTATUS portMessage(
    PVOID portCookie,
    PVOID inputBuffer,
    ULONG inputBufferLength,
    PVOID outputBuffer,
    ULONG outputBufferLength,
    PULONG returnOutputBufferLength);

NTSTATUS initialize(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath);
void cleanup();
NTSTATUS unload(FLT_FILTER_UNLOAD_FLAGS flags);

PFileContext createFileContext();
void referenceContext(PFileContext context);
void dereferenceContext(PFileContext context);

NTSTATUS sendSyncScanRequest(
    PScanRequest request,
    ULONG requestSize,
    PScanResponse response,
    ULONG responseSize);

// Process Notification
NTSTATUS registerProcessCallbacks();
void unregisterProcessCallbacks();
void onProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);

// Callbacks and Registration
extern const FLT_OPERATION_REGISTRATION Callbacks[];
extern const FLT_CONTEXT_REGISTRATION ContextNotifications[];
extern const FLT_REGISTRATION FilterRegistration;

} // namespace FileProtection