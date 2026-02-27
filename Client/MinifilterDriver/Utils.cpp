#include "utils.hpp"

#include "Logger.hpp"
#include "Minifilter.hpp"
#include "ntstrsafe.h"

namespace Minifilter {

static NTSTATUS QueryDriveNtDeviceName(
    _In_ WCHAR DriveLetter,
    _Out_writes_(OutCch) PWCHAR Out,
    _In_ SIZE_T OutCch) {
  if (Out == nullptr || OutCch == 0) {
    return STATUS_INVALID_PARAMETER;
  }

  // 8 wide chars for the size of the path
  WCHAR linkNameBuf[8] = {0};
  NTSTATUS status = RtlStringCchPrintfW(linkNameBuf, ARRAYSIZE(linkNameBuf), L"\\??\\%c:", DriveLetter);
  CHECK_NT_RETURN(status, "RtlStringCchPrintfW failed 0x%08x", status);

  UNICODE_STRING linkName;
  RtlInitUnicodeString(&linkName, linkNameBuf);

  OBJECT_ATTRIBUTES oa;
  InitializeObjectAttributes(&oa, &linkName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

  HANDLE linkHandle = nullptr;
  status = ZwOpenSymbolicLinkObject(&linkHandle, GENERIC_READ, &oa);
  CHECK_NT_RETURN(status, "ZwOpenSymbolicLinkObject failed 0x%08x", status);

  UNICODE_STRING target;
  target.Buffer = Out;
  target.Length = 0;
  target.MaximumLength = (USHORT)min((SIZE_T)0xFFFF, OutCch * sizeof(WCHAR));

  ULONG returnedLength = 0;
  status = ZwQuerySymbolicLinkObject(linkHandle, &target, &returnedLength);
  ZwClose(linkHandle);

  CHECK_NT_RETURN(status, "ZwQuerySymbolicLinkObject failed 0x%08x", status);

  if (target.MaximumLength < sizeof(WCHAR)) {
    return STATUS_BUFFER_TOO_SMALL;
  }

  Out[(target.Length / sizeof(WCHAR))] = L'\0';
  return STATUS_SUCCESS;
}

NTSTATUS
InitProtectedPathFromDosPath(
    _In_ PCWSTR DosPath // e.g. L"C:\\Users\\KAN12\\Desktop\\Aydo"
) {
  if (DosPath == nullptr || DosPath[0] == L'\0') {
    return STATUS_INVALID_PARAMETER;
  }

  // If caller passes our global buffer as input, we must not write into it while still reading.
  // This happens because DriverEntryImpl currently calls InitProtectedPathFromDosPath(gState.ProtectedPath.Buffer)
  // after loading the registry value into gState.ProtectedPathBuffer.
  WCHAR inputCopy[ARRAYSIZE(gState.ProtectedPathBuffer)] = {0};
  PCWSTR stableInput = DosPath;
  if (DosPath == gState.ProtectedPathBuffer) {
    NTSTATUS copyStatus = RtlStringCchCopyW(inputCopy, ARRAYSIZE(inputCopy), DosPath);
    CHECK_NT_RETURN(copyStatus, "RtlStringCchCopyW failed 0x%08x", copyStatus);
    stableInput = inputCopy;
  }

  if (stableInput[0] == L'\\') {
    SIZE_T bytes = (wcslen(stableInput) + 1) * sizeof(WCHAR);
    if (bytes > sizeof(gState.ProtectedPathBuffer)) {
      return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(gState.ProtectedPathBuffer, sizeof(gState.ProtectedPathBuffer));
    RtlCopyMemory(gState.ProtectedPathBuffer, stableInput, bytes);
    RtlInitUnicodeString(&gState.ProtectedPath, gState.ProtectedPathBuffer);
    DbgPrint("Protected NT path (direct) = %wZ\n", &gState.ProtectedPath);
    return STATUS_SUCCESS;
  }

  if (!((stableInput[0] >= L'A' && stableInput[0] <= L'Z') || (stableInput[0] >= L'a' && stableInput[0] <= L'z')) ||
      stableInput[1] != L':') {
    return STATUS_INVALID_PARAMETER;
  }

  WCHAR driveLetter = (WCHAR)RtlUpcaseUnicodeChar(stableInput[0]);

  WCHAR deviceNameBuf[256] = {0};
  NTSTATUS status = QueryDriveNtDeviceName(driveLetter, deviceNameBuf, ARRAYSIZE(deviceNameBuf));
  CHECK_NT_RETURN(status, "QueryDriveNtDeviceName failed 0x%08x", status);

  PCWSTR subPath = stableInput + 2;
  if (subPath[0] == L'\0') {
    subPath = L"\\";
  }

  status = RtlStringCchPrintfW(
      gState.ProtectedPathBuffer,
      ARRAYSIZE(gState.ProtectedPathBuffer),
      L"%s%s",
      deviceNameBuf,
      subPath);
  CHECK_NT_RETURN_CLEANUP(status, 
    RtlZeroMemory(gState.ProtectedPathBuffer, sizeof(gState.ProtectedPathBuffer));, 
    "RtlStringCchPrintfW failed 0x%08x", status);

  RtlInitUnicodeString(&gState.ProtectedPath, gState.ProtectedPathBuffer);
  DbgPrint("Protected NT path (converted) = %wZ\n", &gState.ProtectedPath);
  return STATUS_SUCCESS;
}

BOOLEAN
IsPathProtected(
    _In_ PUNICODE_STRING Name) {
  if (Name == nullptr || Name->Buffer == nullptr) {
    return FALSE;
  }

  if (gState.ProtectedPath.Buffer == nullptr || gState.ProtectedPath.Length == 0) {
    return FALSE;
  }

  if (Name->Length < gState.ProtectedPath.Length) {
    return FALSE;
  }

  return RtlPrefixUnicodeString(&gState.ProtectedPath, Name, TRUE) ? TRUE : FALSE;
}

NTSTATUS
LoadProtectedPathFromRegistry(
    _In_ PUNICODE_STRING RegistryPath) {
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  OBJECT_ATTRIBUTES objAttr;
  HANDLE key = NULL;
  UNICODE_STRING valueName;
  ULONG requiredLength = 0;
  PKEY_VALUE_PARTIAL_INFORMATION kv = NULL;
  SIZE_T allocSize = 0;

  if (RegistryPath == NULL || RegistryPath->Buffer == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  InitializeObjectAttributes(&objAttr, RegistryPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

  status = ZwOpenKey(&key, KEY_QUERY_VALUE, &objAttr);
  CHECK_NT_RETURN(status, "ZwOpenKey failed 0x%08x", status);

  RtlInitUnicodeString(&valueName, L"ProtectedPath");

  // Query to get required buffer size
  status = ZwQueryValueKey(key, &valueName, KeyValuePartialInformation, NULL, 0, &requiredLength);
  if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {
    LOG_ERROR("ZwQueryValueKey initial returned 0x%08x", status);
    ZwClose(key);
    return status;
  }

  allocSize = requiredLength;
#if defined(_MSC_VER) && !defined(__clang__)
  kv = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, allocSize, Constants::PROTECTED_POOL_TAG);
#else
  kv = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPoolNx, allocSize, Constants::PROTECTED_POOL_TAG);
#endif
  if (kv == NULL) {
    ZwClose(key);
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  status = ZwQueryValueKey(key, &valueName, KeyValuePartialInformation, kv, (ULONG)allocSize, &requiredLength);
  CHECK_NT_RETURN_CLEANUP(status, 
    ExFreePoolWithTag(kv, Constants::PROTECTED_POOL_TAG);
    ZwClose(key);, 
    "ZwQueryValueKey read failed 0x%08x", status);

  // We expect a string
  if (kv->Type != REG_SZ && kv->Type != REG_EXPAND_SZ) {
    LOG_ERROR("Registry value type not string: %u", kv->Type);
    ExFreePoolWithTag(kv, Constants::PROTECTED_POOL_TAG);
    ZwClose(key);
    return STATUS_INVALID_PARAMETER;
  }

  // Ensure we don't overflow our buffer; kv->DataLength is in bytes.
  if (kv->DataLength == 0) {
    ExFreePoolWithTag(kv, Constants::PROTECTED_POOL_TAG);
    ZwClose(key);
    return STATUS_INVALID_PARAMETER;
  }

  // number of WCHARs we can store (including null)
  SIZE_T maxWchars = ARRAYSIZE(gState.ProtectedPathBuffer);
  SIZE_T bytesToCopy = kv->DataLength;
  SIZE_T wcharCount = (bytesToCopy / sizeof(WCHAR));

  // clamp
  if (wcharCount >= maxWchars) {
    // copy up to maxWchars-1 and null terminate
    wcharCount = maxWchars - 1;
    bytesToCopy = wcharCount * sizeof(WCHAR);
  }

  RtlZeroMemory(gState.ProtectedPathBuffer, sizeof(gState.ProtectedPathBuffer));
  RtlCopyMemory(gState.ProtectedPathBuffer, kv->Data, bytesToCopy);
  // ensure null termination already by zeroing

  // Initialize UNICODE_STRING from buffer
  RtlInitUnicodeString(&gState.ProtectedPath, gState.ProtectedPathBuffer);

  LOG_INFO("CONFIG: %wZ", &gState.ProtectedPath);

  ExFreePoolWithTag(kv, Constants::PROTECTED_POOL_TAG);
  ZwClose(key);

  return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS
BlockIfProtected(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo) {
  if (NameInfo == NULL) {
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

  if (IsPathProtected(&NameInfo->Name)) {
    // Deny access. Set IoStatus and return COMPLETE.
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;

    LOG_WARNING("BLOCKED: %wZ", &NameInfo->Name);
    return FLT_PREOP_COMPLETE;
  }

  // small op logging to confirm behavior (first few ops)
  if (gState.OpLogCount < 8) {
    LOG_DEBUG("ALLOW: %wZ", &NameInfo->Name);
    gState.OpLogCount++;
  }

  return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

} // namespace Minifilter
