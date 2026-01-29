#include "Utils.hpp"
#include "../IOCTLs.hpp"
#include "Constants.hpp"
#include "Logger.hpp"

namespace FileProtection {

BOOLEAN isProtectedPath(PUNICODE_STRING filePath) {
  if (filePath == nullptr || filePath->Buffer == nullptr || filePath->Length == 0) {
    return FALSE;
  }

  // Convert to uppercase for case-insensitive comparison
  UNICODE_STRING upperPath;
  upperPath.Length = filePath->Length;
  upperPath.MaximumLength = filePath->MaximumLength;
  upperPath.Buffer = (PWCH)ExAllocatePoolZero(PagedPool, filePath->MaximumLength, 'tPpU');

  if (upperPath.Buffer == nullptr) {
    return FALSE;
  }

  RtlCopyUnicodeString(&upperPath, filePath);
  RtlUpcaseUnicodeString(&upperPath, &upperPath, FALSE);

  // Find where the volume name ends (\Device\HarddiskVolumeX\Users...)
  UNICODE_STRING searchPath = upperPath;
  if (upperPath.Length >= 8 * sizeof(WCHAR) && _wcsnicmp(upperPath.Buffer, L"\\DEVICE\\", 8) == 0) {
    USHORT backslashCount = 0;
    for (size_t i = 0; i < (size_t)(upperPath.Length / sizeof(WCHAR)); i++) {
      if (upperPath.Buffer[i] == L'\\') {
        backslashCount++;
        if (backslashCount == 3) {
          searchPath.Buffer = &upperPath.Buffer[i];
          // Add bounds checking to prevent USHORT overflow
          size_t lengthBytes = upperPath.Length - (i * sizeof(WCHAR));
          if (lengthBytes > MAXUSHORT) {
            lengthBytes = MAXUSHORT;
          }
          searchPath.Length = (USHORT)lengthBytes;
          searchPath.MaximumLength = searchPath.Length;
          break;
        }
      }
    }
  }

  UNICODE_STRING protectedDir1, protectedDir2;
  RtlInitUnicodeString(&protectedDir1, Constants::PROTECTED_DIR_1);
  RtlInitUnicodeString(&protectedDir2, Constants::PROTECTED_DIR_2);

  // Convert protected paths to uppercase
  UNICODE_STRING upperProtected1, upperProtected2;
  upperProtected1.Length = protectedDir1.Length;
  upperProtected1.MaximumLength = protectedDir1.MaximumLength;
  upperProtected1.Buffer = (PWCH)ExAllocatePoolZero(PagedPool, protectedDir1.MaximumLength, '1PpU');

  upperProtected2.Length = protectedDir2.Length;
  upperProtected2.MaximumLength = protectedDir2.MaximumLength;
  upperProtected2.Buffer = (PWCH)ExAllocatePoolZero(PagedPool, protectedDir2.MaximumLength, '2PpU');

  BOOLEAN isProtected = FALSE;

  // Fix memory leak: Check both allocations succeeded before proceeding
  if (!upperProtected1.Buffer || !upperProtected2.Buffer) {
    // Cleanup any successful allocation
    if (upperProtected1.Buffer) {
      ExFreePoolWithTag(upperProtected1.Buffer, '1PpU');
    }
    if (upperProtected2.Buffer) {
      ExFreePoolWithTag(upperProtected2.Buffer, '2PpU');
    }
    ExFreePoolWithTag(upperPath.Buffer, 'tPpU');
    return FALSE;
  }

  RtlCopyUnicodeString(&upperProtected1, &protectedDir1);
  RtlUpcaseUnicodeString(&upperProtected1, &upperProtected1, FALSE);

  RtlCopyUnicodeString(&upperProtected2, &protectedDir2);
  RtlUpcaseUnicodeString(&upperProtected2, &upperProtected2, FALSE);

  // Check if path starts with protected directory
  isProtected = RtlPrefixUnicodeString(&upperProtected1, &searchPath, TRUE) ||
                RtlPrefixUnicodeString(&upperProtected2, &searchPath, TRUE);

  // Cleanup
  ExFreePoolWithTag(upperProtected1.Buffer, '1PpU');
  ExFreePoolWithTag(upperProtected2.Buffer, '2PpU');
  ExFreePoolWithTag(upperPath.Buffer, 'tPpU');

  return isProtected;
}

BOOLEAN isProtectedProcess() {
  HANDLE currentPID = PsGetCurrentProcessId();
  KIRQL oldIrql;
  HANDLE protectedPID;

  KeAcquireSpinLock(&g_filterData.Lock, &oldIrql);
  protectedPID = g_filterData.ProtectedPID;
  KeReleaseSpinLock(&g_filterData.Lock, oldIrql);

  return currentPID == protectedPID;
}

NTSTATUS connectToCoreDriver() {
  UNICODE_STRING deviceName;
  OBJECT_ATTRIBUTES objAttr;
  IO_STATUS_BLOCK iosb;
  NTSTATUS status;

  RtlInitUnicodeString(&deviceName, Constants::CORE_DEVICE_NAME);
  InitializeObjectAttributes(&objAttr, &deviceName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);

  status = ZwCreateFile(
      &g_filterData.CoreDriverHandle,
      GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
      &objAttr,
      &iosb,
      nullptr,
      0,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      FILE_OPEN,
      FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
      nullptr,
      0);

  if (NT_SUCCESS(status)) {
    status = getProtectedPID();
  }

  return status;
}

NTSTATUS getProtectedPID() {
  if (g_filterData.CoreDriverHandle == nullptr) {
    return STATUS_INVALID_HANDLE;
  }

  IO_STATUS_BLOCK iosb;
  HANDLE pid = nullptr;

  NTSTATUS status = ZwDeviceIoControlFile(
      g_filterData.CoreDriverHandle,
      nullptr,
      nullptr,
      nullptr,
      &iosb,
      IOCTL_GET_PROTECTED_PID,
      nullptr,
      0,
      &pid,
      sizeof(HANDLE));

  if (NT_SUCCESS(status)) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_filterData.Lock, &oldIrql);
    g_filterData.ProtectedPID = pid;
    KeReleaseSpinLock(&g_filterData.Lock, oldIrql);

    LOG_INFO("Protected PID set to %lu", (ULONG)(ULONG_PTR)pid);
  }

  return status;
}

BOOLEAN isExecutable(PUNICODE_STRING extension) {
  if (extension == nullptr || extension->Length == 0) {
    return FALSE;
  }
  if (extension->Length > 64) {
    return FALSE;
  }

  WCHAR ext[32] = {0};
  USHORT copyLen = (USHORT)min((ULONG)extension->Length, (ULONG)sizeof(ext) - (ULONG)sizeof(WCHAR));
  RtlCopyMemory(ext, extension->Buffer, copyLen);

  for (USHORT i = 0; i < copyLen / (USHORT)sizeof(WCHAR); i++) {
    ext[i] = (WCHAR)RtlDowncaseUnicodeChar(ext[i]);
  }

  UNICODE_STRING uExt;
  uExt.Buffer = ext;
  uExt.Length = copyLen;
  uExt.MaximumLength = sizeof(ext);

  UNICODE_STRING dangerousExts[] = {
      RTL_CONSTANT_STRING(L"exe"),
      RTL_CONSTANT_STRING(L"dll"),
      RTL_CONSTANT_STRING(L"sys"),
      RTL_CONSTANT_STRING(L"scr"),
      RTL_CONSTANT_STRING(L"bat"),
      RTL_CONSTANT_STRING(L"cmd"),
      RTL_CONSTANT_STRING(L"ps1")};

  for (ULONG i = 0; i < sizeof(dangerousExts) / sizeof(dangerousExts[0]); i++) {
    if (RtlCompareUnicodeString(&uExt, &dangerousExts[i], TRUE) == 0) {
      return TRUE;
    }
  }
  return FALSE;
}

} // namespace FileProtection
