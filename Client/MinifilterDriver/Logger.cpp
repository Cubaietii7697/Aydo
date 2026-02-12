#include <fltKernel.h>
#include <ntstrsafe.h>
#include <stdarg.h>

#include "Logger.hpp"

void Logger::log(LogLevel level, const char *format, ...) {
  const char *levelStr = _getLogLevelString(level);
  va_list args;
  va_start(args, format);

  // Check if format contains %wZ - if so, handle it specially
  if (strstr(format, "%wZ") != nullptr) {
    PUNICODE_STRING unicodeStr = va_arg(args, PUNICODE_STRING);

    // Only log if we have a valid unicode string
    if (unicodeStr && unicodeStr->Buffer && unicodeStr->Length > 0) {
      // Extract the prefix from the format string
      if (strstr(format, "BLOCKED:") != nullptr) {
        DbgPrint("[AydoMinifilter:%s] BLOCKED: %.*ws\n", levelStr,
                 unicodeStr->Length / sizeof(WCHAR), unicodeStr->Buffer);
      } else if (strstr(format, "EXEC:") != nullptr) {
        DbgPrint("[AydoMinifilter:%s] EXEC: %.*ws\n", levelStr,
                 unicodeStr->Length / sizeof(WCHAR), unicodeStr->Buffer);
      } else if (strstr(format, "SCAN:") != nullptr) {
        DbgPrint("[AydoMinifilter:%s] SCAN: %.*ws\n", levelStr,
                 unicodeStr->Length / sizeof(WCHAR), unicodeStr->Buffer);
      } else if (strstr(format, "WRITE:") != nullptr) {
        DbgPrint("[AydoMinifilter:%s] WRITE: %.*ws\n", levelStr,
                 unicodeStr->Length / sizeof(WCHAR), unicodeStr->Buffer);
      } else if (strstr(format, "ALLOW (no service):") != nullptr) {
        DbgPrint("[AydoMinifilter:%s] ALLOW (no service): %.*ws\n", levelStr,
                 unicodeStr->Length / sizeof(WCHAR), unicodeStr->Buffer);
      } else if (strstr(format, "ALLOW WRITE (no service):") != nullptr) {
        DbgPrint("[AydoMinifilter:%s] ALLOW WRITE (no service): %.*ws\n", levelStr,
                 unicodeStr->Length / sizeof(WCHAR), unicodeStr->Buffer);
      } else if (strstr(format, "ALLOW:") != nullptr) {
        DbgPrint("[AydoMinifilter:%s] ALLOW: %.*ws\n", levelStr,
                 unicodeStr->Length / sizeof(WCHAR), unicodeStr->Buffer);
      } else if (strstr(format, "CONFIG:") != nullptr) {
        DbgPrint("[AydoMinifilter:%s] CONFIG: %.*ws\n", levelStr,
                 unicodeStr->Length / sizeof(WCHAR), unicodeStr->Buffer);
      } else {
        // SUPPRESS any other %wZ patterns - they're causing the unwanted path dumps
        // Don't print anything for these
      }
    }
  } else {
    // For format strings without %wZ, print them normally
    char formatted[512] = {0};
    (void)RtlStringCbVPrintfA(formatted, sizeof(formatted), format, args);
    DbgPrint("[AydoMinifilter:%s] %s\n", levelStr, formatted);
  }

  va_end(args);
}

const char *Logger::_getLogLevelString(LogLevel level) {
  switch (level) {
  case LogLevel::LOG_DEBUG:
    return "DEBUG";
  case LogLevel::LOG_INFO:
    return "INFO";
  case LogLevel::LOG_WARNING:
    return "WARNING";
  case LogLevel::LOG_ERROR:
    return "ERROR";
  default:
    return "UNKNOWN";
  }
}