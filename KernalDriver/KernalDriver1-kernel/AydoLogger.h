#pragma once
#include <ntddk.h>

#include <stdarg.h>

typedef enum {
  AYDO_LOG_DEBUG = 0,
  AYDO_LOG_INFO = 1,
  AYDO_LOG_WARNING = 2,
  AYDO_LOG_ERROR = 3
} AydoLogLevel;

static inline const char *aydoLogLevelStr(AydoLogLevel lvl) {
  switch (lvl) {
  case AYDO_LOG_DEBUG:
    return "debug";
  case AYDO_LOG_INFO:
    return "info";
  case AYDO_LOG_WARNING:
    return "warning";
  case AYDO_LOG_ERROR:
    return "error";
  default:
    return "info";
  }
}

static inline void aydoLog(AydoLogLevel lvl, const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
             "[AydoKernelDriver: %s] ", aydoLogLevelStr(lvl));
  vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, fmt, args);
  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "\n");
  va_end(args);
}

// convenience macros
#define AYDO_DEBUG(fmt, ...) aydoLog(AYDO_LOG_DEBUG, fmt, __VA_ARGS__)
#define AYDO_INFO(fmt, ...) aydoLog(AYDO_LOG_INFO, fmt, __VA_ARGS__)
#define AYDO_WARNING(fmt, ...) aydoLog(AYDO_LOG_WARNING, fmt, __VA_ARGS__)
#define AYDO_ERROR(fmt, ...) aydoLog(AYDO_LOG_ERROR, fmt, __VA_ARGS__)
