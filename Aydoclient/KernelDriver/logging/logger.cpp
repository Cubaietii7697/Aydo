#include "logger.hpp"

#include "../pch.hpp"

extern "C" const char *aydoLogLevelStr(AydoLogLevel lvl) {
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

extern "C" void aydoLog(AydoLogLevel lvl, const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
             "[AydoKernelDriver: %s] ", aydoLogLevelStr(lvl));
  vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, fmt, args);
  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "\n");
  va_end(args);
}
