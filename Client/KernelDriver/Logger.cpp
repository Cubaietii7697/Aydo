#include <wdm.h>
#include <stdarg.h>

#include "Logger.hpp"

void Logger::log(LogLevel level, const char *format, ...) {
  va_list args;
  va_start(args, format);

  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[AydoKernelDriver: %s] ", _getLogLevelString(level));
  vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, format, args);
  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "\n");

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