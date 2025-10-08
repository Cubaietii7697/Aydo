#pragma once
#include <stdarg.h>

#include "../pch.hpp"

typedef enum {
  AYDO_LOG_DEBUG = 0,
  AYDO_LOG_INFO = 1,
  AYDO_LOG_WARNING = 2,
  AYDO_LOG_ERROR = 3
} AydoLogLevel;

extern "C" const char *aydoLogLevelStr(AydoLogLevel lvl);
extern "C" void aydoLog(AydoLogLevel lvl, const char *fmt, ...);

#define AYDO_DEBUG(fmt, ...) aydoLog(AYDO_LOG_DEBUG, fmt, __VA_ARGS__)
#define AYDO_INFO(fmt, ...) aydoLog(AYDO_LOG_INFO, fmt, __VA_ARGS__)
#define AYDO_WARNING(fmt, ...) aydoLog(AYDO_LOG_WARNING, fmt, __VA_ARGS__)
#define AYDO_ERROR(fmt, ...) aydoLog(AYDO_LOG_ERROR, fmt, __VA_ARGS__)
